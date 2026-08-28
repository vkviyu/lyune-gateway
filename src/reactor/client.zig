//! reactor/client.zig
//!
//! 基于 libxev 的异步 QUIC 客户端。
//! 可以在单线程中与 Server 共享同一个事件循环。

const std = @import("std");
const xev = @import("xev");
const foundation = @import("../foundation/mod.zig");
const net = foundation.net;
const quic = @import("../quic/mod.zig");
const quic_c = quic.c;
const QUICConfig = quic.config.QUICConfig;
const Endpoint = quic.endpoint.Endpoint;
const QUICConnection = quic.connection.Connection;
const io = @import("../io/mod.zig");
const IoLoop = io.loop.IoLoop;
const Packet = io.loop.Packet;

// 复用 io.zig 的常量或自定义
const MAX_BATCH_PACKETS = 64;
const GSO_BUFFER_SIZE = 64 * 1024;

pub const AsyncClient = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    endpoint: Endpoint,
    io_loop: IoLoop,

    // 发送缓冲区 (跟随 Client 实例在堆上)
    gso_buffer: [GSO_BUFFER_SIZE]u8 = undefined,
    packet_batch: [MAX_BATCH_PACKETS]Packet = undefined,

    // 用户回调
    on_connected: ?*const fn (ctx: ?*anyopaque, conn: *QUICConnection) void = null,
    on_stream_data: ?*const fn (ctx: ?*anyopaque, conn: *QUICConnection, stream_id: u64, data: []const u8, is_fin: bool) void = null,
    on_stream_control: ?*const fn (ctx: ?*anyopaque, conn: *QUICConnection, stream_id: u64, event: quic_c.CallbackEvent) void = null,
    on_close: ?*const fn (ctx: ?*anyopaque, conn: *QUICConnection, event: quic_c.CallbackEvent) void = null,
    user_context: ?*anyopaque = null,

    pub const Error = error{
        InitFailed,
        ConnectFailed,
    } || Endpoint.Error || IoLoop.Error;

    /// 初始化异步客户端
    /// loop: 外部传入的 xev.Loop（通常是 GatewayWorker 的 loop）
    pub fn init(
        allocator: std.mem.Allocator,
        config: QUICConfig,
        loop: *xev.Loop,
    ) Error!Self {
        // 2. 初始化 Endpoint
        // thread_id 传 0 即可，客户端通常不需要复杂的 CID 路由
        var endpoint = try Endpoint.init(allocator, config, 0, null);
        errdefer endpoint.deinit();

        // 3. 初始化 IoLoop (绑定随机端口)
        var io_loop = try IoLoop.init(allocator, config.bind_address, config.bind_port, loop, null);
        errdefer io_loop.deinit();

        return .{
            .allocator = allocator,
            .endpoint = endpoint,
            .io_loop = io_loop,
        };
    }

    /// 释放客户端。
    ///
    /// **不关闭连接。** 连接的所有权在调用方（例如 `backend/pool.zig` 的连接池）：
    /// 一个客户端上可以有任意多条连接，客户端自己不持有它们的列表，也就无法逐条
    /// 优雅关闭。要发 CONNECTION_CLOSE 的话必须由所有方在 deinit 之前自己关。
    ///
    /// 残留的连接会随 `picoquic_free` 一起销毁（不发关闭帧，对端靠空闲超时收敛）。
    pub fn deinit(self: *Self) void {
        self.io_loop.deinit();
        self.endpoint.deinit();
    }

    /// 设置回调
    pub fn setCallbacks(
        self: *Self,
        user_context: ?*anyopaque,
        on_connected: ?*const fn (?*anyopaque, *QUICConnection) void,
        on_stream_data: ?*const fn (?*anyopaque, *QUICConnection, u64, []const u8, bool) void,
        on_close: ?*const fn (?*anyopaque, *QUICConnection, quic_c.CallbackEvent) void,
    ) void {
        self.user_context = user_context;
        self.on_connected = on_connected;
        self.on_stream_data = on_stream_data;
        self.on_close = on_close;
    }

    /// 单独注册流控制事件，避免把 RESET_STREAM / STOP_SENDING 伪装成空数据 FIN。
    pub fn setStreamControlCallback(
        self: *Self,
        callback: ?*const fn (?*anyopaque, *QUICConnection, u64, quic_c.CallbackEvent) void,
    ) void {
        self.on_stream_control = callback;
    }

    /// 启动客户端（非阻塞）
    /// 必须在 connect 之前调用
    pub fn start(self: *Self) void {
        // 1. 挂载 IO 回调
        self.io_loop.onRecv(self, handleUdpRecv);
        self.io_loop.onTimer(handleTimer, 100); // 初始 tick

        // 2. 挂载 Endpoint 回调
        self.endpoint.setUserData(self);
        self.endpoint.onConnection(emitConnected);
        self.endpoint.onStreamData(emitStreamData);
        self.endpoint.onStreamControl(emitStreamControl);
        self.endpoint.onConnectionClose(emitClose);

        // 3. 启动 IO 监听（只注册 fd 到 loop，不阻塞）
        self.io_loop.start();
    }

    /// 应用层刚向 picoquic 排入数据后立即驱动一次发送。
    ///
    /// `picoquic_add_to_stream` 只把字节放进协议栈队列，不会唤醒 libxev。客户端空闲时
    /// 下次 QUIC timer 最远可以在 10 秒后；如果调用方只排队而不驱动，新的应用数据就会
    /// 平白滞留到那个 timer。所有调用都发生在持有本客户端的 Worker 线程上，因此这里
    /// 直接复用与 UDP 收包/定时器相同的驱动入口，不需要跨线程通知。
    pub fn flush(self: *Self) void {
        self.processQuicEvents();
    }

    /// 连接到指定地址。
    ///
    /// `placement_hint` 非空时用它作为**客户端自选的 initial DCID**，也就是 Worker 级
    /// 亲和的支点（设计文档 §8.5 策略 B）：握手首包的 DCID 由客户端决定，reuseport
    /// 分类器读其中的 worker_id，就能把首包直接投给目标 Worker，连接从一开始就落对位置。
    ///
    /// 已核实的两条前提：
    /// - picoquic 接受 8–20 字节的自选 initial DCID（`PICOQUIC_ENFORCED_INITIAL_CID_LENGTH`
    ///   是 8，见 `libs/picoquic/picoquic/packet.c` 的 initial 包筛查），12 字节的
    ///   CID v1 正好落在区间内；服务端不会因此改变自己签发的 CID。
    /// - `src/io/reuseport.c` 的分类器本来就只看 DCID 的 magic/version/worker_id，
    ///   不区分这个 CID 是谁选的，因此不需要为 hint 改分流逻辑。
    ///
    /// hint 是**不可信提示，不是凭据**：worker_id 越界时分类器直接回退到四元组哈希，
    /// 连接照样建立，只是落在别的 Worker 上。因此它不需要 MAC，也不能用来做任何授权。
    ///
    /// ## 一个客户端可以承载任意多条连接
    ///
    /// 返回的是 picoquic 的**裸连接句柄**，而不是指向本结构内部某个字段的指针。
    /// 早先的版本存了一个 `active_connection: ?QUICConnection` 并返回 `&它`，
    /// 于是在同一个客户端上开第二条连接会让第一个指针**变成指向新连接的别名**
    /// ——调用方以为自己拿着连接 A，写进去的字节却跑到了连接 B。
    ///
    /// 现在句柄自己就是稳定的（picoquic 分配的 `picoquic_cnx_t*`），复用同一个
    /// 客户端建 N 条连接是安全的。这是把"一条后端连接一个 AsyncClient"收敛成
    /// "一个 Worker 一个 AsyncClient"的前提：那样 socket、picoquic 上下文、定时器、
    /// GSO 缓冲都只有一份，而它们原先是每条后端连接一份。
    ///
    /// 入站包由 picoquic 按 CID 自己解复用（`Endpoint.handleIncomingPacket`），
    /// 因此多连接共用一个 socket 不需要我们做任何分流。
    ///
    /// 连接的**所有权归调用方**：要优雅关闭必须自己 `QUICConnection.fromRaw(handle).close()`，
    /// 客户端的 deinit 不会替你做（它不持有连接列表）。
    pub fn connectAddress(
        self: *Self,
        server_addr: net.Address,
        sni: []const u8,
        placement_hint: ?[io.cid.length]u8,
    ) Error!quic_c.QuicCnx {
        var sockaddr_storage = net.toSockAddrStorage(server_addr);

        const now = quic_c.currentTime();

        var initial_cid = quic_c.nullConnectionId();
        if (placement_hint) |hint| {
            initial_cid.id_len = io.cid.length;
            @memcpy(initial_cid.id[0..hint.len], &hint);
        }

        // 创建底层连接
        const cnx_ptr = quic_c.c.picoquic_create_cnx(
            self.endpoint.getContext(),
            initial_cid,
            quic_c.nullConnectionId(),
            @ptrCast(&sockaddr_storage),
            now,
            0,
            sni.ptr,
            self.endpoint.config.base.alpn.ptr,
            1, // client mode = 1
        ) orelse return Error.ConnectFailed;

        // 启动握手
        const rc = quic_c.c.picoquic_start_client_cnx(cnx_ptr);
        if (rc != 0) return Error.ConnectFailed;

        // 立即驱动一次事件循环（发送 Client Hello）
        self.processQuicEvents();

        return cnx_ptr;
    }

    // =========================================================================
    // 内部处理逻辑 (与 Server Worker 高度一致)
    // =========================================================================

    fn handleUdpRecv(ctx: *anyopaque, data: []const u8, from: net.Address, ts: u64) void {
        const self = castSelf(ctx);
        self.endpoint.handleIncomingPacket(data, from, self.io_loop.getLocalAddr(), ts);
        self.processQuicEvents();
    }

    fn handleTimer(ctx: *anyopaque) void {
        const self = castSelf(ctx);
        self.processQuicEvents();
    }

    /// 核心驱动：发包 + 调整定时器
    fn processQuicEvents(self: *Self) void {
        // 1. 发送所有积压数据
        self.flushPendingPackets();

        // 2. 计算下一次唤醒时间
        const next_wake = self.endpoint.getNextWakeTime();
        const now = quic_c.currentTime();
        var delta: u64 = 0;
        if (next_wake > now) {
            delta = (next_wake - now) / 1000;
        }
        // 限制定时器范围
        if (delta == 0) delta = 1;
        if (delta > 10000) delta = 10000;

        self.io_loop.updateTimer(delta);
    }

    /// 批量发包逻辑
    fn flushPendingPackets(self: *Self) void {
        while (true) {
            const pkt_opt = self.endpoint.preparePendingPacket(&self.gso_buffer);
            if (pkt_opt == null) break;
            const pkt = pkt_opt.?;

            var batch_count: usize = 0;
            var offset: usize = 0;

            while (offset < pkt.data.len) {
                const end = @min(offset + pkt.segment_size, pkt.data.len);
                const chunk = pkt.data[offset..end];

                if (batch_count < MAX_BATCH_PACKETS) {
                    self.packet_batch[batch_count] = .{
                        .data = chunk,
                        .dest = pkt.dest,
                    };
                    batch_count += 1;
                } else {
                    self.io_loop.sendBatch(self.packet_batch[0..batch_count]) catch {};
                    batch_count = 0;
                    continue; // retry current chunk
                }
                offset += pkt.segment_size;
            }

            if (batch_count > 0) {
                self.io_loop.sendBatch(self.packet_batch[0..batch_count]) catch {};
            }

            // Buffer 未满，说明暂时没数据了
            if (pkt.data.len < GSO_BUFFER_SIZE) break;
        }
    }

    // =========================================================================
    // Endpoint 回调 -> 上层用户回调
    //
    // 名字与 on_* 字段一一对应，三个都只做类型还原与转交——客户端不持有连接状态，
    // 所以没有任何需要在回调里维护的东西。
    //
    // 共同约束：conn 指向 endpoint.zig 回调栈上的临时包装（Connection.fromRaw），
    // 只在本次调用期内有效；要长期持有必须存 conn.inner 这个稳定的 C 句柄。
    // =========================================================================

    /// 握手完成。只对应 picoquic 的 .ready 事件（.almost_ready 已在 endpoint.zig 过滤）。
    ///
    /// 调用方在 `connectAddress` 返回时就拿到了句柄，也就是说它在握手完成前就持有
    /// 连接，但只有本回调触发之后才能真正发应用数据。
    fn emitConnected(ctx: ?*anyopaque, conn: *QUICConnection) void {
        const self = castSelf(ctx.?);
        if (self.on_connected) |cb| {
            cb(self.user_context, conn);
        }
    }

    /// 流数据到达。同时覆盖 .stream_data 与 .stream_fin，用 is_fin 区分；
    /// is_fin 为 true 时 data 可能为空（对端只关流不带数据）。
    ///
    /// data 借用 picoquic 内部缓冲，回调返回即失效。上层要留存必须自己复制——
    /// backend/direct.zig 的 onClientStreamData 就是先 dupe 再入队。
    fn emitStreamData(ctx: ?*anyopaque, conn: *QUICConnection, stream_id: u64, data: []const u8, is_fin: bool) void {
        const self = castSelf(ctx.?);
        if (self.on_stream_data) |cb| {
            cb(self.user_context, conn, stream_id, data, is_fin);
        }
    }

    fn emitStreamControl(ctx: ?*anyopaque, conn: *QUICConnection, stream_id: u64, event: quic_c.CallbackEvent) void {
        const self = castSelf(ctx.?);
        if (self.on_stream_control) |cb| cb(self.user_context, conn, stream_id, event);
    }

    /// 连接终止。.close / .application_close / .stateless_reset 三种事件共用此路径。
    ///
    /// 只转交，不做清理：连接状态归调用方，它要在自己的回调里把对应句柄置空。
    /// 这里也**不能**调 close——仍在 picoquic 回调栈内，重入关闭会破坏它的状态机。
    fn emitClose(ctx: ?*anyopaque, conn: *QUICConnection, event: quic_c.CallbackEvent) void {
        const self = castSelf(ctx.?);
        if (self.on_close) |cb| {
            cb(self.user_context, conn, event);
        }
    }

    inline fn castSelf(ctx: *anyopaque) *Self {
        return @as(*Self, @ptrCast(@alignCast(ctx)));
    }
};

// ============================================================================
// 测试
// ============================================================================

// 一个客户端上并存多条连接，是把"一条后端连接一个 AsyncClient"收敛成
// "一个 Worker 一个 AsyncClient"的前提——socket、picoquic 上下文、定时器、
// GSO 缓冲从此各只有一份，而它们原先是每条后端连接一份（约 2.1 MiB + 1 fd）。
//
// 这条用例锁的是**旧 API 表达不出来的那件事**：早先 connectAddress 返回
// `&self.active_connection.?`，第二次调用会把第一个指针变成指向新连接的别名，
// 调用方以为在写连接 A，字节却进了连接 B。
test "one client hosts several independent connections" {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var client = try AsyncClient.init(std.testing.allocator, .{
        // 客户端角色不需要证书；这里也不会真的握手（对端不存在）。
        .base = .{ .verify_cert = false },
    }, &loop);
    defer client.deinit();
    client.start();

    const first = try client.connectAddress(net.initIp4(.{ 127, 0, 0, 1 }, 59001), "a.invalid", null);
    const second = try client.connectAddress(net.initIp4(.{ 127, 0, 0, 1 }, 59002), "b.invalid", null);

    // 两条是不同的连接，且第一条没有被第二条顶掉。
    try std.testing.expect(first != second);

    var conn_first = QUICConnection.fromRaw(first);
    var conn_second = QUICConnection.fromRaw(second);
    try std.testing.expectEqual(first, conn_first.inner);
    try std.testing.expectEqual(second, conn_second.inner);

    // 所有权在调用方：deinit 不会替我们关连接，所以这里自己关。
    // 两条独立关闭都不该影响对方。
    conn_first.close();
    conn_second.close();
}

// test "AsyncClient" {
//     var loop = try xev.Loop.init(.{});
//     var client = try AsyncClient.init(std.testing.allocator, .{ .base = .{ .alpn = "lyune-gateway", .root_cert_file = "server.crt" } }, loop);

//     client.setCallbacks(null, null)
//     client.start();
//     try loop.run(.until_done);

// }
