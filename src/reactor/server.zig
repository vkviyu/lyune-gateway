//! src/reactor/server.zig
//!
//! QUIC 服务端反应堆 (ServerDriver)
//!
//! 职责：
//! 1. 组装 Endpoint (协议) 和 IoLoop (IO)
//! 2. 管理发送缓冲区 (GSO Buffer)
//! 3. 驱动事件循环：收包 -> 协议处理 -> 发包 -> 定时器
//! 4. 按 CID 归属为入站报文选路：本 Worker 处理 / 交接给同机其他 Worker /
//!    经 forward 隧道转给其他节点
//!
//! 它不含应用层业务逻辑（认证、路由键、后端选择都在 worker 层），但确实承担
//! 集群数据面的选路决策——因为归属判断必须在报文进入 picoquic 之前完成。
//!
//! L4 回程状态（普通有状态 UDP LB 下的响应回流）不在本文件，见 return_path.zig；
//! 这里只在选路的四个点上调用它。

const std = @import("std");

const xev = @import("xev");

const foundation = @import("../foundation/mod.zig");
const err_handler = foundation.err;
const net = foundation.net;
const io = @import("../io/mod.zig");
const cluster_cid = io.cid;
const migration = io.handoff;
const forward = io.forward;
const quic = @import("../quic/mod.zig");
const endpoint = quic.endpoint;
const QUICConnection = quic.connection.Connection;
const QUICCallbackEvent = quic.c.CallbackEvent;
const QUICConfig = quic.config.QUICConfig;
const return_path = @import("return_path.zig");

// 复用常量
const GSO_BUFFER_SIZE = 64 * 1024;
const MAX_BATCH_PACKETS = 64;

/// 单 Worker 的 QUIC 服务端驱动器。
/// 拥有 Endpoint/IoLoop，借用 packet_router 与可选 Sender；借用对象必须覆盖 Driver 生命周期。
pub const ServerDriver = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    endpoint: endpoint.Endpoint,
    io_loop: io.loop.IoLoop,
    node_id: u16,
    worker_id: u8,
    packet_router: *migration.LocalPacketRouter,
    forward_sender: ?forward.Sender,
    /// L4 回程状态；仅在部署模式要求响应回流经原入口时创建，见 return_path.zig。
    return_tracker: ?return_path.Tracker = null,

    // 发送缓冲区 (跟随 Driver 实例在堆上)
    gso_buffer: [GSO_BUFFER_SIZE]u8 = undefined,
    packet_batch: [MAX_BATCH_PACKETS]io.loop.Packet = undefined,

    // 用户回调接口
    user_context: ?*anyopaque = null,
    on_connection: ?*const fn (ctx: ?*anyopaque, conn: *QUICConnection) void = null,
    on_stream_data: ?*const fn (ctx: ?*anyopaque, conn: *QUICConnection, sid: u64, data: []const u8, fin: bool) void = null,
    on_datagram: ?*const fn (ctx: ?*anyopaque, conn: *QUICConnection, data: []const u8) void = null,
    on_connection_close: ?*const fn (ctx: ?*anyopaque, conn: *QUICConnection, event: QUICCallbackEvent) void = null,

    /// Driver、Endpoint 与 IoLoop 初始化错误的统一错误集。
    pub const Error = error{
        InitFailed,
        LoopInitFailed,
    } || return_path.Tracker.Error || endpoint.Endpoint.Error || io.loop.IoLoop.Error;

    /// 初始化驱动器并接管 socket_fd；packet_router/forward_sender 只借用，不由 Driver 释放。
    pub fn init(
        allocator: std.mem.Allocator,
        config: QUICConfig,
        node_id: u16,
        thread_id: u8,
        loop: *xev.Loop,
        socket_fd: ?std.posix.socket_t,
        packet_router: *migration.LocalPacketRouter,
        forward_sender: ?forward.Sender,
    ) Error!Self {
        // IoLoop takes ownership of socket_fd immediately, including failure paths.
        var io_loop = try io.loop.IoLoop.init(allocator, config.bind_address, config.bind_port, loop, socket_fd);
        errdefer io_loop.deinit();

        var ed = try endpoint.Endpoint.initWithNode(allocator, config, thread_id, null, node_id);
        errdefer ed.deinit();

        // 只有需要 L4 回程的部署模式才分配这份状态；anycast 模式下 owner 直接回客户端。
        var return_tracker: ?return_path.Tracker = null;
        errdefer if (return_tracker) |*tracker| tracker.deinit();
        if (forward_sender) |sender| {
            if (sender.return_path_enabled) {
                return_tracker = try return_path.Tracker.init(
                    allocator,
                    sender.return_path_capacity,
                    sender.return_path_timeout_us,
                );
            }
        }

        return .{
            .allocator = allocator,
            .endpoint = ed,
            .io_loop = io_loop,
            .node_id = node_id,
            .worker_id = thread_id,
            .packet_router = packet_router,
            .forward_sender = forward_sender,
            .return_tracker = return_tracker,
        };
    }

    /// 释放自有 IoLoop 与 Endpoint；调用方应先停止事件源。
    pub fn deinit(self: *Self) void {
        if (self.return_tracker) |*tracker| tracker.deinit();
        self.io_loop.deinit();
        self.endpoint.deinit();
    }

    /// 注册上层业务回调。
    ///
    /// user_ctx 只借用，必须活过 Driver；三个回调均可为 null（例如只关心连接建立）。
    /// 需要在 start() 之前调用，否则握手完成的连接不会通知到上层。
    pub fn setCallbacks(
        self: *Self,
        user_ctx: ?*anyopaque,
        on_conn: ?*const fn (?*anyopaque, *QUICConnection) void,
        on_data: ?*const fn (?*anyopaque, *QUICConnection, u64, []const u8, bool) void,
        on_close: ?*const fn (?*anyopaque, *QUICConnection, QUICCallbackEvent) void,
    ) void {
        self.user_context = user_ctx;
        self.on_connection = on_conn;
        self.on_stream_data = on_data;
        self.on_connection_close = on_close;
    }

    /// 注册 datagram 回调（不可靠通路，设计文档 §6）。
    ///
    /// 单独一个 setter 而不是塞进 `setCallbacks`：只有面向客户端的监听器需要它。
    /// 集群监听器不需要——跨节点那一跳走的是对等链路上的可靠 `.multicast` 帧
    /// （理由见 egress 的不可靠扇出一节），所以给它注册一个用不上的回调只会让
    /// "谁会收到 datagram"这个问题多一个要排除的答案。
    pub fn setDatagramCallback(
        self: *Self,
        on_datagram: ?*const fn (?*anyopaque, *QUICConnection, []const u8) void,
    ) void {
        self.on_datagram = on_datagram;
    }

    /// 启动驱动器 (非阻塞)
    /// 必须由外部调用 event_loop.run() 来实际运转
    pub fn start(self: *Self) void {
        // 1. 注册 IO 回调 (Driver 内部闭环)
        self.io_loop.onRecv(self, handleUdpRecv);
        // 初始定时器设为 1ms
        self.io_loop.onTimer(handleTimer, 1);

        // 2. 注册 Endpoint 回调 (Driver 内部闭环)
        self.endpoint.setUserData(self);
        self.endpoint.onConnection(emitConnection);
        self.endpoint.onStreamData(emitStreamData);
        self.endpoint.onDatagram(emitDatagram);
        self.endpoint.onConnectionClose(emitConnectionClose);

        // 3. 启动 IO 监听 (向 loop 注册 fd)
        self.io_loop.start();

        std.log.info("ServerDriver active on port {}", .{self.io_loop.getLocalAddr().getPort()});
    }

    /// 从 libxev 注销 I/O 驱动；不释放 Driver。
    pub fn stop(self: *Self) void {
        self.io_loop.stop();
    }

    // ========================================================================
    // 核心驱动逻辑：入站选路、交接包处理、发包与定时器
    // ========================================================================

    /// libxev 收到 UDP 包后的入口。先判断这个包是否真的属于本 Worker：
    /// 若 CID 指向别的 Worker（内核误分流/NAT rebinding），交给本地包路由器转投；
    /// 否则直接喂给本地 picoquic 协议栈处理。
    fn handleUdpRecv(ctx: *anyopaque, data: []const u8, from: net.Address, ts: u64) void {
        const self = castSelf(ctx);
        if (self.routeInbound(data, from, ts)) return;
        // 报文归本 Worker：客户端已能直连本节点，此前的回程路径失效。
        if (self.return_tracker) |*tracker| tracker.forgetRoute(from);
        self.handleOwnedPacket(data, from, ts);
    }

    /// 按 CID 归属为入站报文选路。已被转投时返回 true，归本 Worker 时返回 false。
    ///
    /// 三条出路：跨节点走 forward 隧道、同机跨 Worker 走交接队列、本 Worker 自己处理。
    ///
    /// **只有短包头（1-RTT）包的 CID 才被当作权威。** 长包头包（Initial / Handshake）
    /// 的 DCID 在握手期可能是**客户端自选的**——RFC 9000 允许客户端在首包里放任意
    /// 8–20 字节 DCID，而它与本网关签发的 CID v1 在字节上无法区分。若一并信任：
    ///
    /// - 客户端只要在首包 DCID 里填一个别的 `node_id`，就能驱使入口节点把自己的包
    ///   经隧道转给集群里任意节点，绕过 LB 的负载决策；
    /// - 更糟的是 `grantResponse` 会为每个这样的包分配一条回程授权，而回程表是定容的
    ///   ——伪造 `node_id` 的 Initial 包因此是一条把入口节点回程表打满的 DoS 通路。
    ///
    /// 代价是 anycast / l4_lb 模式下握手期的长包头包不再跨节点纠错。这个代价很小：
    /// 客户端在收到服务端首个响应后才拿到服务端签发的 CID，而握手那几十毫秒内
    /// anycast 路由漂移或有状态 LB 改后端都是罕见事件；连接迁移（NAT rebinding）发的
    /// 是 1-RTT 短包头包，不受影响。
    ///
    /// 反过来，内核 cBPF 仍然会按长包头里的 CID 做尽力而为的分流（见 reuseport.c）。
    /// 这正是 Worker 级放置提示的机制：客户端自选的 initial DCID 只影响"落在哪个
    /// Worker"，改不了"落在哪个节点"，也拿不到任何授权——提示不是凭据。
    fn routeInbound(self: *Self, data: []const u8, from: net.Address, ts: u64) bool {
        if (!isShortHeader(data)) return false;
        const owner = packetOwner(data) orelse return false;

        if (owner.node_id != self.node_id) {
            const sender = self.forward_sender orelse return true;
            // 必须先登记授权再转发：owner 的响应回到本节点时要凭它放行。
            if (sender.return_path_enabled) {
                const tracker = if (self.return_tracker) |*value| value else return true;
                tracker.grantResponse(from, owner.node_id, owner.worker_id, ts) catch |err| {
                    err_handler.reportError(.transport, "L4 return authorization allocation failed", err);
                    return true;
                };
            }
            sender.sendRequest(owner.node_id, owner.worker_id, self.worker_id, data, from) catch |err| {
                err_handler.reportError(.transport, "Cross-node packet forwarding failed", err);
            };
            return true;
        }

        if (owner.worker_id != self.worker_id) {
            self.packet_router.forward(owner.worker_id, data, from, ts) catch |err| {
                err_handler.reportError(.transport, "Cross-Worker packet handoff failed", err);
            };
            return true;
        }

        return false;
    }

    /// 处理由本 Worker 从交接队列取出的报文。
    ///
    /// 来源有两种：同机其他 Worker 误收后转投（无 tunnel 元数据），
    /// 或其他节点经 forward 隧道送来的 request/response（带 tunnel 元数据）。
    pub fn handleHandoffPacket(self: *Self, packet: *const migration.ForwardPacket) void {
        const metadata = packet.tunnel orelse {
            if (self.return_tracker) |*tracker| tracker.forgetRoute(packet.addr_from);
            self.handleOwnedPacket(packet.bytes(), packet.addr_from, packet.received_time);
            return;
        };
        switch (metadata.kind) {
            .request => {
                // 本节点是 owner：记住响应要经由哪个入口回去。
                if (self.return_tracker) |*tracker| {
                    tracker.rememberRoute(
                        packet.addr_from,
                        metadata.source_node_id,
                        metadata.source_worker_id,
                        quic.c.currentTime(),
                    ) catch |err| {
                        err_handler.reportError(.transport, "L4 return path allocation failed", err);
                        return;
                    };
                }
                self.handleOwnedPacket(packet.bytes(), packet.addr_from, 0);
            },
            .response => self.handleReturnResponse(packet, metadata),
        }
    }

    /// 入口 Worker 只发送与此前请求转发记录匹配的回程响应，避免隧道成为 UDP 反射器。
    fn handleReturnResponse(self: *Self, packet: *const migration.ForwardPacket, metadata: migration.TunnelMetadata) void {
        const tracker = if (self.return_tracker) |*value| value else return;
        if (!tracker.isGranted(packet.addr_from, metadata, quic.c.currentTime())) return;
        self.io_loop.send(packet.bytes(), packet.addr_from) catch |err| {
            err_handler.reportError(.transport, "L4 return UDP send failed", err);
        };
    }

    /// 把已确认归属本 Worker 的包喂给协议栈并驱动一次状态机（发包 + 更新定时器）。
    fn handleOwnedPacket(self: *Self, data: []const u8, from: net.Address, ts: u64) void {
        const received_at = if (ts == 0) quic.c.currentTime() else ts;
        self.endpoint.handleIncomingPacket(data, from, self.io_loop.getLocalAddr(), received_at);
        self.processQuicEvents();
    }

    /// QUIC 头部第一个字节的最高位是 header form：1 = 长包头，0 = 短包头。
    ///
    /// 只有短包头（1-RTT）包必定携带服务端签发的 CID，因此只有它的 CID 能被
    /// 当作权威的归属信息，理由见 routeInbound。
    fn isShortHeader(data: []const u8) bool {
        if (data.len == 0) return false;
        return (data[0] & 0x80) == 0;
    }

    /// 从 UDP 包里解析 CID v1 并还原 node/Worker 归属；无法识别时返回 null。
    fn packetOwner(data: []const u8) ?cluster_cid.Fields {
        var dcid = std.mem.zeroes(quic.c.ConnectionId);
        if (!quic.c.parseDcid(data, &dcid)) return null;
        return cluster_cid.parse(dcid.id[0..dcid.id_len]);
    }

    /// libxev 定时器到期后的入口。
    ///
    /// QUIC 有一批纯粹由时间驱动、没有对应入站报文的动作：丢包重传、延迟 ACK、
    /// PTO 探测、空闲超时关连接。它们只能靠定时器唤醒。这里不判断是哪一种到期，
    /// 统一交给 picoquic 在 processQuicEvents 里自己决定该做什么。
    ///
    /// 定时器本身由 IoLoop 负责续期（见 loop.zig 的 timerCallback），
    /// 本函数经 processQuicEvents → updateTimer 把下一次唤醒对齐到协议栈要求的时刻。
    fn handleTimer(ctx: *anyopaque) void {
        const self = castSelf(ctx);
        self.processQuicEvents();
    }

    /// 驱动一次 QUIC 状态机：冲刷待发报文，再把定时器对齐到协议栈要求的下次唤醒时刻。
    ///
    /// 任何可能改变协议栈状态的事件之后都必须调用一次（收包、定时器到期、交接队列取包），
    /// 否则 picoquic 生成的报文会一直积压在它内部队列里，对端只会看到"服务端不回包"。
    ///
    /// 唤醒间隔做了上下夹取，两个边界都是有意的：
    ///   - 下界 1ms：picoquic 经常返回"立即"（next_wake <= now），delta 取 0 会让
    ///     libxev 定时器退化成忙循环，把一个核吃满。
    ///   - 上界 10s：空闲时 picoquic 可能返回很远的唤醒时间，夹住上界保证事件循环
    ///     始终保有一个最低心跳频率。
    fn processQuicEvents(self: *Self) void {
        // 1. 发送所有待发送的包
        self.flushPendingPackets();

        // 2. 计算下一次唤醒时间
        const next_wake = self.endpoint.getNextWakeTime();
        const now = quic.c.currentTime();

        var delta: u64 = 0;
        if (next_wake > now) {
            delta = (next_wake - now) / 1000;
        }

        if (delta == 0) delta = 1;
        if (delta > 10000) delta = 10000;

        self.io_loop.updateTimer(delta);
    }

    /// 按 picoquic 返回的 segment_size 切分 GSO 缓冲，并以最多 64 包一批交给 IoLoop。
    fn flushPendingPackets(self: *Self) void {
        while (true) {
            const pkt_opt = self.endpoint.preparePendingPacket(&self.gso_buffer);
            if (pkt_opt == null) break;
            const pkt = pkt_opt.?;

            // 这个目的地有回程记录时，响应必须原路返回入口节点，不能直接发给客户端：
            // 客户端只认识 LB 的地址，直接发过去会因源地址不匹配被丢弃。
            if (self.return_tracker) |*tracker| {
                if (tracker.lookupRoute(pkt.dest, quic.c.currentTime())) |route| {
                    self.forwardResponseSegments(pkt, route);
                    if (pkt.data.len < GSO_BUFFER_SIZE) break;
                    continue;
                }
            }

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
                    // 批次满了：先冲刷。这里故意不推进 offset，continue 后重新处理
                    // 当前这一段，否则每满一批就会丢掉一个报文。
                    self.io_loop.sendBatch(self.packet_batch[0..batch_count]) catch {};
                    batch_count = 0;
                    continue;
                }
                offset += pkt.segment_size;
            }

            if (batch_count > 0) {
                self.io_loop.sendBatch(self.packet_batch[0..batch_count]) catch {};
            }

            // picoquic 没填满缓冲，说明已经没有待发数据；填满了则可能还有，继续取下一批。
            if (pkt.data.len < GSO_BUFFER_SIZE) break;
        }
    }

    /// 把一个 GSO 缓冲按段拆开，逐段经隧道送回原入口节点。
    ///
    /// 不能整块发：隧道对端会把 payload 当成单个 UDP 数据报交给客户端，
    /// 而客户端期望的是若干个独立的 QUIC 报文。
    fn forwardResponseSegments(self: *Self, packet: endpoint.PacketInfo, route: return_path.Peer) void {
        const sender = self.forward_sender orelse return;
        var offset: usize = 0;
        while (offset < packet.data.len) {
            const end = @min(offset + packet.segment_size, packet.data.len);
            sender.sendResponse(route.node_id, route.worker_id, self.worker_id, packet.data[offset..end], packet.dest) catch |err| {
                err_handler.reportError(.transport, "L4 return tunnel send failed", err);
            };
            offset = end;
        }
    }

    // ========================================================================
    // Endpoint 回调 -> 上层用户回调
    //
    // 这三个函数只做类型还原与转交，不含任何决策；名字与 on_* 字段一一对应。
    //
    // 共同约束：conn 指向 endpoint.zig 回调栈上的临时包装（Connection.fromRaw），
    // 只在本次调用期内有效。上层要长期持有连接必须存 conn.inner 这个 C 句柄
    // ——它才是全局唯一且稳定的（worker/connection.zig 的 ConnectionManager 即以它为键）。
    // ========================================================================

    /// 握手完成。只对应 picoquic 的 .ready 事件，.almost_ready 已被 endpoint.zig 过滤，
    /// 因此进到上层时连接一定可以立即收发。
    fn emitConnection(ctx: ?*anyopaque, conn: *QUICConnection) void {
        const self = castSelf(ctx.?);
        if (self.on_connection) |cb| cb(self.user_context, conn);
    }

    /// 流数据到达。同时覆盖 .stream_data 与 .stream_fin 两个事件，用 fin 区分；
    /// fin 为 true 时 data 可能为空（对端只关流不带数据）。
    ///
    /// data 借用 picoquic 内部缓冲，回调返回即失效，上层要留存必须自己复制。
    fn emitStreamData(ctx: ?*anyopaque, conn: *QUICConnection, sid: u64, data: []const u8, fin: bool) void {
        const self = castSelf(ctx.?);
        if (self.on_stream_data) |cb| cb(self.user_context, conn, sid, data, fin);
    }

    /// 收到一个 QUIC DATAGRAM（不可靠通路，设计文档 §6）。
    ///
    /// 没有 stream_id、没有 fin：datagram 不属于任何流，一个包就是一个完整单元，
    /// 因此也不需要残帧重组。data 同样借用 picoquic 内部缓冲，回调返回即失效。
    fn emitDatagram(ctx: ?*anyopaque, conn: *QUICConnection, data: []const u8) void {
        const self = castSelf(ctx.?);
        if (self.on_datagram) |cb| cb(self.user_context, conn, data);
    }

    /// 连接终止。.close / .application_close / .stateless_reset 三种事件共用此路径，
    /// 由 event 区分原因。
    ///
    /// picoquic 在本回调返回后就会释放 cnx 对象，上层必须在这里清掉所有指向该连接的
    /// 引用（在途请求映射、连接表等），否则后续回程路径会拿到野指针。
    fn emitConnectionClose(ctx: ?*anyopaque, conn: *QUICConnection, event: QUICCallbackEvent) void {
        const self = castSelf(ctx.?);
        if (self.on_connection_close) |cb| cb(self.user_context, conn, event);
    }

    /// 把 Endpoint/IoLoop 回传的类型擦除上下文还原为 Driver 自身。
    /// ctx 恒为 start() 注册的 self，因此不做空判断。
    inline fn castSelf(ctx: *anyopaque) *Self {
        return @as(*Self, @ptrCast(@alignCast(ctx)));
    }
};

test "packet owner parses CID v1 node and Worker" {
    const encoded = cluster_cid.encode(513, 7, .{ 1, 2, 3, 4, 5, 6 });
    var packet: [1 + cluster_cid.length]u8 = undefined;
    packet[0] = 0x40;
    @memcpy(packet[1..], &encoded);
    const owner = ServerDriver.packetOwner(&packet).?;
    try std.testing.expectEqual(@as(u16, 513), owner.node_id);
    try std.testing.expectEqual(@as(u8, 7), owner.worker_id);
}

// l4_lb 模式的回程接线回归测试。
//
// return_path.zig 的单元测试只覆盖两张表自身的行为，无法发现 ServerDriver
// 漏接线——比如转发前忘记登记授权，或收到 request 忘记记住回程。这类缺陷
// 只在生产环境发生错投时才暴露，而那时没人在看日志。
//
// 这里用 Sender 桩绕开真实 UDP 隧道（forward 的线路编解码有自己的单元测试），
// 直接验证三个接线点：转发前必须先授权、收到 request 必须记回程、
// 授权必须精确到 node + worker。
test "l4_lb mode wires response grants and owner routes" {
    const Recorder = struct {
        kind: ?migration.TunnelKind = null,
        target_node_id: u16 = 0,
        calls: usize = 0,

        fn send(
            ptr: *anyopaque,
            kind: migration.TunnelKind,
            target_node_id: u16,
            target_worker_id: u8,
            source_worker_id: u8,
            payload: []const u8,
            client_address: net.Address,
        ) anyerror!void {
            _ = target_worker_id;
            _ = source_worker_id;
            _ = payload;
            _ = client_address;
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.kind = kind;
            self.target_node_id = target_node_id;
            self.calls += 1;
        }
    };

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();
    var router = try migration.LocalPacketRouter.init(std.testing.io, std.testing.allocator, 1, 4);
    defer router.deinit();

    var recorder: Recorder = .{};
    var config: QUICConfig = .{
        .cert_file = "server.crt",
        .key_file = "server.key",
        .bind_address = .{ 127, 0, 0, 1 },
        .bind_port = 0,
    };
    config.base.verify_cert = false;

    var driver = try ServerDriver.init(std.testing.allocator, config, 1, 0, &loop, null, &router, .{
        .ptr = &recorder,
        .return_path_enabled = true,
        .return_path_capacity = 8,
        .return_path_timeout_us = 60 * std.time.us_per_s,
        .sendFn = Recorder.send,
    });
    defer driver.deinit();
    // 必须 start：本测试会走到 handleOwnedPacket，而定时器 completion 只在
    // start 时初始化，否则读取其状态是未定义行为。
    driver.start();

    const client = net.initIp4(.{ 203, 0, 113, 5 }, 40000);
    const now = quic.c.currentTime();

    // 构造 CID 指向 node 2 / worker 3 的短头包；本节点是 node 1，应转发出去。
    const encoded = cluster_cid.encode(2, 3, .{ 9, 8, 7, 6, 5, 4 });
    var foreign: [1 + cluster_cid.length]u8 = undefined;
    foreign[0] = 0x40;
    @memcpy(foreign[1..], &encoded);

    try std.testing.expect(driver.routeInbound(&foreign, client, now));
    try std.testing.expectEqual(@as(usize, 1), recorder.calls);
    try std.testing.expectEqual(migration.TunnelKind.request, recorder.kind.?);
    try std.testing.expectEqual(@as(u16, 2), recorder.target_node_id);

    // 授权必须精确到 node + worker：只有 CID 指向的那个 Worker 能回包。
    const tracker = &driver.return_tracker.?;
    try std.testing.expect(tracker.isGranted(client, .{ .kind = .response, .source_node_id = 2, .source_worker_id = 3 }, now));
    try std.testing.expect(!tracker.isGranted(client, .{ .kind = .response, .source_node_id = 2, .source_worker_id = 4 }, now));
    try std.testing.expect(!tracker.isGranted(client, .{ .kind = .response, .source_node_id = 9, .source_worker_id = 3 }, now));

    // owner 侧：收到 request 隧道包后必须记住响应要回到哪个入口。
    try std.testing.expect(tracker.lookupRoute(client, now) == null);
    const inbound = try migration.ForwardPacket.initTunnel(&foreign, client, .{
        .kind = .request,
        .source_node_id = 7,
        .source_worker_id = 1,
    });
    driver.handleHandoffPacket(&inbound);
    const route = tracker.lookupRoute(client, quic.c.currentTime()).?;
    try std.testing.expectEqual(@as(u16, 7), route.node_id);
    try std.testing.expectEqual(@as(u8, 1), route.worker_id);

    // 客户端随后直连本节点时回程记录必须失效，否则响应会被绕回一个不再需要的入口。
    // 走完整的收包入口，验证 handleUdpRecv 确实接上了 forgetRoute。
    const local_packet = [_]u8{ 0x40, 1, 2, 3 };
    try std.testing.expect(!driver.routeInbound(&local_packet, client, quic.c.currentTime()));
    ServerDriver.handleUdpRecv(&driver, &local_packet, client, quic.c.currentTime());
    try std.testing.expect(tracker.lookupRoute(client, quic.c.currentTime()) == null);
}

// 端到端握手回归测试。
//
// 这条测试同时守住两个曾经让服务端完全不可用的缺陷：
//   1. ALPN 必须以裸 C 字符串传给 picoquic。传成 TLS 长度前缀格式时，
//      picoquic 用 strlen 比较，服务端必然回 no_application_protocol。
//   2. picoquic 的 local_cnxid_length 必须显式设为集群 CID 长度。
//      保持默认 8 字节时，本端签发的 12 字节 CID 无法被自己查到，
//      握手后续报文全部查表 miss。
//
// 因此"客户端与服务端都收到 ready 回调"这一个断言即可覆盖两者：
// 任一缺陷存在，握手都无法完成。
/// 跑一次真实的 loopback 握手，返回双方是否都收到 ready 回调。
///
/// `placement_hint` 原样透传给客户端的 initial DCID（见 client.connectAddress）。
fn runLoopbackHandshake(placement_hint: ?[cluster_cid.length]u8) !bool {
    const AsyncClient = @import("client.zig").AsyncClient;

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var router = try migration.LocalPacketRouter.init(std.testing.io, std.testing.allocator, 1, 4);
    defer router.deinit();

    const Probe = struct {
        server_ready: bool = false,
        client_ready: bool = false,

        fn onServerConnection(ctx: ?*anyopaque, conn: *QUICConnection) void {
            _ = conn;
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.server_ready = true;
        }

        fn onClientConnection(ctx: ?*anyopaque, conn: *QUICConnection) void {
            _ = conn;
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.client_ready = true;
        }
    };
    var probe: Probe = .{};

    var server_config: QUICConfig = .{
        .cert_file = "server.crt",
        .key_file = "server.key",
        .bind_address = .{ 127, 0, 0, 1 },
        .bind_port = 0,
    };
    server_config.base.verify_cert = false;

    var driver = try ServerDriver.init(
        std.testing.allocator,
        server_config,
        1,
        0,
        &loop,
        null,
        &router,
        null,
    );
    defer driver.deinit();
    driver.setCallbacks(&probe, Probe.onServerConnection, null, null);
    driver.start();

    const server_port = driver.io_loop.getLocalAddr().getPort();
    try std.testing.expect(server_port != 0);

    var client_config: QUICConfig = .{
        .bind_address = .{ 127, 0, 0, 1 },
        .bind_port = 0,
    };
    client_config.base.verify_cert = false;

    var client = try AsyncClient.init(std.testing.allocator, client_config, &loop);
    defer client.deinit();
    client.setCallbacks(&probe, Probe.onClientConnection, null, null);
    client.start();

    _ = try client.connectAddress(net.initIp4(.{ 127, 0, 0, 1 }, server_port), "localhost", placement_hint);

    // 单线程内交替驱动服务端与客户端，直到双方就绪或超时。
    var elapsed_ms: usize = 0;
    while (elapsed_ms < 5000) : (elapsed_ms += 1) {
        try loop.run(.no_wait);
        if (probe.server_ready and probe.client_ready) break;
        try std.Io.sleep(std.testing.io, std.Io.Duration.fromMilliseconds(1), .awake);
    }

    return probe.server_ready and probe.client_ready;
}

test "server and client complete a real QUIC handshake" {
    try std.testing.expect(try runLoopbackHandshake(null));
}

// Worker 级亲和的支点验证（设计文档 §8.5 策略 B / §13）。
//
// 客户端自选一个 12 字节的 CID v1 作为 initial DCID，里面的 worker_id 故意与服务端
// 自己的（0）不同。要证明的是两件事：
//
// 1. picoquic 服务端接受这种自选 DCID——它只拒绝短于 8 字节的（packet.c 的 initial
//    包筛查，`PICOQUIC_ENFORCED_INITIAL_CID_LENGTH`），12 字节合法。
// 2. 它不会干扰服务端自己签发的 CID，握手照常完成。
//
// 分流那一半不在这里：reuseport 分类器只看 DCID 的 magic/version/worker_id，不区分
// 这个 CID 是谁选的，已由 reuseport.zig 的用例覆盖。内核 BPF 本身是 Linux only，
// macOS 上 attach 是空实现，只能在真实 Linux 上端到端验证。
test "a client-chosen 12-byte CID v1 as initial DCID still completes the handshake" {
    const hint = cluster_cid.encode(7, 3, .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF });
    try std.testing.expect(try runLoopbackHandshake(hint));
}
