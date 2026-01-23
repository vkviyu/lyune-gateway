//! quic/client_async.zig
//!
//! 基于 libxev 的异步 QUIC 客户端。
//! 可以在单线程中与 Server 共享同一个事件循环。

const std = @import("std");
const xev = @import("xev");
const quic_c = @import("../quic/c.zig");
const Config = @import("../quic/config.zig");
const Endpoint = @import("../quic/endpoint.zig").Endpoint;
const Connection = @import("../quic/connection.zig").Connection;
const io = @import("../transport/io.zig"); // 引用上层 transport 目录

const IoLoop = io.IoLoop;
const Packet = io.Packet;

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
    on_connected: ?*const fn (ctx: ?*anyopaque, conn: *Connection) void = null,
    on_stream_data: ?*const fn (ctx: ?*anyopaque, conn: *Connection, stream_id: u64, data: []const u8, is_fin: bool) void = null,
    on_close: ?*const fn (ctx: ?*anyopaque, conn: *Connection, event: quic_c.CallbackEvent) void = null,
    user_context: ?*anyopaque = null,

    // 当前活跃连接（简单场景通常只维护一个与后端的连接，如需连接池可改为 HashMap）
    active_connection: ?Connection = null,

    pub const Error = error{
        InitFailed,
        ConnectFailed,
        ResolveFailed,
    } || Endpoint.Error || IoLoop.Error;

    /// 初始化异步客户端
    /// loop: 外部传入的 xev.Loop（通常是 GatewayWorker 的 loop）
    pub fn init(
        allocator: std.mem.Allocator,
        config: Config.QuicConfig,
        loop: *xev.Loop,
    ) Error!Self {
        // 2. 初始化 Endpoint
        // thread_id 传 0 即可，客户端通常不需要复杂的 CID 路由
        var endpoint = try Endpoint.init(allocator, config, 0, null);
        errdefer endpoint.deinit();

        // 3. 初始化 IoLoop (绑定随机端口)
        var io_loop = try IoLoop.init(allocator, config.bind_address, config.bind_port, loop);
        errdefer io_loop.deinit();

        return .{
            .allocator = allocator,
            .endpoint = endpoint,
            .io_loop = io_loop,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.active_connection) |*conn| {
            conn.close();
        }
        self.io_loop.deinit();
        self.endpoint.deinit();
    }

    /// 设置回调
    pub fn setCallbacks(
        self: *Self,
        user_context: ?*anyopaque,
        on_connected: ?*const fn (?*anyopaque, *Connection) void,
        on_stream_data: ?*const fn (?*anyopaque, *Connection, u64, []const u8, bool) void,
        on_close: ?*const fn (?*anyopaque, *Connection, quic_c.CallbackEvent) void,
    ) void {
        self.user_context = user_context;
        self.on_connected = on_connected;
        self.on_stream_data = on_stream_data;
        self.on_close = on_close;
    }

    /// 启动客户端（非阻塞）
    /// 必须在 connect 之前调用
    pub fn start(self: *Self) void {
        // 1. 挂载 IO 回调
        self.io_loop.onRecv(self, handleUdpRecv);
        self.io_loop.onTimer(handleTimer, 100); // 初始 tick

        // 2. 挂载 Endpoint 回调
        self.endpoint.setUserData(self);
        self.endpoint.onConnection(internalOnConnected);
        self.endpoint.onStreamData(internalOnStreamData);
        self.endpoint.onConnectionClose(internalOnClose);

        // 3. 启动 IO 监听（只注册 fd 到 loop，不阻塞）
        self.io_loop.start();
    }

    /// 连接到服务器
    /// host: 目标 IP 字符串 (如 "127.0.0.1")
    /// port: 目标端口
    /// sni:  SNI (Server Name Indication)，通常同 host
    pub fn connect(self: *Self, host: []const u8, port: u16, sni: []const u8) Error!*Connection {
        // 简单的同步 DNS 解析（生产环境建议换成异步）
        const list = std.net.getAddressList(self.allocator, host, port) catch return Error.ResolveFailed;
        defer list.deinit();
        if (list.addrs.len == 0) return Error.ResolveFailed;
        const server_addr = list.addrs[0];

        // 将 Zig Address 转为 C sockaddr
        var sockaddr_storage: quic_c.c.struct_sockaddr_storage = undefined;
        const addr_bytes = std.mem.asBytes(&server_addr.any);
        @memcpy(std.mem.asBytes(&sockaddr_storage)[0..addr_bytes.len], addr_bytes);

        const now = quic_c.currentTime();

        // 创建底层连接
        const cnx_ptr = quic_c.c.picoquic_create_cnx(
            self.endpoint.getContext(),
            quic_c.nullConnectionId(),
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

        // 包装 Connection 对象
        self.active_connection = Connection.fromRaw(cnx_ptr);

        // 立即驱动一次事件循环（发送 Client Hello）
        self.processQuicEvents();

        return &self.active_connection.?;
    }

    // =========================================================================
    // 内部处理逻辑 (与 Server Worker 高度一致)
    // =========================================================================

    fn handleUdpRecv(ctx: *anyopaque, data: []const u8, from: std.net.Address, ts: u64) void {
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
    // 内部回调 -> 用户回调 桥接
    // =========================================================================

    fn internalOnConnected(ctx: ?*anyopaque, conn: *Connection) void {
        const self = castSelf(ctx.?);
        if (self.on_connected) |cb| {
            cb(self.user_context, conn);
        }
    }

    fn internalOnStreamData(ctx: ?*anyopaque, conn: *Connection, stream_id: u64, data: []const u8, is_fin: bool) void {
        const self = castSelf(ctx.?);
        if (self.on_stream_data) |cb| {
            cb(self.user_context, conn, stream_id, data, is_fin);
        }
    }

    fn internalOnClose(ctx: ?*anyopaque, conn: *Connection, event: quic_c.CallbackEvent) void {
        const self = castSelf(ctx.?);
        if (self.on_close) |cb| {
            cb(self.user_context, conn, event);
        }
        // 清理引用，但不 close，因为是回调里
        if (self.active_connection) |*c| {
            if (c.ptr == conn.ptr) {
                self.active_connection = null;
            }
        }
    }

    inline fn castSelf(ctx: *anyopaque) *Self {
        return @as(*Self, @ptrCast(@alignCast(ctx)));
    }
};

// test "AsyncClient" {
//     var loop = try xev.Loop.init(.{});
//     var client = try AsyncClient.init(std.testing.allocator, .{ .base = .{ .alpn = "lyune-gateway", .root_cert_file = "server.crt" } }, loop);
    
//     client.setCallbacks(null, null)
//     client.start();
//     try loop.run(.until_done);

// }
