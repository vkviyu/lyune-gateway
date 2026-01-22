//! src/driver/server.zig
//!
//! QUIC 服务端驱动器 (ServerDriver)
//!
//! 职责：
//! 1. 组装 Endpoint (协议) 和 IoLoop (IO)
//! 2. 管理发送缓冲区 (GSO Buffer)
//! 3. 驱动事件循环：收包 -> 协议处理 -> 发包 -> 定时器
//!
//! 它不包含任何业务逻辑，只负责将协议事件 (Connect, Stream, Close) 向上回调。

const std = @import("std");
const xev = @import("xev");
const quic = @import("../quic/mod.zig");
const io = @import("../transport/io.zig");

// 复用常量
const GSO_BUFFER_SIZE = 64 * 1024;
const MAX_BATCH_PACKETS = 64;

pub const ServerDriver = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    endpoint: quic.Endpoint,
    io_loop: io.IoLoop,

    // 发送缓冲区 (跟随 Driver 实例在堆上)
    gso_buffer: [GSO_BUFFER_SIZE]u8 = undefined,
    packet_batch: [MAX_BATCH_PACKETS]io.Packet = undefined,

    // 用户回调接口
    user_context: ?*anyopaque = null,
    on_connection: ?*const fn (ctx: ?*anyopaque, conn: *quic.Connection) void = null,
    on_stream_data: ?*const fn (ctx: ?*anyopaque, conn: *quic.Connection, sid: u64, data: []const u8, fin: bool) void = null,
    on_connection_close: ?*const fn (ctx: ?*anyopaque, conn: *quic.Connection, event: quic.CallbackEvent) void = null,

    pub const Error = error{
        InitFailed,
        LoopInitFailed,
    } || quic.Endpoint.Error || io.IoLoop.Error;

    /// 初始化驱动器
    pub fn init(
        allocator: std.mem.Allocator,
        config: quic.QuicConfig,
        thread_id: u8,
        loop: *xev.Loop,
    ) Error!Self {
        // 初始化 Endpoint
        var endpoint = try quic.Endpoint.init(allocator, config, thread_id, null);
        errdefer endpoint.deinit();

        // 初始化 IO
        var io_loop = try io.IoLoop.init(allocator, config.bind_address, config.bind_port, loop);
        errdefer io_loop.deinit();

        return .{
            .allocator = allocator,
            .endpoint = endpoint,
            .io_loop = io_loop,
        };
    }

    pub fn deinit(self: *Self) void {
        self.io_loop.deinit();
        self.endpoint.deinit();
    }

    /// 设置业务回调
    pub fn setCallbacks(
        self: *Self,
        user_ctx: ?*anyopaque,
        on_conn: ?*const fn (?*anyopaque, *quic.Connection) void,
        on_data: ?*const fn (?*anyopaque, *quic.Connection, u64, []const u8, bool) void,
        on_close: ?*const fn (?*anyopaque, *quic.Connection, quic.CallbackEvent) void,
    ) void {
        self.user_context = user_ctx;
        self.on_connection = on_conn;
        self.on_stream_data = on_data;
        self.on_connection_close = on_close;
    }

    /// 启动驱动器 (非阻塞)
    /// 必须由外部调用 event_loop.run() 来实际运转
    pub fn start(self: *Self) void {
        // 1. 注册 IO 回调 (Driver 内部闭环)
        self.io_loop.onRecv(self, internalOnUdpRecv);
        // 初始定时器设为 1ms
        self.io_loop.onTimer(internalOnTimer, 1);

        // 2. 注册 Endpoint 回调 (Driver 内部闭环)
        self.endpoint.setUserData(self);
        self.endpoint.onConnection(internalOnNewConn);
        self.endpoint.onStreamData(internalOnStreamData);
        self.endpoint.onConnectionClose(internalOnConnClose);

        // 3. 启动 IO 监听 (向 loop 注册 fd)
        self.io_loop.start();

        std.log.info("ServerDriver active on port {}", .{self.io_loop.getLocalAddr().getPort()});
    }

    pub fn stop(self: *Self) void {
        self.io_loop.stop();
    }

    // ========================================================================
    // 核心驱动逻辑 (从 Worker 移动过来的)
    // ========================================================================

    fn internalOnUdpRecv(ctx: *anyopaque, data: []const u8, from: std.net.Address, ts: u64) void {
        const self = castSelf(ctx);
        // 喂数据给协议栈
        self.endpoint.handleIncomingPacket(data, from, self.io_loop.getLocalAddr(), ts);
        // 驱动状态机
        self.processQuicEvents();
    }

    fn internalOnTimer(ctx: *anyopaque) void {
        const self = castSelf(ctx);
        self.processQuicEvents();
    }

    /// 处理 QUIC 事件：发包 + 更新定时器
    fn processQuicEvents(self: *Self) void {
        // 1. 发送所有待发送的包
        self.flushPendingPackets();

        // 2. 计算下一次唤醒时间
        const next_wake = self.endpoint.getNextWakeTime();
        const now = quic.currentTime();

        var delta: u64 = 0;
        if (next_wake > now) {
            delta = (next_wake - now) / 1000;
        }

        if (delta == 0) delta = 1;
        if (delta > 10000) delta = 10000;

        self.io_loop.updateTimer(delta);
    }

    /// 批量发送逻辑
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
                    continue;
                }
                offset += pkt.segment_size;
            }

            if (batch_count > 0) {
                self.io_loop.sendBatch(self.packet_batch[0..batch_count]) catch {};
            }

            if (pkt.data.len < GSO_BUFFER_SIZE) break;
        }
    }

    // ========================================================================
    // 内部回调 -> 用户回调 转发器
    // ========================================================================

    fn internalOnNewConn(ctx: ?*anyopaque, conn: *quic.Connection) void {
        const self = castSelf(ctx.?);
        if (self.on_connection) |cb| cb(self.user_context, conn);
    }

    fn internalOnStreamData(ctx: ?*anyopaque, conn: *quic.Connection, sid: u64, data: []const u8, fin: bool) void {
        const self = castSelf(ctx.?);
        if (self.on_stream_data) |cb| cb(self.user_context, conn, sid, data, fin);
    }

    fn internalOnConnClose(ctx: ?*anyopaque, conn: *quic.Connection, event: quic.CallbackEvent) void {
        const self = castSelf(ctx.?);
        if (self.on_connection_close) |cb| cb(self.user_context, conn, event);
    }

    inline fn castSelf(ctx: *anyopaque) *Self {
        return @as(*Self, @ptrCast(@alignCast(ctx)));
    }
};
