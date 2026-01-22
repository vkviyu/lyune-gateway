//! src/gateway/worker.zig
//!
//! 网关工作者 (GatewayWorker)
//!
//! 职责：
//! - 初始化并运行 ServerDriver (底层引擎)
//! - 维护业务状态 (ConnectionManager)
//! - 处理业务逻辑 (Stream Dispatch, Message Handling)

const std = @import("std");
const xev = @import("xev");
const quic = @import("../quic/mod.zig");
const driver = @import("../driver/server.zig"); // 引入新的 Driver
const connection_mod = @import("connection.zig");
const stream_handler = @import("stream_handler.zig");
const err_handler = @import("../common/mod.zig").err;

// 类型别名
const ConnectionManager = connection_mod.ConnectionManager;
const ConnectionContext = connection_mod.ConnectionContext;
const ServerDriver = driver.ServerDriver;

// 泛型实例化
const BufferedHandler = stream_handler.BufferedMessageHandler(ConnectionContext);
const StreamDelegate = stream_handler.StreamDelegate(ConnectionContext);

pub const GatewayWorker = struct {
    const Self = @This();

    allocator: std.mem.Allocator,

    // 底层驱动器 (替代了 endpoint, io_loop, gso_buffer 等)
    server_driver: ServerDriver,

    // 业务组件
    conn_manager: ConnectionManager,

    // 事件循环 (Worker 拥有所有权)
    event_loop: *xev.Loop,

    running: bool = false,

    /// 创建 Worker 实例
    pub fn init(allocator: std.mem.Allocator, config: quic.QuicConfig, thread_id: u8) !Self {
        // 1. 创建 Event Loop
        const event_loop = try allocator.create(xev.Loop);
        event_loop.* = xev.Loop.init(.{}) catch {
            allocator.destroy(event_loop);
            return error.LoopInitFailed;
        };
        errdefer {
            event_loop.deinit();
            allocator.destroy(event_loop);
        }

        // 2. 创建 Server Driver
        // 注意：Config, ThreadID, Loop 都传给 Driver
        var server_driver = try ServerDriver.init(allocator, config, thread_id, event_loop);
        errdefer server_driver.deinit();

        return .{
            .allocator = allocator,
            .server_driver = server_driver,
            .conn_manager = ConnectionManager.init(allocator),
            .event_loop = event_loop,
        };
    }

    /// 释放资源
    pub fn deinit(self: *Self) void {
        self.conn_manager.deinit();
        self.server_driver.deinit();
        self.event_loop.deinit();
        self.allocator.destroy(self.event_loop);
    }

    /// 启动工作循环（阻塞）
    pub fn run(self: *Self) !void {
        self.running = true;
        defer self.running = false;

        // 1. 注册业务回调到 Driver
        self.server_driver.setCallbacks(self, handleNewConnection, handleStreamData, handleConnectionClose);

        // 2. 启动 Driver (非阻塞)
        self.server_driver.start();

        std.log.info("GatewayWorker loop running...", .{});

        // 3. 运行主循环 (阻塞)
        try self.event_loop.run(.until_done);
    }

    /// 停止工作循环
    pub fn stop(self: *Self) void {
        self.running = false;
        self.server_driver.stop();
    }

    // ========================================================================
    // 业务逻辑回调 (由 Driver 触发)
    // ========================================================================

    /// 新连接建立
    fn handleNewConnection(ud: ?*anyopaque, conn: *quic.Connection) void {
        const self = castSelfOpt(ud) orelse return;

        // 业务逻辑：注册到管理器
        _ = self.conn_manager.add(conn) catch |e| {
            err_handler.reportError(.session, "Failed to register connection", e);
            return;
        };
        std.log.info("[CONN] new: {x}", .{conn.getConnectionIdBytes()});
    }

    /// 连接关闭
    fn handleConnectionClose(ud: ?*anyopaque, conn: *quic.Connection, event: quic.CallbackEvent) void {
        const self = castSelfOpt(ud) orelse return;

        // 业务逻辑：从管理器移除
        self.conn_manager.remove(conn);
        std.log.info("[CONN] closed: {x}, reason: {s}", .{ conn.getConnectionIdBytes(), @tagName(event) });
    }

    /// 流数据到达
    fn handleStreamData(ud: ?*anyopaque, conn: *quic.Connection, stream_id: u64, data: []const u8, is_fin: bool) void {
        const self = castSelfOpt(ud) orelse return;
        const ctx = self.conn_manager.get(conn) orelse return;

        // 业务逻辑：流分发
        if (ctx.getStreamHandler(stream_id)) |handler| {
            handler.onData(data, is_fin);
            if (is_fin) ctx.removeStreamHandler(stream_id);
            return;
        }

        // 新流：创建处理器
        createAndDispatch(self, ctx, stream_id, data, is_fin);
    }

    // ========================================================================
    // 私有辅助函数 (业务相关)
    // ========================================================================

    fn createAndDispatch(self: *Self, ctx: *ConnectionContext, stream_id: u64, data: []const u8, is_fin: bool) void {
        const delegate = StreamDelegate{
            .ptr = ctx,
            .onMessage = onMessageComplete,
        };

        var handler = BufferedHandler.init(self.allocator, delegate, stream_id) catch |e| {
            err_handler.reportError(.session, "Failed to create stream handler", e);
            return;
        };

        ctx.registerStreamHandler(stream_id, handler) catch |e| {
            err_handler.reportError(.session, "Failed to register stream handler", e);
            handler.deinit();
            return;
        };

        handler.onData(data, is_fin);
        if (is_fin) {
            ctx.removeStreamHandler(stream_id);
        }
    }

    fn onMessageComplete(ctx: *ConnectionContext, stream_id: u64, message: []const u8, is_fin: bool) void {
        _ = ctx;
        // 这里可以处理完整的业务消息，比如解析 HTTP/JSON，或者转发给 Router
        if (is_fin) {
            std.log.info("[MSG] complete: stream={}, len={}", .{ stream_id, message.len });
        }
    }

    inline fn castSelfOpt(ud: ?*anyopaque) ?*Self {
        return if (ud) |u| @as(*Self, @ptrCast(@alignCast(u))) else null;
    }
};
