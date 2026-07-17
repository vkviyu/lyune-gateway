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

const foundation = @import("../foundation/mod.zig");
const err_handler = foundation.err;
const control = @import("../control/mod.zig");
const reactor = @import("../reactor/mod.zig");
const ServerDriver = reactor.server.ServerDriver;
const protocol = @import("../protocol/mod.zig");
const backend = @import("../backend/mod.zig");
const quic = @import("../quic/mod.zig");
const QUICConfig = quic.config.QUICConfig;
const QUICConnection = quic.connection.Connection;
const QUICCallbackEvent = quic.c.CallbackEvent;
const BackendTransport = backend.BackendTransport;
const TransportRegistry = backend.TransportRegistry;
const TransportPath = backend.TransportPath;
const connection = @import("connection.zig");
const ConnectionManager = connection.ConnectionManager;
const ConnectionContext = connection.ConnectionContext;

// 引入新的 Driver
// 类型别名
// 泛型实例化
const BufferedHandler = protocol.handler.BufferedMessageHandler(ConnectionContext);
const StreamDelegate = protocol.handler.StreamDelegate(ConnectionContext);

const BackendStreamRoute = struct {
    client_cnx: quic.c.QuicCnx,
    client_stream_id: u64,
};

pub const GatewayWorker = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    event_loop: *xev.Loop,
    worker_id: u8,
    coordinator: *control.Coordinator,
    handoff_async: xev.Async,
    handoff_completion: xev.Completion = undefined,

    // 底层驱动器 (替代了 endpoint, io_loop, gso_buffer 等)
    server_driver: reactor.server.ServerDriver,

    // 业务组件
    conn_manager: ConnectionManager,
    transport_registry: TransportRegistry,
    backend_routes: std.AutoHashMap(u64, BackendStreamRoute),

    // Backend receive polling timer.
    backend_timer: xev.Timer,
    backend_timer_completion: xev.Completion = undefined,
    backend_poll_interval_ms: u64,
    running: bool = false,

    /// 创建 Worker 实例
    pub fn init(allocator: std.mem.Allocator, config: QUICConfig, thread_id: u8, transport_registry: TransportRegistry, backend_poll_interval_ms: u64, socket_fd: ?std.posix.socket_t, coordinator: *control.Coordinator) !Self {

        // GatewayWorker owns a supplied socket from entry, even if setup fails early.
        const event_loop = allocator.create(xev.Loop) catch |err| {
            closeSocket(socket_fd);
            return err;
        };
        event_loop.* = xev.Loop.init(.{}) catch {
            allocator.destroy(event_loop);
            closeSocket(socket_fd);
            return error.LoopInitFailed;
        };
        errdefer {
            event_loop.deinit();
            allocator.destroy(event_loop);
        }

        // 2. 创建 Server Driver
        // 注意：Config, ThreadID, Loop 都传给 Driver
        var server_driver = try ServerDriver.init(
            allocator,
            config,
            thread_id,
            event_loop,
            socket_fd,
            coordinator.packetRouter(),
        );
        errdefer server_driver.deinit();

        var handoff_async = try xev.Async.init();
        errdefer handoff_async.deinit();

        const backend_timer = xev.Timer.init() catch return error.TimerInitFailed;
        errdefer backend_timer.deinit();

        return .{
            .allocator = allocator,
            .event_loop = event_loop,
            .worker_id = thread_id,
            .coordinator = coordinator,
            .handoff_async = handoff_async,
            .server_driver = server_driver,
            .conn_manager = ConnectionManager.init(allocator),
            .transport_registry = transport_registry,
            .backend_routes = std.AutoHashMap(u64, BackendStreamRoute).init(allocator),
            .backend_timer = backend_timer,
            .backend_poll_interval_ms = backend_poll_interval_ms,
        };
    }

    /// 释放资源
    pub fn deinit(self: *Self) void {
        self.coordinator.packetRouter().setNotifier(self.worker_id, null) catch {};
        self.backend_routes.deinit();
        self.backend_timer.deinit();
        self.handoff_async.deinit();
        self.conn_manager.deinit();
        self.server_driver.deinit();
        self.event_loop.deinit();
        self.allocator.destroy(self.event_loop);
    }

    /// 启动工作循环（阻塞）
    pub fn run(self: *Self) !void {
        self.running = true;
        defer self.running = false;

        try self.coordinator.packetRouter().setNotifier(self.worker_id, .{
            .ptr = self,
            .notifyFn = notifyPacketHandoff,
        });
        defer self.coordinator.packetRouter().setNotifier(self.worker_id, null) catch {};
        self.handoff_async.wait(self.event_loop, &self.handoff_completion, Self, self, handoffCallback);

        try self.coordinator.workerStarted(self.worker_id);
        defer self.coordinator.workerStopped(self.worker_id);

        // 1. 注册业务回调到 Driver
        self.server_driver.setCallbacks(self, handleNewConnection, handleStreamData, handleConnectionClose);

        // 2. 启动 Driver (非阻塞)
        self.server_driver.start();
        self.resolveRegisteredTransports();
        self.scheduleBackendPoll(self.backend_poll_interval_ms);

        std.log.info("GatewayWorker loop running...", .{});

        // 3. 运行主循环 (阻塞)
        try self.event_loop.run(.until_done);
    }

    /// 停止工作循环
    pub fn stop(self: *Self) void {
        self.running = false;
        self.server_driver.stop();
    }

    pub fn registerTransport(self: *Self, path: TransportPath, route_key: u8, transport: BackendTransport) void {
        self.transport_registry.register(path, route_key, transport);
    }

    fn resolveRegisteredTransports(self: *Self) void {
        for (0..256) |route_key| {
            const key: u8 = @intCast(route_key);
            if (self.transport_registry.getExact(.direct, key)) |transport| {
                transport.resolve(key, onBackendReady, self);
            }
            if (self.transport_registry.getExact(.relay, key)) |transport| {
                transport.resolve(key, onBackendReady, self);
            }
        }
    }

    // ========================================================================
    // 业务逻辑回调 (由 Driver 触发)
    // ========================================================================

    /// 新连接建立
    fn handleNewConnection(ud: ?*anyopaque, conn: *QUICConnection) void {
        const self = castSelfOpt(ud) orelse return;
        if (!self.coordinator.acceptsNewConnections()) {
            conn.close();
            return;
        }

        // 业务逻辑：注册到管理器
        _ = self.conn_manager.add(conn, self) catch |e| {
            err_handler.reportError(.session, "Failed to register connection", e);
            return;
        };
        std.log.info("[CONN] new: {x}", .{conn.getConnectionIdBytes()});
    }

    /// 连接关闭
    fn handleConnectionClose(ud: ?*anyopaque, conn: *QUICConnection, event: QUICCallbackEvent) void {
        const self = castSelfOpt(ud) orelse return;

        // 业务逻辑：从管理器移除
        self.conn_manager.remove(conn);
        std.log.info("[CONN] closed: {x}, reason: {s}", .{ conn.getConnectionIdBytes(), @tagName(event) });
    }

    /// 流数据到达
    fn handleStreamData(ud: ?*anyopaque, conn: *QUICConnection, stream_id: u64, data: []const u8, is_fin: bool) void {
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
        const self = ctx.gateway_ctx orelse {
            std.log.err("[MSG] missing worker context for stream={}", .{stream_id});
            return;
        };
        const worker: *Self = @ptrCast(@alignCast(self));
        worker.forwardClientMessage(ctx, stream_id, message, is_fin) catch |err| {
            err_handler.reportError(.session, "Failed to forward client message", err);
        };
    }

    fn forwardClientMessage(self: *Self, ctx: *ConnectionContext, client_stream_id: u64, message: []const u8, is_fin: bool) !void {
        if (!is_fin) return;

        var decoder = protocol.codec.FrameDecoder.init(self.allocator);
        defer decoder.deinit();

        const frame = (try decoder.feed(message)) orelse return error.IncompleteFrame;
        const header = frame.header;
        const path = transportPathForMode(header.mode) orelse {
            std.log.warn("[ROUTE] unsupported mode=0x{x}", .{@intFromEnum(header.mode)});
            return;
        };

        const transport = self.transport_registry.get(path, header.route_key) orelse {
            std.log.warn("[ROUTE] route not found: path={s}, route=0x{x}", .{ @tagName(path), header.route_key });
            return;
        };

        const backend_stream_id = try transport.send(header.route_key, message);
        try self.backend_routes.put(backend_stream_id, .{
            .client_cnx = ctx.cnx_handle,
            .client_stream_id = client_stream_id,
        });

        std.log.info("[ROUTE] client_stream={} -> backend_stream={} mode=0x{x} route=0x{x}", .{ client_stream_id, backend_stream_id, @intFromEnum(header.mode), header.route_key });
    }

    fn drainBackendResponses(self: *Self) void {
        self.drainTransportPath(.direct);
        self.drainTransportPath(.relay);
    }

    fn drainTransportPath(self: *Self, path: TransportPath) void {
        for (0..256) |route_key| {
            const key: u8 = @intCast(route_key);
            const transport = self.transport_registry.getExact(path, key) orelse continue;
            self.drainTransport(transport);
        }
    }

    fn drainTransport(self: *Self, transport: BackendTransport) void {
        while (true) {
            const event = transport.receive() catch |err| {
                err_handler.reportError(.session, "Failed to receive backend response", err);
                return;
            } orelse break;
            defer event.deinit(self.allocator);

            const route = self.backend_routes.get(event.stream_id) orelse {
                std.log.warn("[ROUTE] orphan backend response: backend_stream={}", .{event.stream_id});
                continue;
            };

            var client_conn = QUICConnection.fromRaw(route.client_cnx);
            client_conn.streamWrite(route.client_stream_id, event.data, event.is_fin) catch |err| {
                err_handler.reportError(.session, "Failed to write backend response to client", err);
                _ = self.backend_routes.remove(event.stream_id);
                continue;
            };

            if (event.is_fin) {
                _ = self.backend_routes.remove(event.stream_id);
            }
        }
    }

    fn transportPathForMode(mode: protocol.frame.TransportMode) ?TransportPath {
        if (mode.isDirect()) return .direct;
        if (mode.isRelay()) return .relay;
        return null;
    }

    fn scheduleBackendPoll(self: *Self, delay_ms: u64) void {
        self.backend_timer.run(self.event_loop, &self.backend_timer_completion, delay_ms, Self, self, backendPollCallback);
    }

    fn backendPollCallback(
        ud: ?*Self,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        _ = result catch {};

        const self = ud orelse return .disarm;
        if (!self.running) return .disarm;

        self.drainBackendResponses();
        if (self.backend_timer_completion.state() != .active) {
            self.scheduleBackendPoll(self.backend_poll_interval_ms);
        }
        return .disarm;
    }

    fn onBackendReady(ctx: ?*anyopaque, err: ?backend.TransportError) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        _ = self;
        if (err) |e| {
            std.log.err("[BACKEND] transport connect failed: {}", .{e});
        } else {
            std.log.info("[BACKEND] transport ready", .{});
        }
    }

    /// 交接队列的唤醒回调：其他 Worker push 包后调用，通过 xev.Async 唤醒本 Worker 事件循环。
    /// 注意此函数会被别的线程调用，只能做线程安全的 async.notify。
    fn notifyPacketHandoff(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.handoff_async.notify() catch |err| {
            err_handler.reportError(.transport, "Failed to wake packet owner Worker", err);
        };
    }

    /// 被唤醒后在本 Worker 线程内执行：把交接队列里属于自己的包全部取走并处理。
    fn handoffCallback(
        ud: ?*Self,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Async.WaitError!void,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        const self = ud orelse return .disarm;
        _ = result catch |err| {
            err_handler.reportError(.transport, "Packet handoff notification failed", err);
            return if (self.running) .rearm else .disarm;
        };

        // 一次唤醒可能对应多个积压包，循环排空；notify 可能被合并，所以不能只处理一个。
        while (self.coordinator.packetRouter().pop(self.worker_id)) |packet| {
            self.server_driver.handleForwardedPacket(&packet);
        }
        return if (self.running) .rearm else .disarm;
    }

    fn closeSocket(socket_fd: ?std.posix.socket_t) void {
        if (socket_fd) |fd| _ = std.c.close(fd);
    }

    inline fn castSelfOpt(ud: ?*anyopaque) ?*Self {
        return if (ud) |u| @as(*Self, @ptrCast(@alignCast(u))) else null;
    }
};

test "GatewayWorker maps frame modes to transport paths" {
    try std.testing.expectEqual(TransportPath.direct, GatewayWorker.transportPathForMode(.direct_buffered).?);
    try std.testing.expectEqual(TransportPath.direct, GatewayWorker.transportPathForMode(.direct_streaming).?);
    try std.testing.expectEqual(TransportPath.relay, GatewayWorker.transportPathForMode(.relay_buffered).?);
    try std.testing.expectEqual(TransportPath.relay, GatewayWorker.transportPathForMode(.relay_streaming).?);
    try std.testing.expect(GatewayWorker.transportPathForMode(.control) == null);
}
