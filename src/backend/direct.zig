//! 直连 QUIC 传输实现
//!
//! 网关直连后端服务的 BackendTransport 实现。
//! 负责将通用的 BackendTransport 接口调用转发给底层的 AsyncClient。

const std = @import("std");
const xev = @import("xev");
const build_options = @import("build_options");
const foundation = @import("../foundation/mod.zig");
const discovery_mod = @import("../control/discovery.zig");
const quic = @import("../quic/mod.zig");
const reactor = @import("../reactor/mod.zig");
const AsyncClient = reactor.client.AsyncClient;

const backend_mod = @import("transport.zig");
const BackendTransport = backend_mod.BackendTransport;
const TransportError = backend_mod.TransportError;
const ResolveCallback = backend_mod.ResolveCallback;
const TransportRecv = backend_mod.TransportRecv;
const protocol = @import("../protocol/mod.zig");

const Resolver = foundation.resolver.Resolver;
const ResolveHandle = foundation.resolver.ResolveHandle;
const ResolveResult = foundation.resolver.ResolveResult;
const QUICConnection = quic.connection.Connection;

// ============================================================================
// 配置
// ============================================================================

/// 直连传输配置
pub const DirectConfig = struct {
    /// 后端服务器地址
    server_host: [:0]const u8,
    /// 后端服务器端口
    server_port: u16,
    /// ALPN 协议标识
    alpn: [:0]const u8 = "lyune-im",
    /// 接收队列最大容量
    max_recv_queue: usize = 1024,
    /// 是否验证服务器证书
    verify_cert: bool = true,
    /// 根证书文件路径（可选）
    root_cert_file: ?[:0]const u8 = null,
    /// QUIC 空闲超时（毫秒）
    idle_timeout_ms: u64 = 30_000,
    /// QUIC 拥塞控制算法
    congestion_algorithm: quic.config.Config.CongestionAlgorithm = .bbr,
};

// ============================================================================
// 接收数据结构
// ============================================================================

/// 内部队列使用的接收事件。
///
/// `stream_id` 和 `is_fin` 属于后端 QUIC stream 语义，上层需要用它们将后端响应
/// 关联回客户端 stream，并正确处理流式结束。
const ReceivedPacket = struct {
    stream_id: u64,
    data: []u8, // 拥有所有权
    is_fin: bool,

    fn deinit(self: ReceivedPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

// ============================================================================
// 直连传输实现
// ============================================================================

pub const DirectTransport = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    config: DirectConfig,
    event_loop: *xev.Loop,

    /// 异步客户端实例
    async_client: ?AsyncClient,
    resolver: Resolver,
    discovery: ?discovery_mod.ServiceDiscovery,
    resolve_handle: ?ResolveHandle,
    selected_host: ?[:0]u8,
    selected_port: u16,

    /// 接收队列 (使用 Unmanaged，节省内存并手动管理 Allocator)
    recv_queue: std.ArrayList(ReceivedPacket),

    /// 状态标记
    connected: bool,
    closed: bool,

    /// 异步回调：连接就绪回调
    on_ready_callback: ?ResolveCallback,
    /// 异步回调：回调上下文
    on_ready_ctx: ?*anyopaque,
    /// 回调是否已触发（确保只调用一次）
    callback_fired: bool,

    /// 下一个由客户端发起的后端双向 stream id。
    /// QUIC 客户端发起的 bidi stream id 从 0 开始，每次递增 4。
    next_bidi_stream_id: u64,

    // ========================================================================
    // 生命周期
    // ========================================================================

    pub fn init(allocator: std.mem.Allocator, config: DirectConfig, event_loop: *xev.Loop, resolver_impl: Resolver, discovery: ?discovery_mod.ServiceDiscovery) !Self {
        return .{
            .allocator = allocator,
            .config = config,
            .event_loop = event_loop,
            .async_client = null,
            .resolver = resolver_impl,
            .discovery = discovery,
            .resolve_handle = null,
            .selected_host = null,
            .selected_port = 0,
            .recv_queue = .{ .items = &.{}, .capacity = 0 },
            .connected = false,
            .closed = false,
            .on_ready_callback = null,
            .on_ready_ctx = null,
            .callback_fired = false,
            .next_bidi_stream_id = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.resolve_handle) |handle| {
            self.resolver.cancel(handle);
            self.resolve_handle = null;
        }

        // 1. 关闭客户端
        if (self.async_client) |*client| {
            client.deinit();
        }
        self.async_client = null;
        if (self.selected_host) |host| self.allocator.free(host);
        self.selected_host = null;
        self.selected_port = 0;

        // 2. 清理接收队列
        for (self.recv_queue.items) |pkt| {
            pkt.deinit(self.allocator);
        }
        // Unmanaged deinit 需要传入 allocator
        self.recv_queue.deinit(self.allocator);

        self.closed = true;
        self.connected = false;

        // 3. 清理回调状态
        self.on_ready_callback = null;
        self.on_ready_ctx = null;
        self.callback_fired = false;
    }

    // ========================================================================
    // 内部辅助方法
    // ========================================================================

    fn selectEndpoint(self: *Self, route_key: u8) TransportError!void {
        const endpoint = if (self.discovery) |discovery|
            (discovery.snapshot().route(route_key) orelse return TransportError.RouteNotFound).firstHealthy() orelse return TransportError.RouteNotFound
        else
            discovery_mod.ServiceEndpoint{
                .id = "configured-direct-backend",
                .host = self.config.server_host,
                .port = self.config.server_port,
                .weight = 1,
                .state = .healthy,
            };

        const host = self.allocator.dupeZ(u8, endpoint.host) catch return TransportError.OutOfMemory;
        if (self.selected_host) |previous| self.allocator.free(previous);
        self.selected_host = host;
        self.selected_port = endpoint.port;
    }

    /// 启动异步连接（内部使用）
    fn _startConnect(self: *Self, route_key: u8) TransportError!void {
        try self.selectEndpoint(route_key);
        if (self.async_client == null) {
            // 1. 构造底层 QUIC 配置
            const quic_config = quic.config.QUICConfig{
                .base = .{
                    .alpn = self.config.alpn,
                    .root_cert_file = self.config.root_cert_file,
                    .verify_cert = self.config.verify_cert,
                    .idle_timeout_ms = self.config.idle_timeout_ms,
                    .congestion_algorithm = self.config.congestion_algorithm,
                },
                .bind_port = 0,
            };

            // 2. 初始化 AsyncClient
            self.async_client = AsyncClient.init(
                self.allocator,
                quic_config,
                self.event_loop,
            ) catch |err| {
                return switch (err) {
                    error.OutOfMemory => TransportError.OutOfMemory,
                    else => TransportError.ConnectionFailed,
                };
            };

            // 3. 设置回调
            var client = &self.async_client.?;
            client.setCallbacks(
                self,
                onClientConnected,
                onClientStreamData,
                onClientClose,
            );

            // 4. 启动 IO
            client.start();
        }

        // 5. 发起异步 DNS，解析完成后再创建 QUIC 连接。
        self.resolve_handle = self.resolver.resolve(
            self.selected_host.?,
            self.selected_port,
            onResolved,
            self,
        ) catch |err| {
            return switch (err) {
                error.OutOfMemory => TransportError.OutOfMemory,
                error.Timeout => TransportError.Timeout,
                else => TransportError.ConnectionFailed,
            };
        };
    }

    // ========================================================================
    // BackendTransport 接口实现
    // ========================================================================

    /// 建立连接（异步，通过回调通知结果）
    ///
    /// 发起连接但不等待，连接结果通过 on_ready 回调通知。
    /// 如果已连接，立即调用回调返回成功。
    pub fn resolveImpl(
        self: *Self,
        route_key: u8,
        on_ready: ?ResolveCallback,
        ctx: ?*anyopaque,
    ) void {
        // 如果已关闭，立即回调错误
        if (self.closed) {
            if (on_ready) |cb| {
                cb(ctx, TransportError.Closed);
            }
            return;
        }

        // 如果已连接，立即回调成功
        if (self.connected) {
            if (on_ready) |cb| {
                cb(ctx, null);
            }
            return;
        }

        // 保存回调
        self.on_ready_callback = on_ready;
        self.on_ready_ctx = ctx;
        self.callback_fired = false;

        // 发起异步连接
        self._startConnect(route_key) catch |err| {
            self.fireCallback(err);
            return;
        };
    }

    /// 触发回调（内部使用，确保只调用一次）
    fn fireCallback(self: *Self, err: ?TransportError) void {
        if (self.callback_fired) return;
        self.callback_fired = true;

        if (self.on_ready_callback) |cb| {
            cb(self.on_ready_ctx, err);
        }

        // 清理回调引用
        self.on_ready_callback = null;
        self.on_ready_ctx = null;
    }

    /// 发送已经编码好的数据到后端，并返回后端 stream id。
    pub fn sendImpl(self: *Self, route_key: u8, data: []const u8) TransportError!u64 {
        _ = route_key;

        if (self.closed) return TransportError.Closed;
        if (self.async_client == null) return TransportError.ConnectionFailed;

        var client = &self.async_client.?;
        if (client.active_connection) |*conn| {
            if (!conn.isConnected()) return TransportError.ConnectionFailed;

            const stream_id = self.nextBidiStreamId();
            conn.streamWrite(stream_id, data, true) catch return TransportError.SendFailed;
            return stream_id;
        } else {
            return TransportError.ConnectionFailed;
        }
    }

    fn nextBidiStreamId(self: *Self) u64 {
        const stream_id = self.next_bidi_stream_id;
        self.next_bidi_stream_id += 4;
        return stream_id;
    }

    /// 接收后端返回的 stream-aware 事件。
    pub fn receiveImpl(self: *Self) TransportError!?TransportRecv {
        if (self.closed) return TransportError.Closed;

        if (self.recv_queue.items.len > 0) {
            // orderedRemove 不需要 allocator，它只是移动内存
            const pkt = self.recv_queue.orderedRemove(0);
            return .{
                .stream_id = pkt.stream_id,
                .data = pkt.data,
                .is_fin = pkt.is_fin,
            };
        }

        return null;
    }

    /// 关闭
    pub fn closeImpl(self: *Self) void {
        self.deinit();
    }

    /// 转换为接口
    pub fn asTransport(self: *Self) BackendTransport {
        return BackendTransport.init(Self, self);
    }

    // ========================================================================
    // 内部回调处理
    // ========================================================================

    fn onResolved(ctx: ?*anyopaque, result: ResolveResult) void {
        const self: *Self = @ptrCast(@alignCast(ctx.?));
        self.resolve_handle = null;
        if (self.closed) return;

        const address = switch (result) {
            .address => |addr| addr,
            .err => |err| {
                self.fireCallback(switch (err) {
                    error.OutOfMemory => TransportError.OutOfMemory,
                    error.Timeout => TransportError.Timeout,
                    else => TransportError.ConnectionFailed,
                });
                return;
            },
        };

        if (self.async_client) |*client| {
            _ = client.connectAddress(address, self.selected_host orelse return) catch {
                self.fireCallback(TransportError.ConnectionFailed);
                return;
            };
        } else {
            self.fireCallback(TransportError.ConnectionFailed);
        }
    }

    fn onClientConnected(ctx: ?*anyopaque, conn: *QUICConnection) void {
        _ = conn;
        const self: *Self = @ptrCast(@alignCast(ctx));

        self.connected = true;
        std.log.info("[DirectTransport] Connected to {s}:{}", .{ self.selected_host orelse self.config.server_host, self.selected_port });

        // 连接成功，调用用户回调
        self.fireCallback(null);
    }

    fn onClientStreamData(ctx: ?*anyopaque, conn: *QUICConnection, stream_id: u64, data: []const u8, is_fin: bool) void {
        _ = conn;

        const self: *Self = @ptrCast(@alignCast(ctx));

        if (data.len == 0 and !is_fin) return;

        if (self.recv_queue.items.len >= self.config.max_recv_queue) {
            std.log.warn("[DirectTransport] Recv queue full, dropping packet", .{});
            return;
        }

        const data_copy = self.allocator.dupe(u8, data) catch {
            std.log.err("[DirectTransport] OOM on recv", .{});
            return;
        };

        self.recv_queue.append(self.allocator, .{
            .stream_id = stream_id,
            .data = data_copy,
            .is_fin = is_fin,
        }) catch {
            self.allocator.free(data_copy);
            std.log.err("[DirectTransport] OOM on queue append", .{});
        };
    }

    fn onClientClose(ctx: ?*anyopaque, conn: *QUICConnection, event: quic.c.CallbackEvent) void {
        _ = conn;
        _ = event;
        const self: *Self = @ptrCast(@alignCast(ctx));

        const was_connected = self.connected;
        self.connected = false;

        std.log.info("[DirectTransport] Connection closed", .{});

        // 如果连接尚未建立就关闭了，表示连接失败
        if (!was_connected) {
            self.fireCallback(TransportError.ConnectionFailed);
        }
    }
};

// ============================================================================
// 测试
// ============================================================================

const StaticResolver = struct {
    address: foundation.net.Address,

    pub fn resolve(
        self: *StaticResolver,
        host: []const u8,
        port: u16,
        callback: foundation.resolver.ResolveCallback,
        ctx: ?*anyopaque,
    ) foundation.resolver.ResolveError!foundation.resolver.ResolveHandle {
        _ = host;
        const addr = switch (self.address) {
            .ip4 => |ip4| foundation.net.initIp4(ip4.bytes, port),
            .ip6 => |ip6| foundation.net.initIp6(ip6.bytes, port),
        };
        callback(ctx, .{ .address = addr });
        return .{ .id = 0 };
    }

    pub fn cancel(self: *StaticResolver, handle: foundation.resolver.ResolveHandle) void {
        _ = self;
        _ = handle;
    }

    pub fn deinit(self: *StaticResolver) void {
        _ = self;
    }

    fn asResolver(self: *StaticResolver) Resolver {
        return foundation.resolver.Resolver.init(StaticResolver, self);
    }
};

test "DirectTransport init and state check" {
    const allocator = std.testing.allocator;

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var static_resolver = StaticResolver{ .address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 8443) };
    var transport = try DirectTransport.init(allocator, .{
        .server_host = "127.0.0.1",
        .server_port = 8443,
    }, &loop, static_resolver.asResolver(), null);
    defer transport.deinit();

    try std.testing.expectEqual(false, transport.connected);
    try std.testing.expectEqual(false, transport.closed);
    try std.testing.expect(transport.async_client == null);
}

test "DirectTransport selects a healthy endpoint from discovery" {
    const allocator = std.testing.allocator;
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    const endpoints = [_]discovery_mod.ServiceEndpoint{
        .{ .id = "down", .host = "down.internal", .port = 9001, .weight = 1, .state = .unavailable },
        .{ .id = "ready", .host = "ready.internal", .port = 9002, .weight = 10, .state = .healthy },
    };
    const routes = [_]discovery_mod.Route{.{ .route_key = 9, .revision = 1, .endpoints = &endpoints }};
    var static_discovery = discovery_mod.StaticDiscovery.init(&routes);
    var static_resolver = StaticResolver{ .address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 8443) };
    var transport = try DirectTransport.init(allocator, .{
        .server_host = "fallback.internal",
        .server_port = 8443,
    }, &loop, static_resolver.asResolver(), static_discovery.asDiscovery());
    defer transport.deinit();

    try transport.selectEndpoint(9);
    try std.testing.expectEqualStrings("ready.internal", transport.selected_host.?);
    try std.testing.expectEqual(@as(u16, 9002), transport.selected_port);
    try std.testing.expectError(TransportError.RouteNotFound, transport.selectEndpoint(10));
}

test "DirectTransport closed state logic" {
    std.debug.print("\n=== 正在运行测试: DirectTransport closed state ===\n", .{});
    const allocator = std.testing.allocator;
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var static_resolver = StaticResolver{ .address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 8443) };
    var transport = try DirectTransport.init(allocator, .{
        .server_host = "127.0.0.1",
        .server_port = 8443,
    }, &loop, static_resolver.asResolver(), null);

    transport.deinit();

    // 测试关闭状态下的回调行为
    const TestCtx = struct {
        error_received: ?TransportError = null,

        fn onReady(ctx: ?*anyopaque, err: ?TransportError) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.error_received = err;
        }
    };

    var test_ctx = TestCtx{};
    transport.resolveImpl(1, TestCtx.onReady, &test_ctx);
    try std.testing.expect(test_ctx.error_received != null);
    try std.testing.expect(test_ctx.error_received.? == TransportError.Closed);

    try std.testing.expectError(TransportError.Closed, transport.sendImpl(1, "test"));
    try std.testing.expectError(TransportError.Closed, transport.receiveImpl());
}

test "DirectTransport integration test (Real Server)" {
    if (!build_options.enable_integration_tests) return error.SkipZigTest;

    std.debug.print("\n=== 集成测试: 连接本地 8443 服务器 (异步回调版) ===\n", .{});
    const allocator = std.testing.allocator;

    // 1. 初始化 Loop 和 Transport
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var static_resolver = StaticResolver{ .address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 8443) };
    var transport = try DirectTransport.init(allocator, .{
        .server_host = "127.0.0.1",
        .server_port = 8443,
        .alpn = "lyune-im",
        .verify_cert = false,
        .connect_timeout_ms = 6000, // 6秒超时
    }, &loop, static_resolver.asResolver(), null);
    defer transport.deinit();

    // 2. 定义测试上下文和回调
    const TestContext = struct {
        transport: *DirectTransport,
        allocator: std.mem.Allocator,
        connected: bool = false,
        connect_error: ?TransportError = null,
        sent_stream_id: ?u64 = null,

        fn onConnected(ctx: ?*anyopaque, err: ?TransportError) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));

            if (err) |e| {
                self.connect_error = e;
                std.debug.print("!! 连接失败: {}\n", .{e});
                return;
            }

            self.connected = true;
            std.debug.print("-> 连接成功!\n", .{});

            // 连接成功后发送完整的 Lyune Frame，而不是裸字符串。
            const msg = "Hello from Zig Client!";
            var frame_buf: [1024]u8 = undefined;
            var encoder = protocol.codec.FrameEncoder.init(&frame_buf);
            const frame_data = encoder.encode(.direct_buffered, 0x01, msg) catch |encode_err| {
                std.debug.print("!! 编码失败: {}\n", .{encode_err});
                return;
            };
            const stream_id = self.transport.sendImpl(0x01, frame_data) catch |send_err| {
                std.debug.print("!! 发送失败: {}\n", .{send_err});
                return;
            };
            self.sent_stream_id = stream_id;
            std.debug.print("-> 消息已发送: stream={}, body={s}\n", .{ stream_id, msg });
        }
    };

    var test_ctx = TestContext{
        .transport = &transport,
        .allocator = allocator,
    };

    // 3. 发起异步连接
    transport.resolveImpl(0x01, TestContext.onConnected, &test_ctx);
    std.debug.print("-> 正在发起连接...\n", .{});

    // 4. 驱动事件循环直到连接成功或超时
    const timeout_ns = 6 * std.time.ns_per_s;
    var elapsed: u64 = 0;
    const step_ms: u64 = 10;

    while (!test_ctx.connected and test_ctx.connect_error == null) {
        try loop.run(.no_wait);
        try std.Io.sleep(
            std.Io.Threaded.global_single_threaded.io(),
            std.Io.Duration.fromMilliseconds(step_ms),
            .awake,
        );
        elapsed += step_ms * std.time.ns_per_ms;

        if (elapsed > timeout_ns) {
            std.debug.print("!! 测试超时 (6s) !!\n", .{});
            return error.TestTimeout;
        }
    }

    // 5. 检查连接结果
    if (test_ctx.connect_error) |err| {
        std.debug.print("!! 连接错误: {}\n", .{err});
        return error.ConnectionFailed;
    }

    // 6. 继续驱动循环，让数据发送出去并等待回复
    var received_any = false;
    var recv_attempts: usize = 0;
    var decoder = protocol.codec.FrameDecoder.init(allocator);
    defer decoder.deinit();

    while (recv_attempts < 100) : (recv_attempts += 1) {
        try loop.run(.no_wait);

        if (try transport.receiveImpl()) |event| {
            defer event.deinit(allocator);
            if (event.data.len == 0) continue;

            if (test_ctx.sent_stream_id) |sent_stream_id| {
                try std.testing.expectEqual(sent_stream_id, event.stream_id);
            }

            if (try decoder.feed(event.data)) |frame| {
                const body = frame.body;
                std.debug.print(
                    "<- 收到服务器回包: stream={}, fin={}, mode=0x{x}, route=0x{x}, body={s}\n",
                    .{ event.stream_id, event.is_fin, @intFromEnum(frame.header.mode), frame.header.route_key, body },
                );
                try std.testing.expectEqual(protocol.frame.TransportMode.direct_buffered, frame.header.mode);
                try std.testing.expectEqual(@as(u8, 0x01), frame.header.route_key);
                try std.testing.expect(std.mem.indexOf(u8, body, "Echo: Hello from Zig Client!") != null);
                received_any = true;
                break;
            }
        }

        try std.Io.sleep(
            std.Io.Threaded.global_single_threaded.io(),
            std.Io.Duration.fromMilliseconds(10),
            .awake,
        );
    }

    if (!received_any) {
        std.debug.print("!! 未收到有效回包\n", .{});
        return error.NoResponse;
    }

    std.debug.print("=== 集成测试结束 ===\n", .{});
}
