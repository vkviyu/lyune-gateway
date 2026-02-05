//! 直连 QUIC 传输实现
//!
//! 网关直连后端服务的 BackendTransport 实现。
//! 负责将通用的 BackendTransport 接口调用转发给底层的 AsyncClient。

const std = @import("std");
const xev = @import("xev");
const quic = @import("../quic/mod.zig");
const driver = @import("../driver/mod.zig");
const AsyncClient = driver.client.AsyncClient;

const backend_mod = @import("backend.zig");
const BackendTransport = backend_mod.BackendTransport;
const TransportError = backend_mod.TransportError;
const ResolveCallback = backend_mod.ResolveCallback;

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
    alpn: [:0]const u8 = "lyune-gateway",
    /// 接收队列最大容量 (防止内存无限增长)
    max_recv_queue: usize = 1024,
    /// 连接超时（毫秒）
    connect_timeout_ms: u32 = 5000,
    /// 是否验证服务器证书
    verify_cert: bool = true,
    /// 根证书文件路径（可选）
    root_cert_file: ?[:0]const u8 = null,
};

// ============================================================================
// 接收数据结构
// ============================================================================

/// 内部队列使用的接收数据包
const ReceivedPacket = struct {
    data: []u8, // 拥有所有权

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

    // ========================================================================
    // 生命周期
    // ========================================================================

    pub fn init(allocator: std.mem.Allocator, config: DirectConfig, event_loop: *xev.Loop) !Self {
        return .{
            .allocator = allocator,
            .config = config,
            .event_loop = event_loop,
            .async_client = null,
            .recv_queue = .{}, // Unmanaged 直接初始化为空结构体
            .connected = false,
            .closed = false,
            .on_ready_callback = null,
            .on_ready_ctx = null,
            .callback_fired = false,
        };
    }

    pub fn deinit(self: *Self) void {
        // 1. 关闭客户端
        if (self.async_client) |*client| {
            client.deinit();
        }
        self.async_client = null;

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

    /// 启动异步连接（内部使用）
    fn _startConnect(self: *Self) TransportError!void {
        if (self.async_client == null) {
            // 1. 构造底层 QUIC 配置
            const quic_config = quic.config.QUICConfig{
                .base = .{
                    .alpn = self.config.alpn,
                    .root_cert_file = self.config.root_cert_file,
                    .verify_cert = self.config.verify_cert,
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

        // 5. 发起连接
        _ = self.async_client.?.connect(
            self.config.server_host,
            self.config.server_port,
            self.config.server_host,
        ) catch {
            // 连接失败时清理 AsyncClient
            if (self.async_client) |*client| {
                client.deinit();
            }
            self.async_client = null;
            return TransportError.ConnectionFailed;
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
        _ = route_key;

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
        self._startConnect() catch |err| {
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

    /// 发送数据
    pub fn sendImpl(self: *Self, route_key: u8, data: []const u8) TransportError!void {
        _ = route_key;

        if (self.closed) return TransportError.Closed;
        if (self.async_client == null) return TransportError.ConnectionFailed;

        var client = &self.async_client.?;
        if (client.active_connection) |*conn| {
            if (!conn.isConnected()) return TransportError.ConnectionFailed;

            // streamWrite 可能需要根据最新的 connection.zig 调整签名
            conn.streamWrite(0, data, false) catch return TransportError.SendFailed;
        } else {
            return TransportError.ConnectionFailed;
        }
    }

    /// 接收数据
    pub fn receiveImpl(self: *Self) TransportError!?[]const u8 {
        if (self.closed) return TransportError.Closed;

        if (self.recv_queue.items.len > 0) {
            // orderedRemove 不需要 allocator，它只是移动内存
            const pkt = self.recv_queue.orderedRemove(0);
            return pkt.data;
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

    fn onClientConnected(ctx: ?*anyopaque, conn: *QUICConnection) void {
        _ = conn;
        const self: *Self = @ptrCast(@alignCast(ctx));
        
        self.connected = true;
        std.log.info("[DirectTransport] Connected to {s}:{}", .{ self.config.server_host, self.config.server_port });
        
        // 连接成功，调用用户回调
        self.fireCallback(null);
    }

    fn onClientStreamData(ctx: ?*anyopaque, conn: *QUICConnection, stream_id: u64, data: []const u8, is_fin: bool) void {
        _ = conn;
        _ = is_fin;
        _ = stream_id;

        const self: *Self = @ptrCast(@alignCast(ctx));

        if (self.recv_queue.items.len >= self.config.max_recv_queue) {
            std.log.warn("[DirectTransport] Recv queue full, dropping packet", .{});
            return;
        }

        const data_copy = self.allocator.dupe(u8, data) catch {
            std.log.err("[DirectTransport] OOM on recv", .{});
            return;
        };

        self.recv_queue.append(self.allocator, .{ .data = data_copy }) catch {
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

test "DirectTransport init and state check" {
    const allocator = std.testing.allocator;

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var transport = try DirectTransport.init(allocator, .{
        .server_host = "127.0.0.1",
        .server_port = 8443,
    }, &loop);
    defer transport.deinit();

    try std.testing.expectEqual(false, transport.connected);
    try std.testing.expectEqual(false, transport.closed);
    try std.testing.expect(transport.async_client == null);
}

test "DirectTransport closed state logic" {
    std.debug.print("\n=== 正在运行测试: DirectTransport closed state ===\n", .{});
    const allocator = std.testing.allocator;
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var transport = try DirectTransport.init(allocator, .{
        .server_host = "127.0.0.1",
        .server_port = 8443,
    }, &loop);

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
    // 只有当你确定本地 8443 跑着服务器时才运行此测试
    // 为了防止在 CI 环境报错，如果你想跳过，可以 uncomment 下面这行
    // if (true) return error.SkipZigTest;

    std.debug.print("\n=== 集成测试: 连接本地 8443 服务器 (异步回调版) ===\n", .{});
    const allocator = std.testing.allocator;

    // 1. 初始化 Loop 和 Transport
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var transport = try DirectTransport.init(allocator, .{
        .server_host = "127.0.0.1",
        .server_port = 8443,
        .alpn = "lyune-gateway",
        .verify_cert = false,
        .connect_timeout_ms = 6000, // 6秒超时
    }, &loop);
    defer transport.deinit();

    // 2. 定义测试上下文和回调
    const TestContext = struct {
        transport: *DirectTransport,
        allocator: std.mem.Allocator,
        connected: bool = false,
        connect_error: ?TransportError = null,
        
        fn onConnected(ctx: ?*anyopaque, err: ?TransportError) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            
            if (err) |e| {
                self.connect_error = e;
                std.debug.print("!! 连接失败: {}\n", .{e});
                return;
            }
            
            self.connected = true;
            std.debug.print("-> 连接成功!\n", .{});
            
            // 连接成功后发送消息
            const msg = "Hello from Zig Client!";
            self.transport.sendImpl(0x01, msg) catch |send_err| {
                std.debug.print("!! 发送失败: {}\n", .{send_err});
                return;
            };
            std.debug.print("-> 消息已发送: {s}\n", .{msg});
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
        std.Thread.sleep(step_ms * std.time.ns_per_ms);
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
    while (recv_attempts < 50) : (recv_attempts += 1) {
        try loop.run(.no_wait);
        
        if (try transport.receiveImpl()) |data| {
            std.debug.print("<- 收到服务器回包: {s}\n", .{data});
            allocator.free(data);
            received_any = true;
            break;
        }
        
        std.Thread.sleep(10 * std.time.ns_per_ms);
    }

    if (!received_any) {
        std.debug.print("-> 未收到回包 (属正常现象，取决于服务器逻辑)\n", .{});
    }

    std.debug.print("=== 集成测试结束 ===\n", .{});
}
