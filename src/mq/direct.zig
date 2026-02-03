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
    recv_queue: std.ArrayListUnmanaged(ReceivedPacket),

    /// 状态标记
    connected: bool,
    closed: bool,

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
    }

    // ========================================================================
    // BackendTransport 接口实现
    // ========================================================================

    /// 建立连接
    pub fn resolveImpl(self: *Self, route_key: u8) TransportError!void {
        _ = route_key;

        if (self.closed) return TransportError.Closed;
        if (self.connected) return;

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
        ) catch return TransportError.ConnectionFailed;
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

        // 【关键修改】：Unmanaged append 需要传入 allocator
        self.recv_queue.append(self.allocator, .{ .data = data_copy }) catch {
            self.allocator.free(data_copy);
            std.log.err("[DirectTransport] OOM on queue append", .{});
        };
    }

    fn onClientClose(ctx: ?*anyopaque, conn: *QUICConnection, event: quic.c.CallbackEvent) void {
        _ = conn;
        _ = event;
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.connected = false;
        std.log.info("[DirectTransport] Connection closed", .{});
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

    try std.testing.expectError(TransportError.Closed, transport.resolveImpl(1));
    try std.testing.expectError(TransportError.Closed, transport.sendImpl(1, "test"));
    try std.testing.expectError(TransportError.Closed, transport.receiveImpl());
}

test "DirectTransport integration test (Real Server)" {
    // 只有当你确定本地 8443 跑着服务器时才运行此测试
    // 为了防止在 CI 环境报错，如果你想跳过，可以 uncomment 下面这行
    // if (true) return error.SkipZigTest;

    std.debug.print("\n=== 集成测试: 连接本地 8443 服务器 ===\n", .{});
    const allocator = std.testing.allocator;

    // 1. 初始化 Loop
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    // 2. 初始化 Transport
    var transport = try DirectTransport.init(allocator, .{
        .server_host = "127.0.0.1",
        .server_port = 8443,
        .alpn = "lyune-gateway", // 确保这里和你的服务器 ALPN 匹配
        .verify_cert = false, // 开发环境通常忽略自签名证书验证
    }, &loop);
    defer transport.deinit();

    // 3. 发起连接
    try transport.resolveImpl(0x01);
    std.debug.print("-> 正在发起连接...\n", .{});

    // 4. 【关键步骤】驱动事件循环等待连接成功
    // 我们设置一个超时时间，防止测试死锁
    const timeout_ns = 6 * std.time.ns_per_s;
    var elapsed: u64 = 0;
    const step_ms: u64 = 10; // 每 10ms 检查一次，保证 QUIC 握手能及时响应

    while (!transport.connected) {
        // 运行一次事件循环（处理 UDP 收发、定时器）
        // .no_wait 表示如果有事件就处理，没事件不阻塞立即返回
        try loop.run(.no_wait);

        // 稍微休眠一下避免 CPU 100%
        std.Thread.sleep(step_ms * std.time.ns_per_ms);

        elapsed += step_ms * std.time.ns_per_ms;

        if (elapsed > timeout_ns) {
            std.debug.print("!! 连接超时 (6s) !!\n", .{});
            return error.TestTimeout; // 如果连不上，这里会报错
        }
    }
    std.debug.print("-> 连接成功!\n", .{});

    // 5. 发送消息
    const msg = "Hello from Zig Client!";
    try transport.sendImpl(0x01, msg);
    std.debug.print("-> 消息已发送: {s}\n", .{msg});

    // 6. 继续驱动循环，让数据真正发出去，并等待可能的响应
    // 运行 500ms 看看能不能收到回包
    var i: usize = 0;
    var received_any = false;
    while (i < 50) : (i += 1) {
        try loop.run(.no_wait);

        // 尝试接收
        // 如果你的 receiveImpl 返回 !?[]const u8
        if (try transport.receiveImpl()) |data| {
            std.debug.print("<- 收到服务器回包: {s}\n", .{data});
            // 注意：receiveImpl 返回的数据在队列里，
            // 按照我们之前的实现，所有权移交给了 data，需要我们释放
            // 但如果 receiveImpl 返回的是 slice，请根据 receiveImpl 的具体实现决定是否 free
            // 假设 recv_queue.orderedRemove 出来的 data 是调用者拥有的：
            allocator.free(data);
            received_any = true;
            break; // 收到回应就退出
        }

        std.Thread.sleep(10 * std.time.ns_per_ms);
    }

    if (!received_any) {
        std.debug.print("-> 未收到回包 (属正常现象，取决于服务器逻辑)\n", .{});
    }

    std.debug.print("=== 集成测试结束 ===\n", .{});
}
