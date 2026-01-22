//! 直连 QUIC 传输实现
//!
//! 网关直连后端服务的 BackendTransport 实现。
//! 基于 AsyncClient 实现真正的异步 QUIC 通信。
//!
//! ## 设计说明
//!
//! - `sendImpl`: 非阻塞发送，通过 AsyncClient 将数据加入发送队列
//! - `receiveImpl`: 非阻塞接收，从接收队列读取数据
//! - 实际的网络 I/O 由 AsyncClient 的事件循环驱动
//!
//! ## 使用方式
//!
//! ### 独立模式（测试/简单场景）
//!
//! ```zig
//! var transport = try DirectTransport.init(allocator, .{...});
//! defer transport.deinit();
//!
//! try transport.resolveImpl(0x01);  // 发起连接
//! try transport.runOnce();          // 运行事件循环完成握手
//!
//! try transport.sendImpl(0x01, frame_data);  // 发送数据
//! try transport.runOnce();                    // 运行事件循环发送
//!
//! if (try transport.receiveImpl()) |response| {
//!     defer allocator.free(response);
//! }
//! ```
//!
//! ### 集成模式（网关场景）
//!
//! 在网关中，DirectTransport 会被集成到 GatewayWorker 的事件循环中。

const std = @import("std");
const xev = @import("xev");
const quic = @import("../quic/mod.zig");
const client_mod = @import("backend.zig");
const BackendTransport = client_mod.BackendTransport;
const TransportError = client_mod.TransportError;

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
    /// 接收队列最大容量
    max_recv_queue: usize = 64,
    /// 连接超时（毫秒）
    connect_timeout_ms: u32 = 5000,
    /// 是否验证服务器证书
    verify_cert: bool = false,
    /// 根证书文件路径（可选）
    root_cert_file: ?[:0]const u8 = null,
};

// ============================================================================
// 接收数据结构
// ============================================================================

/// 接收到的数据
const ReceivedData = struct {
    stream_id: u64,
    data: []u8,
    is_fin: bool,
};

// ============================================================================
// 直连传输实现
// ============================================================================

/// 直连 QUIC 传输
///
/// 基于 AsyncClient 的异步直连传输。
/// 实现 BackendTransport 接口，用于网关直连模式。
pub const DirectTransport = struct {
    const Self = @This();

    /// 内存分配器
    allocator: std.mem.Allocator,
    /// 配置
    config: DirectConfig,
    /// 外部事件循环
    event_loop: *xev.Loop,
    /// 异步 QUIC 客户端
    async_client: ?quic.AsyncClient,
    /// 接收队列
    recv_queue: std.ArrayList(ReceivedData),
    /// 是否已连接
    connected: bool,
    /// 是否已关闭
    closed: bool,

    /// 初始化
    ///
    /// @param allocator 内存分配器
    /// @param config 直连配置
    /// @param event_loop 外部事件循环指针（与其他组件共享）
    pub fn init(allocator: std.mem.Allocator, config: DirectConfig, event_loop: *xev.Loop) !Self {
        return .{
            .allocator = allocator,
            .config = config,
            .event_loop = event_loop,
            .async_client = null,
            .recv_queue = .{},
            .connected = false,
            .closed = false,
        };
    }

    /// 释放资源
    pub fn deinit(self: *Self) void {
        // 释放接收队列中的数据
        for (self.recv_queue.items) |item| {
            self.allocator.free(item.data);
        }
        self.recv_queue.deinit(self.allocator);

        // 释放客户端
        if (self.async_client) |*client| {
            client.deinit();
        }
        self.async_client = null;

        self.connected = false;
        self.closed = true;
    }

    // ========================================================================
    // BackendTransport 接口实现
    // ========================================================================

    /// 解析/连接目标（接口实现）
    ///
    /// 发起到后端服务器的 QUIC 连接（非阻塞）。
    /// 连接完成后通过回调通知，或者调用 run/runOnce 等待。
    pub fn resolveImpl(self: *Self, route_key: u8) TransportError!void {
        _ = route_key;

        if (self.closed) return TransportError.Closed;
        if (self.connected) return; // 已连接

        // 创建异步客户端（使用外部事件循环）
        self.async_client = quic.AsyncClient.init(self.allocator, .{
            .server_host = self.config.server_host,
            .server_port = self.config.server_port,
            .base = .{
                .alpn = self.config.alpn,
                .root_cert_file = self.config.root_cert_file,
            },
        }, self.event_loop) catch {
            return TransportError.ConnectionFailed;
        };

        // 设置回调
        var client = &self.async_client.?;
        client.setUserData(self);
        client.onConnected(onConnected);
        client.onStreamData(onStreamData);
        client.onDisconnected(onDisconnected);

        // 发起连接
        client.connect() catch {
            self.async_client.?.deinit();
            self.async_client = null;
            return TransportError.ConnectionFailed;
        };
    }

    /// 发送数据（接口实现）
    ///
    /// 将数据加入发送队列（非阻塞）。
    /// 注意：这里发送的是完整帧（帧头 + Body），实现全链路透传。
    pub fn sendImpl(self: *Self, route_key: u8, data: []const u8) TransportError!void {
        _ = route_key;

        if (self.closed) return TransportError.Closed;
        if (!self.connected) return TransportError.ConnectionFailed;

        var client = &(self.async_client orelse return TransportError.ConnectionFailed);

        // 使用默认 stream (0) 发送
        client.sendDefault(data, true) catch {
            return TransportError.SendFailed;
        };
    }

    /// 接收数据（接口实现）
    ///
    /// 从接收队列读取数据（非阻塞）。
    /// 返回 null 表示当前没有数据。
    /// 返回的数据由调用方负责释放。
    pub fn receiveImpl(self: *Self) TransportError!?[]const u8 {
        if (self.closed) return TransportError.Closed;
        if (!self.connected) return TransportError.ConnectionFailed;

        // 从队列取出数据
        if (self.recv_queue.items.len > 0) {
            const item = self.recv_queue.orderedRemove(0);
            return item.data;
        }

        return null;
    }

    /// 关闭（接口实现）
    pub fn closeImpl(self: *Self) void {
        if (self.async_client) |*client| {
            client.stop();
        }
        self.connected = false;
        self.closed = true;
    }

    // ========================================================================
    // 事件循环控制
    // ========================================================================

    /// 运行事件循环（阻塞）
    ///
    /// 运行直到连接关闭或调用 stop()。
    pub fn run(self: *Self) TransportError!void {
        var client = &(self.async_client orelse return TransportError.ConnectionFailed);
        client.run() catch {
            return TransportError.ConnectionFailed;
        };
    }

    /// 停止事件循环
    pub fn stop(self: *Self) void {
        if (self.async_client) |*client| {
            client.stop();
        }
    }

    // ========================================================================
    // 辅助方法
    // ========================================================================

    /// 检查是否已连接
    pub fn isConnected(self: *const Self) bool {
        return self.connected and !self.closed;
    }

    /// 重新连接
    pub fn reconnect(self: *Self) TransportError!void {
        // 先关闭现有连接
        if (self.async_client) |*client| {
            client.deinit();
        }
        self.async_client = null;
        self.connected = false;
        self.closed = false;

        // 重新连接
        try self.resolveImpl(0);
    }

    /// 转换为 BackendTransport 接口
    pub fn asTransport(self: *Self) BackendTransport {
        return BackendTransport.init(Self, self);
    }

    // ========================================================================
    // 内部：回调处理
    // ========================================================================

    fn onConnected(ctx: ?*anyopaque, client: *quic.AsyncClient, conn: *quic.Connection) void {
        _ = client;
        _ = conn;
        const self = castSelf(ctx) orelse return;
        self.connected = true;
        std.log.info("[DirectTransport] Connected to backend", .{});
    }

    fn onStreamData(ctx: ?*anyopaque, client: *quic.AsyncClient, conn: *quic.Connection, stream_id: u64, data: []const u8, is_fin: bool) void {
        _ = client;
        _ = conn;
        const self = castSelf(ctx) orelse return;

        // 复制数据到队列
        const data_copy = self.allocator.dupe(u8, data) catch {
            std.log.err("[DirectTransport] Failed to allocate recv buffer", .{});
            return;
        };

        self.recv_queue.append(self.allocator, .{
            .stream_id = stream_id,
            .data = data_copy,
            .is_fin = is_fin,
        }) catch {
            self.allocator.free(data_copy);
            std.log.err("[DirectTransport] Failed to enqueue recv data", .{});
        };
    }

    fn onDisconnected(ctx: ?*anyopaque, client: *quic.AsyncClient, conn: *quic.Connection) void {
        _ = client;
        _ = conn;
        const self = castSelf(ctx) orelse return;
        self.connected = false;
        std.log.info("[DirectTransport] Disconnected from backend", .{});
    }

    fn castSelf(ctx: ?*anyopaque) ?*Self {
        return if (ctx) |c| @as(*Self, @ptrCast(@alignCast(c))) else null;
    }
};

// ============================================================================
// 测试
// ============================================================================

test "DirectTransport init/deinit" {
    const allocator = std.testing.allocator;

    var event_loop = try xev.Loop.init(.{});
    defer event_loop.deinit();

    var transport = try DirectTransport.init(allocator, .{
        .server_host = "127.0.0.1",
        .server_port = 8443,
    }, &event_loop);
    defer transport.deinit();

    try transport.run();

    try transport.resolveImpl(0x01);

    const data = try transport.receiveImpl();
    _ = data.?;
    // 发送数据
    try transport.sendImpl(0x01, "你好");

    try std.testing.expect(!transport.connected);
    try std.testing.expect(!transport.closed);
    try std.testing.expect(transport.async_client == null);
}

test "DirectTransport as interface" {
    const allocator = std.testing.allocator;

    var event_loop = try xev.Loop.init(.{});
    defer event_loop.deinit();

    var transport = try DirectTransport.init(allocator, .{
        .server_host = "127.0.0.1",
        .server_port = 8443,
    }, &event_loop);
    defer transport.deinit();

    // 转换为接口
    const iface = transport.asTransport();
    _ = iface;
}

test "DirectTransport closed state" {
    const allocator = std.testing.allocator;

    var event_loop = try xev.Loop.init(.{});
    defer event_loop.deinit();

    var transport = try DirectTransport.init(allocator, .{
        .server_host = "127.0.0.1",
        .server_port = 8443,
    }, &event_loop);
    defer transport.deinit();

    // 关闭
    transport.closeImpl();

    // 关闭后操作返回错误
    try std.testing.expectError(TransportError.Closed, transport.sendImpl(0x01, "test"));
    try std.testing.expectError(TransportError.Closed, transport.receiveImpl());
    try std.testing.expectError(TransportError.Closed, transport.resolveImpl(0x01));
}

test "DirectTransport resolve creates client" {
    const allocator = std.testing.allocator;

    var event_loop = try xev.Loop.init(.{});
    defer event_loop.deinit();

    var transport = try DirectTransport.init(allocator, .{
        .server_host = "127.0.0.1",
        .server_port = 8443,
    }, &event_loop);
    defer transport.deinit();

    // 连接应该创建客户端
    try transport.resolveImpl(0x01);

    try std.testing.expect(transport.async_client != null);
}
