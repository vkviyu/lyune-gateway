//! 后端传输接口抽象
//!
//! 本模块定义了网关与后端服务通信的统一接口。
//! 通过接口抽象，使网关核心逻辑与具体中间件实现解耦：
//! - 中继模式：可接入 NATS、RabbitMQ 等消息中间件
//! - 直连模式：可接入服务发现（etcd/Consul）直连后端
//!
//! ## 使用方式
//!
//! ```zig
//! // 获取 Transport 实例
//! const transport = registry.getTransport(route_key) orelse return error.RouteNotFound;
//!
//! // 发送已经编码好的数据到后端（上行），返回后端 stream_id
//! const backend_stream_id = try transport.send(route_key, frame_data);
//!
//! // 接收后端响应（下行）
//! if (try transport.receive()) |event| {
//!     defer event.deinit(allocator);
//!     // 根据 event.stream_id / event.is_fin 处理后端响应
//! }
//! ```

const std = @import("std");

// ============================================================================
// 错误类型
// ============================================================================

/// 传输错误类型
pub const TransportError = error{
    /// 连接后端失败
    ConnectionFailed,
    /// 发送数据失败
    SendFailed,
    /// 接收数据失败
    ReceiveFailed,
    /// 路由未找到（RouteKey 未注册）
    RouteNotFound,
    /// 操作超时
    Timeout,
    /// 连接已关闭
    Closed,
    /// 内存分配失败
    OutOfMemory,
};

// ============================================================================
// 回调类型
// ============================================================================

/// 连接就绪回调类型
///
/// 当 resolve 操作完成（成功或失败）时被调用。
/// - ctx: 用户传入的上下文指针
/// - err: 如果操作失败则包含错误码，成功时为 null
pub const ResolveCallback = *const fn (ctx: ?*anyopaque, err: ?TransportError) void;

/// 后端传输接收事件。
///
/// `data` 由调用方持有，处理完成后必须调用 `deinit` 释放。
/// `stream_id` 是后端连接上的 QUIC stream id，用于上层把后端响应关联回客户端 stream。
pub const TransportRecv = struct {
    stream_id: u64,
    data: []u8,
    is_fin: bool,

    pub fn deinit(self: TransportRecv, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

// ============================================================================
// 后端传输接口
// ============================================================================

/// 后端传输接口
///
/// 统一抽象中继模式（MQ）和直连模式（服务发现）的通信方式。
/// 网关通过此接口与后端服务交互，无需关心底层实现细节。
///
/// ## 接口方法
///
/// - `resolve`: 解析目标，建立连接或获取通道
/// - `send`: 发送已经编码好的字节到后端，并返回后端 stream id
/// - `receive`: 从后端接收 stream-aware 事件
/// - `close`: 关闭连接，释放资源
///
/// ## 实现说明
///
/// 使用 Zig 的接口模式（vtable + type erasure）实现多态。
/// 具体实现包括：
/// - `MemoryTransport`: 内存实现，用于测试和开发
/// - `NatsTransport`: NATS 实现，用于生产环境中继模式
/// - `DirectTransport`: 直连实现，用于生产环境直连模式
pub const BackendTransport = struct {
    /// 类型擦除的实现指针
    ptr: *anyopaque,
    /// 虚函数表
    vtable: *const VTable,

    /// 虚函数表定义
    pub const VTable = struct {
        /// 解析/连接目标（异步）
        ///
        /// 根据 RouteKey 建立到后端的连接或获取通信通道。
        /// 此方法为异步操作，连接结果通过回调通知。
        /// - 中继模式：确保 MQ 连接就绪，订阅对应 topic
        /// - 直连模式：通过服务发现获取后端地址，建立连接
        ///
        /// 参数：
        /// - route_key: 路由键
        /// - on_ready: 连接就绪或失败时的回调（可为 null）
        /// - ctx: 回调上下文
        resolve: *const fn (
            ptr: *anyopaque,
            route_key: u8,
            on_ready: ?ResolveCallback,
            ctx: ?*anyopaque,
        ) void,

        /// 发送数据到后端
        ///
        /// 上行时调用，将上层已经编码好的数据发送给后端服务。
        /// 返回后端连接上的 QUIC stream id，供上层建立请求/响应映射。
        /// - 中继模式：发布消息到对应 topic
        /// - 直连模式：通过连接直接发送
        send: *const fn (ptr: *anyopaque, route_key: u8, data: []const u8) TransportError!u64,

        /// 从后端接收数据
        ///
        /// 下行时调用，接收后端返回的 stream-aware 事件。
        /// 返回 null 表示当前没有数据可读（非阻塞）。
        /// 返回的数据由调用方负责释放。
        receive: *const fn (ptr: *anyopaque) TransportError!?TransportRecv,

        /// 关闭连接
        ///
        /// 释放资源，断开与后端的连接。
        close: *const fn (ptr: *anyopaque) void,
    };

    /// 解析/连接目标（异步）
    ///
    /// 发起连接但不等待，连接结果通过回调通知。
    pub fn resolve(
        self: BackendTransport,
        route_key: u8,
        on_ready: ?ResolveCallback,
        ctx: ?*anyopaque,
    ) void {
        return self.vtable.resolve(self.ptr, route_key, on_ready, ctx);
    }

    /// 发送数据到后端
    pub fn send(self: BackendTransport, route_key: u8, data: []const u8) TransportError!u64 {
        return self.vtable.send(self.ptr, route_key, data);
    }

    /// 从后端接收数据
    pub fn receive(self: BackendTransport) TransportError!?TransportRecv {
        return self.vtable.receive(self.ptr);
    }

    /// 关闭连接
    pub fn close(self: BackendTransport) void {
        return self.vtable.close(self.ptr);
    }

    /// 从具体实现创建接口实例
    ///
    /// 用于将具体实现类型转换为统一的接口类型。
    /// 具体实现需要提供以下方法：
    /// - `resolveImpl(self, route_key, on_ready, ctx) void` (异步)
    /// - `sendImpl(self, route_key, data) !u64`
    /// - `receiveImpl(self) !?TransportRecv`
    /// - `closeImpl(self) void`
    pub fn init(comptime T: type, impl: *T) BackendTransport {
        const gen = struct {
            fn resolveImpl(
                ptr: *anyopaque,
                route_key: u8,
                on_ready: ?ResolveCallback,
                ctx: ?*anyopaque,
            ) void {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.resolveImpl(route_key, on_ready, ctx);
            }

            fn sendImpl(ptr: *anyopaque, route_key: u8, data: []const u8) TransportError!u64 {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.sendImpl(route_key, data);
            }

            fn receiveImpl(ptr: *anyopaque) TransportError!?TransportRecv {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.receiveImpl();
            }

            fn closeImpl(ptr: *anyopaque) void {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.closeImpl();
            }

            const vtable = VTable{
                .resolve = resolveImpl,
                .send = sendImpl,
                .receive = receiveImpl,
                .close = closeImpl,
            };
        };

        return .{
            .ptr = impl,
            .vtable = &gen.vtable,
        };
    }
};

// ============================================================================
// 测试
// ============================================================================

test "BackendTransport interface" {
    // 测试用的简单实现（同步模拟）
    const TestTransport = struct {
        resolved: bool = false,
        sent_data: ?[]const u8 = null,
        closed: bool = false,
        callback_called: bool = false,

        pub fn resolveImpl(
            self: *@This(),
            _: u8,
            on_ready: ?ResolveCallback,
            ctx: ?*anyopaque,
        ) void {
            self.resolved = true;
            // 同步场景下立即调用回调
            if (on_ready) |cb| {
                cb(ctx, null); // 成功
            }
        }

        pub fn sendImpl(self: *@This(), _: u8, data: []const u8) TransportError!u64 {
            self.sent_data = data;
            return 0;
        }

        pub fn receiveImpl(_: *@This()) TransportError!?TransportRecv {
            return null;
        }

        pub fn closeImpl(self: *@This()) void {
            self.closed = true;
        }
    };

    var impl = TestTransport{};
    const transport = BackendTransport.init(TestTransport, &impl);

    // 测试 resolve（异步回调模式）
    const TestCtx = struct {
        called: bool = false,

        fn onReady(ctx: ?*anyopaque, err: ?TransportError) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.called = true;
            // 验证没有错误
            std.testing.expect(err == null) catch {};
        }
    };

    var test_ctx = TestCtx{};
    transport.resolve(0x01, TestCtx.onReady, &test_ctx);
    try std.testing.expect(impl.resolved);
    try std.testing.expect(test_ctx.called);

    // 测试 send
    const test_data = "hello";
    const backend_stream_id = try transport.send(0x01, test_data);
    try std.testing.expectEqual(@as(u64, 0), backend_stream_id);
    try std.testing.expectEqualStrings(test_data, impl.sent_data.?);

    // 测试 receive
    const received = try transport.receive();
    try std.testing.expect(received == null);

    // 测试 close
    transport.close();
    try std.testing.expect(impl.closed);
}
