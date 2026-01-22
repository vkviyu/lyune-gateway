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
//! // 发送数据到后端（上行）
//! try transport.send(route_key, body_data);
//!
//! // 接收后端响应（下行）
//! if (try transport.receive()) |frame_data| {
//!     // 处理完整帧数据
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
/// - `send`: 发送数据到后端（上行时发送 Body）
/// - `receive`: 从后端接收数据（下行时接收完整帧）
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
        /// 解析/连接目标
        ///
        /// 根据 RouteKey 建立到后端的连接或获取通信通道。
        /// - 中继模式：确保 MQ 连接就绪，订阅对应 topic
        /// - 直连模式：通过服务发现获取后端地址，建立连接
        resolve: *const fn (ptr: *anyopaque, route_key: u8) TransportError!void,

        /// 发送数据到后端
        ///
        /// 上行时调用，将 Body 数据发送给后端服务。
        /// - 中继模式：发布消息到对应 topic
        /// - 直连模式：通过连接直接发送
        send: *const fn (ptr: *anyopaque, route_key: u8, data: []const u8) TransportError!void,

        /// 从后端接收数据
        ///
        /// 下行时调用，接收后端返回的完整帧数据。
        /// 返回 null 表示当前没有数据可读（非阻塞）。
        /// 返回的数据由调用方负责释放。
        receive: *const fn (ptr: *anyopaque) TransportError!?[]const u8,

        /// 关闭连接
        ///
        /// 释放资源，断开与后端的连接。
        close: *const fn (ptr: *anyopaque) void,
    };

    /// 解析/连接目标
    pub fn resolve(self: BackendTransport, route_key: u8) TransportError!void {
        return self.vtable.resolve(self.ptr, route_key);
    }

    /// 发送数据到后端
    pub fn send(self: BackendTransport, route_key: u8, data: []const u8) TransportError!void {
        return self.vtable.send(self.ptr, route_key, data);
    }

    /// 从后端接收数据
    pub fn receive(self: BackendTransport) TransportError!?[]const u8 {
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
    /// - `resolveImpl(self, route_key) !void`
    /// - `sendImpl(self, route_key, data) !void`
    /// - `receiveImpl(self) !?[]const u8`
    /// - `closeImpl(self) void`
    pub fn init(comptime T: type, impl: *T) BackendTransport {
        const gen = struct {
            fn resolveImpl(ptr: *anyopaque, route_key: u8) TransportError!void {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.resolveImpl(route_key);
            }

            fn sendImpl(ptr: *anyopaque, route_key: u8, data: []const u8) TransportError!void {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.sendImpl(route_key, data);
            }

            fn receiveImpl(ptr: *anyopaque) TransportError!?[]const u8 {
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
    // 测试用的简单实现
    const TestTransport = struct {
        resolved: bool = false,
        sent_data: ?[]const u8 = null,
        closed: bool = false,

        pub fn resolveImpl(self: *@This(), _: u8) TransportError!void {
            self.resolved = true;
        }

        pub fn sendImpl(self: *@This(), _: u8, data: []const u8) TransportError!void {
            self.sent_data = data;
        }

        pub fn receiveImpl(_: *@This()) TransportError!?[]const u8 {
            return null;
        }

        pub fn closeImpl(self: *@This()) void {
            self.closed = true;
        }
    };

    var impl = TestTransport{};
    const transport = BackendTransport.init(TestTransport, &impl);

    // 测试 resolve
    try transport.resolve(0x01);
    try std.testing.expect(impl.resolved);

    // 测试 send
    const test_data = "hello";
    try transport.send(0x01, test_data);
    try std.testing.expectEqualStrings(test_data, impl.sent_data.?);

    // 测试 receive
    const received = try transport.receive();
    try std.testing.expect(received == null);

    // 测试 close
    transport.close();
    try std.testing.expect(impl.closed);
}