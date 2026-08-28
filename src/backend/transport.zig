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
//! const transport = registry.find(route_id) orelse return error.RouteNotFound;
//!
//! // 发送已经编码好的数据到后端（上行），返回后端 stream_id
//! const backend_stream_id = try transport.send(route_id, frame_data);
//!
//! // 接收后端响应（下行）
//! if (try transport.receive()) |event| {
//!     defer event.deinit(allocator);
//!     // 根据 event.stream_id / event.is_fin 处理后端响应
//! }
//! ```

const std = @import("std");

const protocol = @import("../protocol/mod.zig");
const frame = protocol.frame;

/// 完整路由键（Group + RouteKey 组合），定义见 protocol/frame.zig。
pub const RouteId = frame.RouteId;

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
    /// 路由未找到（RouteId 未注册）
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

/// 后端流回调的种类。RESET_STREAM 与 STOP_SENDING 必须保持为异常终止，不能伪装成
/// 空 FIN；后者会让上层把被取消的响应误判成一次成功的空响应。
pub const RecvKind = enum {
    data,
    stream_reset,
    stop_sending,
};

/// 后端传输接收事件。
///
/// `data` 是对 transport 内部接收缓冲的**借用**，不是调用方拥有的内存：处理完必须
/// 调用 `BackendTransport.releaseRecv` 把槽位还回去，否则接收池会被占满并导致
/// 后续响应被拒。改成借用是为了让接收路径上不再有每分片的堆分配。
///
/// `stream_id` 是后端连接上的 QUIC stream id，用于上层把后端响应关联回客户端 stream。
/// `token` 对调用方不透明，由实现用来定位要归还的槽位，必须原样回传。
pub const TransportRecv = struct {
    stream_id: u64,
    data: []const u8,
    is_fin: bool,
    kind: RecvKind = .data,
    token: u64 = 0,
    /// 这条流是**对端（后端）主动开的**，不是网关开的。
    ///
    /// 它是"后端推送"与"孤儿响应"的判据。两者都查不到回程映射，但含义相反：
    /// 前者要按 `.peer` / `.multicast` 投递给客户端，后者是客户端早已断开、
    /// 条目已被回收的残响，只能丢弃。若不区分，孤儿响应会被当成畸形推送刷日志，
    /// 而真正的推送在客户端断开高峰期会被误判成孤儿。
    ///
    /// 由 transport 实现填写——只有它知道自己开过哪些流。
    peer_initiated: bool = false,
};

/// 一次 transport 接收失败影响哪些后端流。
///
/// `mask == 0` 表示这个 transport 上的全部流；其余实现可以用句柄中稳定的位域
/// 精确圈定故障域。DirectTransport 用句柄高 32 位的 connection id + generation
/// 定位一个连接代际，因此副本断开时不会误伤健康副本或重连后的新流。
pub const StreamSelector = struct {
    mask: u64 = 0,
    value: u64 = 0,

    pub fn matches(self: StreamSelector, stream: u64) bool {
        return stream & self.mask == self.value;
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
        /// 根据 RouteId 建立到后端的连接或获取通信通道。
        /// 此方法为异步操作，连接结果通过回调通知。
        /// - 中继模式：确保 MQ 连接就绪，订阅对应 topic
        /// - 直连模式：通过服务发现获取后端地址，建立连接
        ///
        /// 参数：
        /// - route: 完整路由键（Group + RouteKey 组合）
        /// - on_ready: 连接就绪或失败时的回调（可为 null）
        /// - ctx: 回调上下文
        resolve: *const fn (
            ptr: *anyopaque,
            route: RouteId,
            on_ready: ?ResolveCallback,
            ctx: ?*anyopaque,
        ) void,

        /// 在后端流上发送数据
        ///
        /// handle 为 null 时新开一条后端流，返回它的句柄；否则往该句柄指向的
        /// 既有流上追加。is_fin 为 true 时结束这条流。
        ///
        /// 流式上行必须落在同一条后端流上：客户端一条流对应后端一条流，
        /// 中途换流会让后端收到两段互不相关的字节，也让响应散落到多个 stream id 上。
        /// 因此实现必须保证同一 handle 始终路由到当初开流的那条连接。
        sendStream: *const fn (
            ptr: *anyopaque,
            route: RouteId,
            handle: ?u64,
            data: []const u8,
            is_fin: bool,
        ) TransportError!u64,

        /// 从后端接收数据
        ///
        /// 下行时调用，接收后端返回的 stream-aware 事件。
        /// 返回 null 表示当前没有数据可读（非阻塞）。
        /// 返回的 data 是内部缓冲的借用，处理完必须经 releaseRecv 归还。
        receive: *const fn (ptr: *anyopaque) TransportError!?TransportRecv,

        /// 归还接收槽位
        ///
        /// 必须与每一次成功的 receive 一一对应。不归还不会立即出错，但接收池
        /// 会逐渐被占满，之后的后端响应只能被拒。
        releaseRecv: *const fn (ptr: *anyopaque, recv: TransportRecv) void,

        /// 最近一次 receive 错误影响的流集合。
        ///
        /// 不实现精细故障域的 transport 默认返回全选；调用方只会在 receive 返回
        /// error 后读取它。
        failureSelector: *const fn (ptr: *anyopaque) StreamSelector,

        /// 某条流已达到应用层 deadline，只废弃该流。
        ///
        /// transport 不得因此关闭承载它的共享连接，否则同一连接上仍然健康的交换
        /// 会被连带终止。没有流取消能力的实现可以不实现，接口层会安全退化为 no-op。
        invalidateStream: *const fn (ptr: *anyopaque, stream: u64) void,

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
        route: RouteId,
        on_ready: ?ResolveCallback,
        ctx: ?*anyopaque,
    ) void {
        return self.vtable.resolve(self.ptr, route, on_ready, ctx);
    }

    /// 一次性请求：新开一条后端流，写入数据并立即结束该流。
    ///
    /// buffered 模式与控制帧走这条路径——请求与响应一一对应，不需要续写。
    pub fn send(self: BackendTransport, route: RouteId, data: []const u8) TransportError!u64 {
        return self.vtable.sendStream(self.ptr, route, null, data, true);
    }

    /// 流式上行：在既有后端流上追加分片，或用 null 开出第一条流。
    ///
    /// 客户端一条流上的多个 streaming 帧依次调用本方法，最后一帧带 is_fin，
    /// 后端因此看到一条完整有序的字节流。
    pub fn sendStream(
        self: BackendTransport,
        route: RouteId,
        handle: ?u64,
        data: []const u8,
        is_fin: bool,
    ) TransportError!u64 {
        return self.vtable.sendStream(self.ptr, route, handle, data, is_fin);
    }

    /// 从后端接收数据
    pub fn receive(self: BackendTransport) TransportError!?TransportRecv {
        return self.vtable.receive(self.ptr);
    }

    /// 归还 receive 返回的接收槽位；与每次成功的 receive 一一对应。
    pub fn releaseRecv(self: BackendTransport, recv: TransportRecv) void {
        return self.vtable.releaseRecv(self.ptr, recv);
    }

    /// 最近一次 receive 错误影响的流集合。
    pub fn failureSelector(self: BackendTransport) StreamSelector {
        return self.vtable.failureSelector(self.ptr);
    }

    /// 请求超时后取消对应后端流；共享连接及其余流必须继续存活。
    pub fn invalidateStream(self: BackendTransport, stream: u64) void {
        self.vtable.invalidateStream(self.ptr, stream);
    }

    /// 关闭连接
    pub fn close(self: BackendTransport) void {
        return self.vtable.close(self.ptr);
    }

    /// 这个 transport 实例的身份。
    ///
    /// `sendStream` 返回的句柄**只在单个实例内部唯一**：direct 实现用
    /// `connection_id:16 | generation:16 | stream_id:32` 合成，而 connection_id
    /// 是每个实例各自从 0 开始编号的。
    /// 因此凡是按后端流做索引的表（在途映射、推送重组缓冲）都必须把实例身份并进键里，
    /// 否则两个实例发出同一个句柄时，后一次登记会顶掉前一次，随后 A 的响应被写进
    /// B 的客户端流——跨路由、跨 realm 的串话。
    ///
    /// 用实现指针作身份：它在实例存活期内唯一且稳定，而实例的生命周期覆盖了它开出的
    /// 所有流（transport 由注册表持有到 Worker 退出）。
    pub fn id(self: BackendTransport) usize {
        return @intFromPtr(self.ptr);
    }

    /// 从具体实现创建接口实例
    ///
    /// 用于将具体实现类型转换为统一的接口类型。
    /// 具体实现需要提供以下方法：
    /// - `resolveImpl(self, route, on_ready, ctx) void` (异步)
    /// - `sendStreamImpl(self, route, handle, data, is_fin) !u64`
    /// - `receiveImpl(self) !?TransportRecv`
    /// - `releaseRecvImpl(self, recv) void`
    /// - `closeImpl(self) void`
    pub fn init(comptime T: type, impl: *T) BackendTransport {
        const gen = struct {
            fn resolveImpl(
                ptr: *anyopaque,
                route: RouteId,
                on_ready: ?ResolveCallback,
                ctx: ?*anyopaque,
            ) void {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.resolveImpl(route, on_ready, ctx);
            }

            fn sendStreamImpl(
                ptr: *anyopaque,
                route: RouteId,
                handle: ?u64,
                data: []const u8,
                is_fin: bool,
            ) TransportError!u64 {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.sendStreamImpl(route, handle, data, is_fin);
            }

            fn receiveImpl(ptr: *anyopaque) TransportError!?TransportRecv {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.receiveImpl();
            }

            fn releaseRecvImpl(ptr: *anyopaque, recv: TransportRecv) void {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.releaseRecvImpl(recv);
            }

            fn failureSelectorImpl(ptr: *anyopaque) StreamSelector {
                if (@hasDecl(T, "failureSelectorImpl")) {
                    const self: *T = @ptrCast(@alignCast(ptr));
                    return self.failureSelectorImpl();
                }
                return .{};
            }

            fn invalidateStreamImpl(ptr: *anyopaque, stream: u64) void {
                if (@hasDecl(T, "invalidateStreamImpl")) {
                    const self: *T = @ptrCast(@alignCast(ptr));
                    self.invalidateStreamImpl(stream);
                }
            }

            fn closeImpl(ptr: *anyopaque) void {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.closeImpl();
            }

            const vtable = VTable{
                .resolve = resolveImpl,
                .sendStream = sendStreamImpl,
                .receive = receiveImpl,
                .releaseRecv = releaseRecvImpl,
                .failureSelector = failureSelectorImpl,
                .invalidateStream = invalidateStreamImpl,
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
        last_handle: ?u64 = null,
        last_is_fin: bool = false,
        closed: bool = false,
        callback_called: bool = false,

        pub fn resolveImpl(
            self: *@This(),
            _: RouteId,
            on_ready: ?ResolveCallback,
            ctx: ?*anyopaque,
        ) void {
            self.resolved = true;
            // 同步场景下立即调用回调
            if (on_ready) |cb| {
                cb(ctx, null); // 成功
            }
        }

        pub fn sendStreamImpl(
            self: *@This(),
            _: RouteId,
            handle: ?u64,
            data: []const u8,
            is_fin: bool,
        ) TransportError!u64 {
            self.sent_data = data;
            self.last_handle = handle;
            self.last_is_fin = is_fin;
            return handle orelse 0;
        }

        pub fn receiveImpl(_: *@This()) TransportError!?TransportRecv {
            return null;
        }

        pub fn releaseRecvImpl(_: *@This(), _: TransportRecv) void {}

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
    transport.resolve(RouteId.init(0x01, 0x00), TestCtx.onReady, &test_ctx);
    try std.testing.expect(impl.resolved);
    try std.testing.expect(test_ctx.called);

    // 测试 send（一次性请求：新开流并立即 fin）
    const test_data = "hello";
    const backend_stream_id = try transport.send(RouteId.init(0x01, 0x00), test_data);
    try std.testing.expectEqual(@as(u64, 0), backend_stream_id);
    try std.testing.expectEqualStrings(test_data, impl.sent_data.?);
    try std.testing.expectEqual(@as(?u64, null), impl.last_handle);
    try std.testing.expect(impl.last_is_fin);

    // 测试 sendStream（流式续写：句柄透传，中间分片不 fin）
    const continued = try transport.sendStream(RouteId.init(0x01, 0x00), 7, "chunk", false);
    try std.testing.expectEqual(@as(u64, 7), continued);
    try std.testing.expectEqual(@as(?u64, 7), impl.last_handle);
    try std.testing.expect(!impl.last_is_fin);

    // 测试 receive
    const received = try transport.receive();
    try std.testing.expect(received == null);

    // 测试 close
    transport.close();
    try std.testing.expect(impl.closed);
}

test "stream selector can isolate a connection encoded in the high bits" {
    const selector = StreamSelector{
        .mask = @as(u64, std.math.maxInt(u16)) << 48,
        .value = @as(u64, 7) << 48,
    };
    try std.testing.expect(selector.matches((@as(u64, 7) << 48) | 12));
    try std.testing.expect(!selector.matches((@as(u64, 8) << 48) | 12));
    try std.testing.expect((StreamSelector{}).matches(1234));
}
