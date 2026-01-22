//! 内存传输实现
//!
//! 用于测试和开发的 BackendTransport 实现。
//! 不依赖外部中间件，所有数据在内存中处理。

const std = @import("std");
const client = @import("backend.zig");
const BackendTransport = client.BackendTransport;
const TransportError = client.TransportError;

// ============================================================================
// 发送记录
// ============================================================================

/// 发送消息记录
pub const SentMessage = struct {
    /// 目标 RouteKey
    route_key: u8,
    /// 消息数据（已复制）
    data: []const u8,
    /// 发送时间戳（纳秒）
    timestamp: i128,
};

// ============================================================================
// 内存传输实现
// ============================================================================

/// 内存传输
///
/// 用于测试和开发的 BackendTransport 实现。
/// 在内存中模拟后端服务的行为。
pub const MemoryTransport = struct {
    /// 内存分配器
    allocator: std.mem.Allocator,
    /// 发送消息记录
    sent_messages: std.ArrayList(SentMessage),
    /// 模拟响应队列
    response_queue: std.ArrayList([]const u8),
    /// 已解析的 RouteKey 集合
    resolved_routes: std.AutoHashMap(u8, bool),
    /// 是否启用 Echo 模式
    echo_mode: bool,
    /// 是否已关闭
    closed: bool,

    /// 初始化
    pub fn init(allocator: std.mem.Allocator) MemoryTransport {
        return .{
            .allocator = allocator,
            // ArrayList: unmanaged，初始化为空
            .sent_messages = .{},
            .response_queue = .{},
            // AutoHashMap: managed，使用 init(allocator)
            .resolved_routes = std.AutoHashMap(u8, bool).init(allocator),
            .echo_mode = false,
            .closed = false,
        };
    }

    /// 释放资源
    pub fn deinit(self: *MemoryTransport) void {
        // 释放发送记录中的数据
        for (self.sent_messages.items) |msg| {
            self.allocator.free(msg.data);
        }
        // ArrayList: unmanaged，需要传入 allocator
        self.sent_messages.deinit(self.allocator);

        // 释放响应队列中的数据
        for (self.response_queue.items) |data| {
            self.allocator.free(data);
        }
        self.response_queue.deinit(self.allocator);

        // AutoHashMap: managed，不需要传入 allocator
        self.resolved_routes.deinit();
    }

    // ========================================================================
    // BackendTransport 接口实现
    // ========================================================================

    /// 解析/连接目标（接口实现）
    pub fn resolveImpl(self: *MemoryTransport, route_key: u8) TransportError!void {
        if (self.closed) return TransportError.Closed;
        // AutoHashMap: managed，不需要传入 allocator
        self.resolved_routes.put(route_key, true) catch return TransportError.OutOfMemory;
    }

    /// 发送数据（接口实现）
    pub fn sendImpl(self: *MemoryTransport, route_key: u8, data: []const u8) TransportError!void {
        if (self.closed) return TransportError.Closed;

        // 复制数据
        const data_copy = self.allocator.dupe(u8, data) catch return TransportError.OutOfMemory;
        errdefer self.allocator.free(data_copy);

        // 记录发送消息
        const msg = SentMessage{
            .route_key = route_key,
            .data = data_copy,
            .timestamp = std.time.nanoTimestamp(),
        };
        // ArrayList: unmanaged，需要传入 allocator
        self.sent_messages.append(self.allocator, msg) catch {
            self.allocator.free(data_copy);
            return TransportError.OutOfMemory;
        };

        // Echo 模式：将发送的数据作为响应
        if (self.echo_mode) {
            self.mockResponse(data) catch return TransportError.OutOfMemory;
        }
    }

    /// 接收数据（接口实现）
    pub fn receiveImpl(self: *MemoryTransport) TransportError!?[]const u8 {
        if (self.closed) return TransportError.Closed;

        if (self.response_queue.items.len == 0) {
            return null;
        }

        // 从队列头部取出响应
        return self.response_queue.orderedRemove(0);
    }

    /// 关闭（接口实现）
    pub fn closeImpl(self: *MemoryTransport) void {
        self.closed = true;
    }

    // ========================================================================
    // 测试辅助方法
    // ========================================================================

    /// 注入模拟响应
    pub fn mockResponse(self: *MemoryTransport, data: []const u8) !void {
        const data_copy = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(data_copy);
        // ArrayList: unmanaged，需要传入 allocator
        try self.response_queue.append(self.allocator, data_copy);
    }

    /// 注入多个模拟响应
    pub fn mockResponses(self: *MemoryTransport, responses: []const []const u8) !void {
        for (responses) |data| {
            try self.mockResponse(data);
        }
    }

    /// 获取发送消息记录
    pub fn getSentMessages(self: *const MemoryTransport) []const SentMessage {
        return self.sent_messages.items;
    }

    /// 获取最后发送的消息
    pub fn getLastSentMessage(self: *const MemoryTransport) ?SentMessage {
        if (self.sent_messages.items.len == 0) return null;
        return self.sent_messages.items[self.sent_messages.items.len - 1];
    }

    /// 获取指定 RouteKey 的发送消息数量
    pub fn getSentCountByRoute(self: *const MemoryTransport, route_key: u8) usize {
        var count: usize = 0;
        for (self.sent_messages.items) |msg| {
            if (msg.route_key == route_key) count += 1;
        }
        return count;
    }

    /// 清空发送记录
    pub fn clearSentMessages(self: *MemoryTransport) void {
        for (self.sent_messages.items) |msg| {
            self.allocator.free(msg.data);
        }
        self.sent_messages.clearRetainingCapacity();
    }

    /// 清空响应队列
    pub fn clearResponseQueue(self: *MemoryTransport) void {
        for (self.response_queue.items) |data| {
            self.allocator.free(data);
        }
        self.response_queue.clearRetainingCapacity();
    }

    /// 启用 Echo 模式
    pub fn enableEchoMode(self: *MemoryTransport) void {
        self.echo_mode = true;
    }

    /// 禁用 Echo 模式
    pub fn disableEchoMode(self: *MemoryTransport) void {
        self.echo_mode = false;
    }

    /// 检查 RouteKey 是否已解析
    pub fn isResolved(self: *const MemoryTransport, route_key: u8) bool {
        return self.resolved_routes.get(route_key) orelse false;
    }

    /// 获取响应队列长度
    pub fn getResponseQueueLength(self: *const MemoryTransport) usize {
        return self.response_queue.items.len;
    }

    /// 转换为 BackendTransport 接口
    pub fn asTransport(self: *MemoryTransport) BackendTransport {
        return BackendTransport.init(MemoryTransport, self);
    }
};

// ============================================================================
// 测试
// ============================================================================

test "MemoryTransport basic send/receive" {
    const allocator = std.testing.allocator;
    var transport = MemoryTransport.init(allocator);
    defer transport.deinit();

    // 发送消息
    try transport.sendImpl(0x01, "hello");
    try transport.sendImpl(0x01, "world");
    try transport.sendImpl(0x02, "test");

    // 验证发送记录
    const sent = transport.getSentMessages();
    try std.testing.expectEqual(@as(usize, 3), sent.len);
    try std.testing.expectEqualStrings("hello", sent[0].data);
    try std.testing.expectEqual(@as(u8, 0x01), sent[0].route_key);

    // 验证按 RouteKey 统计
    try std.testing.expectEqual(@as(usize, 2), transport.getSentCountByRoute(0x01));
    try std.testing.expectEqual(@as(usize, 1), transport.getSentCountByRoute(0x02));

    // 未注入响应时返回 null
    const received = try transport.receiveImpl();
    try std.testing.expect(received == null);
}

test "MemoryTransport mock response" {
    const allocator = std.testing.allocator;
    var transport = MemoryTransport.init(allocator);
    defer transport.deinit();

    // 注入模拟响应
    try transport.mockResponse("response1");
    try transport.mockResponse("response2");

    // 接收响应（FIFO 顺序）
    const r1 = (try transport.receiveImpl()).?;
    defer allocator.free(r1);
    try std.testing.expectEqualStrings("response1", r1);

    const r2 = (try transport.receiveImpl()).?;
    defer allocator.free(r2);
    try std.testing.expectEqualStrings("response2", r2);

    // 队列空了
    try std.testing.expect(try transport.receiveImpl() == null);
}

test "MemoryTransport echo mode" {
    const allocator = std.testing.allocator;
    var transport = MemoryTransport.init(allocator);
    defer transport.deinit();

    // 启用 Echo 模式
    transport.enableEchoMode();

    // 发送消息
    try transport.sendImpl(0x01, "echo test");

    // 应该自动产生响应
    try std.testing.expectEqual(@as(usize, 1), transport.getResponseQueueLength());

    const echoed = (try transport.receiveImpl()).?;
    defer allocator.free(echoed);
    try std.testing.expectEqualStrings("echo test", echoed);
}

test "MemoryTransport resolve" {
    const allocator = std.testing.allocator;
    var transport = MemoryTransport.init(allocator);
    defer transport.deinit();

    // 初始状态未解析
    try std.testing.expect(!transport.isResolved(0x01));

    // 解析
    try transport.resolveImpl(0x01);
    try std.testing.expect(transport.isResolved(0x01));
    try std.testing.expect(!transport.isResolved(0x02));
}

test "MemoryTransport close" {
    const allocator = std.testing.allocator;
    var transport = MemoryTransport.init(allocator);
    defer transport.deinit();

    // 关闭前正常工作
    try transport.sendImpl(0x01, "before close");

    // 关闭
    transport.closeImpl();

    // 关闭后操作返回错误
    try std.testing.expectError(TransportError.Closed, transport.sendImpl(0x01, "after close"));
    try std.testing.expectError(TransportError.Closed, transport.receiveImpl());
    try std.testing.expectError(TransportError.Closed, transport.resolveImpl(0x01));
}

test "MemoryTransport as interface" {
    const allocator = std.testing.allocator;
    var transport = MemoryTransport.init(allocator);
    defer transport.deinit();

    // 转换为接口
    const iface = transport.asTransport();

    // 通过接口操作
    try iface.resolve(0x01);
    try iface.send(0x01, "via interface");

    // 验证
    try std.testing.expect(transport.isResolved(0x01));
    try std.testing.expectEqual(@as(usize, 1), transport.getSentMessages().len);
}