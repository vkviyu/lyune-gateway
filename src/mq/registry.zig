//! 传输注册表
//!
//! 管理 TransportMode + RouteKey 到 BackendTransport 实例的映射。
//! 网关通过注册表获取对应的传输实例，实现路由分发。
//!
//! ## 设计说明
//!
//! 不同的 TransportMode 下，相同的 RouteKey 可以映射到不同的 Transport：
//! - relay 模式下 RouteKey 0x01 → NATS transport (topic: "im.messages")
//! - direct 模式下 RouteKey 0x01 → Direct transport (service: "im-service")
//!
//! ## 使用方式
//!
//! ```zig
//! var registry = TransportRegistry.init();
//!
//! // 注册 Transport（需指定传输路径类型）
//! registry.register(.relay, 0x01, &nats_transport);
//! registry.register(.direct, 0x01, &direct_transport);
//!
//! // 获取 Transport
//! if (registry.get(.relay, 0x01)) |transport| {
//!     try transport.send(0x01, data);
//! }
//! ```

const std = @import("std");
const client = @import("backend.zig");
const BackendTransport = client.BackendTransport;
const TransportError = client.TransportError;
const TransportRecv = client.TransportRecv;

// ============================================================================
// 传输路径类型
// ============================================================================

/// 传输路径类型
///
/// 简化版的路径分类，用于注册表索引。
/// 与 protocol/frame.zig 中的 TransportMode 对应：
/// - relay: relay_buffered, relay_streaming
/// - direct: direct_buffered, direct_streaming
pub const TransportPath = enum(u8) {
    /// 中继模式（通过消息中间件）
    relay = 0,
    /// 直连模式（通过服务发现直连）
    direct = 1,

    /// 路径类型数量
    pub const count: usize = 2;
};

// ============================================================================
// 单路径注册表
// ============================================================================

/// 单路径注册表
///
/// 管理单个 TransportPath 下的 RouteKey -> Transport 映射。
const RouteTable = struct {
    /// RouteKey -> Transport 映射
    transports: [256]?BackendTransport,
    /// 默认 Transport
    default_transport: ?BackendTransport,
    /// 已注册数量
    count: usize,

    fn init() RouteTable {
        return .{
            .transports = [_]?BackendTransport{null} ** 256,
            .default_transport = null,
            .count = 0,
        };
    }

    fn register(self: *RouteTable, route_key: u8, transport: BackendTransport) void {
        if (self.transports[route_key] == null) {
            self.count += 1;
        }
        self.transports[route_key] = transport;
    }

    fn unregister(self: *RouteTable, route_key: u8) void {
        if (self.transports[route_key] != null) {
            self.transports[route_key] = null;
            self.count -= 1;
        }
    }

    fn get(self: *const RouteTable, route_key: u8) ?BackendTransport {
        return self.transports[route_key] orelse self.default_transport;
    }

    fn getExact(self: *const RouteTable, route_key: u8) ?BackendTransport {
        return self.transports[route_key];
    }

    fn clear(self: *RouteTable) void {
        self.transports = [_]?BackendTransport{null} ** 256;
        self.default_transport = null;
        self.count = 0;
    }
};

// ============================================================================
// 传输注册表
// ============================================================================

/// 传输注册表
///
/// 管理 TransportPath + RouteKey 到 BackendTransport 的映射关系。
///
/// ## 设计要点
///
/// 1. 按 TransportPath（relay/direct）分组存储
/// 2. 不同路径下的 RouteKey 可以相同但映射不同 Transport
/// 3. 每个路径可设置独立的默认 Transport
pub const TransportRegistry = struct {
    /// 按路径分组的路由表
    tables: [TransportPath.count]RouteTable,

    /// 初始化注册表
    pub fn init() TransportRegistry {
        return .{
            .tables = [_]RouteTable{RouteTable.init()} ** TransportPath.count,
        };
    }

    /// 注册 Transport
    ///
    /// 将 BackendTransport 实例与指定的 路径+RouteKey 关联。
    pub fn register(self: *TransportRegistry, path: TransportPath, route_key: u8, transport: BackendTransport) void {
        self.tables[@intFromEnum(path)].register(route_key, transport);
    }

    /// 注销 Transport
    pub fn unregister(self: *TransportRegistry, path: TransportPath, route_key: u8) void {
        self.tables[@intFromEnum(path)].unregister(route_key);
    }

    /// 获取 Transport
    ///
    /// 根据 路径+RouteKey 获取对应的 Transport。
    /// 如果未注册，返回该路径的默认 Transport。
    pub fn get(self: *const TransportRegistry, path: TransportPath, route_key: u8) ?BackendTransport {
        return self.tables[@intFromEnum(path)].get(route_key);
    }

    /// 获取 Transport（严格模式）
    ///
    /// 仅返回精确匹配的 Transport，不使用默认值。
    pub fn getExact(self: *const TransportRegistry, path: TransportPath, route_key: u8) ?BackendTransport {
        return self.tables[@intFromEnum(path)].getExact(route_key);
    }

    /// 设置默认 Transport
    ///
    /// 为指定路径设置默认 Transport。
    pub fn setDefault(self: *TransportRegistry, path: TransportPath, transport: BackendTransport) void {
        self.tables[@intFromEnum(path)].default_transport = transport;
    }

    /// 清除默认 Transport
    pub fn clearDefault(self: *TransportRegistry, path: TransportPath) void {
        self.tables[@intFromEnum(path)].default_transport = null;
    }

    /// 检查是否已注册
    pub fn contains(self: *const TransportRegistry, path: TransportPath, route_key: u8) bool {
        return self.tables[@intFromEnum(path)].transports[route_key] != null;
    }

    /// 获取指定路径的注册数量
    pub fn getCount(self: *const TransportRegistry, path: TransportPath) usize {
        return self.tables[@intFromEnum(path)].count;
    }

    /// 获取总注册数量
    pub fn getTotalCount(self: *const TransportRegistry) usize {
        var total: usize = 0;
        for (self.tables) |table| {
            total += table.count;
        }
        return total;
    }

    /// 清空指定路径的所有注册
    pub fn clearPath(self: *TransportRegistry, path: TransportPath) void {
        self.tables[@intFromEnum(path)].clear();
    }

    /// 清空所有注册
    pub fn clear(self: *TransportRegistry) void {
        for (&self.tables) |*table| {
            table.clear();
        }
    }
};

// ============================================================================
// 全局注册表
// ============================================================================

/// 全局注册表实例
var global_registry: ?TransportRegistry = null;

/// 获取全局注册表
pub fn getGlobalRegistry() *TransportRegistry {
    if (global_registry == null) {
        global_registry = TransportRegistry.init();
    }
    return &global_registry.?;
}

/// 重置全局注册表（主要用于测试）
pub fn resetGlobalRegistry() void {
    if (global_registry) |*reg| {
        reg.clear();
    }
    global_registry = null;
}

// ============================================================================
// 测试
// ============================================================================

test "TransportRegistry basic operations" {
    const TestTransport = struct {
        id: u8,

        pub fn resolveImpl(_: *@This(), _: u8) TransportError!void {}
        pub fn sendImpl(_: *@This(), _: u8, _: []const u8) TransportError!u64 {
            return 0;
        }
        pub fn receiveImpl(_: *@This()) TransportError!?TransportRecv {
            return null;
        }
        pub fn closeImpl(_: *@This()) void {}
    };

    var impl1 = TestTransport{ .id = 1 };
    var impl2 = TestTransport{ .id = 2 };
    const transport1 = BackendTransport.init(TestTransport, &impl1);
    const transport2 = BackendTransport.init(TestTransport, &impl2);

    var registry = TransportRegistry.init();

    // 测试注册（relay 路径）
    registry.register(.relay, 0x01, transport1);
    registry.register(.relay, 0x02, transport2);
    try std.testing.expectEqual(@as(usize, 2), registry.getCount(.relay));

    // 测试获取
    try std.testing.expect(registry.get(.relay, 0x01) != null);
    try std.testing.expect(registry.get(.relay, 0x02) != null);
    try std.testing.expect(registry.get(.relay, 0x03) == null);

    // 测试 contains
    try std.testing.expect(registry.contains(.relay, 0x01));
    try std.testing.expect(!registry.contains(.relay, 0x03));

    // 测试注销
    registry.unregister(.relay, 0x01);
    try std.testing.expectEqual(@as(usize, 1), registry.getCount(.relay));
    try std.testing.expect(registry.get(.relay, 0x01) == null);
}

test "TransportRegistry different paths same route_key" {
    const TestTransport = struct {
        id: u8,

        pub fn resolveImpl(_: *@This(), _: u8) TransportError!void {}
        pub fn sendImpl(_: *@This(), _: u8, _: []const u8) TransportError!u64 {
            return 0;
        }
        pub fn receiveImpl(_: *@This()) TransportError!?TransportRecv {
            return null;
        }
        pub fn closeImpl(_: *@This()) void {}
    };

    var relay_impl = TestTransport{ .id = 1 };
    var direct_impl = TestTransport{ .id = 2 };
    const relay_transport = BackendTransport.init(TestTransport, &relay_impl);
    const direct_transport = BackendTransport.init(TestTransport, &direct_impl);

    var registry = TransportRegistry.init();

    // 相同 RouteKey 注册到不同路径
    registry.register(.relay, 0x01, relay_transport);
    registry.register(.direct, 0x01, direct_transport);

    // 各路径独立计数
    try std.testing.expectEqual(@as(usize, 1), registry.getCount(.relay));
    try std.testing.expectEqual(@as(usize, 1), registry.getCount(.direct));
    try std.testing.expectEqual(@as(usize, 2), registry.getTotalCount());

    // 各路径独立获取
    try std.testing.expect(registry.get(.relay, 0x01) != null);
    try std.testing.expect(registry.get(.direct, 0x01) != null);

    // 验证是不同的 Transport（通过 ptr 地址）
    const relay_t = registry.get(.relay, 0x01).?;
    const direct_t = registry.get(.direct, 0x01).?;
    try std.testing.expect(relay_t.ptr != direct_t.ptr);
}

test "TransportRegistry default transport per path" {
    const TestTransport = struct {
        id: u8,

        pub fn resolveImpl(_: *@This(), _: u8) TransportError!void {}
        pub fn sendImpl(_: *@This(), _: u8, _: []const u8) TransportError!u64 {
            return 0;
        }
        pub fn receiveImpl(_: *@This()) TransportError!?TransportRecv {
            return null;
        }
        pub fn closeImpl(_: *@This()) void {}
    };

    var relay_default = TestTransport{ .id = 0 };
    var direct_default = TestTransport{ .id = 1 };
    const relay_transport = BackendTransport.init(TestTransport, &relay_default);
    const direct_transport = BackendTransport.init(TestTransport, &direct_default);

    var registry = TransportRegistry.init();

    // 未注册且无默认值
    try std.testing.expect(registry.get(.relay, 0x01) == null);
    try std.testing.expect(registry.get(.direct, 0x01) == null);

    // 为各路径设置默认值
    registry.setDefault(.relay, relay_transport);
    registry.setDefault(.direct, direct_transport);

    // 各路径返回各自的默认值
    try std.testing.expect(registry.get(.relay, 0x01) != null);
    try std.testing.expect(registry.get(.direct, 0x01) != null);

    // getExact 不使用默认值
    try std.testing.expect(registry.getExact(.relay, 0x01) == null);
    try std.testing.expect(registry.getExact(.direct, 0x01) == null);
}

test "TransportRegistry clear" {
    const TestTransport = struct {
        pub fn resolveImpl(_: *@This(), _: u8) TransportError!void {}
        pub fn sendImpl(_: *@This(), _: u8, _: []const u8) TransportError!u64 {
            return 0;
        }
        pub fn receiveImpl(_: *@This()) TransportError!?TransportRecv {
            return null;
        }
        pub fn closeImpl(_: *@This()) void {}
    };

    var impl = TestTransport{};
    const transport = BackendTransport.init(TestTransport, &impl);

    var registry = TransportRegistry.init();
    registry.register(.relay, 0x01, transport);
    registry.register(.direct, 0x01, transport);
    registry.setDefault(.relay, transport);

    try std.testing.expectEqual(@as(usize, 2), registry.getTotalCount());

    // 清空单个路径
    registry.clearPath(.relay);
    try std.testing.expectEqual(@as(usize, 0), registry.getCount(.relay));
    try std.testing.expectEqual(@as(usize, 1), registry.getCount(.direct));

    // 清空全部
    registry.clear();
    try std.testing.expectEqual(@as(usize, 0), registry.getTotalCount());
}
