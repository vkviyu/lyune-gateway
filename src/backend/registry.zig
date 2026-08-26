//! 传输注册表
//!
//! 管理 TransportPath + ScopedRoute 到 BackendTransport 实例的映射。
//! 网关通过注册表获取对应的传输实例，实现路由分发。
//!
//! ## 设计说明
//!
//! 路由键是 ScopedRoute（RealmId + Group + RouteKey）。不同的 TransportPath 下，
//! 相同的 ScopedRoute 可以映射到不同的 Transport：
//! - relay 路径下 (realm 0, 0x01, 0x00) → NATS transport (topic: "im.messages")
//! - direct 路径下 (realm 0, 0x01, 0x00) → Direct transport (service: "im-service")
//!
//! ## 为什么键里必须带 realm
//!
//! `(group, route_key)` 是客户端在帧头里自己填的，两个接入方各自把 (0x01, 0x00)
//! 用作自己的消息服务是完全正常的。键里不带 realm，后注册的那个就会顶掉前一个，
//! 于是 A 的客户端把消息发进了 B 的后端（设计文档 §12.2）。
//!
//! ## 使用方式
//!
//! ```zig
//! var registry = TransportRegistry.init(allocator);
//! defer registry.deinit();
//!
//! // 注册 Transport（需指定传输路径类型）
//! try registry.register(.relay, .init(0, 0x01, 0x00), &nats_transport);
//! try registry.register(.direct, .init(0, 0x02, 0x00), &direct_transport);
//!
//! // 按组合键查找（路径由注册关系决定）
//! const key = ScopedRoute.init(0, 0x01, 0x00);
//! if (registry.find(key)) |transport| {
//!     try transport.send(key.route, data);
//! }
//! ```

const std = @import("std");
const foundation = @import("../foundation/mod.zig");
const client = @import("transport.zig");
const BackendTransport = client.BackendTransport;
const TransportError = client.TransportError;
const TransportRecv = client.TransportRecv;
const ResolveCallback = client.ResolveCallback;
pub const RouteId = client.RouteId;
pub const RealmId = foundation.realm.RealmId;

// ============================================================================
// 注册表键
// ============================================================================

/// 注册表的查找键：隔离域 + 路由键。
///
/// 客户端只在帧头里给出 `(group, route_key)`，realm 由网关从这条连接的 SNI 解析
/// 后补上（见 foundation/realm.zig）。因此客户端无法把请求送进别人的 realm——
/// 它没有任何字段能影响键的高 16 位。
pub const ScopedRoute = packed struct(u32) {
    route: RouteId = .{},
    realm: RealmId = foundation.realm.default_realm,

    pub fn init(realm: RealmId, group: u8, route_key: u8) ScopedRoute {
        return .{ .realm = realm, .route = RouteId.init(group, route_key) };
    }

    /// 把客户端给出的路由键放进某个 realm 的命名空间。
    pub fn scoped(realm: RealmId, route: RouteId) ScopedRoute {
        return .{ .realm = realm, .route = route };
    }
};

// ============================================================================
// 传输路径类型
// ============================================================================

/// 传输路径类型
///
/// 服务端的部署决策：一个服务注册在哪条路径下，决定网关用哪种方式触达它。
/// 客户端帧头不携带路径信息，路径由 RouteId 的注册关系查表得出。
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
/// 管理单个 TransportPath 下的 ScopedRoute -> Transport 映射。
const RouteTable = struct {
    /// ScopedRoute -> Transport 映射
    transports: std.AutoHashMap(ScopedRoute, BackendTransport),
    /// 默认 Transport
    default_transport: ?BackendTransport,

    fn init(allocator: std.mem.Allocator) RouteTable {
        return .{
            .transports = std.AutoHashMap(ScopedRoute, BackendTransport).init(allocator),
            .default_transport = null,
        };
    }

    fn deinit(self: *RouteTable) void {
        self.transports.deinit();
    }

    fn register(self: *RouteTable, route: ScopedRoute, transport: BackendTransport) !void {
        try self.transports.put(route, transport);
    }

    fn unregister(self: *RouteTable, route: ScopedRoute) void {
        _ = self.transports.remove(route);
    }

    fn get(self: *const RouteTable, route: ScopedRoute) ?BackendTransport {
        return self.transports.get(route) orelse self.default_transport;
    }

    fn getExact(self: *const RouteTable, route: ScopedRoute) ?BackendTransport {
        return self.transports.get(route);
    }

    fn count(self: *const RouteTable) usize {
        return self.transports.count();
    }

    fn clear(self: *RouteTable) void {
        self.transports.clearRetainingCapacity();
        self.default_transport = null;
    }
};

// ============================================================================
// 传输注册表
// ============================================================================

/// 传输注册表
///
/// 管理 TransportPath + ScopedRoute 到 BackendTransport 的映射关系。
///
/// ## 设计要点
///
/// 1. 按 TransportPath（relay/direct）分组存储
/// 2. 不同路径下的 ScopedRoute 可以相同但映射不同 Transport
/// 3. 每个路径可设置独立的默认 Transport
pub const TransportRegistry = struct {
    /// 按路径分组的路由表
    tables: [TransportPath.count]RouteTable,

    /// 初始化注册表
    pub fn init(allocator: std.mem.Allocator) TransportRegistry {
        var tables: [TransportPath.count]RouteTable = undefined;
        for (&tables) |*table| table.* = RouteTable.init(allocator);
        return .{ .tables = tables };
    }

    /// 释放注册表
    pub fn deinit(self: *TransportRegistry) void {
        for (&self.tables) |*table| table.deinit();
    }

    /// 注册 Transport
    ///
    /// 将 BackendTransport 实例与指定的 路径+ScopedRoute 关联。
    pub fn register(self: *TransportRegistry, path: TransportPath, route: ScopedRoute, transport: BackendTransport) !void {
        try self.tables[@intFromEnum(path)].register(route, transport);
    }

    /// 注销 Transport
    pub fn unregister(self: *TransportRegistry, path: TransportPath, route: ScopedRoute) void {
        self.tables[@intFromEnum(path)].unregister(route);
    }

    /// 获取 Transport
    ///
    /// 根据 路径+ScopedRoute 获取对应的 Transport。
    /// 如果未注册，返回该路径的默认 Transport。
    pub fn get(self: *const TransportRegistry, path: TransportPath, route: ScopedRoute) ?BackendTransport {
        return self.tables[@intFromEnum(path)].get(route);
    }

    /// 获取 Transport（严格模式）
    ///
    /// 仅返回精确匹配的 Transport，不使用默认值。
    pub fn getExact(self: *const TransportRegistry, path: TransportPath, route: ScopedRoute) ?BackendTransport {
        return self.tables[@intFromEnum(path)].getExact(route);
    }

    /// 按 ScopedRoute 组合键查找 Transport（路径无关）
    ///
    /// 传输路径由注册关系决定：客户端只指定 Group + RouteKey，realm 由网关按 SNI
    /// 补上，网关依次在 direct、relay 表中精确查找，最后回退到各路径的默认 Transport。
    /// 同一 ScopedRoute 不应同时注册在两条路径上（direct 优先生效）。
    ///
    /// 默认 Transport 是**全 realm 共享**的，因此只应在单 realm 部署里使用：
    /// 多 realm 部署必须把 fallback 留空，否则一个拼错的路由键会落进别人的后端。
    pub fn find(self: *const TransportRegistry, route: ScopedRoute) ?BackendTransport {
        if (self.tables[@intFromEnum(TransportPath.direct)].getExact(route)) |transport| return transport;
        if (self.tables[@intFromEnum(TransportPath.relay)].getExact(route)) |transport| return transport;
        if (self.tables[@intFromEnum(TransportPath.direct)].default_transport) |transport| return transport;
        return self.tables[@intFromEnum(TransportPath.relay)].default_transport;
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
    pub fn contains(self: *const TransportRegistry, path: TransportPath, route: ScopedRoute) bool {
        return self.tables[@intFromEnum(path)].getExact(route) != null;
    }

    /// 获取指定路径的注册数量
    pub fn getCount(self: *const TransportRegistry, path: TransportPath) usize {
        return self.tables[@intFromEnum(path)].count();
    }

    /// 获取总注册数量
    pub fn getTotalCount(self: *const TransportRegistry) usize {
        var total: usize = 0;
        for (&self.tables) |*table| {
            total += table.count();
        }
        return total;
    }

    /// 遍历指定路径下已注册的 (ScopedRoute, Transport) 项
    pub fn iterator(self: *const TransportRegistry, path: TransportPath) std.AutoHashMap(ScopedRoute, BackendTransport).Iterator {
        return self.tables[@intFromEnum(path)].transports.iterator();
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
// 测试
// ============================================================================

const TestTransport = struct {
    id: u8 = 0,

    pub fn resolveImpl(_: *@This(), _: RouteId, _: ?ResolveCallback, _: ?*anyopaque) void {}
    pub fn sendStreamImpl(_: *@This(), _: RouteId, handle: ?u64, _: []const u8, _: bool) TransportError!u64 {
        return handle orelse 0;
    }
    pub fn receiveImpl(_: *@This()) TransportError!?TransportRecv {
        return null;
    }
    pub fn releaseRecvImpl(_: *@This(), _: TransportRecv) void {}
    pub fn closeImpl(_: *@This()) void {}
};

test "TransportRegistry basic operations" {
    var impl1 = TestTransport{ .id = 1 };
    var impl2 = TestTransport{ .id = 2 };
    const transport1 = BackendTransport.init(TestTransport, &impl1);
    const transport2 = BackendTransport.init(TestTransport, &impl2);

    var registry = TransportRegistry.init(std.testing.allocator);
    defer registry.deinit();

    // 测试注册（relay 路径）
    try registry.register(.relay, ScopedRoute.init(0, 0x01, 0x00), transport1);
    try registry.register(.relay, ScopedRoute.init(0, 0x02, 0x00), transport2);
    try std.testing.expectEqual(@as(usize, 2), registry.getCount(.relay));

    // 测试获取
    try std.testing.expect(registry.get(.relay, ScopedRoute.init(0, 0x01, 0x00)) != null);
    try std.testing.expect(registry.get(.relay, ScopedRoute.init(0, 0x02, 0x00)) != null);
    try std.testing.expect(registry.get(.relay, ScopedRoute.init(0, 0x03, 0x00)) == null);

    // 测试 contains
    try std.testing.expect(registry.contains(.relay, ScopedRoute.init(0, 0x01, 0x00)));
    try std.testing.expect(!registry.contains(.relay, ScopedRoute.init(0, 0x03, 0x00)));

    // 测试注销
    registry.unregister(.relay, ScopedRoute.init(0, 0x01, 0x00));
    try std.testing.expectEqual(@as(usize, 1), registry.getCount(.relay));
    try std.testing.expect(registry.get(.relay, ScopedRoute.init(0, 0x01, 0x00)) == null);
}

test "TransportRegistry combined group and route_key routing" {
    var impl_a = TestTransport{ .id = 1 };
    var impl_b = TestTransport{ .id = 2 };
    const transport_a = BackendTransport.init(TestTransport, &impl_a);
    const transport_b = BackendTransport.init(TestTransport, &impl_b);

    var registry = TransportRegistry.init(std.testing.allocator);
    defer registry.deinit();

    // 同一 group 下不同 route_key 是不同的路由
    try registry.register(.direct, ScopedRoute.init(0, 0x01, 0x00), transport_a);
    try registry.register(.direct, ScopedRoute.init(0, 0x01, 0x01), transport_b);

    try std.testing.expectEqual(@intFromPtr(&impl_a), @intFromPtr(registry.find(ScopedRoute.init(0, 0x01, 0x00)).?.ptr));
    try std.testing.expectEqual(@intFromPtr(&impl_b), @intFromPtr(registry.find(ScopedRoute.init(0, 0x01, 0x01)).?.ptr));
    // 组合键任一分量不匹配都视为未注册
    try std.testing.expect(registry.find(ScopedRoute.init(0, 0x01, 0x02)) == null);
    try std.testing.expect(registry.find(ScopedRoute.init(0, 0x02, 0x00)) == null);
}

test "TransportRegistry different paths same RouteId" {
    var relay_impl = TestTransport{ .id = 1 };
    var direct_impl = TestTransport{ .id = 2 };
    const relay_transport = BackendTransport.init(TestTransport, &relay_impl);
    const direct_transport = BackendTransport.init(TestTransport, &direct_impl);

    var registry = TransportRegistry.init(std.testing.allocator);
    defer registry.deinit();

    // 相同 RouteId 注册到不同路径
    try registry.register(.relay, ScopedRoute.init(0, 0x01, 0x00), relay_transport);
    try registry.register(.direct, ScopedRoute.init(0, 0x01, 0x00), direct_transport);

    // 各路径独立计数
    try std.testing.expectEqual(@as(usize, 1), registry.getCount(.relay));
    try std.testing.expectEqual(@as(usize, 1), registry.getCount(.direct));
    try std.testing.expectEqual(@as(usize, 2), registry.getTotalCount());

    // 各路径独立获取
    try std.testing.expect(registry.get(.relay, ScopedRoute.init(0, 0x01, 0x00)) != null);
    try std.testing.expect(registry.get(.direct, ScopedRoute.init(0, 0x01, 0x00)) != null);

    // 验证是不同的 Transport（通过 ptr 地址）
    const relay_t = registry.get(.relay, ScopedRoute.init(0, 0x01, 0x00)).?;
    const direct_t = registry.get(.direct, ScopedRoute.init(0, 0x01, 0x00)).?;
    try std.testing.expect(relay_t.ptr != direct_t.ptr);
}

test "TransportRegistry default transport per path" {
    var relay_default = TestTransport{ .id = 0 };
    var direct_default = TestTransport{ .id = 1 };
    const relay_transport = BackendTransport.init(TestTransport, &relay_default);
    const direct_transport = BackendTransport.init(TestTransport, &direct_default);

    var registry = TransportRegistry.init(std.testing.allocator);
    defer registry.deinit();

    // 未注册且无默认值
    try std.testing.expect(registry.get(.relay, ScopedRoute.init(0, 0x01, 0x00)) == null);
    try std.testing.expect(registry.get(.direct, ScopedRoute.init(0, 0x01, 0x00)) == null);

    // 为各路径设置默认值
    registry.setDefault(.relay, relay_transport);
    registry.setDefault(.direct, direct_transport);

    // 各路径返回各自的默认值
    try std.testing.expect(registry.get(.relay, ScopedRoute.init(0, 0x01, 0x00)) != null);
    try std.testing.expect(registry.get(.direct, ScopedRoute.init(0, 0x01, 0x00)) != null);

    // getExact 不使用默认值
    try std.testing.expect(registry.getExact(.relay, ScopedRoute.init(0, 0x01, 0x00)) == null);
    try std.testing.expect(registry.getExact(.direct, ScopedRoute.init(0, 0x01, 0x00)) == null);
}

test "TransportRegistry clear" {
    var impl = TestTransport{};
    const transport = BackendTransport.init(TestTransport, &impl);

    var registry = TransportRegistry.init(std.testing.allocator);
    defer registry.deinit();

    try registry.register(.relay, ScopedRoute.init(0, 0x01, 0x00), transport);
    try registry.register(.direct, ScopedRoute.init(0, 0x01, 0x00), transport);
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

test "TransportRegistry find resolves path by registration" {
    var direct_impl = TestTransport{ .id = 1 };
    var relay_impl = TestTransport{ .id = 2 };
    const direct_transport = BackendTransport.init(TestTransport, &direct_impl);
    const relay_transport = BackendTransport.init(TestTransport, &relay_impl);

    var registry = TransportRegistry.init(std.testing.allocator);
    defer registry.deinit();

    try registry.register(.direct, ScopedRoute.init(0, 0x01, 0x00), direct_transport);
    try registry.register(.relay, ScopedRoute.init(0, 0x02, 0x00), relay_transport);

    // 路径由注册关系决定，调用方无需指定
    try std.testing.expectEqual(@intFromPtr(&direct_impl), @intFromPtr(registry.find(ScopedRoute.init(0, 0x01, 0x00)).?.ptr));
    try std.testing.expectEqual(@intFromPtr(&relay_impl), @intFromPtr(registry.find(ScopedRoute.init(0, 0x02, 0x00)).?.ptr));
    try std.testing.expect(registry.find(ScopedRoute.init(0, 0x03, 0x00)) == null);

    // 同一 ScopedRoute 意外双注册时 direct 优先
    try registry.register(.relay, ScopedRoute.init(0, 0x01, 0x00), relay_transport);
    try std.testing.expectEqual(@intFromPtr(&direct_impl), @intFromPtr(registry.find(ScopedRoute.init(0, 0x01, 0x00)).?.ptr));
}

test "the same route key in two realms resolves to two different transports" {
    // §12.2 的核心回归：两个接入方各自把 (0x01, 0x00) 当作自己的消息服务是常态。
    // 键里不带 realm 时后注册的会顶掉前一个，A 的客户端就把消息发进了 B 的后端。
    var realm_a_impl = TestTransport{ .id = 1 };
    var realm_b_impl = TestTransport{ .id = 2 };
    const realm_a = BackendTransport.init(TestTransport, &realm_a_impl);
    const realm_b = BackendTransport.init(TestTransport, &realm_b_impl);

    var registry = TransportRegistry.init(std.testing.allocator);
    defer registry.deinit();

    try registry.register(.direct, ScopedRoute.init(7, 0x01, 0x00), realm_a);
    try registry.register(.direct, ScopedRoute.init(9, 0x01, 0x00), realm_b);

    try std.testing.expectEqual(@as(usize, 2), registry.getCount(.direct));
    try std.testing.expectEqual(@intFromPtr(&realm_a_impl), @intFromPtr(registry.find(ScopedRoute.init(7, 0x01, 0x00)).?.ptr));
    try std.testing.expectEqual(@intFromPtr(&realm_b_impl), @intFromPtr(registry.find(ScopedRoute.init(9, 0x01, 0x00)).?.ptr));

    // 没登记过这条路由的 realm 查不到任何东西，不会回落到别人的 transport。
    try std.testing.expect(registry.find(ScopedRoute.init(8, 0x01, 0x00)) == null);

    // 注销只影响本 realm。
    registry.unregister(.direct, ScopedRoute.init(7, 0x01, 0x00));
    try std.testing.expect(registry.find(ScopedRoute.init(7, 0x01, 0x00)) == null);
    try std.testing.expect(registry.find(ScopedRoute.init(9, 0x01, 0x00)) != null);
}
