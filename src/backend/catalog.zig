//! 直连路由目录
//!
//! 回答一个问题：**`ScopedRoute(realm, group, route_key)` 对应哪些后端实例地址。**
//! 它是"配置里声明了什么"，而 `TransportRegistry` 是"这个 Worker 已经建好了什么"——
//! 两者刻意分开，因为前者是进程级共享的声明，后者是每 Worker 私有的实例。
//!
//! ## 为什么要有它
//!
//! 新增接入方必须不重启（设计文档 §12.5），而"新增一个 realm"只登记 SNI 是没用的：
//! 那个 realm 的客户端能连上，但每次交换都 `route not found`，也无法认证。所以路由声明
//! 也要能在运行期追加。
//!
//! ## 与 realm 表同一套并发形态
//!
//! 定容 slab + 原子长度，语义与 `foundation/realm.zig` 的 `Table` 完全一致：
//!
//! - 启动期按 `capacity` 一次分配，运行期只填后面的空位；
//! - **已登记部分只读、永不移动、永不释放**，所以正在查表的读者不可能踩到搬迁或悬垂；
//! - 写者先填好槽位，再用 release 序发布长度；读者用 acquire 序读长度，因此读到的长度
//!   所覆盖的槽位内容必定已经写完。
//!
//! 只有一个写者（处理 SIGHUP 的那条线程，见 app/reload.zig），所以追加不需要 CAS。
//! 不支持删除：一条还有在途交换的路由没有安全的移除时机，而"上线一个新接入方"只需要追加。
//!
//! `endpoints` 与其中的 host 字符串借用别处的内存，那块内存的生命周期必须覆盖整个进程
//! 运行期（启动期那批由 `RuntimeConfig` 持有，运行期追加的由 `Reloader` 持有）。

const std = @import("std");

const direct = @import("direct.zig");
const registry = @import("registry.zig");

const ScopedRoute = registry.ScopedRoute;

pub const Error = error{
    /// 目录已满（`slots` 用尽）。
    CatalogFull,
    /// 这个 ScopedRoute 已经登记过了。
    DuplicateRoute,
};

/// 一条直连路由的声明。
pub const RouteEntry = struct {
    route: ScopedRoute = .{},
    endpoints: []const direct.Endpoint = &.{},
};

/// 进程级共享的直连路由目录。
pub const RouteCatalog = struct {
    /// 定容槽位；下标小于 `len` 的部分只读。
    slots: []RouteEntry = &.{},
    /// 已登记条目数，原子发布（见文件头）。
    len: std.atomic.Value(usize) = .init(0),

    /// 已登记的条目（只读视图）。
    pub fn entries(self: *const RouteCatalog) []const RouteEntry {
        return self.slots[0..self.len.load(.acquire)];
    }

    /// 查一条路由的声明。
    ///
    /// 线性扫描：它只在 `TransportRegistry` 查不到时才被调用，也就是每条路由在每个
    /// Worker 上一生一次，不在任何热路径上。
    pub fn find(self: *const RouteCatalog, route: ScopedRoute) ?RouteEntry {
        for (self.entries()) |entry| {
            if (@as(u32, @bitCast(entry.route)) == @as(u32, @bitCast(route))) return entry;
        }
        return null;
    }

    /// 追加一条路由声明。`endpoints` 必须在进程生命周期内有效（本目录只借用）。
    ///
    /// 只允许单一写者调用。写槽位与发布长度的顺序不能调换——先发布长度就等于让读者
    /// 看见一个还没填好的槽位。
    pub fn register(self: *RouteCatalog, entry: RouteEntry) Error!void {
        if (self.find(entry.route) != null) return Error.DuplicateRoute;
        const at = self.len.load(.monotonic);
        if (at == self.slots.len) return Error.CatalogFull;
        self.slots[at] = entry;
        self.len.store(at + 1, .release);
    }
};

// ============================================================================
// 测试
// ============================================================================

fn testEndpoints() []const direct.Endpoint {
    return &.{.{ .host = "127.0.0.1", .port = 9000 }};
}

test "a route can be found by its scoped key" {
    var slots: [4]RouteEntry = @splat(.{});
    var catalog = RouteCatalog{ .slots = &slots };

    try catalog.register(.{ .route = ScopedRoute.init(1, 2, 3), .endpoints = testEndpoints() });
    try std.testing.expect(catalog.find(ScopedRoute.init(1, 2, 3)) != null);

    // realm 参与键：同样的 (group, route_key) 在别的 realm 里是另一条路由，
    // 这正是 §12.2 的隔离要求，也是"目录不能只按 RouteId 建键"的理由。
    try std.testing.expect(catalog.find(ScopedRoute.init(2, 2, 3)) == null);
}

test "the catalog refuses duplicates and reports exhaustion" {
    var slots: [2]RouteEntry = @splat(.{});
    var catalog = RouteCatalog{ .slots = &slots };

    try catalog.register(.{ .route = ScopedRoute.init(1, 0, 0), .endpoints = testEndpoints() });
    // 重复登记会让 find 命中哪条取决于插入顺序——把一个配置错误变成一次随机的错投。
    try std.testing.expectError(
        Error.DuplicateRoute,
        catalog.register(.{ .route = ScopedRoute.init(1, 0, 0), .endpoints = testEndpoints() }),
    );

    try catalog.register(.{ .route = ScopedRoute.init(2, 0, 0), .endpoints = testEndpoints() });
    try std.testing.expectError(
        Error.CatalogFull,
        catalog.register(.{ .route = ScopedRoute.init(3, 0, 0), .endpoints = testEndpoints() }),
    );
}

test "appending never disturbs what is already registered" {
    // 这条钉住的是并发形态的核心不变量：读者手上可能正拿着一条旧条目的切片，
    // 追加不能移动或改写它，否则那个读者会读到别人的 endpoints。
    var slots: [8]RouteEntry = @splat(.{});
    var catalog = RouteCatalog{ .slots = &slots };

    try catalog.register(.{ .route = ScopedRoute.init(1, 0, 0), .endpoints = testEndpoints() });
    const first = catalog.find(ScopedRoute.init(1, 0, 0)).?;

    var i: u8 = 2;
    while (i < 8) : (i += 1) {
        try catalog.register(.{ .route = ScopedRoute.init(i, 0, 0), .endpoints = testEndpoints() });
    }

    const again = catalog.find(ScopedRoute.init(1, 0, 0)).?;
    try std.testing.expectEqual(first.endpoints.ptr, again.endpoints.ptr);
    try std.testing.expectEqual(@as(usize, 7), catalog.entries().len);
}
