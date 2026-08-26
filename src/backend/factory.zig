//! 每 Worker 一份的直连 transport 工厂
//!
//! 它回答的是"实例归谁、什么时候建"这两件事：
//!
//! - **归谁**：`DirectTransport` 实例的所有权在这里，而不是在装配层的栈上。搬进来是为了
//!   让运行期新增的路由也有地方放——栈上的定长数组一旦装配完就没法再加。
//! - **什么时候建**：启动期声明的路由照旧预建（`prewarm`），运行期新增的路由**惰性建**
//!   （`ensure`，由 `TransportRegistry` 查不到时触发）。
//!
//! ## 为什么必须在 Worker 自己的线程上创建
//!
//! 一个 `DirectTransport` 持有绑在**某一条** `xev.Loop` 上的句柄（DNS 解析、连接重试
//! 定时器），以及那个 Worker 私有的 `BackendPool` 引用。在别的线程上建好再交过去，
//! 等于把 completion 挂到了另一条事件循环上——那不是竞态，是直接跑错循环。
//!
//! 所以热加载的分工是：**写者（信号线程）只往共享目录里追加声明，实例由各 Worker
//! 在自己线程上按需建**。这条分工顺带带来一个好处：没有那个 realm 流量的 Worker
//! 不会为它白付一个 socket 与若干后端连接。
//!
//! ## 定容
//!
//! 槽位启动期一次分配。实例地址必须稳定（注册表里存的是指针），所以槽位数组绝不能
//! 扩容搬迁——用满就明确报错，而不是悄悄 realloc 把已注册的指针全变成野指针。

const std = @import("std");
const xev = @import("xev");

const foundation = @import("../foundation/mod.zig");

const catalog = @import("catalog.zig");
const direct = @import("direct.zig");
const pool_mod = @import("pool.zig");
const registry = @import("registry.zig");

const DirectTransport = direct.DirectTransport;
const RouteEntry = catalog.RouteEntry;

pub const Error = error{
    /// 槽位用尽：本 Worker 能承载的直连路由数达到 `capacity`。
    TooManyRoutes,
    OutOfMemory,
};

pub const DirectFactory = struct {
    allocator: std.mem.Allocator,
    event_loop: *xev.Loop,
    resolver: foundation.resolver.Resolver,
    /// 每 Worker 一份的共享传输设施；**借用**，销毁顺序上它必须晚于本工厂。
    pool: *pool_mod.BackendPool,
    /// 直连传输的公共参数模板；每条路由只替换 `endpoints`。
    template: direct.DirectConfig,

    /// 实例仓库；`live` 之前的槽位已建好且地址稳定。
    slots: []DirectTransport,
    live: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        event_loop: *xev.Loop,
        resolver: foundation.resolver.Resolver,
        pool: *pool_mod.BackendPool,
        template: direct.DirectConfig,
        capacity: usize,
    ) Error!DirectFactory {
        const slots = try allocator.alloc(DirectTransport, capacity);
        return .{
            .allocator = allocator,
            .event_loop = event_loop,
            .resolver = resolver,
            .pool = pool,
            .template = template,
            .slots = slots,
        };
    }

    /// 销毁全部已建实例。
    ///
    /// 必须早于 `pool` 销毁：每个 transport 在 deinit 里会把连接从池的索引上摘掉、
    /// 把接收槽位还回来。
    pub fn deinit(self: *DirectFactory) void {
        for (self.slots[0..self.live]) |*transport| transport.deinit();
        self.allocator.free(self.slots);
        self.live = 0;
    }

    /// 为一条路由声明建一个实例，返回稳定地址。
    ///
    /// 调用方负责把它登记进 `TransportRegistry`；本工厂不认识注册表——它只管"造与持有"，
    /// 这样"造实例"与"登记映射"两件事的失败可以分别处置。
    pub fn create(self: *DirectFactory, entry: RouteEntry) Error!*DirectTransport {
        if (self.live == self.slots.len) return Error.TooManyRoutes;
        var config = self.template;
        config.endpoints = entry.endpoints;

        const slot = &self.slots[self.live];
        slot.* = DirectTransport.init(
            self.allocator,
            config,
            self.event_loop,
            self.resolver,
            entry.route.realm,
            self.pool,
        ) catch return Error.OutOfMemory;
        self.live += 1;
        return slot;
    }
};

// ============================================================================
// 测试
// ============================================================================

const StaticResolver = struct {
    address: foundation.net.Address,

    pub fn resolve(
        self: *StaticResolver,
        host: []const u8,
        port: u16,
        callback: foundation.resolver.ResolveCallback,
        ctx: ?*anyopaque,
    ) foundation.resolver.ResolveError!foundation.resolver.ResolveHandle {
        _ = host;
        const addr = switch (self.address) {
            .ip4 => |ip4| foundation.net.initIp4(ip4.bytes, port),
            .ip6 => |ip6| foundation.net.initIp6(ip6.bytes, port),
        };
        callback(ctx, .{ .address = addr });
        return .{ .id = 0 };
    }

    pub fn cancel(_: *StaticResolver, _: foundation.resolver.ResolveHandle) void {}

    pub fn deinit(_: *StaticResolver) void {}

    fn asResolver(self: *StaticResolver) foundation.resolver.Resolver {
        return foundation.resolver.Resolver.init(StaticResolver, self);
    }
};

test "the factory hands out stable addresses and refuses to grow past capacity" {
    // 地址稳定是硬要求：注册表里存的是指针，槽位数组一旦搬迁，已登记的映射全变野指针。
    // 所以用满时必须明确报错，绝不能 realloc。
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var pool = try pool_mod.BackendPool.init(std.testing.allocator, &loop, .{ .recv_slots = 8, .max_slots_per_conn = 8 });
    defer pool.deinit();

    var static_resolver = StaticResolver{ .address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 8443) };
    var factory = try DirectFactory.init(
        std.testing.allocator,
        &loop,
        static_resolver.asResolver(),
        &pool,
        .{ .endpoints = &.{} },
        2,
    );
    defer factory.deinit();

    const endpoints = [_]direct.Endpoint{.{ .host = "127.0.0.1", .port = 9000 }};
    const first = try factory.create(.{ .route = registry.ScopedRoute.init(1, 0, 0), .endpoints = &endpoints });
    const second = try factory.create(.{ .route = registry.ScopedRoute.init(2, 0, 0), .endpoints = &endpoints });
    try std.testing.expect(first != second);
    // realm 随路由传进实例：它决定这条连接占用的共享接收槽位算在谁头上。
    try std.testing.expectEqual(@as(u16, 1), first.realm);
    try std.testing.expectEqual(@as(u16, 2), second.realm);

    try std.testing.expectError(
        Error.TooManyRoutes,
        factory.create(.{ .route = registry.ScopedRoute.init(3, 0, 0), .endpoints = &endpoints }),
    );
}
