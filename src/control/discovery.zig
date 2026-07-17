//! 服务发现抽象
//!
//! 网关直连模式下需要知道「某个 RouteKey 对应哪些后端实例、它们健康吗」。本模块把
//! 这一职责抽象成稳定的 provider 接口 ServiceDiscovery，让上层（DirectTransport、
//! Coordinator）不关心后端信息来自静态配置还是 etcd/Consul。
//!
//! 设计要点：
//!   - 快照（Snapshot）是不可变、带版本号的只读视图，provider 在下次 refresh 成功前
//!     一直持有其引用的内存，读方无需加锁；
//!   - 当前生产装配使用配置驱动的 StaticDiscovery，将来替换成远端 registry 时，
//!     只需实现同一套 vtable，业务数据面代码不用改。

const std = @import("std");

/// 后端实例的健康状态。
pub const EndpointState = enum {
    /// 健康，可承接新请求。
    healthy,
    /// 正在优雅下线，不再接新请求（保留给已有连接）。
    draining,
    /// 不可用，跳过。
    unavailable,
};

/// 一个后端服务实例。host 保持字符串形式（可能是域名），由上层异步 DNS 解析成地址。
pub const ServiceEndpoint = struct {
    id: []const u8,
    host: []const u8,
    port: u16,
    /// 负载权重，0 表示不参与选择。
    weight: u16,
    state: EndpointState,
};

/// 一个 RouteKey 到其后端实例集合的映射。
pub const Route = struct {
    route_key: u8,
    /// 版本号，用于检测路由是否发生变化。
    revision: u64,
    endpoints: []const ServiceEndpoint,

    /// 返回第一个健康且权重非零的实例。当前是最简单的选择策略，
    /// 后续可扩展为加权轮询/一致性哈希等。
    pub fn firstHealthy(self: Route) ?ServiceEndpoint {
        for (self.endpoints) |endpoint| {
            if (endpoint.state == .healthy and endpoint.weight != 0) return endpoint;
        }
        return null;
    }
};

/// provider 返回的不可变、带版本的路由视图。
/// 在 provider 下一次成功 refresh 之前，其引用的内存始终有效。
pub const Snapshot = struct {
    revision: u64,
    routes: []const Route,

    /// 按 RouteKey 查找路由，未找到返回 null。
    pub fn route(self: Snapshot, route_key: u8) ?Route {
        for (self.routes) |entry| {
            if (entry.route_key == route_key) return entry;
        }
        return null;
    }
};

/// 稳定的服务发现 provider 边界，可承载静态配置、etcd、Consul 等实现。
/// 采用 vtable + 类型擦除的多态模式（与 mq/backend.zig 同风格）。
pub const ServiceDiscovery = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// 返回当前路由快照（读操作，不阻塞）。
        snapshot: *const fn (ptr: *anyopaque) Snapshot,
        /// 尝试拉取最新路由；仅当装载了新快照时返回 true。
        refresh: *const fn (ptr: *anyopaque) anyerror!bool,
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub fn snapshot(self: ServiceDiscovery) Snapshot {
        return self.vtable.snapshot(self.ptr);
    }

    /// 只有在装载了新快照时才返回 true。
    pub fn refresh(self: ServiceDiscovery) !bool {
        return self.vtable.refresh(self.ptr);
    }

    pub fn deinit(self: ServiceDiscovery) void {
        self.vtable.deinit(self.ptr);
    }

    /// 从具体实现类型生成接口实例。实现需提供 snapshot/refresh/deinit 三个方法。
    pub fn init(comptime T: type, implementation: *T) ServiceDiscovery {
        const Adapter = struct {
            fn snapshotImpl(ptr: *anyopaque) Snapshot {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.snapshot();
            }

            fn refreshImpl(ptr: *anyopaque) anyerror!bool {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.refresh();
            }

            fn deinitImpl(ptr: *anyopaque) void {
                const self: *T = @ptrCast(@alignCast(ptr));
                self.deinit();
            }

            const vtable: VTable = .{
                .snapshot = snapshotImpl,
                .refresh = refreshImpl,
                .deinit = deinitImpl,
            };
        };
        return .{ .ptr = implementation, .vtable = &Adapter.vtable };
    }
};

/// 配置驱动的静态 provider，在接入远端 registry 之前使用。
/// 路由集合在启动时固定，refresh 永远返回 false（没有动态更新）。
pub const StaticDiscovery = struct {
    current: Snapshot,

    /// 用一组静态路由构造，版本号取所有路由 revision 的最大值。
    pub fn init(routes: []const Route) StaticDiscovery {
        var revision: u64 = 0;
        for (routes) |route| revision = @max(revision, route.revision);
        return .{ .current = .{ .revision = revision, .routes = routes } };
    }

    pub fn asDiscovery(self: *StaticDiscovery) ServiceDiscovery {
        return ServiceDiscovery.init(StaticDiscovery, self);
    }

    pub fn snapshot(self: *StaticDiscovery) Snapshot {
        return self.current;
    }

    /// 静态实现没有动态更新，恒定返回 false。
    pub fn refresh(_: *StaticDiscovery) !bool {
        return false;
    }

    pub fn deinit(_: *StaticDiscovery) void {}
};

test "static discovery exposes versioned healthy routes" {
    const endpoints = [_]ServiceEndpoint{
        .{ .id = "draining", .host = "127.0.0.1", .port = 9001, .weight = 1, .state = .draining },
        .{ .id = "ready", .host = "backend.internal", .port = 9002, .weight = 10, .state = .healthy },
    };
    const routes = [_]Route{.{ .route_key = 7, .revision = 42, .endpoints = &endpoints }};
    var implementation = StaticDiscovery.init(&routes);
    const discovery = implementation.asDiscovery();

    const snapshot = discovery.snapshot();
    try std.testing.expectEqual(@as(u64, 42), snapshot.revision);
    const endpoint = snapshot.route(7).?.firstHealthy().?;
    try std.testing.expectEqualStrings("ready", endpoint.id);
    try std.testing.expect(!(try discovery.refresh()));
}
