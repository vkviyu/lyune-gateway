//! app/reload —— 配置热加载（只接受新增）
//!
//! 它解决的是"上线一个新接入方不能重启"（设计文档 §12.5）。
//!
//! ## 为什么是 SIGHUP + 重读配置文件，而不是一个管理端口
//!
//! 1. **不新增任何网络暴露面。** 授权就是"谁能给这个进程发信号"，由操作系统按 uid 判定，
//!    不需要我们自己写一套认证——而一个写错的管理端口认证就是一个远程后门。
//! 2. **原样复用既有的解析与校验。** 走的还是 `foundation.config.load`，因此热加载自动
//!    继承了全部启动期校验（域名重复、路由指向未登记 realm、`(realm, group, route_key)`
//!    重复……）。另建一条命令通路就等于把这些校验抄第二遍，两份迟早不一致。
//! 3. **形态与现状连续**：运维本来就是"编辑 JSON + 重启"，现在只是去掉了重启。
//!
//! 实现上用一条 `sigwait` 线程而不是信号处理函数：处理函数受异步信号安全约束（不能分配、
//! 不能加锁），而重读配置两样都要。做法是在拉起任何线程之前把 SIGHUP 屏蔽掉（屏蔽字会被
//! 后续线程继承），于是这个信号只会停在待决状态，由专职线程的 `sigwait` 取走——处理逻辑
//! 因此运行在一条普通线程上，什么都能做。
//!
//! ## 为什么只接受新增
//!
//! - **改**：改一个 realm 的 id 或域名，等于把现有连接的命名空间悄悄重新划分；改一条路由的
//!   endpoints，等于让在途交换的后半段发给另一个后端。
//! - **删**：一条还有在途交换的路由、一个还有连接的 realm，都没有安全的移除时机。
//!
//! 两者都做不到"安全地生效"，所以一律拒绝并**整次拒绝**（全有或全无）：部分生效会让
//! 配置文件与进程状态处于一个谁都说不清的中间态。删除的判据是"表里有、文件里没有"——
//! 因此运维也不能靠删掉文件里的条目来清理，那会让整次热加载失败并留一条日志。
//!
//! ## 内存
//!
//! 两张表只借用字符串与 endpoint 数组，所以本模块分配的内存必须活到进程结束。它们记在
//! `owned_*` 里，在 `deinit` 里释放——而 `deinit` 只在**所有 Worker 都已停止之后**调用，
//! 那时不存在任何读者。刻意不做"永不释放"：那会在带泄漏检测的分配器下变成一堆噪音，
//! 掩盖真正的泄漏。

const std = @import("std");
const builtin = @import("builtin");

const backend = @import("../backend/mod.zig");
const foundation = @import("../foundation/mod.zig");

const GatewayConfig = foundation.config.GatewayConfig;
/// 配置树里的后端实例地址（`host` 是普通切片），与 `backend.direct.Endpoint`
/// （`host` 带 0 结尾，picoquic 要）不是同一个类型，所以追加时要 dupeSentinel 一次。
const RawEndpoint = GatewayConfig.Direct.Route.Endpoint;

pub const Error = error{
    /// 已登记的 realm 在新配置里换了编号。
    RealmChanged,
    /// 已登记的 realm 在新配置里不见了。
    RealmRemoved,
    /// 已登记的路由在新配置里换了后端地址。
    RouteChanged,
    /// 已登记的路由在新配置里不见了。
    RouteRemoved,
};

/// 一次热加载的结果。
pub const Summary = struct {
    realms_added: usize = 0,
    routes_added: usize = 0,
};

pub const Reloader = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    /// 配置文件路径；借用调用方（`app.serve` 的参数）的内存。
    path: []const u8,
    /// SNI → realm 解析表；本模块是它唯一的写者。
    realms: *foundation.realm.Table,
    /// 直连路由目录；本模块是它唯一的写者。
    routes: *backend.RouteCatalog,

    /// 被两张表借用、由本模块持有的内存（见文件头"内存"一节）。
    ///
    /// host 单独一份列表：它是 `dupeSentinel` 出来的 `[:0]u8`（picoquic 要 0 结尾），
    /// 实际分配长度比 `len` 多一个字节。当成 `[]u8` 释放会按错误的长度归还——分配器
    /// 会当场报 "Invalid free"。
    owned_strings: std.ArrayList([]u8),
    owned_hosts: std.ArrayList([:0]u8),
    owned_endpoints: std.ArrayList([]backend.direct.Endpoint),

    /// 停机标志；由 `shutdown` 置位后用一次自发的 SIGHUP 把等待中的线程叫醒。
    stop: std.atomic.Value(bool) = .init(false),

    pub fn init(
        io: std.Io,
        allocator: std.mem.Allocator,
        path: []const u8,
        realms: *foundation.realm.Table,
        routes: *backend.RouteCatalog,
    ) Reloader {
        return .{
            .io = io,
            .allocator = allocator,
            .path = path,
            .realms = realms,
            .routes = routes,
            .owned_strings = .{ .items = &.{}, .capacity = 0 },
            .owned_hosts = .{ .items = &.{}, .capacity = 0 },
            .owned_endpoints = .{ .items = &.{}, .capacity = 0 },
        };
    }

    /// 释放热加载期间分配的内存。**必须在所有 Worker 停止之后调用。**
    pub fn deinit(self: *Reloader) void {
        for (self.owned_endpoints.items) |list| self.allocator.free(list);
        self.owned_endpoints.deinit(self.allocator);
        for (self.owned_hosts.items) |host| self.allocator.free(host);
        self.owned_hosts.deinit(self.allocator);
        for (self.owned_strings.items) |bytes| self.allocator.free(bytes);
        self.owned_strings.deinit(self.allocator);
    }

    /// 重读配置文件并把新增的 realm 与路由追加进两张表。
    ///
    /// 全有或全无：先把整份新配置与当前状态比对完，确认只有新增，才开始追加。
    pub fn apply(self: *Reloader) !Summary {
        var loaded = try foundation.config.load(self.io, self.allocator, self.path);
        defer loaded.deinit(self.allocator);
        const config = loaded.parsed.value;

        try self.checkRealms(config);
        try self.checkRoutes(config);

        var summary: Summary = .{};
        for (config.realms) |raw| {
            if (self.findRealm(raw.server_name) != null) continue;
            const sni = try self.own(raw.server_name);
            try self.realms.register(sni, raw.id);
            summary.realms_added += 1;
            std.log.info("[RELOAD] realm registered: id={} name={s}", .{ raw.id, raw.server_name });
        }
        for (config.backend.direct.routes) |raw| {
            const scope = backend.ScopedRoute.init(raw.realm, raw.group, raw.route_key);
            if (self.routes.find(scope) != null) continue;
            const endpoints = try self.ownEndpoints(raw.endpoints);
            try self.routes.register(.{ .route = scope, .endpoints = endpoints });
            summary.routes_added += 1;
            std.log.info("[RELOAD] route registered: realm={} group=0x{x} route=0x{x} replicas={}", .{
                raw.realm,
                raw.group,
                raw.route_key,
                endpoints.len,
            });
        }
        return summary;
    }

    // ------------------------------------------------------------------------
    // 比对：只允许新增
    // ------------------------------------------------------------------------

    fn checkRealms(self: *Reloader, config: GatewayConfig) Error!void {
        for (config.realms) |raw| {
            const existing = self.findRealm(raw.server_name) orelse continue;
            if (existing != raw.id) {
                std.log.warn("[RELOAD] refusing: realm '{s}' changed id {} -> {}", .{ raw.server_name, existing, raw.id });
                return Error.RealmChanged;
            }
        }
        for (self.realms.entries()) |entry| {
            for (config.realms) |raw| {
                if (std.ascii.eqlIgnoreCase(entry.sni, raw.server_name)) break;
            } else {
                std.log.warn("[RELOAD] refusing: realm '{s}' is missing from the new config (removal is not supported)", .{entry.sni});
                return Error.RealmRemoved;
            }
        }
    }

    fn checkRoutes(self: *Reloader, config: GatewayConfig) Error!void {
        for (config.backend.direct.routes) |raw| {
            const scope = backend.ScopedRoute.init(raw.realm, raw.group, raw.route_key);
            const existing = self.routes.find(scope) orelse continue;
            if (!sameEndpoints(existing.endpoints, raw.endpoints)) {
                std.log.warn("[RELOAD] refusing: route realm={} group=0x{x} route=0x{x} changed its endpoints", .{
                    raw.realm,
                    raw.group,
                    raw.route_key,
                });
                return Error.RouteChanged;
            }
        }
        for (self.routes.entries()) |entry| {
            for (config.backend.direct.routes) |raw| {
                const scope = backend.ScopedRoute.init(raw.realm, raw.group, raw.route_key);
                if (@as(u32, @bitCast(entry.route)) == @as(u32, @bitCast(scope))) break;
            } else {
                std.log.warn("[RELOAD] refusing: route realm={} group=0x{x} route=0x{x} is missing from the new config (removal is not supported)", .{
                    entry.route.realm,
                    entry.route.route.group,
                    entry.route.route.route_key,
                });
                return Error.RouteRemoved;
            }
        }
    }

    fn findRealm(self: *Reloader, name: []const u8) ?foundation.realm.RealmId {
        for (self.realms.entries()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.sni, name)) return entry.realm;
        }
        return null;
    }

    fn sameEndpoints(current: []const backend.direct.Endpoint, incoming: []const RawEndpoint) bool {
        if (current.len != incoming.len) return false;
        for (current, incoming) |a, b| {
            if (a.port != b.port) return false;
            if (!std.mem.eql(u8, a.host, b.host)) return false;
        }
        return true;
    }

    // ------------------------------------------------------------------------
    // 内存接管
    // ------------------------------------------------------------------------

    fn own(self: *Reloader, text: []const u8) ![]const u8 {
        const copy = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(copy);
        try self.owned_strings.append(self.allocator, copy);
        return copy;
    }

    fn ownEndpoints(self: *Reloader, incoming: []const RawEndpoint) ![]backend.direct.Endpoint {
        const list = try self.allocator.alloc(backend.direct.Endpoint, incoming.len);
        errdefer self.allocator.free(list);
        // 先把数组挂进 owned 再填内容：填到一半失败时，已经 dupe 出来的 host
        // 也已经各自挂在 owned_strings 上，deinit 一样能收干净。
        try self.owned_endpoints.append(self.allocator, list);
        for (incoming, list) |raw, *endpoint| {
            const host = try self.allocator.dupeSentinel(u8, raw.host, 0);
            errdefer self.allocator.free(host);
            try self.owned_hosts.append(self.allocator, host);
            endpoint.* = .{ .host = host, .port = raw.port };
        }
        return list;
    }
};

// ============================================================================
// 信号线程
// ============================================================================

/// 屏蔽 SIGHUP。**必须在拉起任何线程之前调用**：屏蔽字由后续线程继承，
/// 漏掉这一步就会有别的线程抢到这个信号并按默认动作终止进程。
pub fn blockSignal() void {
    if (builtin.os.tag == .windows) return;
    var set = std.posix.sigemptyset();
    std.posix.sigaddset(&set, std.posix.SIG.HUP);
    std.posix.sigprocmask(std.posix.SIG.BLOCK, &set, null);
}

/// 起一条专职线程等 SIGHUP。
pub fn spawn(reloader: *Reloader) !std.Thread {
    return std.Thread.spawn(.{}, waitLoop, .{reloader});
}

/// 置停机标志并把等待中的线程叫醒，然后 join。
///
/// 用 `kill(getpid())` 而不是 `raise()`：`raise` 把信号投给**当前**线程，而当前线程
/// 正屏蔽着它，信号会一直挂在这条线程上，等待中的那条永远收不到。进程定向的信号在
/// 所有线程都屏蔽时进入进程级待决队列，正是 `sigwait` 能取到的那一份。
pub fn shutdown(reloader: *Reloader, thread: std.Thread) void {
    reloader.stop.store(true, .release);
    if (builtin.os.tag != .windows) {
        std.posix.kill(std.c.getpid(), std.posix.SIG.HUP) catch {};
    }
    thread.join();
}

fn waitLoop(reloader: *Reloader) void {
    if (builtin.os.tag == .windows) return;
    var set = std.posix.sigemptyset();
    std.posix.sigaddset(&set, std.posix.SIG.HUP);

    while (true) {
        var sig: c_int = 0;
        if (std.c.sigwait(&set, &sig) != 0) continue;
        if (reloader.stop.load(.acquire)) return;

        const summary = reloader.apply() catch |err| {
            // 热加载失败不影响运行中的服务：两张表一个字节都没动。
            std.log.err("[RELOAD] configuration reload failed: {s}", .{@errorName(err)});
            continue;
        };
        std.log.info("[RELOAD] applied: {} realm(s), {} route(s) added", .{ summary.realms_added, summary.routes_added });
    }
}

// ============================================================================
// 测试
// ============================================================================

test "only additions are accepted" {
    var realm_slots: [4]foundation.realm.Table.Entry = @splat(.{});
    realm_slots[0] = .{ .sni = "a.gw.example.com", .realm = 1 };
    var realms = foundation.realm.Table{ .slots = &realm_slots, .len = .init(1), .fallback = null };

    var route_slots: [4]backend.RouteEntry = @splat(.{});
    const endpoints = [_]backend.direct.Endpoint{.{ .host = "10.0.0.1", .port = 9000 }};
    route_slots[0] = .{ .route = backend.ScopedRoute.init(1, 1, 0), .endpoints = &endpoints };
    var routes = backend.RouteCatalog{ .slots = &route_slots, .len = .init(1) };

    var reloader = Reloader.init(std.testing.io, std.testing.allocator, "unused", &realms, &routes);
    defer reloader.deinit();

    var config = GatewayConfig{
        .runtime = .{ .threads = 1 },
        .server = .{
            .listen_host = "127.0.0.1",
            .listen_port = 8443,
            .certificate_file = "c",
            .private_key_file = "k",
            .quic = .{ .max_connections = 1, .idle_timeout_ms = 1000, .alpn = "lyune/1", .congestion_control = "bbr" },
        },
        .backend = .{ .direct = .{
            .routes = &.{},
            .verify_certificate = false,
            .root_certificate_file = null,
            .max_receive_queue = 1,
            .idle_timeout_ms = 1000,
            .alpn = "lyune/1",
            .congestion_control = "bbr",
        } },
        .worker = .{ .backend_poll_interval_ms = 10 },
        .cluster = .{
            .node_id = 1,
            .advertise_host = "127.0.0.1",
            .advertise_port = 7946,
            .handoff_queue_capacity = 16,
        },
        .realms = &.{},
    };

    // 少了已登记的 realm：整次拒绝。运维不能靠删文件里的条目来清理。
    config.realms = &.{};
    config.backend.direct.routes = &.{
        .{ .realm = 1, .group = 1, .route_key = 0, .endpoints = &.{.{ .host = "10.0.0.1", .port = 9000 }} },
    };
    try std.testing.expectError(Error.RealmRemoved, reloader.checkRealms(config));

    // 换了 id：等于把现有连接的命名空间悄悄重新划分。
    config.realms = &.{.{ .server_name = "a.gw.example.com", .id = 2 }};
    try std.testing.expectError(Error.RealmChanged, reloader.checkRealms(config));

    // 原样保留 + 新增一个：通过。
    config.realms = &.{
        .{ .server_name = "a.gw.example.com", .id = 1 },
        .{ .server_name = "b.gw.example.com", .id = 2 },
    };
    try reloader.checkRealms(config);

    // 路由换了后端地址：在途交换的后半段会发给另一个后端。
    config.backend.direct.routes = &.{
        .{ .realm = 1, .group = 1, .route_key = 0, .endpoints = &.{.{ .host = "10.0.0.2", .port = 9000 }} },
    };
    try std.testing.expectError(Error.RouteChanged, reloader.checkRoutes(config));

    // 路由不见了：同样整次拒绝。
    config.backend.direct.routes = &.{};
    try std.testing.expectError(Error.RouteRemoved, reloader.checkRoutes(config));
}

test "owned memory is released even for a partially built route" {
    // testing.allocator 会在泄漏时让本用例失败：这条钉住的是"表只借用、Reloader 持有"
    // 这个约定——漏一条就是进程生命周期的泄漏，而它只在长期运行后才显形。
    var realm_slots: [4]foundation.realm.Table.Entry = @splat(.{});
    var realms = foundation.realm.Table{ .slots = &realm_slots, .len = .init(0), .fallback = null };
    var route_slots: [4]backend.RouteEntry = @splat(.{});
    var routes = backend.RouteCatalog{ .slots = &route_slots, .len = .init(0) };

    var reloader = Reloader.init(std.testing.io, std.testing.allocator, "unused", &realms, &routes);
    defer reloader.deinit();

    const sni = try reloader.own("c.gw.example.com");
    try realms.register(sni, 3);
    const endpoints = try reloader.ownEndpoints(&.{
        .{ .host = "10.0.0.3", .port = 9001 },
        .{ .host = "10.0.0.4", .port = 9002 },
    });
    try routes.register(.{ .route = backend.ScopedRoute.init(3, 1, 0), .endpoints = endpoints });

    try std.testing.expectEqual(@as(foundation.realm.RealmId, 3), realms.resolve("c.gw.example.com").?);
    try std.testing.expectEqual(@as(usize, 2), routes.find(backend.ScopedRoute.init(3, 1, 0)).?.endpoints.len);
}
