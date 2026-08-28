//! 在途请求表
//!
//! 网关把客户端请求转给后端之后，必须记住"后端这条流的响应该写回哪个客户端流"。
//! 本模块拥有这份映射，以及已委托给认证服务、等待回包的认证请求。
//!
//! ## 为什么独立成模块
//!
//! 这两张表是两条无界内存增长的防线，而它们的回收路径有三条：
//!   1. 正常路径——后端响应带 fin 时删除；
//!   2. 连接关闭——客户端走了，属于它的条目必须全清，否则回程会拿到野指针；
//!   3. 超时兜底——后端不回包、只回一半、或 fin 丢失时，条目只能靠时间回收。
//!
//! 任何一条漏掉都不会立刻报错，而是慢慢涨到 OOM 或在生产上偶发野指针。
//! 把状态与三条回收路径放在同一个模块里，这些不变量才能被单独测试，
//! 而不是只能靠"整个 Worker 跑起来"间接验证。
//!
//! ## 为什么 realm 存在条目里
//!
//! 两张表都是每 Worker 定容的共享池，因此都要按 realm 讲公平（设计文档 §12.4）。
//! 而配额的归还要求"知道这一格是谁的"，三条回收路径里有两条跑的时候连接可能已经
//! 从管理器里摘掉了（关闭清理本身就发生在摘除之前，过期兜底更是与连接无关），
//! 反查必然拿不到 realm。所以 realm 随条目一起存，回收时从条目上取。
//!
//! 与之配套：两张表的**删除只有一个出口**（`dropRoute` / `dropAuth`），配额递减贴在
//! 那里。三条回收路径都经由它，就不存在"某条路径忘了还"的可能。

const std = @import("std");

const foundation = @import("../foundation/mod.zig");
const quic = @import("../quic/mod.zig");
const backend = @import("../backend/transport.zig");

const RealmId = foundation.realm.RealmId;

/// 一条后端流的全局唯一键。
///
/// 句柄本身只在单个 transport 实例内部唯一（见 backend/transport.zig 的
/// `BackendTransport.id`）。两张在途表是**全 Worker 共享**的，因此键必须把实例身份
/// 带上：否则两个 transport 发出同一个句柄时，后一次 `openRoute` 会顶掉前一次，
/// 而先到的那条响应会被写进另一个客户端的流——跨路由、跨 realm 的串话。
pub const StreamKey = struct {
    /// `BackendTransport.id()`：发出这个句柄的 transport 实例。
    transport: usize,
    /// 该实例内部的流句柄。
    stream: u64,
};

/// 单个 Worker 允许的在途请求上限（两张表各自计）。
///
/// 没有上限就是一条无界内存增长路径。超限时拒绝新请求并回 gateway_error，
/// 比静默膨胀到 OOM 更可诊断。
pub const max_requests: u32 = 16384;

/// 普通回程映射与认证等待的超时周期（微秒）。
///
/// 普通回程映射按双向应用帧的最后活动时刻计算；认证等待仍按创建时刻计算，
/// 避免恶意认证服务靠零碎响应无限占住 buffer。真正的请求 deadline 仍需要
/// transport 层支持取消，不由这张兜底表表达。
pub const request_timeout_us: u64 = 60 * std.time.us_per_s;

/// 一次批量回收扫描能带走的条目数。
///
/// 用固定数组分批而不是维护反向索引：回收只发生在连接关闭与周期性过期两处，
/// 都是低频路径，用一次全表扫描换热路径零分配是值得的。
const purge_batch: usize = 64;

/// 需要把后端响应写回的客户端流。
pub const ClientResponse = struct {
    cnx: quic.c.QuicCnx,
    stream_id: u64,
};

/// 后端响应的去向。
///
/// `.discard` 用于 `ResponseMode.none`：Gateway 已用空 FIN 结束客户端方向，但仍需
/// 跟踪后端流直到 FIN/失败/超时，避免把合法的收尾误记为孤儿响应，也避免后端流状态
/// 无界增长。它不携带客户端句柄，因此后续失败不会被错误地写回一个已经结束的流。
pub const ResponseTarget = union(enum) {
    client: ClientResponse,
    discard,
};

/// 后端流 -> 响应去向的回程映射。
pub const Route = struct {
    target: ResponseTarget,
    /// 发起这条请求的连接所属 realm；配额归还时从这里取（见文件开头）。
    realm: RealmId,
    /// 最近一次成功转发完整应用帧的时刻（微秒）。客户端上行和后端下行都会刷新；
    /// 后端不回包、双方都停止活动或 fin 丢失时，条目最终由空闲超时回收。
    last_active_at: u64,
};

/// 超时摘出的普通请求。key 仍需保留：Worker 用它找到 transport，并按后端流句柄
/// 精确淘汰无响应的连接；Route 则决定是否以及向哪个客户端回错。
pub const ExpiredRoute = struct {
    key: StreamKey,
    route: Route,
};

/// 已转发给认证服务、等待回包的认证请求。
pub const PendingAuth = struct {
    client_cnx: quic.c.QuicCnx,
    client_stream_id: u64,
    /// 发起这次认证的连接所属 realm；配额归还时从这里取。
    realm: RealmId,
    /// 累积认证服务的响应分片，收到 fin 后整体解码。
    buffer: std.ArrayList(u8),
    /// 创建时刻（微秒），用于兜底过期。
    created_at: u64,
    /// 客户端发来 STOP_SENDING 后仍要消费认证结果并完成准入状态变更，但不能再向
    /// 那条流写响应。把它留在等待项里可避免把合法后端收尾误记为孤儿响应。
    response_suppressed: bool = false,
};

pub const ExpiredAuth = struct {
    key: StreamKey,
    pending: PendingAuth,
};

/// 准入判定结果。
///
/// "表满"与"你超额"分开报，运维才能区分"整机满了"和"这家接入方超了它的公平份额"
/// ——两者的处置完全不同（扩容 vs 找接入方）。
pub const Admit = enum { ok, table_full, realm_over_share };

/// 在途条目的回收条件。
pub const Filter = union(enum) {
    /// 回收属于某个客户端连接的全部条目。
    connection: quic.c.QuicCnx,
    /// 回收活动/创建时刻早于该 deadline 的条目。
    older_than: u64,

    fn matchesAuth(self: Filter, cnx: quic.c.QuicCnx, timestamp: u64) bool {
        return switch (self) {
            .connection => |target| cnx == target,
            .older_than => |deadline| timestamp < deadline,
        };
    }

    fn matchesRoute(self: Filter, route: Route) bool {
        return switch (self) {
            .connection => |target| switch (route.target) {
                .client => |client| client.cnx == target,
                .discard => false,
            },
            .older_than => |deadline| route.last_active_at < deadline,
        };
    }
};

/// 两张在途表及其回收逻辑。
///
/// 线程私有：每个 Worker 一份，只由本 Worker 的事件循环线程访问，因此不加锁。
pub const Tables = struct {
    allocator: std.mem.Allocator,
    routes: std.AutoHashMap(StreamKey, Route),
    auths: std.AutoHashMap(StreamKey, PendingAuth),
    /// 回程映射的按 realm 公平上限（见 foundation/quota.zig）。
    ///
    /// 少了它，一个吵闹的接入方能把 `max_requests` 吃干，其他所有接入方的请求
    /// 一起被拒——而它们的后端明明是空闲的。
    route_quota: foundation.quota.Quota,
    /// 认证等待表的按 realm 公平上限。
    ///
    /// 这个池更值得单独限：认证是连接建立的必经一步，被它挡住的表现是
    /// "整个 realm 谁都登录不上"。
    auth_quota: foundation.quota.Quota,
    /// 当前已知的最早过期时刻。它可能因为条目被刷新或提前删除而偏早，但绝不偏晚：
    /// 到点扫描后重新计算即可。这样既不会每个 backend poll 都扫全表，也不会因固定
    /// 扫描相位把 60 秒超时放大到接近 120 秒。
    next_expiry_at: ?u64 = null,

    pub fn init(allocator: std.mem.Allocator) foundation.quota.Error!Tables {
        var route_quota = try foundation.quota.Quota.init(
            allocator,
            foundation.quota.max_tracked_realms,
            max_requests,
            foundation.quota.default_watermark_percent,
        );
        errdefer route_quota.deinit(allocator);

        var auth_quota = try foundation.quota.Quota.init(
            allocator,
            foundation.quota.max_tracked_realms,
            max_requests,
            foundation.quota.default_watermark_percent,
        );
        errdefer auth_quota.deinit(allocator);

        return .{
            .allocator = allocator,
            .routes = std.AutoHashMap(StreamKey, Route).init(allocator),
            .auths = std.AutoHashMap(StreamKey, PendingAuth).init(allocator),
            .route_quota = route_quota,
            .auth_quota = auth_quota,
        };
    }

    /// 释放两张表。
    ///
    /// auths 的每个 value 里都有独立分配的 buffer，HashMap.deinit 不会替你释放，
    /// 必须先逐个 deinit。配额计数不必逐个归还——整块计数数组随即释放。
    pub fn deinit(self: *Tables) void {
        var it = self.auths.valueIterator();
        while (it.next()) |pending| pending.buffer.deinit(self.allocator);
        self.auths.deinit();
        self.routes.deinit();
        self.route_quota.deinit(self.allocator);
        self.auth_quota.deinit(self.allocator);
    }

    // ========================================================================
    // 回程映射
    // ========================================================================

    /// 这个 realm 现在能否再登记一条回程映射。过期项由 Worker 的统一过期路径摘出并
    /// 给客户端明确回错；这里不能为了腾位置静默删除，否则旧请求会一直等到自身 deadline。
    pub fn reserveRoute(self: *Tables, realm: RealmId, now: u64) Admit {
        _ = now;
        if (self.routes.count() >= max_requests) return .table_full;
        if (!self.route_quota.allows(realm)) return .realm_over_share;
        return .ok;
    }

    /// 登记一条回程映射。调用前应先用 reserveRoute 确认还有配额。
    pub fn openRoute(self: *Tables, key: StreamKey, route: Route) !void {
        const entry = try self.routes.getOrPut(key);
        // 键复用不是纯理论：句柄只在单个 transport 实例内唯一，而实例在后端重连后
        // 会从头发号。直接覆盖旧条目就等于悄悄丢掉一次归还——那正是"配额被永久蚕食"
        // 的成因，而且症状要几天后才显现。
        if (entry.found_existing) self.route_quota.release(entry.value_ptr.realm);
        entry.value_ptr.* = route;
        self.route_quota.acquire(route.realm);
        self.noteExpiry(route.last_active_at);
    }

    pub fn lookupRoute(self: *const Tables, key: StreamKey) ?Route {
        return self.routes.get(key);
    }

    /// 刷新普通回程映射的空闲时钟。返回 false 表示映射已经被其他回收路径删除。
    ///
    /// Tables 是 Worker 线程私有的，因此更新 value 不需要锁；调用方只在接纳完整
    /// 上行帧或成功写回完整下行事件时刷新，残帧与纯 QUIC keepalive 不能续命。
    pub fn touchRoute(self: *Tables, key: StreamKey, now: u64) bool {
        const route = self.routes.getPtr(key) orelse return false;
        route.last_active_at = now;
        return true;
    }

    pub fn closeRoute(self: *Tables, key: StreamKey) void {
        self.dropRoute(key);
    }

    /// 客户端不再接收某条流的返回方向时，把目标原地降级为 discard。
    ///
    /// 不删除映射：后端请求仍可能已经完整提交，后续 FIN/失败仍需有正常回收路径。
    /// 这是低频控制事件，O(n) 扫描换取热路径不维护第二张反向索引。
    pub fn suppressClientResponse(self: *Tables, cnx: quic.c.QuicCnx, stream_id: u64) bool {
        var it = self.routes.valueIterator();
        while (it.next()) |route| switch (route.target) {
            .client => |client| {
                if (client.cnx != cnx or client.stream_id != stream_id) continue;
                route.target = .discard;
                return true;
            },
            .discard => {},
        };
        return false;
    }

    pub fn routeCount(self: *const Tables) u32 {
        return self.routes.count();
    }

    // ========================================================================
    // 认证等待表
    // ========================================================================

    /// 这个 realm 现在能否再登记一条等待中的认证。理由同 reserveRoute：真正过期由
    /// Worker 回 auth_failure，容量判定不能把它静默吞掉。
    pub fn reserveAuth(self: *Tables, realm: RealmId, now: u64) Admit {
        _ = now;
        if (self.auths.count() >= max_requests) return .table_full;
        if (!self.auth_quota.allows(realm)) return .realm_over_share;
        return .ok;
    }

    /// 登记一条等待中的认证请求，接管其 buffer 的所有权。
    pub fn trackAuth(self: *Tables, key: StreamKey, pending: PendingAuth) !void {
        const entry = try self.auths.getOrPut(key);
        // 覆盖旧条目会同时漏掉一次 buffer 释放和一次配额归还，理由同 openRoute。
        if (entry.found_existing) {
            entry.value_ptr.buffer.deinit(self.allocator);
            self.auth_quota.release(entry.value_ptr.realm);
        }
        entry.value_ptr.* = pending;
        self.auth_quota.acquire(pending.realm);
        self.noteExpiry(pending.created_at);
    }

    pub fn hasAuth(self: *const Tables, key: StreamKey) bool {
        return self.auths.contains(key);
    }

    /// 取可写引用，用于往 buffer 里累积响应分片。
    pub fn authPtr(self: *Tables, key: StreamKey) ?*PendingAuth {
        return self.auths.getPtr(key);
    }

    /// 摘出条目并转移 buffer 所有权：调用方负责 deinit 它。
    pub fn takeAuth(self: *Tables, key: StreamKey) ?PendingAuth {
        return self.dropAuth(key);
    }

    pub fn authCount(self: *const Tables) u32 {
        return self.auths.count();
    }

    /// 认证请求已经交给后端时，STOP_SENDING 只取消返回方向，不撤销请求副作用。
    /// 后端结果仍会更新连接准入状态；completeAuth 根据该位跳过流写入。
    pub fn suppressAuthResponse(self: *Tables, cnx: quic.c.QuicCnx, stream_id: u64) bool {
        var it = self.auths.valueIterator();
        while (it.next()) |pending| {
            if (pending.client_cnx != cnx or pending.client_stream_id != stream_id) continue;
            pending.response_suppressed = true;
            return true;
        }
        return false;
    }

    // ========================================================================
    // 后端故障回收
    // ========================================================================

    /// 摘出一次后端故障影响的普通回程映射，所有权转移到 out。
    ///
    /// 固定批量接口让 Worker 可以一边回错客户端一边继续扫描，故障路径零分配。
    pub fn takeFailedRoutes(
        self: *Tables,
        transport_id: usize,
        selector: backend.StreamSelector,
        out: []Route,
    ) usize {
        var keys: [purge_batch]StreamKey = undefined;
        const limit = @min(keys.len, out.len);
        if (limit == 0) return 0;

        var count: usize = 0;
        var it = self.routes.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            if (key.transport != transport_id or !selector.matches(key.stream)) continue;
            keys[count] = key;
            count += 1;
            if (count == limit) break;
        }
        for (keys[0..count], 0..) |key, index| out[index] = self.takeRoute(key).?;
        return count;
    }

    /// 摘出一次后端故障影响的认证等待，buffer 所有权转移到 out。
    pub fn takeFailedAuths(
        self: *Tables,
        transport_id: usize,
        selector: backend.StreamSelector,
        out: []PendingAuth,
    ) usize {
        var keys: [purge_batch]StreamKey = undefined;
        const limit = @min(keys.len, out.len);
        if (limit == 0) return 0;

        var count: usize = 0;
        var it = self.auths.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            if (key.transport != transport_id or !selector.matches(key.stream)) continue;
            keys[count] = key;
            count += 1;
            if (count == limit) break;
        }
        for (keys[0..count], 0..) |key, index| out[index] = self.dropAuth(key).?;
        return count;
    }

    // ========================================================================
    // 有界且可见的超时回收
    // ========================================================================

    fn noteExpiry(self: *Tables, timestamp: u64) void {
        const deadline = timestamp +| request_timeout_us;
        if (self.next_expiry_at == null or deadline < self.next_expiry_at.?) {
            self.next_expiry_at = deadline;
        }
    }

    /// 最早已知 deadline 到达才需要扫表。next_expiry_at 允许偏早，因此 true 只表示
    /// “应当扫描并重算”，不保证一定能摘到条目。
    pub fn expirationDue(self: *const Tables, now: u64) bool {
        return if (self.next_expiry_at) |deadline| now >= deadline else false;
    }

    /// 摘出空闲达到 request_timeout_us 的普通请求。调用方拥有返回的 Route，并负责向
    /// client 目标回明确错误；discard 目标只需回收。
    pub fn takeExpiredRoutes(self: *Tables, now: u64, out: []ExpiredRoute) usize {
        var keys: [purge_batch]StreamKey = undefined;
        const limit = @min(keys.len, out.len);
        if (limit == 0) return 0;

        var count: usize = 0;
        var it = self.routes.iterator();
        while (it.next()) |entry| {
            if (now -| entry.value_ptr.last_active_at < request_timeout_us) continue;
            keys[count] = entry.key_ptr.*;
            count += 1;
            if (count == limit) break;
        }
        for (keys[0..count], 0..) |key, index| {
            out[index] = .{ .key = key, .route = self.takeRoute(key).? };
        }
        return count;
    }

    /// 摘出达到绝对认证 deadline 的等待项；buffer 所有权随条目转移给调用方。
    pub fn takeExpiredAuths(self: *Tables, now: u64, out: []ExpiredAuth) usize {
        var keys: [purge_batch]StreamKey = undefined;
        const limit = @min(keys.len, out.len);
        if (limit == 0) return 0;

        var count: usize = 0;
        var it = self.auths.iterator();
        while (it.next()) |entry| {
            if (now -| entry.value_ptr.created_at < request_timeout_us) continue;
            keys[count] = entry.key_ptr.*;
            count += 1;
            if (count == limit) break;
        }
        for (keys[0..count], 0..) |key, index| {
            out[index] = .{ .key = key, .pending = self.dropAuth(key).? };
        }
        return count;
    }

    /// 一次到期扫描完成后重新计算最早 deadline。刷新/提前删除只会让旧提示偏早，
    /// 因而无须在热路径维护堆或反向索引；这次 O(n) 扫描只发生在真实 deadline 到点时。
    pub fn refreshExpiryDeadline(self: *Tables) void {
        self.next_expiry_at = null;
        var routes = self.routes.valueIterator();
        while (routes.next()) |route| self.noteExpiry(route.last_active_at);
        var auths = self.auths.valueIterator();
        while (auths.next()) |pending| self.noteExpiry(pending.created_at);
    }

    // ========================================================================
    // 回收
    // ========================================================================

    /// routes 的唯一删除出口；配额递减贴在这里，三条回收路径都经由它。
    fn takeRoute(self: *Tables, key: StreamKey) ?Route {
        const removed = self.routes.fetchRemove(key) orelse return null;
        self.route_quota.release(removed.value.realm);
        return removed.value;
    }

    fn dropRoute(self: *Tables, key: StreamKey) void {
        _ = self.takeRoute(key);
    }

    /// auths 的唯一删除出口。返回摘出的条目，buffer 所有权随之转移给调用方。
    fn dropAuth(self: *Tables, key: StreamKey) ?PendingAuth {
        const removed = self.auths.fetchRemove(key) orelse return null;
        self.auth_quota.release(removed.value.realm);
        return removed.value;
    }

    /// 按给定条件回收两张表里的条目。
    pub fn purge(self: *Tables, filter: Filter) void {
        var keys: [purge_batch]StreamKey = undefined;

        while (true) {
            var count: usize = 0;
            var it = self.routes.iterator();
            while (it.next()) |entry| {
                if (!filter.matchesRoute(entry.value_ptr.*)) continue;
                keys[count] = entry.key_ptr.*;
                count += 1;
                if (count == keys.len) break;
            }
            for (keys[0..count]) |key| self.dropRoute(key);
            if (count < keys.len) break;
        }

        while (true) {
            var count: usize = 0;
            var it = self.auths.iterator();
            while (it.next()) |entry| {
                if (!filter.matchesAuth(entry.value_ptr.client_cnx, entry.value_ptr.created_at)) continue;
                keys[count] = entry.key_ptr.*;
                count += 1;
                if (count == keys.len) break;
            }
            for (keys[0..count]) |key| {
                if (self.dropAuth(key)) |removed| {
                    var buffer = removed.buffer;
                    buffer.deinit(self.allocator);
                }
            }
            if (count < keys.len) break;
        }
    }
};

// ============================================================================
// 测试
// ============================================================================

fn fakeCnx(addr: usize) quic.c.QuicCnx {
    return @ptrFromInt(addr);
}

/// 测试里的默认 transport 身份；只有跨 transport 隔离的用例才换成别的。
const test_transport: usize = 0xA000;

fn streamKey(stream: u64) StreamKey {
    return .{ .transport = test_transport, .stream = stream };
}

fn clientRoute(cnx: quic.c.QuicCnx, stream_id: u64, realm: RealmId, last_active_at: u64) Route {
    return .{
        .target = .{ .client = .{ .cnx = cnx, .stream_id = stream_id } },
        .realm = realm,
        .last_active_at = last_active_at,
    };
}

fn routeClient(route: Route) ClientResponse {
    return switch (route.target) {
        .client => |client| client,
        .discard => unreachable,
    };
}

test "route lifecycle: open, lookup, close" {
    var tables = try Tables.init(std.testing.allocator);
    defer tables.deinit();

    const cnx = fakeCnx(0x1000);
    try tables.openRoute(streamKey(7), clientRoute(cnx, 4, 1, 100));

    const found = tables.lookupRoute(streamKey(7)).?;
    try std.testing.expectEqual(@as(u64, 4), routeClient(found).stream_id);
    try std.testing.expectEqual(@as(u32, 1), tables.routeCount());

    tables.closeRoute(streamKey(7));
    try std.testing.expect(tables.lookupRoute(streamKey(7)) == null);
    try std.testing.expectEqual(@as(u32, 0), tables.routeCount());
}

test "the same handle from two transports is two different entries" {
    // 关键回归：句柄只在单个 transport 内部唯一，两个实例都从同样的编号开始发号。
    // 键里漏掉实例身份时，后一次登记会顶掉前一次，A 的响应就被写进 B 的客户端流。
    var tables = try Tables.init(std.testing.allocator);
    defer tables.deinit();

    const client_a = fakeCnx(0x1000);
    const client_b = fakeCnx(0x2000);
    const from_a = StreamKey{ .transport = 0xA000, .stream = 4 };
    const from_b = StreamKey{ .transport = 0xB000, .stream = 4 };

    try tables.openRoute(from_a, clientRoute(client_a, 1, 1, 10));
    try tables.openRoute(from_b, clientRoute(client_b, 2, 2, 10));

    try std.testing.expectEqual(@as(u32, 2), tables.routeCount());
    try std.testing.expectEqual(client_a, routeClient(tables.lookupRoute(from_a).?).cnx);
    try std.testing.expectEqual(client_b, routeClient(tables.lookupRoute(from_b).?).cnx);

    // 关掉一个不影响另一个。
    tables.closeRoute(from_a);
    try std.testing.expect(tables.lookupRoute(from_a) == null);
    try std.testing.expect(tables.lookupRoute(from_b) != null);
}

test "backend failure takes only streams in its transport and selector" {
    var tables = try Tables.init(std.testing.allocator);
    defer tables.deinit();

    const transport_a: usize = 0xA000;
    const transport_b: usize = 0xB000;
    const conn_1 = @as(u64, 1) << 48;
    const conn_2 = @as(u64, 2) << 48;
    const client = fakeCnx(0x1000);

    try tables.openRoute(.{ .transport = transport_a, .stream = conn_1 | 4 }, clientRoute(client, 4, 1, 10));
    try tables.openRoute(.{ .transport = transport_a, .stream = conn_2 | 8 }, clientRoute(client, 8, 1, 10));
    try tables.openRoute(.{ .transport = transport_b, .stream = conn_1 | 4 }, clientRoute(client, 12, 2, 10));
    try tables.trackAuth(.{ .transport = transport_a, .stream = conn_1 | 12 }, .{
        .client_cnx = client,
        .client_stream_id = 16,
        .realm = 1,
        .buffer = .{ .items = &.{}, .capacity = 0 },
        .created_at = 10,
    });

    const selector = backend.StreamSelector{
        .mask = @as(u64, std.math.maxInt(u16)) << 48,
        .value = conn_1,
    };
    var routes: [4]Route = undefined;
    try std.testing.expectEqual(@as(usize, 1), tables.takeFailedRoutes(transport_a, selector, &routes));
    try std.testing.expectEqual(@as(u64, 4), routeClient(routes[0]).stream_id);

    var auths: [4]PendingAuth = undefined;
    try std.testing.expectEqual(@as(usize, 1), tables.takeFailedAuths(transport_a, selector, &auths));
    auths[0].buffer.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 2), tables.routeCount());
    try std.testing.expect(tables.lookupRoute(.{ .transport = transport_a, .stream = conn_2 | 8 }) != null);
    try std.testing.expect(tables.lookupRoute(.{ .transport = transport_b, .stream = conn_1 | 4 }) != null);
    try std.testing.expectEqual(@as(u32, 0), tables.authCount());
    try std.testing.expectEqual(@as(usize, 2), tables.route_quota.total);
    try std.testing.expectEqual(@as(usize, 0), tables.auth_quota.total);
}

// 连接关闭必须清空属于它的全部条目。
//
// 漏掉一条就意味着后端响应到达时 lookupRoute 返回一个已被 picoquic 释放的
// cnx 指针，随后被交给 picoquic_add_to_stream——生产上表现为随机崩溃。
test "purge by connection removes only that connection's entries" {
    var tables = try Tables.init(std.testing.allocator);
    defer tables.deinit();

    const doomed = fakeCnx(0x1000);
    const survivor = fakeCnx(0x2000);

    try tables.openRoute(streamKey(1), clientRoute(doomed, 0, 1, 10));
    try tables.openRoute(streamKey(2), clientRoute(survivor, 0, 1, 10));
    try tables.openRoute(streamKey(3), clientRoute(doomed, 4, 1, 10));
    try tables.trackAuth(streamKey(11), .{
        .client_cnx = doomed,
        .client_stream_id = 8,
        .realm = 1,
        .buffer = .{ .items = &.{}, .capacity = 0 },
        .created_at = 10,
    });
    try tables.trackAuth(streamKey(12), .{
        .client_cnx = survivor,
        .client_stream_id = 8,
        .realm = 1,
        .buffer = .{ .items = &.{}, .capacity = 0 },
        .created_at = 10,
    });

    tables.purge(.{ .connection = doomed });

    try std.testing.expectEqual(@as(u32, 1), tables.routeCount());
    try std.testing.expect(tables.lookupRoute(streamKey(2)) != null);
    try std.testing.expectEqual(@as(u32, 1), tables.authCount());
    try std.testing.expect(tables.hasAuth(streamKey(12)));
}

// 批量扫描以 purge_batch 为单位分批，超过一批时必须继续扫而不是只删一批。
test "purge sweeps more entries than one batch" {
    var tables = try Tables.init(std.testing.allocator);
    defer tables.deinit();

    const cnx = fakeCnx(0x1000);
    const total = purge_batch * 2 + 5;
    var i: u64 = 0;
    while (i < total) : (i += 1) {
        try tables.openRoute(streamKey(i), clientRoute(cnx, i, 1, 10));
    }
    try std.testing.expectEqual(@as(u32, @intCast(total)), tables.routeCount());

    tables.purge(.{ .connection = cnx });
    try std.testing.expectEqual(@as(u32, 0), tables.routeCount());
}

test "purge by age keeps fresh entries" {
    var tables = try Tables.init(std.testing.allocator);
    defer tables.deinit();

    const cnx = fakeCnx(0x1000);
    try tables.openRoute(streamKey(1), clientRoute(cnx, 0, 1, 100));
    try tables.openRoute(streamKey(2), clientRoute(cnx, 1, 1, 900));

    tables.purge(.{ .older_than = 500 });

    try std.testing.expect(tables.lookupRoute(streamKey(1)) == null);
    try std.testing.expect(tables.lookupRoute(streamKey(2)) != null);
}

test "no-response routes outlive the client but still expire" {
    var tables = try Tables.init(std.testing.allocator);
    defer tables.deinit();

    const cnx = fakeCnx(0x1000);
    try tables.openRoute(streamKey(1), .{
        .target = .discard,
        .realm = 1,
        .last_active_at = 100,
    });
    try tables.openRoute(streamKey(2), clientRoute(cnx, 4, 1, 100));

    // 连接关闭只能回收仍然引用该连接的响应路由。no-response 已经没有客户端句柄，
    // 必须留到后端 FIN/失败/超时，否则它的合法收尾会被误报成孤儿响应。
    tables.purge(.{ .connection = cnx });
    try std.testing.expectEqual(@as(u32, 1), tables.routeCount());
    const retained = tables.lookupRoute(streamKey(1)).?;
    try std.testing.expect(retained.target == .discard);

    // 后端永远不收尾时仍受同一空闲超时约束，不能成为无界泄漏。
    tables.purge(.{ .older_than = 500 });
    try std.testing.expectEqual(@as(u32, 0), tables.routeCount());
    try std.testing.expectEqual(@as(usize, 0), tables.route_quota.total);
}

test "backend failure returns discard routes without a client handle" {
    var tables = try Tables.init(std.testing.allocator);
    defer tables.deinit();

    try tables.openRoute(streamKey(7), .{
        .target = .discard,
        .realm = 3,
        .last_active_at = 10,
    });

    var failed: [1]Route = undefined;
    try std.testing.expectEqual(@as(usize, 1), tables.takeFailedRoutes(test_transport, .{}, &failed));
    try std.testing.expect(failed[0].target == .discard);
    try std.testing.expectEqual(@as(u32, 0), tables.routeCount());
    try std.testing.expectEqual(@as(usize, 0), tables.route_quota.total);
}

test "STOP_SENDING suppresses response without losing cleanup state" {
    var tables = try Tables.init(std.testing.allocator);
    defer tables.deinit();

    const cnx = fakeCnx(0x1000);
    try tables.openRoute(streamKey(3), clientRoute(cnx, 8, 1, 100));
    try tables.trackAuth(streamKey(4), .{
        .client_cnx = cnx,
        .client_stream_id = 12,
        .realm = 1,
        .buffer = .{ .items = &.{}, .capacity = 0 },
        .created_at = 100,
    });

    try std.testing.expect(tables.suppressClientResponse(cnx, 8));
    try std.testing.expect(!tables.suppressClientResponse(cnx, 99));
    switch (tables.lookupRoute(streamKey(3)).?.target) {
        .discard => {},
        .client => return error.TestUnexpectedResult,
    }

    try std.testing.expect(tables.suppressAuthResponse(cnx, 12));
    try std.testing.expect(!tables.suppressAuthResponse(cnx, 99));
    try std.testing.expect(tables.authPtr(streamKey(4)).?.response_suppressed);

    // 客户端连接清理不再删除已降级的普通路由，但认证仍属于连接并正常释放。
    tables.purge(.{ .connection = cnx });
    try std.testing.expectEqual(@as(u32, 1), tables.routeCount());
    try std.testing.expectEqual(@as(u32, 0), tables.authCount());
}

test "route activity refreshes idle deadline without extending auth lifetime" {
    var tables = try Tables.init(std.testing.allocator);
    defer tables.deinit();

    const cnx = fakeCnx(0x1000);
    try tables.openRoute(streamKey(1), clientRoute(cnx, 0, 1, 100));
    try tables.trackAuth(streamKey(2), .{
        .client_cnx = cnx,
        .client_stream_id = 4,
        .realm = 1,
        .buffer = .{ .items = &.{}, .capacity = 0 },
        .created_at = 100,
    });

    try std.testing.expect(tables.touchRoute(streamKey(1), 900));
    try std.testing.expectEqual(@as(u64, 900), tables.lookupRoute(streamKey(1)).?.last_active_at);

    // 同一个 cutoff 下，活跃的普通路由存活；认证仍按创建时刻到期。
    tables.purge(.{ .older_than = 500 });
    try std.testing.expect(tables.lookupRoute(streamKey(1)) != null);
    try std.testing.expectEqual(@as(u32, 0), tables.authCount());

    tables.closeRoute(streamKey(1));
    try std.testing.expect(!tables.touchRoute(streamKey(1), 1_000));
}

// 过期调度按最早真实 deadline 触发；不能受固定扫描相位影响而多挂一个周期。
test "expiration follows the earliest real deadline and returns owned entries" {
    var tables = try Tables.init(std.testing.allocator);
    defer tables.deinit();

    const cnx = fakeCnx(0x1000);
    try tables.openRoute(streamKey(1), clientRoute(cnx, 0, 1, 100));
    try tables.trackAuth(streamKey(2), .{
        .client_cnx = cnx,
        .client_stream_id = 4,
        .realm = 1,
        .buffer = .{ .items = &.{}, .capacity = 0 },
        .created_at = 200,
    });

    try std.testing.expect(!tables.expirationDue(100 + request_timeout_us - 1));
    try std.testing.expect(tables.expirationDue(100 + request_timeout_us));

    var routes: [2]ExpiredRoute = undefined;
    var auths: [2]ExpiredAuth = undefined;
    try std.testing.expectEqual(@as(usize, 1), tables.takeExpiredRoutes(100 + request_timeout_us, &routes));
    try std.testing.expectEqual(streamKey(1), routes[0].key);
    try std.testing.expectEqual(@as(u64, 0), routeClient(routes[0].route).stream_id);
    try std.testing.expectEqual(@as(usize, 0), tables.takeExpiredAuths(100 + request_timeout_us, &auths));
    tables.refreshExpiryDeadline();

    try std.testing.expect(!tables.expirationDue(200 + request_timeout_us - 1));
    try std.testing.expect(tables.expirationDue(200 + request_timeout_us));
    try std.testing.expectEqual(@as(usize, 1), tables.takeExpiredAuths(200 + request_timeout_us, &auths));
    try std.testing.expectEqual(streamKey(2), auths[0].key);
    auths[0].pending.buffer.deinit(std.testing.allocator);
    tables.refreshExpiryDeadline();
    try std.testing.expect(tables.next_expiry_at == null);
}

test "route activity can move a stale earliest deadline later" {
    var tables = try Tables.init(std.testing.allocator);
    defer tables.deinit();

    const cnx = fakeCnx(0x1000);
    try tables.openRoute(streamKey(1), clientRoute(cnx, 0, 1, 100));
    try std.testing.expect(tables.touchRoute(streamKey(1), 900));

    // 旧提示允许偏早：扫描摘不到条目后重算到刷新后的 deadline。
    try std.testing.expect(tables.expirationDue(100 + request_timeout_us));
    var routes: [1]ExpiredRoute = undefined;
    try std.testing.expectEqual(@as(usize, 0), tables.takeExpiredRoutes(100 + request_timeout_us, &routes));
    tables.refreshExpiryDeadline();
    try std.testing.expect(!tables.expirationDue(900 + request_timeout_us - 1));
    try std.testing.expect(tables.expirationDue(900 + request_timeout_us));
}

test "auth buffers are freed by take, purge and deinit" {
    var tables = try Tables.init(std.testing.allocator);
    const cnx = fakeCnx(0x1000);

    // 1) takeAuth 转移所有权，由调用方释放。
    var owned: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
    try owned.appendSlice(std.testing.allocator, "taken");
    try tables.trackAuth(streamKey(1), .{ .client_cnx = cnx, .client_stream_id = 0, .realm = 1, .buffer = owned, .created_at = 10 });
    var taken = tables.takeAuth(streamKey(1)).?;
    try std.testing.expectEqualStrings("taken", taken.buffer.items);
    taken.buffer.deinit(std.testing.allocator);

    // 2) purge 自己释放。
    var purged: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
    try purged.appendSlice(std.testing.allocator, "purged");
    try tables.trackAuth(streamKey(2), .{ .client_cnx = cnx, .client_stream_id = 0, .realm = 1, .buffer = purged, .created_at = 10 });
    tables.purge(.{ .connection = cnx });
    try std.testing.expectEqual(@as(u32, 0), tables.authCount());

    // 3) deinit 兜底释放剩下的。testing.allocator 会在泄漏时让本用例失败。
    var leftover: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
    try leftover.appendSlice(std.testing.allocator, "leftover");
    try tables.trackAuth(streamKey(3), .{ .client_cnx = cnx, .client_stream_id = 0, .realm = 1, .buffer = leftover, .created_at = 10 });
    tables.deinit();
}

test "a realm over its fair share is refused while others still get in" {
    var tables = try Tables.init(std.testing.allocator);
    defer tables.deinit();

    const cnx = fakeCnx(0x1000);
    // 水位线以下不讲公平：先把 realm 1 灌到水位线之上，它此刻仍是唯一活跃 realm，
    // 份额 = 全池，所以还放行。
    const above_watermark = max_requests * foundation.quota.default_watermark_percent / 100 + 1;
    var i: u64 = 0;
    while (i < above_watermark) : (i += 1) {
        try std.testing.expectEqual(Admit.ok, tables.reserveRoute(1, 0));
        try tables.openRoute(streamKey(i), clientRoute(cnx, i, 1, 0));
    }

    // realm 2 进来，活跃变 2，份额腰斩。realm 1 已经超了，realm 2 照常放行
    // ——这就是"只拒超额的那个"。
    try std.testing.expectEqual(Admit.ok, tables.reserveRoute(2, 0));
    try tables.openRoute(streamKey(above_watermark), clientRoute(cnx, 0, 2, 0));
    try std.testing.expectEqual(Admit.realm_over_share, tables.reserveRoute(1, 0));
    try std.testing.expectEqual(Admit.ok, tables.reserveRoute(2, 0));
}

test "quota counters return to zero through all three reclaim paths" {
    // 这条钉住的是最难查的那类故障：某条回收路径没归还计数 → 那个 realm 的配额被
    // 永久蚕食 → "这家接入方过几天就连不上了"。三条路径必须逐一覆盖。
    var tables = try Tables.init(std.testing.allocator);
    defer tables.deinit();

    const cnx = fakeCnx(0x1000);
    var round: usize = 0;
    while (round < 3) : (round += 1) {
        var realm: RealmId = 1;
        while (realm <= 4) : (realm += 1) {
            const base = @as(u64, realm) * 100;
            try tables.openRoute(streamKey(base), clientRoute(cnx, 0, realm, 0));
            try tables.openRoute(streamKey(base + 1), clientRoute(cnx, 1, realm, 0));
            try tables.openRoute(streamKey(base + 2), clientRoute(cnx, 2, realm, 0));
            try tables.trackAuth(streamKey(base + 3), .{
                .client_cnx = cnx,
                .client_stream_id = 3,
                .realm = realm,
                .buffer = .{ .items = &.{}, .capacity = 0 },
                .created_at = 0,
            });
            try tables.trackAuth(streamKey(base + 4), .{
                .client_cnx = cnx,
                .client_stream_id = 4,
                .realm = realm,
                .buffer = .{ .items = &.{}, .capacity = 0 },
                .created_at = 0,
            });
        }

        // 路径 1：正常回收。
        realm = 1;
        while (realm <= 4) : (realm += 1) {
            const base = @as(u64, realm) * 100;
            tables.closeRoute(streamKey(base));
            var entry = tables.takeAuth(streamKey(base + 3)).?;
            entry.buffer.deinit(std.testing.allocator);
        }

        // 路径 3：过期兜底（先做，剩下的留给连接关闭）。
        tables.purge(.{ .older_than = 1 });
        try std.testing.expectEqual(@as(u32, 0), tables.routeCount());
        try std.testing.expectEqual(@as(u32, 0), tables.authCount());

        // 路径 2：连接关闭。表已空，这一趟只验证空表回收不会把计数减穿。
        tables.purge(.{ .connection = cnx });
    }

    try std.testing.expectEqual(@as(usize, 0), tables.route_quota.total);
    try std.testing.expectEqual(@as(usize, 0), tables.route_quota.active_realms);
    try std.testing.expectEqual(@as(usize, 0), tables.auth_quota.total);
    try std.testing.expectEqual(@as(usize, 0), tables.auth_quota.active_realms);
}

test "reusing a stream key does not leak a quota slot" {
    // 后端重连后同一个 transport 实例会从头发号，键复用是真实场景。覆盖旧条目时
    // 漏掉一次归还，计数就再也回不到零。
    var tables = try Tables.init(std.testing.allocator);
    defer tables.deinit();

    const cnx = fakeCnx(0x1000);
    try tables.openRoute(streamKey(4), clientRoute(cnx, 0, 1, 0));
    try tables.openRoute(streamKey(4), clientRoute(cnx, 1, 2, 0));
    try std.testing.expectEqual(@as(usize, 1), tables.route_quota.total);
    try std.testing.expectEqual(@as(u32, 0), tables.route_quota.count(1));
    try std.testing.expectEqual(@as(u32, 1), tables.route_quota.count(2));

    // 认证表同理，而且覆盖时还得把旧 buffer 释放掉，否则 testing.allocator 会报泄漏。
    var first: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
    try first.appendSlice(std.testing.allocator, "first");
    try tables.trackAuth(streamKey(9), .{ .client_cnx = cnx, .client_stream_id = 0, .realm = 1, .buffer = first, .created_at = 0 });
    var second: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
    try second.appendSlice(std.testing.allocator, "second");
    try tables.trackAuth(streamKey(9), .{ .client_cnx = cnx, .client_stream_id = 1, .realm = 2, .buffer = second, .created_at = 0 });
    try std.testing.expectEqual(@as(usize, 1), tables.auth_quota.total);
    try std.testing.expectEqual(@as(u32, 0), tables.auth_quota.count(1));
}
