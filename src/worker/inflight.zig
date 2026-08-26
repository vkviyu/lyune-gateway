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

/// 在途请求的最大存活时间（微秒）。
///
/// 取值需要明显大于正常后端响应时间，它只是兜底回收，不是超时语义：
/// 真正的请求超时需要 transport 层支持取消，属于后续能力。
pub const request_timeout_us: u64 = 60 * std.time.us_per_s;

/// 一次批量回收扫描能带走的条目数。
///
/// 用固定数组分批而不是维护反向索引：回收只发生在连接关闭与周期性过期两处，
/// 都是低频路径，用一次全表扫描换热路径零分配是值得的。
const purge_batch: usize = 64;

/// 后端流 -> 客户端流的回程映射。
pub const Route = struct {
    client_cnx: quic.c.QuicCnx,
    client_stream_id: u64,
    /// 发起这条请求的连接所属 realm；配额归还时从这里取（见文件开头）。
    realm: RealmId,
    /// 创建时刻（微秒）。用于兜底过期：后端不回包、只回一半、连接中断
    /// 都会让条目滞留，仅靠 is_fin 回收不够。
    created_at: u64,
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
    /// 回收创建时刻早于该 deadline 的条目。
    older_than: u64,

    fn matches(self: Filter, cnx: quic.c.QuicCnx, created_at: u64) bool {
        return switch (self) {
            .connection => |target| cnx == target,
            .older_than => |deadline| created_at < deadline,
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
    /// 上次执行过期回收的时刻（微秒）。
    /// 用于把全表扫描摊薄到超时周期上，而不是跟随后端轮询频率。
    last_purge_at: u64 = 0,

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

    /// 这个 realm 现在能否再登记一条回程映射；表已满时先做一次过期回收再复查。
    ///
    /// 回收必须在配额判定之前：它会归还计数，跳过就会把"刚腾出来的位置"判成超额。
    pub fn reserveRoute(self: *Tables, realm: RealmId, now: u64) Admit {
        if (self.routes.count() >= max_requests) {
            self.purge(.{ .older_than = now -| request_timeout_us });
            if (self.routes.count() >= max_requests) return .table_full;
        }
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
    }

    pub fn lookupRoute(self: *const Tables, key: StreamKey) ?Route {
        return self.routes.get(key);
    }

    pub fn closeRoute(self: *Tables, key: StreamKey) void {
        self.dropRoute(key);
    }

    pub fn routeCount(self: *const Tables) u32 {
        return self.routes.count();
    }

    // ========================================================================
    // 认证等待表
    // ========================================================================

    /// 这个 realm 现在能否再登记一条等待中的认证；表已满时先做一次过期回收再复查。
    pub fn reserveAuth(self: *Tables, realm: RealmId, now: u64) Admit {
        if (self.auths.count() >= max_requests) {
            self.purge(.{ .older_than = now -| request_timeout_us });
            if (self.auths.count() >= max_requests) return .table_full;
        }
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

    // ========================================================================
    // 回收
    // ========================================================================

    /// routes 的唯一删除出口；配额递减贴在这里，三条回收路径都经由它。
    fn dropRoute(self: *Tables, key: StreamKey) void {
        const removed = self.routes.fetchRemove(key) orelse return;
        self.route_quota.release(removed.value.realm);
    }

    /// auths 的唯一删除出口。返回摘出的条目，buffer 所有权随之转移给调用方。
    fn dropAuth(self: *Tables, key: StreamKey) ?PendingAuth {
        const removed = self.auths.fetchRemove(key) orelse return null;
        self.auth_quota.release(removed.value.realm);
        return removed.value;
    }

    /// 摊薄的过期回收：距上次扫描不足一个超时周期就跳过。
    ///
    /// 后端轮询的频率（默认几毫秒）远高于超时周期（60 秒），跟着它扫全表纯属浪费。
    pub fn purgeExpired(self: *Tables, now: u64) void {
        if (now -| self.last_purge_at < request_timeout_us) return;
        self.purge(.{ .older_than = now -| request_timeout_us });
        self.last_purge_at = now;
    }

    /// 按给定条件回收两张表里的条目。
    pub fn purge(self: *Tables, filter: Filter) void {
        var keys: [purge_batch]StreamKey = undefined;

        while (true) {
            var count: usize = 0;
            var it = self.routes.iterator();
            while (it.next()) |entry| {
                if (!filter.matches(entry.value_ptr.client_cnx, entry.value_ptr.created_at)) continue;
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
                if (!filter.matches(entry.value_ptr.client_cnx, entry.value_ptr.created_at)) continue;
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

test "route lifecycle: open, lookup, close" {
    var tables = try Tables.init(std.testing.allocator);
    defer tables.deinit();

    const cnx = fakeCnx(0x1000);
    try tables.openRoute(streamKey(7), .{ .client_cnx = cnx, .client_stream_id = 4, .realm = 1, .created_at = 100 });

    const found = tables.lookupRoute(streamKey(7)).?;
    try std.testing.expectEqual(@as(u64, 4), found.client_stream_id);
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

    try tables.openRoute(from_a, .{ .client_cnx = client_a, .client_stream_id = 1, .realm = 1, .created_at = 10 });
    try tables.openRoute(from_b, .{ .client_cnx = client_b, .client_stream_id = 2, .realm = 2, .created_at = 10 });

    try std.testing.expectEqual(@as(u32, 2), tables.routeCount());
    try std.testing.expectEqual(client_a, tables.lookupRoute(from_a).?.client_cnx);
    try std.testing.expectEqual(client_b, tables.lookupRoute(from_b).?.client_cnx);

    // 关掉一个不影响另一个。
    tables.closeRoute(from_a);
    try std.testing.expect(tables.lookupRoute(from_a) == null);
    try std.testing.expect(tables.lookupRoute(from_b) != null);
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

    try tables.openRoute(streamKey(1), .{ .client_cnx = doomed, .client_stream_id = 0, .realm = 1, .created_at = 10 });
    try tables.openRoute(streamKey(2), .{ .client_cnx = survivor, .client_stream_id = 0, .realm = 1, .created_at = 10 });
    try tables.openRoute(streamKey(3), .{ .client_cnx = doomed, .client_stream_id = 4, .realm = 1, .created_at = 10 });
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
        try tables.openRoute(streamKey(i), .{ .client_cnx = cnx, .client_stream_id = i, .realm = 1, .created_at = 10 });
    }
    try std.testing.expectEqual(@as(u32, @intCast(total)), tables.routeCount());

    tables.purge(.{ .connection = cnx });
    try std.testing.expectEqual(@as(u32, 0), tables.routeCount());
}

test "purge by age keeps fresh entries" {
    var tables = try Tables.init(std.testing.allocator);
    defer tables.deinit();

    const cnx = fakeCnx(0x1000);
    try tables.openRoute(streamKey(1), .{ .client_cnx = cnx, .client_stream_id = 0, .realm = 1, .created_at = 100 });
    try tables.openRoute(streamKey(2), .{ .client_cnx = cnx, .client_stream_id = 1, .realm = 1, .created_at = 900 });

    tables.purge(.{ .older_than = 500 });

    try std.testing.expect(tables.lookupRoute(streamKey(1)) == null);
    try std.testing.expect(tables.lookupRoute(streamKey(2)) != null);
}

// 过期回收必须按超时周期摊薄，不能跟随后端轮询频率。
test "purgeExpired throttles to one sweep per timeout window" {
    var tables = try Tables.init(std.testing.allocator);
    defer tables.deinit();

    const cnx = fakeCnx(0x1000);
    const now = request_timeout_us * 3;
    try tables.openRoute(streamKey(1), .{ .client_cnx = cnx, .client_stream_id = 0, .realm = 1, .created_at = 0 });

    // 第一次调用：last_purge_at 还是 0，距今已超过一个周期，应当真正扫表。
    tables.purgeExpired(now);
    try std.testing.expectEqual(@as(u32, 0), tables.routeCount());
    try std.testing.expectEqual(now, tables.last_purge_at);

    // 紧接着再调：不足一个周期，必须直接跳过，连新插入的老条目也不动。
    try tables.openRoute(streamKey(2), .{ .client_cnx = cnx, .client_stream_id = 1, .realm = 1, .created_at = 0 });
    tables.purgeExpired(now + 1);
    try std.testing.expectEqual(@as(u32, 1), tables.routeCount());
    try std.testing.expectEqual(now, tables.last_purge_at);

    // 又过了一个周期：再次扫表。
    tables.purgeExpired(now + request_timeout_us);
    try std.testing.expectEqual(@as(u32, 0), tables.routeCount());
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
        try tables.openRoute(streamKey(i), .{ .client_cnx = cnx, .client_stream_id = i, .realm = 1, .created_at = 0 });
    }

    // realm 2 进来，活跃变 2，份额腰斩。realm 1 已经超了，realm 2 照常放行
    // ——这就是"只拒超额的那个"。
    try std.testing.expectEqual(Admit.ok, tables.reserveRoute(2, 0));
    try tables.openRoute(streamKey(above_watermark), .{ .client_cnx = cnx, .client_stream_id = 0, .realm = 2, .created_at = 0 });
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
            try tables.openRoute(streamKey(base), .{ .client_cnx = cnx, .client_stream_id = 0, .realm = realm, .created_at = 0 });
            try tables.openRoute(streamKey(base + 1), .{ .client_cnx = cnx, .client_stream_id = 1, .realm = realm, .created_at = 0 });
            try tables.openRoute(streamKey(base + 2), .{ .client_cnx = cnx, .client_stream_id = 2, .realm = realm, .created_at = 0 });
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
    try tables.openRoute(streamKey(4), .{ .client_cnx = cnx, .client_stream_id = 0, .realm = 1, .created_at = 0 });
    try tables.openRoute(streamKey(4), .{ .client_cnx = cnx, .client_stream_id = 1, .realm = 2, .created_at = 0 });
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
