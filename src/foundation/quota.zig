//! 按 realm 的加权准入
//!
//! 定容共享池 + 多 realm 的组合必然带来吵闹邻居问题（设计文档 §12.4）：所有上限都是
//! 每 Worker 全局值，一个 realm 能把池吃干、饿死其他所有人。
//!
//! ## 为什么是加权准入而不是预留
//!
//! 两条路：**预留**（启动时把池切成 N 份，每 realm 一份）或**加权准入**（池保持共享，
//! 按 realm 计数，超过份额才拒）。选后者，三条理由：
//!
//! 1. **预留与"realm 注册要动态"直接冲突**（§12.5）。池是启动期定容的，新增一个 realm
//!    就得重切份额 → 要重启。而 SaaS 上线前必须能动态加接入方。
//! 2. **预留在机器空闲时也封顶大 realm**——资源明明有，却因为"不是你的份"而拒绝。
//! 3. **小 realm 的预留份额是永久浪费的 RSS**，realm 越多浪费越多。
//!
//! ## 水位线以下完全不管
//!
//! 池用量低于水位线时**无条件放行**：小 realm 可以自由突发，零浪费。只有到了水位线
//! 以上才按公平份额拒绝，而且只拒超额的那个 realm，其他 realm 不受影响。
//!
//! 这等于"只在争用时才讲公平"，与调度器的做法一致。反过来"始终按份额"会让空闲机器上
//! 的突发流量被无谓地拒掉。
//!
//! ## 公平份额 = 容量 / 活跃 realm 数
//!
//! 活跃 = 当前占用大于 0。每次 acquire 都数一遍活跃 realm 是 O(max_realms)，在热路径上
//! 太贵，因此只在某个 realm 的占用发生 0↔1 跃变时重算——那是低频事件，而且结果精确，
//! 不是估算。
//!
//! ## 一条必须在设计时就防住的风险
//!
//! **计数必须在获取/归还资源的同一个函数里增减，绝不能放在调用点。** 漏掉一条归还路径
//! 的后果是那个 realm 的配额被永久蚕食，症状是"这家接入方的用户过几天就连不上了"
//! ——极难定位。因此 `acquire` / `release` 应当紧贴池的 take / put，并且用例要断言
//! 一轮建立-销毁之后计数归零。

const std = @import("std");

pub const Error = error{OutOfMemory};

/// 配额计数覆盖的 realm id 上限，全部池共用同一个值。
///
/// 计数数组按 realm id 直接索引（realm id 是配置里任选的 u16，不是紧凑下标），
/// 所以这个数字决定数组长度：1024 × 4 字节 × 每 Worker 的池数量，量级是几十 KB。
///
/// id 超出范围的 realm **不受配额约束**（见 `allows`）：那说明 realm 表本身配得离谱，
/// 而配额不是发现配置错误的地方——在这里拒绝会把一个配置问题变成一次难解释的容量故障。
pub const max_tracked_realms: usize = 1024;

/// 开始讲公平的默认水位线（占容量的百分比）。
///
/// 七成之前无条件放行，理由见本文件开头："空闲机器上的突发不该被拒"。所有池共用
/// 同一个值：不同池各设一个数字只会让"到底哪个池先拒的"变得难查。
pub const default_watermark_percent: u8 = 70;

pub const Quota = struct {
    /// 每 realm 的当前占用；下标即 RealmId。
    counts: []u32,
    /// 池容量。
    capacity: usize,
    /// 当前总占用。
    total: usize,
    /// 当前占用大于 0 的 realm 数量；公平份额的分母。
    active_realms: usize,
    /// 开始讲公平的水位线（占容量的百分比）。
    watermark_percent: u8,

    /// `max_realms` 决定计数数组长度；realm id 超出范围的请求一律放行，
    /// 因为那说明 realm 表本身配错了，配额不是发现它的地方。
    pub fn init(allocator: std.mem.Allocator, max_realms: usize, capacity: usize, watermark_percent: u8) Error!Quota {
        const counts = try allocator.alloc(u32, @max(max_realms, 1));
        @memset(counts, 0);
        return .{
            .counts = counts,
            .capacity = @max(capacity, 1),
            .total = 0,
            .active_realms = 0,
            .watermark_percent = @min(watermark_percent, 100),
        };
    }

    pub fn deinit(self: *Quota, allocator: std.mem.Allocator) void {
        allocator.free(self.counts);
    }

    /// 这个 realm 现在能否再占一格。
    ///
    /// 只判断，不记账——调用方确认要占时再调 `acquire`。分开是为了让"池本身也满了"
    /// 这种情形由调用方按自己的语义处理（有的池要报错，有的池要丢最旧的）。
    pub fn allows(self: *const Quota, realm: u16) bool {
        if (realm >= self.counts.len) return true;
        // 水位线以下不讲公平：小 realm 可以自由突发。
        if (self.total * 100 < self.capacity * self.watermark_percent) return true;

        const share = self.capacity / @max(self.active_realms, 1);
        return self.counts[realm] < share;
    }

    /// 占一格。
    pub fn acquire(self: *Quota, realm: u16) void {
        if (realm >= self.counts.len) return;
        if (self.counts[realm] == 0) self.active_realms += 1;
        self.counts[realm] += 1;
        self.total += 1;
    }

    /// 归还一格。
    ///
    /// 对未占用的 realm 调用是安全的空操作——但它意味着调用方的配对出了问题，
    /// 因此断言在调试构建里会先炸出来。
    pub fn release(self: *Quota, realm: u16) void {
        if (realm >= self.counts.len) return;
        std.debug.assert(self.counts[realm] > 0);
        if (self.counts[realm] == 0) return;
        self.counts[realm] -= 1;
        self.total -= 1;
        if (self.counts[realm] == 0) self.active_realms -= 1;
    }

    pub fn count(self: *const Quota, realm: u16) u32 {
        if (realm >= self.counts.len) return 0;
        return self.counts[realm];
    }
};

// ============================================================================
// 测试
// ============================================================================

test "below the watermark nobody is limited" {
    var quota = try Quota.init(std.testing.allocator, 8, 100, 70);
    defer quota.deinit(std.testing.allocator);

    // 一个 realm 独占到水位线之前都放行——空闲机器上的突发不该被拒。
    var i: usize = 0;
    while (i < 70) : (i += 1) {
        try std.testing.expect(quota.allows(1));
        quota.acquire(1);
    }
    try std.testing.expectEqual(@as(u32, 70), quota.count(1));
}

test "above the watermark the over-share realm is refused and others are not" {
    var quota = try Quota.init(std.testing.allocator, 8, 100, 70);
    defer quota.deinit(std.testing.allocator);

    // realm 1 先占到水位线。此刻只有它活跃，份额 = 100/1，所以仍然放行。
    var i: usize = 0;
    while (i < 70) : (i += 1) quota.acquire(1);
    try std.testing.expect(quota.allows(1));

    // realm 2 进来，活跃变 2，份额降到 50。realm 1 已占 70 > 50 → 被拒。
    quota.acquire(2);
    try std.testing.expect(!quota.allows(1));
    // 而 realm 2 只占了 1 格，远低于份额 → 照常放行。这是"只拒超额的那个"。
    try std.testing.expect(quota.allows(2));
}

test "the fair share follows the active realm count" {
    var quota = try Quota.init(std.testing.allocator, 8, 100, 0);
    defer quota.deinit(std.testing.allocator);

    // 水位线设 0：全程讲公平，便于观察份额本身。
    quota.acquire(1);
    quota.acquire(2);
    quota.acquire(3);
    try std.testing.expectEqual(@as(usize, 3), quota.active_realms);

    // 份额 = 100/3 = 33。三个 realm 各占 1，都还能占。
    try std.testing.expect(quota.allows(1));

    // realm 1 占到 33 就到顶。
    var i: usize = 1;
    while (i < 33) : (i += 1) quota.acquire(1);
    try std.testing.expectEqual(@as(u32, 33), quota.count(1));
    try std.testing.expect(!quota.allows(1));
    // 别人不受影响。
    try std.testing.expect(quota.allows(2));
}

test "a realm dropping to zero gives its share back" {
    var quota = try Quota.init(std.testing.allocator, 8, 100, 0);
    defer quota.deinit(std.testing.allocator);

    quota.acquire(1);
    quota.acquire(2);
    try std.testing.expectEqual(@as(usize, 2), quota.active_realms);

    // realm 2 退场，份额从 50 回到 100。
    quota.release(2);
    try std.testing.expectEqual(@as(usize, 1), quota.active_realms);

    var i: usize = 1;
    while (i < 100) : (i += 1) {
        try std.testing.expect(quota.allows(1));
        quota.acquire(1);
    }
}

test "counters return to zero after a full churn cycle" {
    // 这条是防"配额被永久蚕食"的那道回归：漏掉一条归还路径的症状是
    // "这家接入方的用户过几天就连不上了"，极难定位，所以必须有用例钉住。
    var quota = try Quota.init(std.testing.allocator, 8, 32, 70);
    defer quota.deinit(std.testing.allocator);

    var round: usize = 0;
    while (round < 5) : (round += 1) {
        var realm: u16 = 1;
        while (realm <= 4) : (realm += 1) {
            var i: usize = 0;
            while (i < 6) : (i += 1) quota.acquire(realm);
        }
        realm = 1;
        while (realm <= 4) : (realm += 1) {
            var i: usize = 0;
            while (i < 6) : (i += 1) quota.release(realm);
        }
    }

    try std.testing.expectEqual(@as(usize, 0), quota.total);
    try std.testing.expectEqual(@as(usize, 0), quota.active_realms);
    var realm: u16 = 0;
    while (realm < 8) : (realm += 1) try std.testing.expectEqual(@as(u32, 0), quota.count(realm));
}

test "an out-of-range realm is always allowed" {
    // realm id 越界说明 realm 表本身配错了。配额不是发现它的地方——在这里拒绝会把
    // 一个配置错误变成一次难解释的容量故障。
    var quota = try Quota.init(std.testing.allocator, 4, 8, 0);
    defer quota.deinit(std.testing.allocator);

    try std.testing.expect(quota.allows(99));
    quota.acquire(99);
    quota.release(99);
    try std.testing.expectEqual(@as(usize, 0), quota.total);
}
