//! 选址：`(realm, dest_id)` 应该落在哪个 (节点, Worker) 上
//!
//! 这是设计文档 §8.5「第二层：选路策略」的实现。它回答的**不是**"连接在哪"，
//! 而是"连接**必须**在哪"——一个所有节点都能独立算出同一答案的纯函数。
//!
//! ## 为什么需要它
//!
//! 网关里有两套互不兼容的寻址方案（§8.4）：CID 内嵌位置（网关自选、位置长在标识
//! 里、自寻址，因此从来不需要目录）与 `dest_id`（认证服务选、握手后才知道、一对多、
//! 跨重连稳定，因此必须与位置无关）。位置无关标识必然需要一张目录，而方案一的全部
//! 优雅之处正是"不需要目录"。
//!
//! 本模块用**函数取代目录**：位置不是记下来供人查的，而是由一个纯函数定义的。
//! 代价是必须**强制**连接搬到函数算出来的位置上去——这就是重定向存在的理由，
//! 它是这条路线的必需零件，不是补丁。
//!
//! ## 两种策略共用一条投递通路
//!
//! `Strategy` 只决定"目标集合有多大"，不决定"怎么送"：
//!
//! - `.broadcast` —— 目标集合是全部节点 × 全部 Worker，各自查本地索引，查不到是
//!   正常情形。完全无状态，不需要重定向。
//! - `.affinity` —— 目标集合恰好是 `{home}`，查不到就是 bug。需要强制重定向来维持
//!   不变量。
//!
//! **刻意不做成两条代码路径。** 两者的正确性不变量不同（亲和要强制重定向、广播不要），
//! 做成两套实现的话运维配错就是静默的消息丢失，而这类错误没有任何报错会提示。
//!
//! ## 一个必须记住的脆弱点
//!
//! 「函数取代目录」的正确性依赖**所有节点看到同一份节点列表**，而那份列表来自 SWIM，
//! 是最终一致的。视图不一致的窗口里两次计算会得到不同答案，表现是消息静默丢失。
//! 用 HRW（见下）把漂移范围限制到最小是必要的第一道，成员变更后的**双查**是第二道
//! （`prev_nodes` / `previousHomeNode`），而第三道是**把漂移的连接重新归位**
//! （`worker.zig` 的 `rehomeDrifted`）。
//!
//! 三道各自解决不同的一半，缺一不可：
//!
//! - 双查解决**视图不一致**：投递方同时发往新旧两个 home，谁手上有这条连接谁投出去。
//!   它是有时限的——窗口只需覆盖 SWIM 收敛，因为窗口内新旧两份视图的并集必定包含
//!   真正的那个位置。
//! - 重新归位解决**不变量被破坏**：连接是长寿的（IM 客户端挂几小时很正常），
//!   而它的 home 会因为别人扩容而漂走。光靠有时限的双查，窗口一过这条连接就再也
//!   收不到推送——**永久静默丢失**。所以必须把它赶回新 home（复用认证时那条
//!   `redirect` 通路），让函数与现实重新对齐。

const std = @import("std");

/// 选路策略。
pub const Strategy = enum {
    /// 投递指令发给集群里每个节点、节点内发给每个 Worker。
    broadcast,
    /// 只发给 `home(realm, dest_id)` 算出的那一个位置。
    affinity,
};

/// 一条连接应当所处的位置。
pub const Location = struct {
    node_id: u16,
    worker_id: u8,
};

/// 一个键在双查窗口里的候选位置，最多两个（新 home + 漂移前的旧 home）。
///
/// 把"1 个还是 2 个"收进一个类型，是为了让**标记转投、本地投递判定、回报结算**三处
/// 用同一份枚举。这三处必须一致：只在标记时双查而结算时只看新 home，会把"已经送到
/// 旧 home"误报成不可达，后端于是又写一份离线，用户拿到两条一样的消息。
pub const Candidates = struct {
    items: [2]Location,
    len: u8,

    pub fn slice(self: *const Candidates) []const Location {
        return self.items[0..self.len];
    }
};

/// 把 `(realm, dest_id)` 混成一个 64 位选址键。
///
/// `dest_id` 由各接入方的认证服务生成，很可能是自增主键，因此必须过一次混淆；
/// realm 也要参与，否则两个 realm 里的同号标识会被钉到同一个位置，让大 realm 的
/// 热点直接传染给小 realm。
pub fn key(realm: u16, dest_id: u64) u64 {
    const salted = dest_id ^ (@as(u64, realm) *% 0xD6E8_FEB8_6659_FD93);
    return salted *% 0x9E3779B97F4A7C15;
}

/// 某个键在本节点内应当落在哪个 Worker。
///
/// Worker 数量是静态配置，节点内不会变，所以直接取模就够——不需要一致性哈希
/// （那是为"成员会变"准备的）。取高 32 位是因为低位已经被 `key` 的乘法混淆吃掉了
/// 一部分熵，而取模只用得到低位。
pub fn homeWorker(hashed: u64, worker_count: u8) u8 {
    if (worker_count <= 1) return 0;
    return @intCast((hashed >> 32) % worker_count);
}

/// 某个键在集群里应当落在哪个节点（HRW / rendezvous hashing）。
///
/// 为每个候选节点算一个分数 `mix(hashed, node_id)`，取分数最大的那个。
///
/// **为什么是 HRW 而不是哈希环**：两者都满足"节点数变化时只有 1/N 的键漂移"这条
/// 关键性质，但 HRW 不需要构建环、不需要虚拟节点、不需要任何运行期状态——它是候选
/// 列表的纯函数。而 `% node_count` 不行：加一个节点会让几乎所有键的 home 同时漂移。
///
/// 代价是 O(节点数) 次乘法。节点数是几十量级、且只在跨节点投递时才算，可以忽略。
/// 空列表返回 null（集群视图还没建立起来）。
pub fn homeNode(hashed: u64, nodes: []const u16) ?u16 {
    var best: ?u16 = null;
    var best_score: u64 = 0;
    for (nodes) |node_id| {
        // 每个节点一个独立的混淆，否则分数只是 node_id 的单调函数，
        // 所有键都会选中同一个节点。
        const score = (hashed ^ (@as(u64, node_id) *% 0xC2B2_AE3D_27D4_EB4F)) *% 0x9E3779B97F4A7C15;
        if (best == null or score > best_score) {
            best = node_id;
            best_score = score;
        }
    }
    return best;
}

/// 一个 Worker 手上的选址视图。
///
/// 节点列表是**快照**，不是实时查询：`membership.Table` 的零锁读接口是按 node_id
/// 逐个 lookup 的（遍历只允许 SWIM 线程做），而 HRW 需要完整的候选集合。每个目标
/// 都扫一遍全表会让扇出退化成 O(目标数 × max_nodes)。
///
/// 快照由 Worker 在自己的周期定时器里刷新，因此**必然滞后**。这正是 §8.5 说的那个
/// 脆弱点，不是本实现引入的：视图不一致的窗口靠 HRW 限制漂移范围 + 扩缩容双查覆盖。
pub const View = struct {
    strategy: Strategy,
    /// 本 Worker 自己的位置，用来判断 home 是不是自己。
    self: Location,
    /// 本节点的 Worker 数量。
    worker_count: u8,
    /// 集群里可作为投递目标的节点快照；单机部署恒为 `&.{self.node_id}`。
    nodes: []const u16 = &.{},
    /// 成员变更之前的那份节点快照；空表示双查窗口已过或从未发生变更。
    ///
    /// 窗口的开闭由 Worker 管理（它有时钟），本结构只做纯计算——把时间放进来会让
    /// 一个纯函数变得要靠"现在几点"才能测。
    prev_nodes: []const u16 = &.{},

    /// 这个键的 home 位置；`.broadcast` 下没有单一 home，返回 null。
    ///
    /// 节点列表为空时退化到"就是本节点"：集群视图还没建立起来时，本地投递
    /// 比丢弃更接近正确——单机部署本来就是这个形态。
    pub fn home(self: View, realm: u16, dest_id: u64) ?Location {
        if (self.strategy == .broadcast) return null;
        const hashed = key(realm, dest_id);
        return .{
            .node_id = homeNode(hashed, self.nodes) orelse self.self.node_id,
            .worker_id = homeWorker(hashed, self.worker_count),
        };
    }

    /// 双查用：这个键在**变更前**那份视图里的 home 节点，仅当它与现在不同时返回。
    ///
    /// 只回答节点这一级：`worker_count` 是静态配置，成员变更不会改变 Worker 归属，
    /// 所以变更前后的 `worker_id` 必然相同，多返回一次只会让调用方误以为要比对它。
    ///
    /// 返回 null 的三种情形都表示"不需要额外投一份"：广播（本来就发给所有节点）、
    /// 窗口已过或没发生变更（`prev_nodes` 为空）、这个键没漂移（HRW 下这是绝大多数）。
    pub fn previousHomeNode(self: View, realm: u16, dest_id: u64) ?u16 {
        if (self.strategy == .broadcast) return null;
        if (self.prev_nodes.len == 0) return null;
        const hashed = key(realm, dest_id);
        const previous = homeNode(hashed, self.prev_nodes) orelse return null;
        const current = homeNode(hashed, self.nodes) orelse self.self.node_id;
        return if (previous == current) null else previous;
    }

    /// 这个键当前该被投到哪些位置。
    ///
    /// 稳定期恰好一个；成员刚变过且这个键正好漂移了，就是两个（新旧各一）。
    /// `.broadcast` 下没有单一 home，返回 0 个——调用方改用"发给所有位置"。
    pub fn candidates(self: View, realm: u16, dest_id: u64) Candidates {
        const current = self.home(realm, dest_id) orelse return .{ .items = undefined, .len = 0 };
        var result = Candidates{ .items = .{ current, current }, .len = 1 };
        if (self.previousHomeNode(realm, dest_id)) |node_id| {
            // worker_id 不随成员变更而变（worker_count 是静态配置），所以旧位置
            // 只换节点。
            result.items[1] = .{ .node_id = node_id, .worker_id = current.worker_id };
            result.len = 2;
        }
        return result;
    }

    /// 这个键的 home 是否就是本 Worker（双查窗口里新旧任一命中都算）。
    ///
    /// `.broadcast` 下恒为 true：广播模式下每个 Worker 都该查一遍自己的索引，
    /// "本地不该有它"这个概念不存在。
    ///
    /// 窗口里放宽到"任一"是必需的：连接可能还挂在漂移前的那个位置上，只认新 home
    /// 会让本地那条连接在窗口里完全收不到推送。
    pub fn isHome(self: View, realm: u16, dest_id: u64) bool {
        const list = self.candidates(realm, dest_id);
        if (list.len == 0) return true;
        for (list.slice()) |location| {
            if (location.node_id == self.self.node_id and location.worker_id == self.self.worker_id) return true;
        }
        return false;
    }

    /// 这个键的 home 节点是否就是本节点（双查窗口里新旧任一命中都算）。
    ///
    /// 认证成功后的强制重定向只看**节点**这一级：客户端能选连哪个节点地址，
    /// 选不了节点内的哪个 Worker（那由内核 reuseport BPF 按 CID 决定）。
    ///
    /// 窗口里同样放宽到"任一"，但理由不同：此刻本节点的视图可能比别人新也可能比别人
    /// 旧，按一份不稳定的视图去重定向会让客户端在两个节点之间来回弹。窗口内两个位置
    /// 都算合法，窗口一过再由漂移巡检（`worker.rehomeDrifted`）统一赶回去。
    pub fn isHomeNode(self: View, realm: u16, dest_id: u64) bool {
        const list = self.candidates(realm, dest_id);
        if (list.len == 0) return true;
        for (list.slice()) |location| {
            if (location.node_id == self.self.node_id) return true;
        }
        return false;
    }
};

// ============================================================================
// 测试
// ============================================================================

test "the same key resolves to the same location from every node" {
    // 这是整套方案的枢纽：没有任何知识被传递，两次计算独立进行，
    // 但因为输入与函数相同，答案必然相同。
    const nodes = [_]u16{ 1, 2, 3 };
    const from_node_3 = View{ .strategy = .affinity, .self = .{ .node_id = 3, .worker_id = 0 }, .worker_count = 4, .nodes = &nodes };
    const from_node_1 = View{ .strategy = .affinity, .self = .{ .node_id = 1, .worker_id = 2 }, .worker_count = 4, .nodes = &nodes };

    const a = from_node_3.home(7, 123).?;
    const b = from_node_1.home(7, 123).?;
    try std.testing.expectEqual(a.node_id, b.node_id);
    try std.testing.expectEqual(a.worker_id, b.worker_id);
}

test "realm participates in placement so identical dest_ids do not collide" {
    const nodes = [_]u16{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var same_location: usize = 0;
    for (1..64) |dest_id| {
        const in_realm_1 = homeNode(key(1, dest_id), &nodes).?;
        const in_realm_2 = homeNode(key(2, dest_id), &nodes).?;
        if (in_realm_1 == in_realm_2) same_location += 1;
    }
    // 8 个节点下随机撞上同一个约占 1/8。远高于这个比例说明 realm 没有真正参与混淆，
    // 那会让大 realm 的热点传染给小 realm。
    try std.testing.expect(same_location < 63 / 4);
}

test "adding a node only moves a small share of keys (HRW property)" {
    const before = [_]u16{ 1, 2, 3, 4 };
    const after = [_]u16{ 1, 2, 3, 4, 5 };

    var moved: usize = 0;
    const total: usize = 2000;
    for (0..total) |dest_id| {
        const hashed = key(0, dest_id);
        if (homeNode(hashed, &before).? != homeNode(hashed, &after).?) moved += 1;
    }
    // 理论值是 1/5 = 20%。放宽到 30% 以容忍抽样噪声；`% node_count` 在这个用例上
    // 会搬走约 80%，所以这条断言真的能抓住退化。
    try std.testing.expect(moved * 100 / total < 30);
}

test "broadcast has no single home and treats every worker as home" {
    const view = View{ .strategy = .broadcast, .self = .{ .node_id = 1, .worker_id = 3 }, .worker_count = 8 };
    try std.testing.expect(view.home(0, 42) == null);
    // 广播下每个 Worker 都该查自己的索引，"本地不该有它"这个概念不存在。
    try std.testing.expect(view.isHome(0, 42));
    try std.testing.expect(view.isHomeNode(0, 42));
}

test "an empty membership snapshot degrades to the local node" {
    // 集群视图还没建立起来时本地投递比丢弃更接近正确；单机部署本来就是这个形态。
    const view = View{ .strategy = .affinity, .self = .{ .node_id = 9, .worker_id = 0 }, .worker_count = 1 };
    try std.testing.expectEqual(@as(u16, 9), view.home(0, 42).?.node_id);
    try std.testing.expect(view.isHomeNode(0, 42));
}

test "the double lookup only fires for keys that actually moved" {
    // 双查的代价必须与漂移范围成正比，而不是"变更期间每条推送都翻倍"。HRW 下
    // 加一个节点只搬 1/N 的键，所以绝大多数键的 previousHomeNode 应当是 null。
    const before = [_]u16{ 1, 2, 3, 4 };
    const after = [_]u16{ 1, 2, 3, 4, 5 };
    const view = View{
        .strategy = .affinity,
        .self = .{ .node_id = 1, .worker_id = 0 },
        .worker_count = 4,
        .nodes = &after,
        .prev_nodes = &before,
    };

    var extra: usize = 0;
    const total: usize = 2000;
    for (0..total) |dest_id| {
        if (view.previousHomeNode(0, dest_id)) |previous| {
            extra += 1;
            // 返回的一定是旧视图里的答案，而且必定与新视图不同——否则就是白发一份。
            const hashed = key(0, dest_id);
            try std.testing.expectEqual(homeNode(hashed, &before).?, previous);
            try std.testing.expect(previous != homeNode(hashed, &after).?);
        }
    }
    // 理论值 1/5；放宽到 30% 容忍抽样噪声。
    try std.testing.expect(extra * 100 / total < 30);
    // 但也必须真的有一批键触发了双查，否则这个机制等于没接上。
    try std.testing.expect(extra > total / 20);
}

test "the double lookup is off when there is nothing to cover" {
    const nodes = [_]u16{ 1, 2, 3 };

    // 窗口已过（prev_nodes 为空）：不再多发。
    const settled = View{ .strategy = .affinity, .self = .{ .node_id = 1, .worker_id = 0 }, .worker_count = 2, .nodes = &nodes };
    try std.testing.expect(settled.previousHomeNode(0, 42) == null);

    // 广播策略：本来就发给所有节点，双查无意义。
    const broadcasting = View{
        .strategy = .broadcast,
        .self = .{ .node_id = 1, .worker_id = 0 },
        .worker_count = 2,
        .nodes = &nodes,
        .prev_nodes = &[_]u16{ 1, 2 },
    };
    try std.testing.expect(broadcasting.previousHomeNode(0, 42) == null);

    // 两份视图相同：每个键都没漂移。
    const unchanged = View{
        .strategy = .affinity,
        .self = .{ .node_id = 1, .worker_id = 0 },
        .worker_count = 2,
        .nodes = &nodes,
        .prev_nodes = &nodes,
    };
    for (0..200) |dest_id| try std.testing.expect(unchanged.previousHomeNode(0, dest_id) == null);
}

test "during the window both the old and the new home claim the key" {
    // 这是双查为什么必须同时放宽 isHome 的地方：连接还挂在旧 home 上，只认新 home
    // 会让本地那条连接在窗口里完全收不到推送。
    const before = [_]u16{ 1, 2, 3, 4 };
    const after = [_]u16{ 1, 2, 3, 4, 5 };

    // 找一个真的漂移了的键。
    var moved_id: ?u64 = null;
    for (0..2000) |dest_id| {
        const hashed = key(0, dest_id);
        if (homeNode(hashed, &before).? != homeNode(hashed, &after).?) {
            moved_id = dest_id;
            break;
        }
    }
    const dest_id = moved_id.?;
    const hashed = key(0, dest_id);
    const old_node = homeNode(hashed, &before).?;
    const new_node = homeNode(hashed, &after).?;
    const worker_id = homeWorker(hashed, 4);

    const at_old = View{
        .strategy = .affinity,
        .self = .{ .node_id = old_node, .worker_id = worker_id },
        .worker_count = 4,
        .nodes = &after,
        .prev_nodes = &before,
    };
    const at_new = View{
        .strategy = .affinity,
        .self = .{ .node_id = new_node, .worker_id = worker_id },
        .worker_count = 4,
        .nodes = &after,
        .prev_nodes = &before,
    };

    try std.testing.expectEqual(@as(u8, 2), at_new.candidates(0, dest_id).len);
    // 窗口内两边都认，因此谁手上有这条连接谁就投出去，且认证时都不会把它踢走。
    try std.testing.expect(at_old.isHome(0, dest_id));
    try std.testing.expect(at_new.isHome(0, dest_id));
    try std.testing.expect(at_old.isHomeNode(0, dest_id));
    try std.testing.expect(at_new.isHomeNode(0, dest_id));

    // 窗口一过，旧位置不再是 home——这正是漂移巡检要把它赶走的依据。
    const settled = View{
        .strategy = .affinity,
        .self = .{ .node_id = old_node, .worker_id = worker_id },
        .worker_count = 4,
        .nodes = &after,
    };
    try std.testing.expect(!settled.isHomeNode(0, dest_id));
    try std.testing.expectEqual(@as(u8, 1), settled.candidates(0, dest_id).len);
}

test "worker placement spreads across all workers" {
    var hits: [4]usize = @splat(0);
    for (0..4000) |dest_id| hits[homeWorker(key(0, dest_id), 4)] += 1;
    // 每个 Worker 都必须拿到一份；只用低位取模或忘记混淆时会出现空桶。
    for (hits) |count| try std.testing.expect(count > 4000 / 8);
}

test "a single-worker node always places at worker 0" {
    try std.testing.expectEqual(@as(u8, 0), homeWorker(key(0, 12345), 1));
    try std.testing.expectEqual(@as(u8, 0), homeWorker(key(0, 12345), 0));
}
