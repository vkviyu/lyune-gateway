//! 确定性内存网络模拟器（仅测试使用）
//!
//! 设计文档 §8 的落地：把 SWIM 状态机接在一个虚拟网络上，
//! 用【虚拟时钟 + 固定随机种子】驱动整个集群，可注入丢包、随机延迟、
//! 网络分区、节点冻结（模拟长时间停顿）与节点崩溃。
//! 给定相同的种子与操作序列，每次运行的结果完全一致——任何测试失败
//! 都可以用种子精确复现。
//!
//! 模拟器同时内置「incarnation 单调」不变量检查（设计文档 §8.2 不变量 3）：
//! 每个虚拟 tick 之后校验所有视图中所有成员的 incarnation 不回退，
//! 违反立即 panic，使所有跑在模拟器上的测试都自动携带这条检查。

const std = @import("std");
const membership = @import("mod.zig");
const codec = @import("codec.zig");
const swim_mod = @import("swim.zig");
const foundation = @import("../../foundation/mod.zig");
const net = foundation.net;

const NodeId = membership.NodeId;
const Swim = swim_mod.Swim;

/// 模拟器参数。
pub const Options = struct {
    /// 全局随机种子：驱动丢包判定、延迟采样，并派生各节点状态机的种子。
    seed: u64 = 1,
    /// 虚拟时钟步长。
    tick_ms: u64 = 100,
    /// 丢包率 [0,1)，对每帧独立判定。
    loss_rate: f32 = 0,
    /// 单向传输延迟的均匀分布区间。
    min_delay_ms: u64 = 5,
    max_delay_ms: u64 = 50,
};

/// 在途/待处理的一帧消息。
const Flight = struct {
    deliver_at: u64,
    to: usize,
    from_address: net.Address,
    len: u16,
    data: [codec.max_message_size]u8 = undefined,

    fn bytes(self: *const Flight) []const u8 {
        return self.data[0..self.len];
    }
};

/// 模拟集群中的一个节点。
pub const Node = struct {
    swim: Swim,
    address: net.Address,
    /// 冻结：进程停顿——不 tick、不处理消息，但入站消息在 inbox 里排队（类似内核缓冲）。
    frozen: bool = false,
    /// 崩溃：彻底消失——不 tick，发给它的消息在投递时丢弃。
    crashed: bool = false,
    /// 冻结期间挂起的入站消息。
    inbox: std.ArrayList(Flight) = .empty,
};

/// 测试专用的确定性 SWIM 集群与虚拟网络；不是生产 transport。
pub const Sim = struct {
    allocator: std.mem.Allocator,
    options: Options,
    rng: std.Random.DefaultPrng,
    now_ms: u64 = 0,
    nodes: std.ArrayList(Node) = .empty,
    flights: std.ArrayList(Flight) = .empty,
    /// 被切断的节点对（无序对，双向阻断）。
    blocked_pairs: std.ArrayList([2]usize) = .empty,
    /// incarnation 单调性检查的上次观测值：[viewer][subject_node_id]。
    last_incarnations: ?[]u32 = null,

    /// 创建空模拟器；所有节点应在首次 run 前通过 addNode 加入。
    pub fn init(allocator: std.mem.Allocator, options: Options) Sim {
        return .{
            .allocator = allocator,
            .options = options,
            .rng = std.Random.DefaultPrng.init(options.seed),
        };
    }

    /// 销毁所有虚拟节点、在途报文和不变量检查状态。
    pub fn deinit(self: *Sim) void {
        for (self.nodes.items) |*entry| {
            entry.swim.deinit();
            entry.inbox.deinit(self.allocator);
        }
        self.nodes.deinit(self.allocator);
        self.flights.deinit(self.allocator);
        self.blocked_pairs.deinit(self.allocator);
        if (self.last_incarnations) |slice| self.allocator.free(slice);
        self.* = undefined;
    }

    /// 添加一个节点，地址固定为 10.0.0.<node_id>:7946。
    /// 所有节点必须在第一次 run 之前添加完毕。返回节点下标。
    pub fn addNode(self: *Sim, node_id: NodeId, params: membership.Params) !usize {
        std.debug.assert(self.last_incarnations == null); // run 之后禁止再加节点
        const address = nodeAddress(node_id);
        const node_swim = try Swim.init(self.allocator, .{
            .node_id = node_id,
            .address = address,
            .max_nodes = 64,
            // 每个节点独立但确定的种子。
            .seed = self.options.seed ^ (@as(u64, node_id) *% 0x9e37_79b9_7f4a_7c15),
            .params = params,
        });
        try self.nodes.append(self.allocator, .{ .swim = node_swim, .address = address });
        return self.nodes.items.len - 1;
    }

    /// 按模拟器下标返回可变节点；指针只在 nodes 不再扩容后稳定。
    pub fn node(self: *Sim, index: usize) *Node {
        return &self.nodes.items[index];
    }

    /// 便捷：让 index 节点把 seed_index 节点当作静态种子。
    pub fn seedWith(self: *Sim, index: usize, seed_index: usize) !void {
        const seed_node = &self.nodes.items[seed_index];
        try self.nodes.items[index].swim.addPeer(seed_node.swim.config.node_id, seed_node.address);
    }

    /// 切断/恢复一对节点之间的双向通信（模拟网络分区）。
    pub fn setPartition(self: *Sim, a: usize, b: usize, blocked: bool) !void {
        const pair: [2]usize = .{ @min(a, b), @max(a, b) };
        for (self.blocked_pairs.items, 0..) |existing, index| {
            if (existing[0] == pair[0] and existing[1] == pair[1]) {
                if (!blocked) _ = self.blocked_pairs.swapRemove(index);
                return;
            }
        }
        if (blocked) try self.blocked_pairs.append(self.allocator, pair);
    }

    /// 永久标记节点崩溃；后续不再 tick，发往该节点的报文被丢弃。
    pub fn crash(self: *Sim, index: usize) void {
        self.nodes.items[index].crashed = true;
    }

    /// 暂停或恢复节点；冻结期间不 tick，但入站报文继续在 inbox 中排队。
    pub fn setFrozen(self: *Sim, index: usize, frozen: bool) void {
        self.nodes.items[index].frozen = frozen;
    }

    /// 查询 viewer 节点视图中某成员的状态；未知返回 null。
    pub fn viewStatus(self: *Sim, viewer: usize, subject: NodeId) ?membership.NodeStatus {
        const member = self.nodes.items[viewer].swim.view().get(subject) orelse return null;
        return member.status;
    }

    /// 推进 steps 个虚拟 tick。每 tick：投递到期消息 → 各节点处理入站与协议时钟 →
    /// 收集出站消息进入虚拟网络 → 校验 incarnation 单调不变量。
    pub fn run(self: *Sim, steps: usize) !void {
        if (self.last_incarnations == null) {
            const n = self.nodes.items.len;
            const slice = try self.allocator.alloc(u32, n * 64);
            @memset(slice, 0);
            self.last_incarnations = slice;
        }

        for (0..steps) |_| {
            self.now_ms += self.options.tick_ms;
            try self.deliverDueFlights();

            for (self.nodes.items, 0..) |*current, index| {
                if (current.crashed or current.frozen) continue;

                // 先处理积压的入站消息（含冻结期间攒下的），再推协议时钟。
                for (current.inbox.items) |*flight| {
                    try current.swim.handleMessage(self.now_ms, flight.from_address, flight.bytes());
                }
                current.inbox.clearRetainingCapacity();
                try current.swim.tick(self.now_ms);
                try self.routeOutgoing(index);
            }

            self.checkIncarnationMonotonic();
        }
    }

    /// 按 run 的粒度推进指定的虚拟毫秒数。
    pub fn runMs(self: *Sim, duration_ms: u64) !void {
        try self.run(duration_ms / self.options.tick_ms);
    }

    fn deliverDueFlights(self: *Sim) !void {
        var index: usize = 0;
        while (index < self.flights.items.len) {
            const flight = &self.flights.items[index];
            if (flight.deliver_at > self.now_ms) {
                index += 1;
                continue;
            }
            const dest = &self.nodes.items[flight.to];
            // 崩溃节点的包直接消失；冻结节点的包排队等待解冻。
            if (!dest.crashed) try dest.inbox.append(self.allocator, flight.*);
            // orderedRemove 保持剩余消息的相对顺序，保证确定性。
            _ = self.flights.orderedRemove(index);
        }
    }

    /// 把 index 节点 outbox 里的帧投入虚拟网络：查目的节点、判丢包/分区、采样延迟。
    fn routeOutgoing(self: *Sim, index: usize) !void {
        const source = &self.nodes.items[index];
        for (source.swim.pendingOutgoing()) |*outgoing| {
            const dest_index = self.findNodeByAddress(outgoing.to) orelse continue;
            if (self.isBlocked(index, dest_index)) continue;
            if (self.options.loss_rate > 0 and self.rng.random().float(f32) < self.options.loss_rate) continue;

            const delay = self.rng.random().intRangeAtMost(u64, self.options.min_delay_ms, self.options.max_delay_ms);
            var flight: Flight = .{
                .deliver_at = self.now_ms + delay,
                .to = dest_index,
                .from_address = source.address,
                .len = outgoing.len,
            };
            @memcpy(flight.data[0..outgoing.len], outgoing.bytes());
            try self.flights.append(self.allocator, flight);
        }
        source.swim.clearOutgoing();
    }

    fn findNodeByAddress(self: *Sim, address: net.Address) ?usize {
        for (self.nodes.items, 0..) |*candidate, index| {
            if (std.meta.eql(candidate.address, address)) return index;
        }
        return null;
    }

    fn isBlocked(self: *Sim, a: usize, b: usize) bool {
        const pair: [2]usize = .{ @min(a, b), @max(a, b) };
        for (self.blocked_pairs.items) |existing| {
            if (existing[0] == pair[0] and existing[1] == pair[1]) return true;
        }
        return false;
    }

    /// 不变量 3：任何视图中任何成员的 incarnation 永不回退。
    fn checkIncarnationMonotonic(self: *Sim) void {
        const slice = self.last_incarnations.?;
        for (self.nodes.items, 0..) |*viewer, viewer_index| {
            var it = viewer.swim.view().iterator();
            while (it.next()) |member| {
                const cell = &slice[viewer_index * 64 + member.node_id];
                if (member.incarnation < cell.*) {
                    std.debug.panic(
                        "incarnation 回退：viewer={d} subject={d} {d} -> {d}",
                        .{ viewer_index, member.node_id, cell.*, member.incarnation },
                    );
                }
                cell.* = member.incarnation;
            }
        }
    }
};

fn nodeAddress(node_id: NodeId) net.Address {
    return net.initIp4(.{ 10, 0, 0, @intCast(node_id) }, 7946);
}

// ============================================================================
// 模拟测试：设计文档 §8.2 的不变量
// ============================================================================

const testing = std.testing;

/// 组一个 node_id 为 1..count、全部以节点 1 为种子的集群（星形引导，最接近真实部署）。
fn starCluster(sim: *Sim, count: usize) !void {
    for (1..count + 1) |id| _ = try sim.addNode(@intCast(id), .{});
    for (1..count) |index| try sim.seedWith(index, 0);
}

test "star-seeded cluster converges to full mutual alive views" {
    // 新节点只认识种子节点 1；靠「初始化自宣告 + 搭载 gossip」学习到彼此。
    var sim = Sim.init(testing.allocator, .{ .seed = 7 });
    defer sim.deinit();
    try starCluster(&sim, 4);

    try sim.runMs(30_000);

    // 不变量 4（视图收敛）：每个节点都把其余 3 个标为 alive。
    for (0..4) |viewer| {
        for (1..5) |subject| {
            const subject_id: NodeId = @intCast(subject);
            if (sim.node(viewer).swim.config.node_id == subject_id) continue;
            try testing.expectEqual(membership.NodeStatus.alive, sim.viewStatus(viewer, subject_id).?);
        }
    }
}

test "no responsive node is ever declared dead under 20% packet loss" {
    // 不变量 1（不误杀）：持续丢包只允许造成瞬时 suspect，绝不允许到达 dead。
    var sim = Sim.init(testing.allocator, .{ .seed = 11, .loss_rate = 0.2 });
    defer sim.deinit();
    try starCluster(&sim, 4);

    // 分段推进，每段之后都检查一次（比只查末态更严格）。
    for (0..20) |_| {
        try sim.runMs(5_000);
        for (0..4) |viewer| {
            for (1..5) |subject| {
                const subject_id: NodeId = @intCast(subject);
                if (sim.node(viewer).swim.config.node_id == subject_id) continue;
                const status = sim.viewStatus(viewer, subject_id) orelse continue;
                try testing.expect(status != .dead);
            }
        }
    }
}

test "crashed node is eventually declared dead by every survivor" {
    // 不变量 2（最终发现）：真正死掉的节点在有限时间内被全员标记为 dead。
    var sim = Sim.init(testing.allocator, .{ .seed = 13 });
    defer sim.deinit();
    try starCluster(&sim, 4);

    try sim.runMs(15_000); // 先收敛
    sim.crash(3); // node_id 4 崩溃

    // 上界：协议周期 1s，suspicion 超时 4×log2ceil(4)×1s = 8s，留足传播余量。
    try sim.runMs(40_000);
    for (0..3) |viewer| {
        try testing.expectEqual(membership.NodeStatus.dead, sim.viewStatus(viewer, 4).?);
    }
}

test "frozen node is suspected, then refutes with a higher incarnation" {
    // 反驳链路端到端验证：停顿节点被怀疑 → 解冻后收到怀疑传闻 → 抬升 incarnation
    // 广播 alive → 全员视图回到 alive（这正是防误杀机制的完整闭环）。
    var sim = Sim.init(testing.allocator, .{ .seed = 17 });
    defer sim.deinit();
    try starCluster(&sim, 3);

    try sim.runMs(10_000); // 先收敛
    sim.setFrozen(2, true); // node_id 3 停顿
    try sim.runMs(4_000); // 足够被探测失败并标记 suspect
    try testing.expect(sim.viewStatus(0, 3) == .suspect or sim.viewStatus(1, 3) == .suspect);

    sim.setFrozen(2, false); // 解冻，在 suspicion 超时（8s）之前恢复
    try sim.runMs(20_000);

    for (0..2) |viewer| {
        const member = sim.node(viewer).swim.view().get(3).?;
        try testing.expectEqual(membership.NodeStatus.alive, member.status);
        try testing.expect(member.incarnation >= 1); // 反驳必然抬升过 incarnation
    }
    try testing.expect(sim.node(2).swim.stats.refutations >= 1);
}

test "partitioned halves declare each other dead but stay healthy internally" {
    // 先验证分区期间跨区互判 dead、区内照常服务，再恢复链路并验证 anti-entropy
    // 联系 dead 成员、触发 incarnation 反驳，最终重建全量 alive 视图。
    var sim = Sim.init(testing.allocator, .{ .seed = 19 });
    defer sim.deinit();
    try starCluster(&sim, 4);
    try sim.runMs(15_000); // 先收敛

    // 切断 {节点1,2} 与 {节点3,4} 之间的全部链路。
    for (0..2) |a| {
        for (2..4) |b| try sim.setPartition(a, b, true);
    }
    try sim.runMs(60_000);

    // 跨区互判 dead。
    for (0..2) |viewer| {
        try testing.expectEqual(membership.NodeStatus.dead, sim.viewStatus(viewer, 3).?);
        try testing.expectEqual(membership.NodeStatus.dead, sim.viewStatus(viewer, 4).?);
    }
    for (2..4) |viewer| {
        try testing.expectEqual(membership.NodeStatus.dead, sim.viewStatus(viewer, 1).?);
        try testing.expectEqual(membership.NodeStatus.dead, sim.viewStatus(viewer, 2).?);
    }
    // 区内保持 alive（互相探测正常，不被对侧的死亡传闻污染）。
    try testing.expectEqual(membership.NodeStatus.alive, sim.viewStatus(0, 2).?);
    try testing.expectEqual(membership.NodeStatus.alive, sim.viewStatus(1, 1).?);
    try testing.expectEqual(membership.NodeStatus.alive, sim.viewStatus(2, 4).?);
    try testing.expectEqual(membership.NodeStatus.alive, sim.viewStatus(3, 3).?);

    // 恢复全部跨区链路。anti-entropy 会主动联系 dead 成员，交换全量视图；收到关于
    // 自己的 dead 断言后节点提升 incarnation 反驳，最终两侧重新互认 alive。
    for (0..2) |a| {
        for (2..4) |b| try sim.setPartition(a, b, false);
    }
    try sim.runMs(120_000);
    for (0..4) |viewer| {
        for (1..5) |subject| {
            const subject_id: NodeId = @intCast(subject);
            if (sim.node(viewer).swim.config.node_id == subject_id) continue;
            try testing.expectEqual(membership.NodeStatus.alive, sim.viewStatus(viewer, subject_id).?);
        }
    }
}

test "randomized churn soak: many seeds, no invariant violation" {
    // 小型随机浸泡：不同种子跑多轮「收敛 → 崩溃一个 → 确认发现」，
    // incarnation 单调检查在每个 tick 自动执行。任一失败都可用种子复现。
    for ([_]u64{ 23, 29, 31, 37, 41 }) |seed| {
        var sim = Sim.init(testing.allocator, .{ .seed = seed, .loss_rate = 0.1 });
        defer sim.deinit();
        try starCluster(&sim, 5);

        try sim.runMs(20_000);
        sim.crash(4); // node_id 5
        try sim.runMs(50_000);

        for (0..4) |viewer| {
            try testing.expectEqual(membership.NodeStatus.dead, sim.viewStatus(viewer, 5).?);
        }
    }
}
