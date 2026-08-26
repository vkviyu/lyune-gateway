//! control/membership —— 集群成员管理组件
//!
//! 对上层（迷路包转发、drain、路由元数据传播）暴露稳定的成员视图接口；
//! 协议实现是 SWIM（见 swim.zig），但上层只依赖本文件定义的类型与 Table 的读侧方法，
//! 不感知协议细节，将来替换/升级协议实现无需改动上层。
//!
//! 线程模型（与设计文档 docs/cluster_design.md §5 一致）：
//!   - 写侧：只有 SWIM 协议线程会修改成员表；
//!   - 读侧：数据面线程（转发热路径）通过 Table.lookup 做零锁读取（每槽位 seqlock）。
//!
//! 组成：
//!   - mod.zig       本文件：NodeId/NodeStatus/Member/Params/EventListener/Table
//!   - crypto.zig    HMAC-SHA256 原语与常量时间校验
//!   - codec.zig     gossip 消息编解码与认证标签
//!   - swim.zig      SWIM 纯状态机（不含任何 I/O，可确定性模拟测试）
//!   - transport.zig 非阻塞 UDP socket
//!   - runner.zig    独立协议线程、时钟与 join/leave 命令交接
//!   - sim.zig       确定性内存网络模拟器（仅测试使用）

const std = @import("std");
const foundation = @import("../../foundation/mod.zig");
const net = foundation.net;

pub const crypto = @import("crypto.zig");
pub const codec = @import("codec.zig");
pub const swim = @import("swim.zig");
pub const transport = @import("transport.zig");
pub const runner = @import("runner.zig");
pub const sim = @import("sim.zig");

pub const Swim = swim.Swim;
pub const Transport = transport.Transport;

/// 节点标识。集群内唯一、静态配置分配（见设计文档 §4.2），同时被编码进 CID v1。
pub const NodeId = u16;

/// 0 保留为非法值：CID 中 node_id 为 0 说明布局损坏，配置中为 0 说明未正确配置。
pub const invalid_node_id: NodeId = 0;

/// 成员状态机。合并规则见 swim.zig applyEvent：
/// incarnation 高者胜；同 incarnation 时 left/dead > suspect > alive。
pub const NodeStatus = enum(u8) {
    /// 正常存活，可作为转发目标。
    alive = 0,
    /// 疑似故障（探测超时）。仍然转发——宁可多转一跳，不误杀活节点的连接。
    suspect = 1,
    /// 确认死亡（suspicion 超时未被反驳）。迷路包不再转发给它。
    dead = 2,
    /// 主动优雅下线（drain 广播）。与 dead 的区别：不经过 suspicion 流程。
    left = 3,
};

/// 成员表中一条成员的完整快照（按值拷贝返回，读取方拿到的是一致性副本）。
pub const Member = struct {
    node_id: NodeId,
    /// gossip 通告地址；转发层复用其 IP 并替换为集群统一的 forward_port。
    address: net.Address,
    status: NodeStatus,
    /// SWIM incarnation：节点每次反驳对自己的怀疑时递增，是消息新旧比较的依据。
    incarnation: u32,

    /// 该成员当前是否可作为迷路包转发目标（alive/suspect 都转发，见设计文档 §6.4）。
    pub fn isForwardable(self: Member) bool {
        return self.status == .alive or self.status == .suspect;
    }
};

/// SWIM 协议参数。默认值面向数十节点的网关集群；全部可由配置覆盖。
pub const Params = struct {
    /// 协议周期：每周期随机探测一个成员。
    protocol_period_ms: u64 = 1000,
    /// 直接 ping 的等待超时；超时后转入间接探测（ping-req）。必须小于协议周期。
    probe_timeout_ms: u64 = 500,
    /// 间接探测时委托的成员数量（SWIM 论文的 k）。
    indirect_probes: u8 = 3,
    /// suspicion 超时倍率：超时 = suspicion_mult × log2ceil(N+1) × protocol_period。
    suspicion_mult: u32 = 4,
    /// gossip 事件重传倍率：每条事件最多搭载 retransmit_mult × log2ceil(N+1) 次。
    retransmit_mult: u32 = 4,
    /// 单条消息最多搭载的 gossip 事件数（约束消息体积在单个 UDP 包内）。
    max_piggyback: u8 = 6,
    /// Lifeguard 本地健康倍率上限；超时会在 1..上限之间动态放大。
    lhm_max_multiplier: u8 = 8,
    /// anti-entropy 全量同步周期；为 0 时关闭定期同步。
    sync_interval_ms: u64 = 30_000,
    /// 动态 suspicion 最多使用多少个独立确认来源缩短超时。
    suspicion_confirmations: u8 = 4,

    /// 参数合法性检查，init 时调用。
    pub fn validate(self: Params) error{InvalidParams}!void {
        if (self.protocol_period_ms == 0) return error.InvalidParams;
        if (self.probe_timeout_ms == 0 or self.probe_timeout_ms >= self.protocol_period_ms) return error.InvalidParams;
        if (self.suspicion_mult == 0 or self.retransmit_mult == 0) return error.InvalidParams;
        if (self.max_piggyback == 0 or self.max_piggyback > codec.max_events) return error.InvalidParams;
        if (self.lhm_max_multiplier == 0) return error.InvalidParams;
        if (self.suspicion_confirmations == 0 or self.suspicion_confirmations > 8) return error.InvalidParams;
    }
};

/// 成员状态变更监听器（vtable 类型擦除，风格同 foundation.resolver.Resolver）。
/// 回调在 SWIM 协议线程内同步执行，实现方不得阻塞。
pub const EventListener = struct {
    ptr: *anyopaque,
    onUpdateFn: *const fn (ptr: *anyopaque, member: Member) void,

    /// 在 SWIM 协议线程同步通知一次已接受的成员变化；实现不得阻塞或回入状态机。
    pub fn onUpdate(self: EventListener, member: Member) void {
        self.onUpdateFn(self.ptr, member);
    }
};

/// 成员表：集群成员视图的唯一权威存储，也是上层依赖的「MembershipView」实现。
///
/// 存储用 node_id 直接索引的定长槽位数组（node_id 必须 < max_nodes），
/// 读侧 lookup 是转发热路径，每包一次，因此用 per-slot seqlock 实现零锁读：
/// 写入前把版本号置为奇数、写完置回偶数；读取方前后各读一次版本号，
/// 不一致或为奇数则重试。写侧只有单个 SWIM 线程，seqlock 无写写竞争。
pub const Table = struct {
    allocator: std.mem.Allocator,
    slots: []Slot,
    /// 已占用槽位数（含 dead/left），只由写线程维护/读取。
    used_count: u16 = 0,
    /// alive + suspect 的成员数，用于 log2 缩放与探测轮转，只由写线程维护/读取。
    active_count: u16 = 0,

    const Slot = struct {
        /// 单调递增的发布序号；0 表示该槽从未被写入。
        /// 低位用于选择活跃缓冲，写者先写非活跃缓冲再递增序号发布。
        sequence: std.atomic.Value(u32) = .init(0),
        buffers: [buffer_count]Data = @splat(.{}),

        /// 发布缓冲个数。
        ///
        /// 这里用"多缓冲发布"而不是 seqlock：seqlock 需要读者在两次版本读
        /// 之间读取非原子字段，而 address 是 tagged union，无法原子化，
        /// 只能依赖编译器不重排——实测在并发压力下会读到跨写入周期的混合状态。
        /// 多缓冲发布让写者永远不触碰读者正在读的那份数据，因此读侧无需重试，
        /// 也不存在撕裂。缓冲取 4 份，读者必须慢过 4 次连续 upsert 才可能
        /// 被追上；upsert 由 SWIM 协议驱动（毫秒到秒级），读侧只有几条指令。
        const buffer_count = 4;

        const Data = struct {
            used: bool = false,
            address: net.Address = undefined,
            status: NodeStatus = .alive,
            incarnation: u32 = 0,
        };

        /// 返回当前已发布的数据；从未写入时返回 null。
        /// ordering 由调用方按读侧/写侧选择。
        fn published(self: *const Slot, comptime ordering: std.builtin.AtomicOrder) ?*const Data {
            const seq = self.sequence.load(ordering);
            if (seq == 0) return null;
            return &self.buffers[seq % buffer_count];
        }
    };

    /// upsert 的结果，供调用方决定是否通知监听器/重新 gossip。
    pub const UpsertResult = enum { inserted, updated };

    /// 分配按 node_id 直接索引的固定容量成员表。
    pub fn init(allocator: std.mem.Allocator, max_nodes: u16) !Table {
        if (max_nodes == 0) return error.InvalidMaxNodes;
        const slots = try allocator.alloc(Slot, max_nodes);
        for (slots) |*slot| slot.* = .{};
        return .{ .allocator = allocator, .slots = slots };
    }

    /// 释放全部槽位；调用前必须停止唯一写线程和并发读者。
    pub fn deinit(self: *Table) void {
        self.allocator.free(self.slots);
        self.* = undefined;
    }

    /// 容量上限（node_id 必须小于此值）。
    pub fn capacity(self: *const Table) u16 {
        return @intCast(self.slots.len);
    }

    /// 【读侧，任意线程】按 node_id 查成员，返回一致性快照；未知节点返回 null。
    /// 转发热路径专用：无锁，两次 acquire 读 + 一次结构体拷贝。
    ///
    /// 正确性依据：写者按序号轮转写入非活跃缓冲，要覆盖读者刚读的那一份，
    /// 必须推进整整 buffer_count 次。因此只要前后两次序号之差小于
    /// buffer_count，读到的就是某一次 upsert 的完整快照。序号差达到或超过
    /// buffer_count 说明读者被追上，重试即可（生产中 upsert 由 SWIM 驱动，
    /// 频率远低于一次结构体拷贝，这条分支实际不会命中）。
    pub fn lookup(self: *const Table, node_id: NodeId) ?Member {
        if (node_id == invalid_node_id or node_id >= self.slots.len) return null;
        const slot = &self.slots[node_id];
        while (true) {
            const first = slot.sequence.load(.acquire);
            if (first == 0) return null;
            const data = slot.buffers[first % Slot.buffer_count];
            const second = slot.sequence.load(.acquire);
            if (second -% first >= Slot.buffer_count) {
                std.atomic.spinLoopHint();
                continue;
            }
            if (!data.used) return null;
            return .{
                .node_id = node_id,
                .address = data.address,
                .status = data.status,
                .incarnation = data.incarnation,
            };
        }
    }

    /// 【写侧，仅 SWIM 线程】按 node_id 读当前值；写线程读自己发布的数据，无需 acquire。
    pub fn get(self: *const Table, node_id: NodeId) ?Member {
        if (node_id == invalid_node_id or node_id >= self.slots.len) return null;
        const data = self.slots[node_id].published(.monotonic) orelse return null;
        if (!data.used) return null;
        return .{
            .node_id = node_id,
            .address = data.address,
            .status = data.status,
            .incarnation = data.incarnation,
        };
    }

    /// 【写侧，仅 SWIM 线程】插入或更新一条成员记录。
    /// 只负责存储与计数，状态迁移的合法性由调用方（swim.zig 合并规则）保证。
    pub fn upsert(self: *Table, member: Member) !UpsertResult {
        if (member.node_id == invalid_node_id) return error.InvalidNodeId;
        if (member.node_id >= self.slots.len) return error.NodeIdOutOfRange;
        const slot = &self.slots[member.node_id];
        const current = slot.published(.monotonic);
        const inserted = current == null or !current.?.used;

        // 维护 active_count：进入/离开 {alive, suspect} 集合时增减。
        const was_active = if (current) |data|
            data.used and (data.status == .alive or data.status == .suspect)
        else
            false;
        const now_active = member.status == .alive or member.status == .suspect;

        // 多缓冲发布：先整体写入下一个非活跃缓冲，再用 release 递增序号。
        // 读者要么看到旧序号（读到旧缓冲的完整快照），要么看到新序号
        // （读到新缓冲的完整快照），不存在中间状态，因此读侧无需重试。
        const seq = slot.sequence.load(.monotonic);
        const next = seq +% 1;
        slot.buffers[next % Slot.buffer_count] = .{
            .used = true,
            .address = member.address,
            .status = member.status,
            .incarnation = member.incarnation,
        };
        slot.sequence.store(next, .release);

        if (inserted) self.used_count += 1;
        if (was_active and !now_active) self.active_count -= 1;
        if (!was_active and now_active) self.active_count += 1;
        return if (inserted) .inserted else .updated;
    }

    /// 【写侧，仅 SWIM 线程】遍历所有已占用槽位。
    pub fn iterator(self: *const Table) Iterator {
        return .{ .table = self };
    }

    /// 单写协议线程使用的成员遍历器；不提供并发读快照语义，数据面应使用 lookup/snapshot。
    pub const Iterator = struct {
        table: *const Table,
        next_id: usize = 0,

        /// 返回下一条已占用成员记录，遍历结束返回 null。
        pub fn next(self: *Iterator) ?Member {
            while (self.next_id < self.table.slots.len) {
                const id: NodeId = @intCast(self.next_id);
                self.next_id += 1;
                if (self.table.get(id)) |member| return member;
            }
            return null;
        }
    };

    /// 【读侧，任意线程】全量快照（诊断/管理接口用），调用方负责释放返回的切片。
    pub fn snapshot(self: *const Table, allocator: std.mem.Allocator) ![]Member {
        var list: std.ArrayList(Member) = .empty;
        errdefer list.deinit(allocator);
        for (0..self.slots.len) |id| {
            if (self.lookup(@intCast(id))) |member| try list.append(allocator, member);
        }
        return list.toOwnedSlice(allocator);
    }
};

test {
    @import("std").testing.refAllDecls(@This());
}

test "table lookup/upsert roundtrip and counts" {
    var table = try Table.init(std.testing.allocator, 16);
    defer table.deinit();

    const addr = net.initIp4(.{ 10, 0, 0, 1 }, 7946);
    try std.testing.expect(table.lookup(3) == null);

    try std.testing.expectEqual(Table.UpsertResult.inserted, try table.upsert(.{
        .node_id = 3,
        .address = addr,
        .status = .alive,
        .incarnation = 0,
    }));
    try std.testing.expectEqual(@as(u16, 1), table.used_count);
    try std.testing.expectEqual(@as(u16, 1), table.active_count);

    const member = table.lookup(3).?;
    try std.testing.expectEqual(NodeStatus.alive, member.status);
    try std.testing.expect(member.isForwardable());

    // 转为 dead：active_count 归零，used_count 不变，不再可转发。
    try std.testing.expectEqual(Table.UpsertResult.updated, try table.upsert(.{
        .node_id = 3,
        .address = addr,
        .status = .dead,
        .incarnation = 1,
    }));
    try std.testing.expectEqual(@as(u16, 1), table.used_count);
    try std.testing.expectEqual(@as(u16, 0), table.active_count);
    try std.testing.expect(!table.lookup(3).?.isForwardable());
}

test "table rejects invalid node ids" {
    var table = try Table.init(std.testing.allocator, 4);
    defer table.deinit();
    const addr = net.initIp4(.{ 10, 0, 0, 1 }, 7946);

    try std.testing.expectError(error.InvalidNodeId, table.upsert(.{ .node_id = 0, .address = addr, .status = .alive, .incarnation = 0 }));
    try std.testing.expectError(error.NodeIdOutOfRange, table.upsert(.{ .node_id = 4, .address = addr, .status = .alive, .incarnation = 0 }));
    try std.testing.expect(table.lookup(0) == null);
    try std.testing.expect(table.lookup(9999) == null);
}

test "lookup returns self-consistent snapshots under concurrent writes" {
    var table = try Table.init(std.testing.allocator, 4);
    defer table.deinit();

    // 写线程让 incarnation、address 的两个字节、port、status 保持固定关系。
    // 读者若拿到不满足该关系的组合，说明它看到了 seqlock 临界区内的中间状态。
    const Writer = struct {
        table: *Table,
        stop: std.atomic.Value(bool) = .init(false),

        fn run(self: *@This()) void {
            var counter: u32 = 1;
            while (!self.stop.load(.acquire)) : (counter +%= 1) {
                const tag: u8 = @truncate(counter);
                _ = self.table.upsert(.{
                    .node_id = 1,
                    .address = net.initIp4(.{ 10, 0, tag, tag }, tag),
                    .status = if (tag % 2 == 0) .alive else .suspect,
                    .incarnation = tag,
                }) catch return;
            }
        }
    };

    var writer: Writer = .{ .table = &table };
    const thread = try std.Thread.spawn(.{}, Writer.run, .{&writer});
    defer {
        writer.stop.store(true, .release);
        thread.join();
    }

    var round: usize = 0;
    while (round < 200_000) : (round += 1) {
        const member = table.lookup(1) orelse continue;
        const tag: u8 = @truncate(member.incarnation);
        try std.testing.expectEqual(tag, member.address.ip4.bytes[2]);
        try std.testing.expectEqual(tag, member.address.ip4.bytes[3]);
        try std.testing.expectEqual(@as(u16, tag), member.address.ip4.port);
        const expected: NodeStatus = if (tag % 2 == 0) .alive else .suspect;
        try std.testing.expectEqual(expected, member.status);
    }
}
