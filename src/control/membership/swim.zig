//! SWIM 成员协议纯状态机
//!
//! 实现 SWIM（Scalable Weakly-consistent Infection-style Process Group Membership）
//! 的核心状态机：随机轮转探测（ping）、k 委托间接探测（ping-req）、怀疑与反驳
//! （suspect / alive + incarnation）、搭载式 gossip 传播（piggyback）。
//!
//! 设计上的硬约束：本文件【不做任何 I/O、不读系统时钟、不用全局随机源】。
//!   - 输入：handleMessage(收到的字节) 与 tick(当前毫秒时刻)；
//!   - 输出：outbox 里待发送的编码帧 + 通过 EventListener 通知的视图变更。
//! 随机性来自 init 注入的种子。因此给定相同的输入序列，行为完全可复现——
//! 这是 sim.zig 确定性模拟测试的前提（设计文档 §8）。
//!
//! 状态机包含 anti-entropy 分片全量同步、Lifeguard 三项扩展、HMAC 双密钥认证、
//! 有界重放缓存、join/left 与静态 node_id 地址冲突检测。真实时钟和 UDP I/O 由
//! runner.zig 单线程驱动；Coordinator 负责 runner 与节点间转发隧道的进程级装配。

const std = @import("std");
const membership = @import("mod.zig");
const codec = @import("codec.zig");
const foundation = @import("../../foundation/mod.zig");
const net = foundation.net;

const NodeId = membership.NodeId;
const Table = membership.Table;

/// 一帧待发送的编码消息。定长内联存储，无堆分配，可按值放入 outbox。
pub const Outgoing = struct {
    to: net.Address,
    len: u16,
    data: [codec.max_message_size]u8 = undefined,

    /// 返回当前帧的有效字节；切片借用 Outgoing 的内联存储。
    pub fn bytes(self: *const Outgoing) []const u8 {
        return self.data[0..self.len];
    }
};

/// 状态机配置。
pub const Config = struct {
    /// 本节点 id（集群内唯一，静态配置）。
    node_id: NodeId,
    /// 本节点对外通告的 gossip 地址；转发层复用其 IP 并替换为 forward_port。
    address: net.Address,
    /// 成员表容量上限，node_id 必须小于此值。
    max_nodes: u16 = 1024,
    /// 随机种子：生产环境用随机值，模拟测试用固定值以保证可复现。
    seed: u64,
    /// gossip 当前预共享密钥；为空表示单机/开发模式不启用认证。
    secret: []const u8 = &.{},
    /// 轮换期旧密钥，仅用于验收入站消息；发送始终使用 secret。
    previous_secret: []const u8 = &.{},
    params: membership.Params = .{},
};

/// 已认证成员消息暴露出的 node_id 地址冲突。
///
/// node_id 是静态唯一身份；继续运行会让 CID 转发目标不确定，因此真实 runner 必须 fail-fast。
pub const IdentityConflict = struct {
    node_id: NodeId,
    expected_address: net.Address,
    observed_address: net.Address,
};

/// 可观测计数器。只增不减，由协议线程写，诊断路径读（不要求严格同步）。
pub const Stats = struct {
    /// 解码失败而被丢弃的入站消息数（含畸形包与版本不符）。
    decode_failures: u64 = 0,
    /// HMAC 校验失败而被丢弃的消息数。
    auth_failures: u64 = 0,
    /// 发起的直接探测次数。
    probes_sent: u64 = 0,
    /// 对「关于自己的怀疑/死亡断言」的反驳次数。
    refutations: u64 = 0,
    /// 合并规则接受（引起视图变化）的 gossip 事件数。
    events_accepted: u64 = 0,
    /// 发出的消息帧总数。
    messages_sent: u64 = 0,
    /// 发起的 anti-entropy 全量同步次数。
    syncs_started: u64 = 0,
    /// 接收的 anti-entropy 响应分片数。
    sync_chunks_received: u64 = 0,
    /// Buddy System 主动发给被怀疑节点的通知数。
    buddy_notifications: u64 = 0,
    /// 物理源地址与静态身份不匹配而被丢弃的消息数。
    ///
    /// 这类不匹配不进入 fail-fast：源地址不在 HMAC 覆盖范围内，攻击者可以
    /// 从任意地址重放捕获到的合法报文来伪造它。多网卡、容器重调度、NAT 后
    /// 的 gossip 也会正常触发。作为告警信号观察即可。
    address_mismatches: u64 = 0,
    /// 本地健康倍率增加次数。
    health_penalties: u64 = 0,
    /// 本地健康倍率恢复次数。
    health_recoveries: u64 = 0,
};

/// 在途直接探测的状态。每个协议周期至多一个。
const Probe = struct {
    target: NodeId,
    seq: u32,
    /// 直接 ping 的应答截止时刻；超时后转入间接探测。
    direct_deadline: u64,
    /// 协议周期结束时刻；到点仍无应答则本地断言 suspect。
    period_deadline: u64,
    indirect_sent: bool = false,
};

/// 间接探测的中转登记：收到 ping-req 后代发 ping，等 target 的 ack 回来再转发给请求方。
const Relay = struct {
    requester_address: net.Address,
    target: NodeId,
    /// 请求方原始探测序号（转发 ack 时原样带回）。
    original_seq: u32,
    /// 本节点代发 ping 使用的序号（用于匹配 target 的 ack）。
    relay_seq: u32,
    deadline: u64,
};

/// 待传播的 gossip 事件及其剩余搭载次数。
const GossipEntry = struct {
    event: codec.Event,
    transmits_left: u32,
};

const Suspicion = struct {
    started_at: u64,
    deadline: u64,
    confirmations: u8 = 0,
    /// 已计入该 suspicion 的独立发送者，避免同一来源重复缩短超时。
    sources: [8]NodeId = undefined,
    source_count: u8 = 0,
};

const SyncSession = struct {
    peer: NodeId,
    next_id: NodeId = 1,
    deadline: u64,
};

const replay_cache_capacity = 128;
const ReplayEntry = struct {
    sender: NodeId,
    tag: [codec.auth_tag_size]u8,
};

/// 间接探测委托数与中转表的硬上限。
const max_indirect_probes = 8;
const relay_capacity = 16;

/// 单写者 SWIM 状态机。
/// 调用方必须串行执行 tick/handleMessage/join/leave；Table.lookup 可由数据面线程并发读取。
pub const Swim = struct {
    allocator: std.mem.Allocator,
    config: Config,
    /// 集群成员视图（不含本节点自身）。读侧接口见 Table.lookup。
    table: Table,
    /// 本节点 incarnation：每次反驳对自己的怀疑时递增。
    incarnation: u32 = 0,
    /// 优雅离开后保持 left，后续同步和怀疑处理不得把自己复活。
    has_left: bool = false,
    /// 首个已认证身份冲突；真实 runner 观察到后终止进程。
    identity_conflict: ?IdentityConflict = null,
    /// 探测序号计数器（直接探测与代发探测共用，保证本节点内唯一）。
    seq_counter: u32 = 0,
    rng: std.Random.DefaultPrng,
    /// 待发送帧。调用方每轮 tick/handleMessage 后取走并清空（pendingOutgoing/clearOutgoing）。
    outbox: std.ArrayList(Outgoing) = .empty,
    /// gossip 传播队列：每个 node_id 至多一条（新事件覆盖旧事件）。
    gossip_queue: std.ArrayList(GossipEntry) = .empty,
    /// 随机化轮转探测顺序（SWIM 论文 §4.3：轮转保证有界的故障发现时间）。
    probe_order: std.ArrayList(NodeId) = .empty,
    probe_cursor: usize = 0,
    probe: ?Probe = null,
    /// 间接探测中转表。定长、惰性过期，写满时覆盖最旧的槽位。
    relays: [relay_capacity]?Relay = @splat(null),
    relay_next: usize = 0,
    /// 按 node_id 索引的 suspicion 状态；到点仍未被反驳则断言 dead。
    suspicions: []?Suspicion,
    /// Lifeguard Local Health Multiplier，范围为 1..params.lhm_max_multiplier。
    health_multiplier: u8 = 1,
    /// anti-entropy 的下一次调度时刻。
    next_sync_at: u64 = 0,
    sync: ?SyncSession = null,
    /// 已认证报文的有限重放缓存；只由协议线程访问。
    replay_cache: [replay_cache_capacity]?ReplayEntry = @splat(null),
    replay_next: usize = 0,
    /// 下一个协议周期的开始时刻。
    next_period_at: u64 = 0,
    listener: ?membership.EventListener = null,
    stats: Stats = .{},

    /// 初始化确定性状态机并把本节点 alive 事件加入传播队列；不创建线程或 socket。
    pub fn init(allocator: std.mem.Allocator, config: Config) !Swim {
        try config.params.validate();
        if (config.node_id == membership.invalid_node_id) return error.InvalidNodeId;
        if (config.node_id >= config.max_nodes) return error.NodeIdOutOfRange;
        if (config.params.indirect_probes > max_indirect_probes) return error.InvalidParams;

        var table = try Table.init(allocator, config.max_nodes);
        errdefer table.deinit();
        const suspicions = try allocator.alloc(?Suspicion, config.max_nodes);
        errdefer allocator.free(suspicions);
        @memset(suspicions, null);

        var self: Swim = .{
            .allocator = allocator,
            .config = config,
            .table = table,
            .rng = std.Random.DefaultPrng.init(config.seed),
            .suspicions = suspicions,
            .next_sync_at = config.params.sync_interval_ms,
        };
        // 把自己的 alive 事件放进传播队列：新节点向种子发起首次探测时，
        // 对方就能从搭载事件里学到我们的 node_id 与地址（最小化的接入通告）。
        try self.queueGossip(self.selfEvent(.alive));
        return self;
    }

    /// 释放成员表、suspicion 槽位及协议队列；调用前不得再有写侧操作。
    pub fn deinit(self: *Swim) void {
        self.outbox.deinit(self.allocator);
        self.gossip_queue.deinit(self.allocator);
        self.probe_order.deinit(self.allocator);
        self.allocator.free(self.suspicions);
        self.table.deinit();
        self.* = undefined;
    }

    /// 注册成员变更监听器（回调在协议线程内同步执行，不得阻塞）。
    pub fn setListener(self: *Swim, listener: ?membership.EventListener) void {
        self.listener = listener;
    }

    /// 向一个静态种子发起 join。响应使用 anti-entropy 全量同步填充本地视图。
    /// 传输层只需把 pendingOutgoing 投递出去；没有 seeds 时该方法不会被调用。
    pub fn joinSeed(self: *Swim, address: net.Address) !void {
        self.sync = .{ .peer = membership.invalid_node_id, .deadline = self.scaledProtocolPeriod() };
        self.stats.syncs_started += 1;
        try self.sendSyncRequest(address, 1);
    }

    /// 广播优雅下线事件。left 不会被普通 gossip 的 alive 重新覆盖，
    /// 只有后续 join/重新加入并使用更高 incarnation 才能恢复。
    pub fn leave(self: *Swim) !void {
        if (self.has_left) return;
        self.has_left = true;
        self.incarnation +%= 1;
        const event = self.selfEvent(.left);
        try self.queueGossip(event);
        // 用一次控制消息立即把 left 带给当前成员，而不是等待下一轮探测。
        var it = self.table.iterator();
        while (it.next()) |member| {
            if (member.status != .left) try self.send(.ack, self.config.node_id, 0, 0, member.address);
        }
    }

    /// 注入静态种子成员（配置的 seeds 列表）。incarnation 从 0 起，
    /// 与对方节点的初始 incarnation 一致，保证怀疑/反驳的比较基准对齐。
    pub fn addPeer(self: *Swim, node_id: NodeId, address: net.Address) !void {
        if (node_id == self.config.node_id) return error.InvalidNodeId;
        const member: membership.Member = .{
            .node_id = node_id,
            .address = address,
            .status = .alive,
            .incarnation = 0,
        };
        _ = try self.table.upsert(member);
        self.notifyListener(member);
    }

    /// 集群成员只读视图（上层转发路径经由 Table.lookup 消费）。
    pub fn view(self: *const Swim) *const Table {
        return &self.table;
    }

    /// 待发送帧的只读切片。调用方发送完毕后必须调用 clearOutgoing。
    pub fn pendingOutgoing(self: *const Swim) []const Outgoing {
        return self.outbox.items;
    }

    /// 清空已由传输层消费的待发送帧，同时保留容量供后续协议周期复用。
    pub fn clearOutgoing(self: *Swim) void {
        self.outbox.clearRetainingCapacity();
    }

    /// 返回首次检测到的 node_id 地址冲突；冲突一旦出现便保持到状态机销毁。
    pub fn identityConflict(self: *const Swim) ?IdentityConflict {
        return self.identity_conflict;
    }

    // ========================================================================
    // 时间驱动：协议周期、探测超时、suspicion 超时
    // ========================================================================

    /// 推进协议时钟。now_ms 必须单调不减（同一毫秒可重复调用）。
    /// 建议调用频率不低于 probe_timeout 的一半，保证超时判定及时。
    pub fn tick(self: *Swim, now_ms: u64) !void {
        try self.expireSuspicions(now_ms);
        try self.driveProbe(now_ms);
        try self.driveAntiEntropy(now_ms);
        if (self.probe == null and now_ms >= self.next_period_at) {
            self.next_period_at = now_ms + self.scaledProtocolPeriod();
            try self.startProbe(now_ms);
        }
    }

    /// suspicion 到期仍未被反驳的成员，本地断言 dead 并向全集群传播。
    fn expireSuspicions(self: *Swim, now_ms: u64) !void {
        for (self.suspicions, 0..) |suspicion, id| {
            if (suspicion == null or now_ms < suspicion.?.deadline) continue;
            self.suspicions[id] = null;
            const member = self.table.get(@intCast(id)) orelse continue;
            if (member.status != .suspect) continue;
            try self.applyEvent(now_ms, .{
                .node_id = member.node_id,
                .status = .dead,
                .incarnation = member.incarnation,
                .address = member.address,
            });
        }
    }

    /// 推进在途探测：直接超时 → 发起间接探测；周期结束仍无应答 → 断言 suspect。
    fn driveProbe(self: *Swim, now_ms: u64) !void {
        if (self.probe == null) return;
        const probe = &self.probe.?;

        if (!probe.indirect_sent and now_ms >= probe.direct_deadline) {
            probe.indirect_sent = true;
            try self.sendIndirectProbes(probe.target, probe.seq);
        }

        if (now_ms >= probe.period_deadline) {
            const target = probe.target;
            // 注意：置空后 probe 指针即失效，后续只使用局部拷贝的 target。
            self.probe = null;
            self.penalizeHealth();
            const member = self.table.get(target) orelse return;
            if (member.status == .alive) {
                // 直接与间接探测全部失败：本地断言 suspect，等待对方反驳或超时判死。
                try self.applyEvent(now_ms, .{
                    .node_id = member.node_id,
                    .status = .suspect,
                    .incarnation = member.incarnation,
                    .address = member.address,
                });
                try self.sendBuddyNotification(member);
            }
        }
    }

    /// 开启新一轮探测：按随机化轮转顺序选取下一个 alive/suspect 成员。
    fn startProbe(self: *Swim, now_ms: u64) !void {
        const member = try self.nextProbeTarget() orelse return;
        self.seq_counter +%= 1;
        self.probe = .{
            .target = member.node_id,
            .seq = self.seq_counter,
            .direct_deadline = now_ms + self.scaledProbeTimeout(),
            .period_deadline = now_ms + self.scaledProtocolPeriod(),
        };
        self.stats.probes_sent += 1;
        try self.send(.ping, self.config.node_id, self.seq_counter, 0, member.address);
    }

    /// 轮转取下一个可探测成员；一轮走完后重建并重新洗牌。
    fn nextProbeTarget(self: *Swim) !?membership.Member {
        // 至多两轮：第一轮把游标走到头，第二轮用重建后的顺序。
        for (0..2) |_| {
            while (self.probe_cursor < self.probe_order.items.len) {
                const id = self.probe_order.items[self.probe_cursor];
                self.probe_cursor += 1;
                const member = self.table.get(id) orelse continue;
                if (member.status == .alive or member.status == .suspect) return member;
            }
            try self.rebuildProbeOrder();
            if (self.probe_order.items.len == 0) return null;
        }
        return null;
    }

    fn rebuildProbeOrder(self: *Swim) !void {
        self.probe_order.clearRetainingCapacity();
        self.probe_cursor = 0;
        var it = self.table.iterator();
        while (it.next()) |member| {
            if (member.status == .alive or member.status == .suspect) {
                try self.probe_order.append(self.allocator, member.node_id);
            }
        }
        self.rng.random().shuffle(NodeId, self.probe_order.items);
    }

    /// 委托 k 个随机成员间接探测 target（蓄水池采样，避免临时分配）。
    fn sendIndirectProbes(self: *Swim, target: NodeId, seq: u32) !void {
        const k = self.config.params.indirect_probes;
        var chosen: [max_indirect_probes]membership.Member = undefined;
        var count: usize = 0;
        var seen: usize = 0;

        var it = self.table.iterator();
        while (it.next()) |member| {
            if (member.node_id == target) continue;
            if (member.status != .alive and member.status != .suspect) continue;
            seen += 1;
            if (count < k) {
                chosen[count] = member;
                count += 1;
            } else {
                const j = self.rng.random().intRangeLessThan(usize, 0, seen);
                if (j < k) chosen[j] = member;
            }
        }
        for (chosen[0..count]) |helper| {
            try self.send(.ping_req, self.config.node_id, seq, target, helper.address);
        }
    }

    // ========================================================================
    // 消息处理
    // ========================================================================

    /// 处理一条入站消息。解码失败静默丢弃并计数（网络输入不可信，不上抛）。
    /// 返回错误仅代表内存分配失败。
    pub fn handleMessage(self: *Swim, now_ms: u64, from: net.Address, bytes: []const u8) !void {
        const message = if (self.config.secret.len == 0)
            codec.decode(bytes) catch {
                self.stats.decode_failures += 1;
                return;
            }
        else blk: {
            const authenticated = codec.decodeAuthenticatedWithFallback(bytes, self.config.secret, self.config.previous_secret) catch |err| {
                switch (err) {
                    error.InvalidAuthTag, error.MissingAuthTag, error.SecretTooShort => self.stats.auth_failures += 1,
                    else => self.stats.decode_failures += 1,
                }
                return;
            };
            const tag_start = bytes.len - codec.auth_tag_size;
            var tag: [codec.auth_tag_size]u8 = undefined;
            @memcpy(&tag, bytes[tag_start..]);
            if (!self.acceptReplay(authenticated.sender, tag)) {
                self.stats.auth_failures += 1;
                return;
            }
            break :blk authenticated;
        };
        // 物理源地址不在 HMAC 覆盖范围内：攻击者可以从任意地址重放捕获到的
        // 合法报文，让接收方误判身份冲突。因此这里只丢弃报文并计数，
        // 绝不据此触发 fail-fast。真正的 node_id 克隆由 applyEventFrom
        // 基于已认证的事件内容判定。
        if (message.sender == self.config.node_id) {
            if (!std.meta.eql(self.config.address, from)) self.stats.address_mismatches += 1;
            return;
        }
        // relay ACK 保留逻辑目标为 sender，却由 helper 的地址发出，不能用源地址校验。
        // 其余消息的 sender 就是物理发送者，可检查静态 node_id 的地址绑定。
        if (message.type != .ack) {
            if (self.table.get(message.sender)) |known_sender| {
                if (!std.meta.eql(known_sender.address, from)) {
                    self.stats.address_mismatches += 1;
                    return;
                }
            }
        }

        // 先合并搭载的成员事件——任何消息都是 gossip 的载体。
        for (message.events()) |event| try self.applyEventFrom(now_ms, event, message.sender);

        switch (message.type) {
            .ping => try self.send(.ack, self.config.node_id, message.seq, 0, from),
            .ping_req => try self.handlePingReq(now_ms, from, message),
            .ack => try self.handleAck(now_ms, message),
            .sync => try self.handleSync(now_ms, from, message),
        }
    }

    fn acceptReplay(self: *Swim, sender: NodeId, tag: [codec.auth_tag_size]u8) bool {
        for (self.replay_cache) |entry| {
            if (entry) |cached| {
                if (cached.sender == sender and std.mem.eql(u8, &cached.tag, &tag)) return false;
            }
        }
        self.replay_cache[self.replay_next] = .{ .sender = sender, .tag = tag };
        self.replay_next = (self.replay_next + 1) % replay_cache_capacity;
        return true;
    }

    /// 代发探测：登记中转项，用自己的序号 ping target。
    fn handlePingReq(self: *Swim, now_ms: u64, from: net.Address, message: codec.Message) !void {
        const target = self.table.get(message.target) orelse return;
        self.seq_counter +%= 1;
        const relay_index = self.selectRelaySlot(now_ms);
        self.relays[relay_index] = .{
            .requester_address = from,
            .target = message.target,
            .original_seq = message.seq,
            .relay_seq = self.seq_counter,
            .deadline = now_ms + self.config.params.probe_timeout_ms,
        };
        try self.send(.ping, self.config.node_id, self.seq_counter, 0, target.address);
    }

    /// 优先复用空槽，其次回收过期项；只有所有 relay 都有效时才按环形指针牺牲一项。
    fn selectRelaySlot(self: *Swim, now_ms: u64) usize {
        var expired_index: ?usize = null;
        for (0..relay_capacity) |offset| {
            const index = (self.relay_next + offset) % relay_capacity;
            const relay = self.relays[index] orelse {
                self.relay_next = (index + 1) % relay_capacity;
                return index;
            };
            if (expired_index == null and now_ms > relay.deadline) expired_index = index;
        }

        const index = expired_index orelse self.relay_next;
        self.relay_next = (index + 1) % relay_capacity;
        return index;
    }

    fn handleAck(self: *Swim, now_ms: u64, message: codec.Message) !void {
        // 情形一：应答的是本节点在途的直接探测。
        if (self.probe) |probe| {
            if (probe.seq == message.seq and probe.target == message.sender) {
                self.probe = null;
                self.recoverHealth();
                return;
            }
        }
        // 情形二：应答的是本节点代发的探测，把 ack 转回原请求方。
        // 转发帧的 sender 保持为 target（ack 的逻辑发出者），请求方按 (seq, sender) 匹配。
        for (&self.relays) |*slot| {
            const relay = slot.* orelse continue;
            if (relay.relay_seq != message.seq or relay.target != message.sender) continue;
            slot.* = null;
            if (now_ms > relay.deadline) return; // 迟到的 ack，请求方早已超时，转发无意义
            try self.send(.ack, message.sender, relay.original_seq, 0, relay.requester_address);
            return;
        }
    }

    // ========================================================================
    // 合并规则：SWIM 的正确性核心
    // ========================================================================

    /// 记录地址不一致的静态身份；返回 true 表示本次观察构成冲突。
    ///
    /// 只允许由 applyEventFrom 调用，输入必须是已通过 HMAC 校验的事件内容
    /// （event.address），不能是物理 UDP 源地址。源地址不在认证覆盖范围内，
    /// 用它驱动 fail-fast 等于把进程退出的开关交给任何能重放报文的人。
    fn noteIdentityConflict(self: *Swim, node_id: NodeId, expected: net.Address, observed: net.Address) bool {
        if (std.meta.eql(expected, observed)) return false;
        if (self.identity_conflict == null) {
            self.identity_conflict = .{
                .node_id = node_id,
                .expected_address = expected,
                .observed_address = observed,
            };
        }
        return true;
    }

    /// 把一条成员事件合并进本地视图。
    /// 比较规则：incarnation 高者胜；同 incarnation 时 left/dead > suspect > alive。
    /// 被接受的事件会重新进入传播队列（感染式扩散）。
    fn applyEvent(self: *Swim, now_ms: u64, event: codec.Event) !void {
        return self.applyEventFrom(now_ms, event, null);
    }

    fn applyEventFrom(self: *Swim, now_ms: u64, event: codec.Event, source: ?NodeId) !void {
        if (event.node_id == self.config.node_id) {
            if (self.noteIdentityConflict(event.node_id, self.config.address, event.address)) return;
            return self.handleSelfEvent(event);
        }
        if (event.node_id == membership.invalid_node_id) return;
        if (event.node_id >= self.config.max_nodes) return;

        const current = self.table.get(event.node_id);
        if (current) |member| {
            if (self.noteIdentityConflict(event.node_id, member.address, event.address)) return;
        }
        const accepted = switch (event.status) {
            .alive => blk: {
                // alive 需要严格更高的 incarnation 才能覆盖既有状态（含反驳 suspect、
                // 复活 dead/left——即带新 incarnation 的重新加入）；全新成员直接接纳。
                if (current == null) break :blk true;
                break :blk event.incarnation > current.?.incarnation;
            },
            .suspect => blk: {
                if (current == null) break :blk true; // 未知成员的怀疑也采纳，地址随事件学习
                if (event.incarnation > current.?.incarnation) break :blk true;
                break :blk event.incarnation == current.?.incarnation and current.?.status == .alive;
            },
            .dead, .left => blk: {
                // dead/left 是本 incarnation 的终态：同代即可覆盖 alive/suspect。
                // 对未知成员的死亡断言直接忽略（本来就不认识，接纳只会造成幽灵条目）。
                if (current == null) break :blk false;
                if (current.?.status == event.status) break :blk false;
                break :blk event.incarnation >= current.?.incarnation;
            },
        };
        if (!accepted) {
            if (event.status == .suspect and source != null) {
                if (current) |member| {
                    if (member.status == .suspect and member.incarnation == event.incarnation) {
                        self.confirmSuspicion(now_ms, event.node_id, source.?);
                    }
                }
            }
            return;
        }

        const member: membership.Member = .{
            .node_id = event.node_id,
            .address = if (current) |c| c.address else event.address,
            .status = event.status,
            .incarnation = event.incarnation,
        };
        _ = try self.table.upsert(member);
        self.stats.events_accepted += 1;

        // suspicion 计时器随状态迁移开启/关闭。
        if (event.status == .suspect) {
            if (self.suspicions[event.node_id] == null) {
                self.suspicions[event.node_id] = .{
                    .started_at = now_ms,
                    .deadline = now_ms + self.suspicionTimeout(),
                    .sources = @splat(0),
                    .source_count = 0,
                };
            }
            self.confirmSuspicion(now_ms, event.node_id, source orelse self.config.node_id);
        } else {
            self.suspicions[event.node_id] = null;
        }

        try self.queueGossip(.{
            .node_id = member.node_id,
            .status = member.status,
            .incarnation = member.incarnation,
            .address = member.address,
        });
        self.notifyListener(member);
    }

    /// 按独立来源收集 suspect 确认；确认越多，剩余等待窗口越短。
    fn confirmSuspicion(self: *Swim, now_ms: u64, node_id: NodeId, source: NodeId) void {
        var suspicion = &(self.suspicions[node_id].?);
        for (suspicion.sources[0..suspicion.source_count]) |existing| {
            if (existing == source) return;
        }
        if (suspicion.source_count < suspicion.sources.len) {
            suspicion.sources[suspicion.source_count] = source;
            suspicion.source_count += 1;
        }
        if (suspicion.confirmations < self.config.params.suspicion_confirmations) {
            suspicion.confirmations += 1;
        }
        const total = self.suspicionTimeout();
        const divisor = @as(u64, suspicion.confirmations);
        const remaining = @max(@as(u64, 1), total / divisor);
        suspicion.deadline = @min(suspicion.deadline, now_ms + remaining);
    }

    /// 关于本节点自身的事件：怀疑/死亡断言必须立刻反驳，否则会被集群错误淘汰。
    fn handleSelfEvent(self: *Swim, event: codec.Event) !void {
        if (self.has_left) return;
        if (event.status == .suspect or event.status == .dead or event.status == .left) self.penalizeHealth();
        switch (event.status) {
            .alive => {
                // 比自己 incarnation 还高的 alive 断言：说明存在 node_id 冲突的克隆节点。
                // 纯状态机无法终止进程，这里抬高自己的 incarnation 重申身份；
                // 运行器（后续步骤）应监控此计数并按设计文档 §4.2 fail-fast。
                if (event.incarnation > self.incarnation) {
                    self.incarnation = event.incarnation + 1;
                    try self.queueGossip(self.selfEvent(.alive));
                }
            },
            .suspect, .dead, .left => {
                if (event.incarnation >= self.incarnation) {
                    self.incarnation = event.incarnation + 1;
                    self.stats.refutations += 1;
                    try self.queueGossip(self.selfEvent(.alive));
                }
            },
        }
    }

    // ========================================================================
    // gossip 传播队列与发送
    // ========================================================================

    /// 事件入播队列。同一 node_id 只保留最新事件（旧事件的重传已无意义）。
    fn queueGossip(self: *Swim, event: codec.Event) !void {
        const transmits = self.transmitLimit();
        for (self.gossip_queue.items) |*entry| {
            if (entry.event.node_id == event.node_id) {
                entry.* = .{ .event = event, .transmits_left = transmits };
                return;
            }
        }
        try self.gossip_queue.append(self.allocator, .{ .event = event, .transmits_left = transmits });
    }

    /// 编码并投递一帧消息到 outbox，同时搭载传播队列里的事件。
    /// sender 通常是本节点；转发 ack 时保持为 ack 的逻辑发出者。
    fn send(
        self: *Swim,
        message_type: codec.MessageType,
        sender: NodeId,
        seq: u32,
        target: NodeId,
        to: net.Address,
    ) !void {
        var events: [codec.max_events]codec.Event = undefined;
        const event_count = self.pickPiggyback(&events);

        var outgoing: Outgoing = .{ .to = to, .len = 0 };
        // 缓冲区尺寸按最大消息预留，编码只会因逻辑 bug 失败，视为不可达。
        const encoded = if (self.config.secret.len == 0)
            codec.encode(message_type, sender, seq, target, events[0..event_count], &outgoing.data) catch unreachable
        else
            codec.encodeAuthenticated(message_type, sender, seq, target, events[0..event_count], &outgoing.data, self.config.secret) catch unreachable;
        outgoing.len = @intCast(encoded.len);
        try self.outbox.append(self.allocator, outgoing);
        self.stats.messages_sent += 1;
    }

    /// 选出本帧搭载的事件：优先剩余重传次数最多的（即最新、传播最少的事件），
    /// 每选中一次扣减一次配额，配额耗尽的条目从队列移除。
    fn pickPiggyback(self: *Swim, out: *[codec.max_events]codec.Event) usize {
        const queue = self.gossip_queue.items;
        const want = @min(@as(usize, self.config.params.max_piggyback), queue.len);
        var picked: [codec.max_events]usize = undefined;
        var count: usize = 0;

        while (count < want) {
            var best: ?usize = null;
            for (queue, 0..) |entry, index| {
                if (std.mem.indexOfScalar(usize, picked[0..count], index) != null) continue;
                if (best == null or entry.transmits_left > queue[best.?].transmits_left) best = index;
            }
            const index = best orelse break;
            picked[count] = index;
            out[count] = queue[index].event;
            queue[index].transmits_left -= 1;
            count += 1;
        }

        // 清理配额耗尽的条目（倒序 swapRemove，不影响未处理下标）。
        var index = self.gossip_queue.items.len;
        while (index > 0) {
            index -= 1;
            if (self.gossip_queue.items[index].transmits_left == 0) {
                _ = self.gossip_queue.swapRemove(index);
            }
        }
        return count;
    }

    fn sendBuddyNotification(self: *Swim, member: membership.Member) !void {
        var events = [_]codec.Event{.{
            .node_id = member.node_id,
            .status = .suspect,
            .incarnation = member.incarnation,
            .address = member.address,
        }};
        var outgoing: Outgoing = .{ .to = member.address, .len = 0 };
        const encoded = if (self.config.secret.len == 0)
            codec.encode(.ping, self.config.node_id, 0, member.node_id, &events, &outgoing.data) catch unreachable
        else
            codec.encodeAuthenticated(.ping, self.config.node_id, 0, member.node_id, &events, &outgoing.data, self.config.secret) catch unreachable;
        outgoing.len = @intCast(encoded.len);
        try self.outbox.append(self.allocator, outgoing);
        self.stats.buddy_notifications += 1;
        self.stats.messages_sent += 1;
    }

    fn penalizeHealth(self: *Swim) void {
        if (self.health_multiplier < self.config.params.lhm_max_multiplier) {
            self.health_multiplier += 1;
            self.stats.health_penalties += 1;
        }
    }

    fn recoverHealth(self: *Swim) void {
        if (self.health_multiplier > 1) {
            self.health_multiplier -= 1;
            self.stats.health_recoveries += 1;
        }
    }

    // ========================================================================
    // anti-entropy：有界、分片的全量视图交换
    // ========================================================================

    fn driveAntiEntropy(self: *Swim, now_ms: u64) !void {
        if (self.config.params.sync_interval_ms == 0) return;
        if (self.sync) |session| {
            if (now_ms < session.deadline) return;
            self.sync = null;
        }
        if (now_ms < self.next_sync_at) return;
        const peer = self.randomSyncPeer() orelse return;
        self.sync = .{ .peer = peer.node_id, .deadline = now_ms + self.scaledProtocolPeriod() };
        self.next_sync_at = now_ms + self.config.params.sync_interval_ms;
        self.stats.syncs_started += 1;
        try self.sendSyncRequest(peer.address, 1);
    }

    fn randomSyncPeer(self: *Swim) ?membership.Member {
        var chosen: ?membership.Member = null;
        var seen: usize = 0;
        var it = self.table.iterator();
        while (it.next()) |member| {
            if (member.status == .left) continue;
            seen += 1;
            if (self.rng.random().intRangeLessThan(usize, 0, seen) == 0) chosen = member;
        }
        return chosen;
    }

    fn sendSyncRequest(self: *Swim, to: net.Address, cursor: NodeId) !void {
        var events = [_]codec.Event{self.currentSelfEvent()};
        self.seq_counter +%= 1;
        var outgoing: Outgoing = .{ .to = to, .len = 0 };
        const encoded = if (self.config.secret.len == 0)
            codec.encodeWithFlags(.sync, self.config.node_id, self.seq_counter, cursor, &events, &outgoing.data, codec.sync_request_flag) catch unreachable
        else
            codec.encodeAuthenticatedWithFlags(.sync, self.config.node_id, self.seq_counter, cursor, &events, &outgoing.data, self.config.secret, codec.sync_request_flag) catch unreachable;
        outgoing.len = @intCast(encoded.len);
        try self.outbox.append(self.allocator, outgoing);
        self.stats.messages_sent += 1;
    }

    fn handleSync(self: *Swim, now_ms: u64, from: net.Address, message: codec.Message) !void {
        if ((message.flags & codec.sync_request_flag) != 0) {
            var events: [codec.max_events]codec.Event = undefined;
            events[0] = self.currentSelfEvent();
            var count: usize = 1;
            var cursor: NodeId = message.target;
            while (cursor < self.config.max_nodes and count < events.len) : (cursor += 1) {
                if (self.table.get(cursor)) |member| {
                    events[count] = .{ .node_id = member.node_id, .status = member.status, .incarnation = member.incarnation, .address = member.address };
                    count += 1;
                }
            }
            var flags: u8 = 0;
            if (cursor < self.config.max_nodes) flags |= codec.sync_more_flag;
            var outgoing: Outgoing = .{ .to = from, .len = 0 };
            const encoded = if (self.config.secret.len == 0)
                codec.encodeWithFlags(.sync, self.config.node_id, message.seq, cursor, events[0..count], &outgoing.data, flags) catch unreachable
            else
                codec.encodeAuthenticatedWithFlags(.sync, self.config.node_id, message.seq, cursor, events[0..count], &outgoing.data, self.config.secret, flags) catch unreachable;
            outgoing.len = @intCast(encoded.len);
            try self.outbox.append(self.allocator, outgoing);
            self.stats.messages_sent += 1;
            return;
        }

        if (self.sync) |*session| {
            // join 尚不知道 seed 的 NodeId，只能先按地址建立临时会话。
            if (session.peer != membership.invalid_node_id and message.sender != session.peer) return;
            if (session.peer == membership.invalid_node_id) session.peer = message.sender;
            self.stats.sync_chunks_received += 1;
            session.deadline = now_ms + self.scaledProtocolPeriod();
            if ((message.flags & codec.sync_more_flag) != 0) {
                session.next_id = message.target;
                try self.sendSyncRequest(from, session.next_id);
            } else {
                self.sync = null;
            }
        }
    }

    // ========================================================================
    // Lifeguard 派生量与工具
    // ========================================================================

    fn scaledProbeTimeout(self: *const Swim) u64 {
        return self.config.params.probe_timeout_ms * @as(u64, self.health_multiplier);
    }

    fn scaledProtocolPeriod(self: *const Swim) u64 {
        return self.config.params.protocol_period_ms * @as(u64, self.health_multiplier);
    }

    /// 事件最大搭载次数 = retransmit_mult × ⌈log2(N+1)⌉（N 含自身，感染式扩散的覆盖保证）。
    fn transmitLimit(self: *const Swim) u32 {
        return self.config.params.retransmit_mult * self.logScale();
    }

    /// suspicion 超时 = suspicion_mult × ⌈log2(N+1)⌉ × 协议周期，
    /// 给被怀疑节点留出「听到怀疑 + 反驳传播回来」的时间窗口。
    fn suspicionTimeout(self: *const Swim) u64 {
        return @as(u64, self.config.params.suspicion_mult) * self.logScale() * self.config.params.protocol_period_ms * @as(u64, self.health_multiplier);
    }

    fn logScale(self: *const Swim) u32 {
        const n: u32 = @as(u32, self.table.active_count) + 1;
        return @max(1, std.math.log2_int_ceil(u32, n));
    }

    fn currentSelfEvent(self: *const Swim) codec.Event {
        return self.selfEvent(if (self.has_left) .left else .alive);
    }

    fn selfEvent(self: *const Swim, status: membership.NodeStatus) codec.Event {
        return .{
            .node_id = self.config.node_id,
            .status = status,
            .incarnation = self.incarnation,
            .address = self.config.address,
        };
    }

    fn notifyListener(self: *Swim, member: membership.Member) void {
        if (self.listener) |listener| listener.onUpdate(member);
    }
};

// ============================================================================
// 单元测试：不经过模拟器，手工构造消息驱动状态机，验证单节点视角的协议行为。
// 端到端行为（收敛/误杀/分区）见 sim.zig 的模拟测试。
// ============================================================================

const testing = std.testing;

fn testConfig(node_id: NodeId) Config {
    return .{
        .node_id = node_id,
        .address = net.initIp4(.{ 10, 0, 0, @intCast(node_id) }, 7946),
        .max_nodes = 16,
        .seed = 42,
    };
}

fn peerAddress(node_id: NodeId) net.Address {
    return net.initIp4(.{ 10, 0, 0, @intCast(node_id) }, 7946);
}

/// 测试辅助：以 sender 名义构造一帧消息。
fn buildMessage(
    message_type: codec.MessageType,
    sender: NodeId,
    seq: u32,
    target: NodeId,
    events: []const codec.Event,
    buf: *[codec.max_message_size]u8,
) []const u8 {
    return codec.encode(message_type, sender, seq, target, events, buf) catch unreachable;
}

test "probe gets acked: member stays alive" {
    var node = try Swim.init(testing.allocator, testConfig(1));
    defer node.deinit();
    try node.addPeer(2, peerAddress(2));

    // t=0 开启周期并 ping 成员 2。
    try node.tick(0);
    try testing.expectEqual(@as(usize, 1), node.pendingOutgoing().len);
    const ping = codec.decode(node.pendingOutgoing()[0].bytes()) catch unreachable;
    try testing.expectEqual(codec.MessageType.ping, ping.type);
    node.clearOutgoing();

    // 成员 2 应答同 seq 的 ack。
    var buf: [codec.max_message_size]u8 = undefined;
    try node.handleMessage(100, peerAddress(2), buildMessage(.ack, 2, ping.seq, 0, &.{}, &buf));

    // 周期结束后成员 2 仍是 alive。
    try node.tick(1000);
    try testing.expectEqual(membership.NodeStatus.alive, node.view().get(2).?.status);
}

test "unacked probe: suspect after period, dead after suspicion timeout" {
    var node = try Swim.init(testing.allocator, testConfig(1));
    defer node.deinit();
    try node.addPeer(2, peerAddress(2));

    try node.tick(0); // ping 发出，无人应答
    try node.tick(500); // 直接超时 → 间接探测（无其他成员可委托，无帧发出）
    try node.tick(1000); // 周期结束 → suspect
    try testing.expectEqual(membership.NodeStatus.suspect, node.view().get(2).?.status);

    // LHM 在本地探测失败后提升到 2，故 suspicion 超时为
    // 4 × log2ceil(2) × 1000ms × 2 = 8000ms。
    try node.tick(7999);
    try testing.expectEqual(membership.NodeStatus.suspect, node.view().get(2).?.status);
    try node.tick(9000);
    try testing.expectEqual(membership.NodeStatus.dead, node.view().get(2).?.status);
}

test "suspicion about self is refuted with higher incarnation" {
    var node = try Swim.init(testing.allocator, testConfig(2));
    defer node.deinit();
    try node.addPeer(1, peerAddress(1));

    // 成员 1 的 ping 搭载了「怀疑节点 2（自己），incarnation 0」的事件。
    const suspect_self = [_]codec.Event{.{
        .node_id = 2,
        .status = .suspect,
        .incarnation = 0,
        .address = peerAddress(2),
    }};
    var buf: [codec.max_message_size]u8 = undefined;
    try node.handleMessage(0, peerAddress(1), buildMessage(.ping, 1, 7, 0, &suspect_self, &buf));

    // 反驳：incarnation 抬升到 1，且应答的 ack 搭载了新的 alive 自宣告。
    try testing.expectEqual(@as(u32, 1), node.incarnation);
    try testing.expectEqual(@as(u64, 1), node.stats.refutations);
    try testing.expectEqual(@as(usize, 1), node.pendingOutgoing().len);
    const ack = codec.decode(node.pendingOutgoing()[0].bytes()) catch unreachable;
    try testing.expectEqual(codec.MessageType.ack, ack.type);
    var found_refutation = false;
    for (ack.events()) |event| {
        if (event.node_id == 2 and event.status == .alive and event.incarnation == 1) found_refutation = true;
    }
    try testing.expect(found_refutation);
}

test "ping_req relay: forward probe and relay ack back" {
    // 节点 3 是中转方：收到 1 对 2 的间接探测请求。
    var node = try Swim.init(testing.allocator, testConfig(3));
    defer node.deinit();
    try node.addPeer(1, peerAddress(1));
    try node.addPeer(2, peerAddress(2));

    var buf: [codec.max_message_size]u8 = undefined;
    try node.handleMessage(0, peerAddress(1), buildMessage(.ping_req, 1, 99, 2, &.{}, &buf));

    // 代发的 ping 使用节点 3 自己的序号。
    try testing.expectEqual(@as(usize, 1), node.pendingOutgoing().len);
    const relay_ping = codec.decode(node.pendingOutgoing()[0].bytes()) catch unreachable;
    try testing.expectEqual(codec.MessageType.ping, relay_ping.type);
    try testing.expectEqual(@as(NodeId, 3), relay_ping.sender);
    node.clearOutgoing();

    // 目标 2 的 ack 回来后，转发给请求方 1：sender 保持 2、seq 还原为 99。
    try node.handleMessage(10, peerAddress(2), buildMessage(.ack, 2, relay_ping.seq, 0, &.{}, &buf));
    try testing.expectEqual(@as(usize, 1), node.pendingOutgoing().len);
    const forwarded = codec.decode(node.pendingOutgoing()[0].bytes()) catch unreachable;
    try testing.expectEqual(codec.MessageType.ack, forwarded.type);
    try testing.expectEqual(@as(NodeId, 2), forwarded.sender);
    try testing.expectEqual(@as(u32, 99), forwarded.seq);
    try testing.expect(std.meta.eql(peerAddress(1), node.pendingOutgoing()[0].to));
}

test "relay slot selection reuses an empty slot before overwriting a live relay" {
    var node = try Swim.init(testing.allocator, testConfig(1));
    defer node.deinit();
    node.relays[0] = .{
        .requester_address = peerAddress(2),
        .target = 3,
        .original_seq = 10,
        .relay_seq = 11,
        .deadline = 100,
    };
    node.relay_next = 0;

    try testing.expectEqual(@as(usize, 1), node.selectRelaySlot(50));
    try testing.expectEqual(@as(NodeId, 3), node.relays[0].?.target);
    try testing.expectEqual(@as(usize, 2), node.relay_next);
}

test "relay slot selection reclaims an expired slot before cyclic eviction" {
    var node = try Swim.init(testing.allocator, testConfig(1));
    defer node.deinit();
    for (&node.relays, 0..) |*slot, index| {
        slot.* = .{
            .requester_address = peerAddress(2),
            .target = @intCast(index + 1),
            .original_seq = @intCast(index),
            .relay_seq = @intCast(index + 100),
            .deadline = 100,
        };
    }
    node.relays[5].?.deadline = 49;
    node.relay_next = 0;

    try testing.expectEqual(@as(usize, 5), node.selectRelaySlot(50));
    try testing.expectEqual(@as(u32, 100), node.relays[0].?.relay_seq);
    try testing.expectEqual(@as(usize, 6), node.relay_next);
}

test "gossip learns unknown member from piggybacked alive event" {
    var node = try Swim.init(testing.allocator, testConfig(1));
    defer node.deinit();
    try node.addPeer(2, peerAddress(2));

    const newcomer = [_]codec.Event{.{
        .node_id = 5,
        .status = .alive,
        .incarnation = 0,
        .address = peerAddress(5),
    }};
    var buf: [codec.max_message_size]u8 = undefined;
    try node.handleMessage(0, peerAddress(2), buildMessage(.ping, 2, 1, 0, &newcomer, &buf));

    const learned = node.view().get(5).?;
    try testing.expectEqual(membership.NodeStatus.alive, learned.status);
    try testing.expect(std.meta.eql(peerAddress(5), learned.address));
}

test "stale events are rejected by incarnation rules" {
    var node = try Swim.init(testing.allocator, testConfig(1));
    defer node.deinit();
    try node.addPeer(2, peerAddress(2));

    var buf: [codec.max_message_size]u8 = undefined;
    // 先接受 incarnation 2 的 alive。
    const fresh = [_]codec.Event{.{ .node_id = 2, .status = .alive, .incarnation = 2, .address = peerAddress(2) }};
    try node.handleMessage(0, peerAddress(2), buildMessage(.ping, 2, 1, 0, &fresh, &buf));
    try testing.expectEqual(@as(u32, 2), node.view().get(2).?.incarnation);

    // 旧 incarnation 的 suspect 不能生效（不变量：incarnation 单调）。
    const stale = [_]codec.Event{.{ .node_id = 2, .status = .suspect, .incarnation = 1, .address = peerAddress(2) }};
    try node.handleMessage(1, peerAddress(3), buildMessage(.ping, 3, 2, 0, &stale, &buf));
    try testing.expectEqual(membership.NodeStatus.alive, node.view().get(2).?.status);
    try testing.expectEqual(@as(u32, 2), node.view().get(2).?.incarnation);

    // 同 incarnation 的 suspect 可以覆盖 alive（SWIM 规则）。
    const same_inc = [_]codec.Event{.{ .node_id = 2, .status = .suspect, .incarnation = 2, .address = peerAddress(2) }};
    try node.handleMessage(2, peerAddress(3), buildMessage(.ping, 3, 3, 0, &same_inc, &buf));
    try testing.expectEqual(membership.NodeStatus.suspect, node.view().get(2).?.status);
}

test "join and leave use authenticated lifecycle events" {
    const secret = "0123456789abcdef";
    var node = try Swim.init(testing.allocator, .{
        .node_id = 1,
        .address = peerAddress(1),
        .max_nodes = 16,
        .seed = 42,
        .secret = secret,
    });
    defer node.deinit();
    try node.joinSeed(peerAddress(2));
    try testing.expectEqual(@as(usize, 1), node.pendingOutgoing().len);
    const request = codec.decodeAuthenticated(node.pendingOutgoing()[0].bytes(), secret) catch unreachable;
    try testing.expectEqual(codec.MessageType.sync, request.type);
    try testing.expect((request.flags & codec.sync_request_flag) != 0);
    node.clearOutgoing();
    try node.addPeer(2, peerAddress(2));
    try node.leave();
    try testing.expect(node.incarnation > 0);
    try testing.expect(node.pendingOutgoing().len > 0);
    const left_message = codec.decodeAuthenticated(node.pendingOutgoing()[0].bytes(), secret) catch unreachable;
    var found_left = false;
    for (left_message.events()) |event| {
        if (event.node_id == 1 and event.status == .left and event.incarnation == node.incarnation) found_left = true;
    }
    try testing.expect(found_left);
}

test "self-claiming sender from another address is counted instead of fail-fast" {
    const secret = "0123456789abcdef";
    var node = try Swim.init(testing.allocator, .{
        .node_id = 1,
        .address = peerAddress(1),
        .max_nodes = 16,
        .seed = 42,
        .secret = secret,
    });
    defer node.deinit();

    var buf: [codec.max_message_size]u8 = undefined;
    const encoded = codec.encodeAuthenticated(.ping, 1, 9, 0, &.{}, &buf, secret) catch unreachable;
    try node.handleMessage(0, peerAddress(9), encoded);
    // 物理源地址不在 HMAC 覆盖范围内，任何能重放报文的人都能伪造它，
    // 因此只丢弃并计数，绝不进入 fail-fast 状态。
    try testing.expect(node.identityConflict() == null);
    try testing.expectEqual(@as(u64, 1), node.stats.address_mismatches);
}

test "authenticated member address change records an identity conflict" {
    const secret = "0123456789abcdef";
    var node = try Swim.init(testing.allocator, .{
        .node_id = 1,
        .address = peerAddress(1),
        .max_nodes = 16,
        .seed = 42,
        .secret = secret,
    });
    defer node.deinit();
    try node.addPeer(2, peerAddress(2));

    const events = [_]codec.Event{.{
        .node_id = 2,
        .status = .alive,
        .incarnation = 1,
        .address = peerAddress(9),
    }};
    var buf: [codec.max_message_size]u8 = undefined;
    const encoded = codec.encodeAuthenticated(.ping, 3, 10, 0, &events, &buf, secret) catch unreachable;
    try node.handleMessage(0, peerAddress(3), encoded);
    const conflict = node.identityConflict().?;
    try testing.expectEqual(@as(NodeId, 2), conflict.node_id);
    try testing.expect(std.meta.eql(peerAddress(2), conflict.expected_address));
    try testing.expect(std.meta.eql(peerAddress(9), conflict.observed_address));
    try testing.expect(std.meta.eql(peerAddress(2), node.view().lookup(2).?.address));
}

test "known peer sending from another address is counted instead of fail-fast" {
    const secret = "0123456789abcdef";
    var node = try Swim.init(testing.allocator, .{
        .node_id = 1,
        .address = peerAddress(1),
        .max_nodes = 16,
        .seed = 42,
        .secret = secret,
    });
    defer node.deinit();
    try node.addPeer(2, peerAddress(2));

    var buf: [codec.max_message_size]u8 = undefined;
    const encoded = codec.encodeAuthenticated(.ping, 2, 11, 0, &.{}, &buf, secret) catch unreachable;
    try node.handleMessage(0, peerAddress(9), encoded);
    // 报文被丢弃并计数，但不触发 fail-fast，也不修改成员视图。
    try testing.expect(node.identityConflict() == null);
    try testing.expectEqual(@as(u64, 1), node.stats.address_mismatches);
    try testing.expect(std.meta.eql(peerAddress(2), node.view().lookup(2).?.address));
}

test "relayed ack source address does not create identity conflict" {
    const secret = "0123456789abcdef";
    var node = try Swim.init(testing.allocator, .{
        .node_id = 1,
        .address = peerAddress(1),
        .max_nodes = 16,
        .seed = 42,
        .secret = secret,
    });
    defer node.deinit();
    try node.addPeer(2, peerAddress(2));
    try node.addPeer(3, peerAddress(3));

    var buf: [codec.max_message_size]u8 = undefined;
    const encoded = codec.encodeAuthenticated(.ack, 2, 11, 0, &.{}, &buf, secret) catch unreachable;
    try node.handleMessage(0, peerAddress(3), encoded);
    try testing.expect(node.identityConflict() == null);
}

test "authenticated replay is rejected after the first delivery" {
    const secret = "0123456789abcdef";
    var node = try Swim.init(testing.allocator, .{
        .node_id = 1,
        .address = peerAddress(1),
        .max_nodes = 16,
        .seed = 42,
        .secret = secret,
    });
    defer node.deinit();
    var buf: [codec.max_message_size]u8 = undefined;
    const encoded = codec.encodeAuthenticated(.ping, 2, 9, 0, &.{}, &buf, secret) catch unreachable;
    try node.handleMessage(0, peerAddress(2), encoded);
    node.clearOutgoing();
    try node.handleMessage(1, peerAddress(2), encoded);
    try testing.expectEqual(@as(u64, 1), node.stats.auth_failures);
    try testing.expectEqual(@as(usize, 0), node.pendingOutgoing().len);
}

test "malformed inbound bytes are counted and dropped" {
    var node = try Swim.init(testing.allocator, testConfig(1));
    defer node.deinit();

    try node.handleMessage(0, peerAddress(2), "not a swim message");
    try testing.expectEqual(@as(u64, 1), node.stats.decode_failures);
    try testing.expectEqual(@as(usize, 0), node.pendingOutgoing().len);
}

test "Lifeguard health, buddy notification, and confirmation tracking" {
    var node = try Swim.init(testing.allocator, testConfig(1));
    defer node.deinit();
    try node.addPeer(2, peerAddress(2));

    try node.tick(0);
    node.clearOutgoing();
    try node.tick(1000);
    try testing.expectEqual(membership.NodeStatus.suspect, node.view().get(2).?.status);
    try testing.expectEqual(@as(u8, 2), node.health_multiplier);
    try testing.expectEqual(@as(u64, 1), node.stats.buddy_notifications);

    var buf: [codec.max_message_size]u8 = undefined;
    const suspect = [_]codec.Event{.{
        .node_id = 2,
        .status = .suspect,
        .incarnation = 0,
        .address = peerAddress(2),
    }};
    try node.handleMessage(1001, peerAddress(3), buildMessage(.ping, 3, 1, 0, &suspect, &buf));
    try testing.expect(node.suspicions[2].?.confirmations >= 2);
    try testing.expect(node.suspicions[2].?.deadline <= 1001 + node.suspicionTimeout());
}

test "anti entropy sync rebuilds a missing member view" {
    var node = try Swim.init(testing.allocator, testConfig(1));
    defer node.deinit();
    var peer = try Swim.init(testing.allocator, testConfig(2));
    defer peer.deinit();
    try node.addPeer(2, peerAddress(2));
    try peer.addPeer(1, peerAddress(1));
    try peer.addPeer(3, peerAddress(3));

    var request_buf: [codec.max_message_size]u8 = undefined;
    const request = codec.encodeWithFlags(.sync, 1, 0, 1, &.{}, &request_buf, codec.sync_request_flag) catch unreachable;
    try peer.handleMessage(30_000, peerAddress(1), request);
    const response = peer.pendingOutgoing()[0];
    const response_message = codec.decode(response.bytes()) catch unreachable;
    try testing.expectEqual(codec.MessageType.sync, response_message.type);
    try testing.expect(response_message.events().len > 0);

    node.sync = .{ .peer = 2, .deadline = 31_000 };
    try node.handleMessage(30_001, peerAddress(2), response.bytes());
    try testing.expect(node.view().get(3) != null);
    try testing.expectEqual(@as(u64, 1), node.stats.sync_chunks_received);
}
