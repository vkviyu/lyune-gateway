//! 流式推送的会话表（设计文档 §5.3）
//!
//! 一次性推送（OPEN 带 `eof`）不需要任何状态：一帧进来、扇出、结束。流式推送
//! （OPEN + DATA×N）需要状态，因为**目标列表只出现在 OPEN 上**——后续 DATA 帧
//! 上没有目标，网关必须记住"这条流要发给谁、我为每个目标开的是哪条流"。
//!
//! ## 会话身份就是它所在的那条流
//!
//! 线格式里**没有**会话字段。每一跳都用它所在的那条流来标识会话：
//!
//! - 后端 → 网关：后端那条 QUIC 流（`inflight.StreamKey`），即 `Session.origin`
//! - 网关 → 同机另一个 Worker：交接信封的 `AppMessage.session`，即 `Session.id`
//! - 网关 → 另一个节点：对等链路上一条专属流，即 `Session.nodes[i]`
//! - 网关 → 客户端：该连接上一条专属推送流，即 `Session.locals[i].stream_id`
//!
//! 同机跨 Worker 用信封而不是帧，与 `realm` 完全同一个理由（§12.3）：会话号是网关
//! 内部的记账，让目标 Worker 从帧里读它就等于把内部状态暴露成协议字段，而后端可以
//! 伪造它。跨节点用一条专属流，因为对等链路本来就是 QUIC，一条流天然就是一个会话
//! ——而且帧头里根本没有 8 字节可用（只有一个保留字节，realm 提示已经占了两个）。
//!
//! ## 本地目标存 token 而不是传输对象地址
//!
//! 一个会话可能横跨几十秒，中途有连接断开是常态。存原始 QUIC/WSS 对象地址就是一条
//! use-after-free 路径：槽位被新连接复用后，那一帧会写进**另一个用户**的连接。
//! `ConnToken` 带 generation，`byToken` 失配即返回 null，那个目标就自然掉出会话
//! ——这与 kick 的定位方式是同一套（见 connection.zig 的 `byToken`）。
//!
//! 因此这张表刻意**不是**"每连接一张会话表"：原始设计里那个形状省不掉"发起方还得
//! 知道会话里有哪些连接"这份状态，而 generation 校验过的 token 一份就够了。
//!
//! ## 定容 + 线性扫描
//!
//! 并发流式会话数是个位到几十的量级（见 `max_sessions`），所以定位直接线性扫描，
//! 不需要哈希索引；表在启动期一次分配，运行期零分配。

const std = @import("std");

const foundation = @import("../foundation/mod.zig");
const RealmId = foundation.realm.RealmId;
const connection = @import("connection.zig");
const ConnToken = connection.ConnToken;
const inflight = @import("inflight.zig");
const peer_link = @import("peer_link.zig");

/// 一帧 OPEN 里允许的流式目标数。
///
/// 取个位数不是为了省内存：**在网关里把一条流复制 N 份，出口带宽就乘以 N**。
/// 个位数以上的流式扇出是架构选错了位置——那种需求应该由后端推给广播层，而不是
/// 让网关做扇出。一次性推送不受这条限制（它只有一帧，成本是 O(1) 的读 + N 次写）。
///
/// 这一道是后端**能控制**的（列表是它编的），所以超限直接拒掉整个会话。
pub const max_list_targets: usize = 8;

/// 一个位置上允许附着的客户端连接数。
///
/// 比 `max_list_targets` 宽，因为一个 `dest_id` 可以对应多条连接（同一账号的多台
/// 设备，§5.6），而**这个放大网关只能被动接受**：后端说"发给这个人"，人有几台
/// 设备不是它能决定的。按 8 个目标 × 4 台设备取整。
pub const max_local_targets: usize = 32;

/// 一个会话能横跨的对等节点数。
///
/// 与 `max_list_targets` 同一个理由：跨节点复制一份，出口带宽也乘一份。
/// 超限时后面那些节点掉出会话（记 warn），而不是把已经建好的部分推倒。
pub const max_nodes: usize = 8;

/// 单个 Worker 的并发流式会话上限。
///
/// 每个会话占着若干条客户端流、若干条对等链路流，以及本表一个条目。没有上限就是
/// 一条无界增长路径：一个只发 OPEN 就不管了的后端能把 Worker 拖死。
pub const max_sessions: usize = 64;

/// 会话的最长静默时间（微秒）。
///
/// 超时是**兜底回收**，不是超时语义：正常结束靠 eof，异常结束靠后端流 FIN。
/// 它兜的是"后端既不发 eof 也不关流"这一种——没有它，那些会话会一直占着客户端
/// 的推送流，客户端则一直等一段永远不来的尾巴。
pub const idle_timeout_us: u64 = 60 * std.time.us_per_s;

/// 一个本地投递目标：generation 校验过的连接标识 + 为这次会话开的那条推送流。
pub const LocalTarget = struct {
    token: ConnToken,
    stream_id: u64,
};

/// 一个流式推送会话在**本 Worker** 上的全部状态。
pub const Session = struct {
    /// 槽位是否在用。
    active: bool = false,
    /// 会话号；跨 Worker 交接时放进信封（`AppMessage.session`）。
    ///
    /// 高 8 位是创建它的 worker_id，所以它在**本节点内**唯一——信封因此不需要
    /// 再带一个"来自哪个 Worker"。
    id: u64 = 0,
    /// 会话所属隔离域。投递时不从帧里读（§12.3）。
    realm: RealmId = 0,
    /// 本 Worker 是发起方时，喂进这个会话的那条后端推送流。
    ///
    /// 由对等链路或同机交接创建的会话没有它——那两种情形的入站流不是后端流。
    origin: ?inflight.StreamKey = null,
    locals: [max_local_targets]LocalTarget = undefined,
    local_len: u8 = 0,
    nodes: [max_nodes]peer_link.Stream = undefined,
    node_len: u8 = 0,
    /// 受理过本会话 OPEN 的同机 Worker，下标即 worker_id。
    ///
    /// 必须记住而不是每帧重算：DATA 帧上没有目标列表，重算不出 home。
    workers: [256]bool = @splat(false),
    last_active: u64 = 0,

    pub fn localTargets(self: *const Session) []const LocalTarget {
        return self.locals[0..self.local_len];
    }

    pub fn remoteNodes(self: *const Session) []const peer_link.Stream {
        return self.nodes[0..self.node_len];
    }

    /// 附上一个本地目标；超过 `max_local_targets` 返回 false。
    pub fn addLocal(self: *Session, target: LocalTarget) bool {
        if (self.local_len >= max_local_targets) return false;
        self.locals[self.local_len] = target;
        self.local_len += 1;
        return true;
    }

    /// 附上一个对等节点上的会话流；超过 `max_nodes` 返回 false。
    pub fn addNode(self: *Session, stream: peer_link.Stream) bool {
        if (self.node_len >= max_nodes) return false;
        self.nodes[self.node_len] = stream;
        self.node_len += 1;
        return true;
    }
};

/// 本 Worker 的流式会话表。线程私有。
pub const Table = struct {
    allocator: std.mem.Allocator,
    /// 本 Worker 的编号，用来给会话号打上出处。
    worker_id: u8,
    sessions: []Session,
    /// 会话号的低位计数器。
    counter: u64 = 0,
    /// 当前在用的会话数。
    ///
    /// 存着而不是每次扫表算：一次性推送的热路径上每来一帧都要先问"这条流上有会话吗"，
    /// 没有流式推送在跑时那次询问应该是一次整数比较，而不是 64 次结构体字段比较。
    live: usize = 0,
    /// 可观测量：开过的会话数、因表满被拒的次数。
    opened: u64 = 0,
    refused: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, worker_id: u8) !Table {
        const sessions = try allocator.alloc(Session, max_sessions);
        @memset(sessions, .{});
        return .{ .allocator = allocator, .worker_id = worker_id, .sessions = sessions };
    }

    pub fn deinit(self: *Table) void {
        self.allocator.free(self.sessions);
    }

    /// 生成一个本节点内唯一的会话号。
    ///
    /// 高 8 位是 worker_id，低位是计数器，因此两个 Worker 各自发号也不会撞。
    /// 永不返回 0——0 在信封里的含义是"这不是流式会话"。
    pub fn nextId(self: *Table) u64 {
        self.counter = (self.counter +% 1) & 0x00FF_FFFF_FFFF_FFFF;
        if (self.counter == 0) self.counter = 1;
        return (@as(u64, self.worker_id) << 56) | self.counter;
    }

    /// 占一个槽位；表满时返回 null。
    pub fn open(self: *Table, id: u64, realm: RealmId, origin: ?inflight.StreamKey, now: u64) ?*Session {
        for (self.sessions) |*session| {
            if (session.active) continue;
            session.* = .{
                .active = true,
                .id = id,
                .realm = realm,
                .origin = origin,
                .last_active = now,
            };
            self.live += 1;
            self.opened += 1;
            return session;
        }
        self.refused += 1;
        return null;
    }

    pub fn findById(self: *Table, id: u64) ?*Session {
        if (id == 0 or self.live == 0) return null;
        for (self.sessions) |*session| {
            if (session.active and session.id == id) return session;
        }
        return null;
    }

    /// 按喂进它的那条后端流定位；给下行 DATA 帧用。
    pub fn findByOrigin(self: *Table, key: inflight.StreamKey) ?*Session {
        if (self.live == 0) return null;
        for (self.sessions) |*session| {
            if (!session.active) continue;
            const origin = session.origin orelse continue;
            if (origin.transport == key.transport and origin.stream == key.stream) return session;
        }
        return null;
    }

    /// 释放槽位。调用方负责先收尾各条流（见 egress 的 `writeSessionFrame`/`abortSession`）。
    pub fn close(self: *Table, session: *Session) void {
        if (!session.active) return;
        session.* = .{};
        self.live -= 1;
    }

    /// 找一个已经静默超时的会话；没有则返回 null。
    ///
    /// 返回而不是就地清理：收尾要重置客户端那几条推送流，那需要连接管理器，
    /// 而本表刻意不认识它。
    pub fn expired(self: *Table, now: u64) ?*Session {
        if (self.live == 0) return null;
        for (self.sessions) |*session| {
            if (!session.active) continue;
            if (now -| session.last_active >= idle_timeout_us) return session;
        }
        return null;
    }

    pub fn liveCount(self: *const Table) usize {
        return self.live;
    }
};

// ============================================================================
// 测试
// ============================================================================

test "session ids carry their originating worker and never collide across workers" {
    const allocator = std.testing.allocator;

    var first = try Table.init(allocator, 0);
    defer first.deinit();
    var second = try Table.init(allocator, 3);
    defer second.deinit();

    // 两个 Worker 各发三个号，六个号必须互不相同——信封里只有会话号，撞号就是
    // 一条流的 DATA 被写进另一条流。
    var seen: [6]u64 = undefined;
    for (0..3) |i| {
        seen[i * 2] = first.nextId();
        seen[i * 2 + 1] = second.nextId();
    }
    for (seen, 0..) |a, i| {
        try std.testing.expect(a != 0);
        for (seen[i + 1 ..]) |b| try std.testing.expect(a != b);
    }

    // 高 8 位就是出处。
    try std.testing.expectEqual(@as(u64, 3), seen[1] >> 56);
}

test "a full table refuses instead of evicting a live session" {
    const allocator = std.testing.allocator;
    var table = try Table.init(allocator, 1);
    defer table.deinit();

    var first: ?*Session = null;
    for (0..max_sessions) |_| {
        const session = table.open(table.nextId(), 7, null, 100).?;
        if (first == null) first = session;
    }

    // 满了之后拒绝。挤掉一个在用的会话会让那个客户端收到一段残缺的字节流，
    // 而它没有任何方式发现自己被截断了。
    try std.testing.expect(table.open(table.nextId(), 7, null, 100) == null);
    try std.testing.expectEqual(@as(u64, 1), table.refused);
    try std.testing.expect(first.?.active);

    table.close(first.?);
    try std.testing.expect(table.open(table.nextId(), 7, null, 100) != null);
}

test "sessions are found by origin stream and by id" {
    const allocator = std.testing.allocator;
    var table = try Table.init(allocator, 1);
    defer table.deinit();

    const key: inflight.StreamKey = .{ .transport = 0xAB, .stream = 12 };
    const id = table.nextId();
    _ = table.open(id, 5, key, 100).?;

    try std.testing.expectEqual(id, table.findById(id).?.id);
    try std.testing.expectEqual(id, table.findByOrigin(key).?.id);

    // 同一个句柄、不同的 transport 实例必须查不到：句柄只在单个实例内唯一，
    // 只用句柄做键会让两个后端的推送被拼进同一个会话。
    try std.testing.expect(table.findByOrigin(.{ .transport = 0xCD, .stream = 12 }) == null);
    try std.testing.expect(table.findById(0) == null);
}

test "an idle session becomes collectable" {
    const allocator = std.testing.allocator;
    var table = try Table.init(allocator, 1);
    defer table.deinit();

    const session = table.open(table.nextId(), 5, null, 1_000).?;
    try std.testing.expect(table.expired(1_000 + idle_timeout_us - 1) == null);
    try std.testing.expect(table.expired(1_000 + idle_timeout_us) == session);

    // 活动过就重新计时：兜底回收不能把一个正在传输的会话收走。
    session.last_active = 1_000 + idle_timeout_us;
    try std.testing.expect(table.expired(1_000 + idle_timeout_us) == null);
}

test "local targets and node streams are bounded" {
    var session: Session = .{ .active = true };

    for (0..max_local_targets) |i| {
        try std.testing.expect(session.addLocal(.{ .token = .{ .slot = @intCast(i) }, .stream_id = i }));
    }
    try std.testing.expect(!session.addLocal(.{ .token = .{}, .stream_id = 999 }));
    try std.testing.expectEqual(max_local_targets, session.localTargets().len);

    for (0..max_nodes) |i| {
        try std.testing.expect(session.addNode(.{ .node_id = @intCast(i + 1), .epoch = 0, .stream_id = 0 }));
    }
    try std.testing.expect(!session.addNode(.{ .node_id = 99, .epoch = 0, .stream_id = 0 }));
    try std.testing.expectEqual(max_nodes, session.remoteNodes().len);
}
