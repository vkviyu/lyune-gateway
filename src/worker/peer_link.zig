//! 节点间应用层投递的**出站**链路（设计文档 §8.5）
//!
//! 本节点作为 QUIC 客户端连到对等网关节点的集群端口，在上面说**同一套帧协议**：
//! `.peer` / `.multicast` 的 OPEN + 目标列表。对面收到的是一条 peer-initiated 流，
//! 走的正是它已经写好的扇出路径（`egress.deliverFromPeer`）——不需要新的线格式，
//! 也不需要新的分派分支。
//!
//! > 一个网关节点，对它的对等节点来说，就是"一个会推送的后端"。
//!
//! ## 为什么不是 forward 隧道
//!
//! 那条隧道是裸 UDP：单个数据报载荷上限 65507，扣掉隧道自己的 32 字节头 + 最多
//! 16 字节地址 + 32 字节 HMAC 只剩 65427，而应用帧上限是 8 + 65535 = 65543。
//! **一整帧塞不进一个数据报，这是算术，不是设计选择。** 给隧道加分片重组等于在 UDP
//! 上重新实现一遍 QUIC 已经做好的事（分片 id、乱序、超时回收、丢一片全帧作废）。
//!
//! 走 QUIC 之后帧长不再有额外上限，而且可靠有序、拥塞控制、加密全部免费。
//!
//! ## realm 怎么带：零新增线格式
//!
//! `.peer` / `.multicast` 的 OPEN 里 `group + route_key` 那两字节本来就是保留的
//! （§5.1 说明它们只在有路由键的目的地下有意义），而 `RealmId` 恰好是 u16。
//! 发送前把 realm 打进这两字节即可（`FrameHeader.encode` 把它们写在偏移 6、7）。
//!
//! 它只在**对等节点连接**上被这样解释——那一侧的判据是"这条连接从集群监听器进来"，
//! 而集群监听器要求集群 CA 签发的客户端证书。客户端/后端连接上这两字节仍然是保留字节。
//!
//! ## 身份：mTLS，没有应用层握手
//!
//! 我们出示 `cluster.peer_cert_file` / `peer_key_file`（集群 CA 签发），并用
//! `peer_ca_file` 校验对端。对面那个端口开了 `require_client_auth`，所以
//! "握手成功"就等价于"双方都是网关节点"。因此这里**没有** cluster_hello、
//! 没有 nonce、没有 HMAC、没有防重放窗口、没有时钟依赖。
//!
//! ## 为什么自己持有一个 AsyncClient 而不复用 backend/pool.zig 的那个
//!
//! 两条理由：
//!
//! 1. **TLS 参数不同**。后端连接用的是后端那套证书，集群链路用集群 CA 签发的客户端
//!    证书。`BackendPool.acquireClient` 会因参数不一致明确报错——它刻意不静默复用，
//!    因为静默复用就是一次证书校验降级。
//! 2. **不需要接收池**。跨节点投递是单向的：一次性投递写完就 fin，流式会话在一条专属
//!    流上连写多帧（§5.3），两种形态对面都不回任何内容。所以这里一个字节的接收缓冲
//!    都不用留，复用那个带 8 MiB 槽位池的结构是浪费。
//!
//! 链路数是"对等节点数"量级（几十），所以 cnx → 链路的定位直接线性扫描，
//! 不像后端连接那样需要哈希索引。

const std = @import("std");
const xev = @import("xev");

const control = @import("../control/mod.zig");
const foundation = @import("../foundation/mod.zig");
const err_handler = foundation.err;
const protocol = @import("../protocol/mod.zig");
const codec = protocol.codec;
const quic = @import("../quic/mod.zig");
const QUICConfig = quic.config.QUICConfig;
const QUICConnection = quic.connection.Connection;
const reactor = @import("../reactor/mod.zig");
const AsyncClient = reactor.client.AsyncClient;

/// 重连退避的起始与上限间隔（微秒）。与 backend/direct.zig 用同一组数量级：
/// 对等节点和后端一样是"长期存在、偶发抖动"的对端。
const backoff_base_us: u64 = 100 * std.time.us_per_ms;
const backoff_max_us: u64 = 30 * std.time.us_per_s;

/// 一条链路的生命周期状态。
///
/// 与 `backend/direct.zig` 的 `ConnState` 同形，理由也相同：用显式状态机而不是
/// connected/connecting 两个 bool，后者无法表达"曾经连上、现在断了、可以重连"，
/// 会让断开后 connecting 永远停在 true。
const LinkState = enum { idle, connecting, ready, backoff };

pub const Config = struct {
    /// 允许同时保持的对等链路数上限。
    ///
    /// 超限时对新节点的投递被判为不可达（回报给后端），而不是挤掉一条在用的链路
    /// ——后者会让两个节点互相踢，表现成周期性的投递失败。
    max_links: usize = 64,
    /// 对等节点的集群监听端口。集群同构假设：全集群同一个端口。
    peer_port: u16,
};

pub const Error = error{OutOfMemory};

/// 一条到某个对等节点的链路。
const Link = struct {
    /// 0 表示这个槽位空闲。
    node_id: u16 = 0,
    cnx: ?quic.c.QuicCnx = null,
    state: LinkState = .idle,
    failure_count: u32 = 0,
    retry_at: u64 = 0,
    /// 下一条客户端发起的双向流 id（从 0 开始，每次 +4）。
    next_stream_id: u64 = 0,
    /// 连接世代，每次握手成功 +1。
    ///
    /// 只给流式会话用（`Stream.epoch`）：一次性投递写完就结束，不关心链路此后
    /// 是否重连；而会话要在同一条流上写很多帧，必须能发现"这条流所在的连接
    /// 已经不是当初那条了"。
    epoch: u32 = 0,
};

/// 对等链路上一条属于某个流式会话的专属流（设计文档 §5.3）。
///
/// 跨节点这一跳的会话身份就是它——帧头里塞不进会话号（只有一个保留字节，
/// realm 提示已经占了两个），而对等链路本来就是 QUIC，一条流天然就是一个会话。
/// 接收节点看到的形态与后端直连时完全一样：OPEN 然后 DATA。
pub const Stream = struct {
    node_id: u16,
    /// 开这条流时链路的连接世代。
    ///
    /// 链路断了重连之后，同一个流号在新连接上是另一条流（很可能根本不存在）。
    /// 少了这道校验，一次重连就会让会话的后半段被写进一条陌生的流里。
    epoch: u32,
    stream_id: u64,
};

pub const PeerLinks = struct {
    allocator: std.mem.Allocator,
    event_loop: *xev.Loop,
    coordinator: *control.Coordinator,
    config: Config,

    /// 集群链路专用的 QUIC 客户端；懒建——没有任何跨节点投递时不占 socket。
    client: ?AsyncClient,
    /// 建客户端用的配置（含我方证书与集群 CA）。
    client_config: QUICConfig,

    links: []Link,

    /// 打 realm 补丁用的缓冲：原帧字节是借用的，不能就地改。
    ///
    /// 一份就够——`send` 是同步的，写完就交给 picoquic 了（它会把负载拷进自己的
    /// 发送队列），本函数返回后这块缓冲即可复用。
    scratch: []u8,

    /// 可观测量：成功递交给 QUIC 的帧数与因链路不可用而被拒的帧数。
    sent: u64 = 0,
    refused: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        event_loop: *xev.Loop,
        coordinator: *control.Coordinator,
        peer_quic: QUICConfig,
        config: Config,
    ) Error!PeerLinks {
        const links = try allocator.alloc(Link, @max(config.max_links, 1));
        errdefer allocator.free(links);
        @memset(links, .{});

        const scratch = try allocator.alloc(u8, codec.MAX_FRAME_SIZE);
        errdefer allocator.free(scratch);

        // 服务端那套配置拿来做客户端：证书与 CA 照用，但绑定端口要交给系统随机分配，
        // 而 require_client_auth 是服务端角色的开关，客户端角色下没有意义。
        var client_config = peer_quic;
        client_config.bind_port = 0;
        client_config.require_client_auth = false;

        return .{
            .allocator = allocator,
            .event_loop = event_loop,
            .coordinator = coordinator,
            .config = config,
            .client = null,
            .client_config = client_config,
            .links = links,
            .scratch = scratch,
        };
    }

    pub fn deinit(self: *PeerLinks) void {
        // 先逐条优雅关闭，再释放客户端：`AsyncClient.deinit` 不持有连接列表，
        // 不会替我们发 CONNECTION_CLOSE（见 reactor/client.zig）。
        for (self.links) |*link| {
            if (link.cnx) |cnx_handle| {
                var conn = QUICConnection.fromRaw(cnx_handle);
                conn.close();
                link.cnx = null;
            }
        }
        if (self.client) |*client| client.deinit();
        self.client = null;
        self.allocator.free(self.links);
        self.allocator.free(self.scratch);
    }

    /// 把一帧投给某个对等节点，返回**是否被受理**。
    ///
    /// 语义与设计文档 §5.5 一致：受理 = 已经递交给 QUIC，不等于对面已经投到客户端。
    /// 给这一跳单独加 ack 并不能让端到端可靠（客户端那一跳照样会丢），只是把不可靠
    /// 往后推一格。
    ///
    /// 链路还没就绪时返回 false 并**顺手发起建连**，因此下一次投递就有机会命中。
    /// 返回 false 的目标会被扇出侧回报为不可达，后端由此转离线存储——这比静默排队
    /// 好：排队意味着后端以为消息在路上，而它可能永远发不出去。
    pub fn send(self: *PeerLinks, node_id: u16, realm: u16, frame_bytes: []const u8) bool {
        const now = quic.c.currentTime();
        const link = self.readyLink(node_id, now) orelse return false;

        const patched = self.patchRealm(frame_bytes, realm) orelse {
            self.refused += 1;
            return false;
        };

        const stream_id = link.next_stream_id;
        link.next_stream_id += 4;
        return self.write(link, stream_id, patched, true, now);
    }

    /// 为一个流式会话在这条链路上开一条专属流，并把 OPEN 帧写进去。
    ///
    /// 返回的 `Stream` 就是这个会话在这个节点上的身份，后续 DATA 用 `sendOn` 写。
    /// 链路不可用时返回 null，该节点因此掉出这个会话——**不排队**，理由同 `send`。
    pub fn beginSession(self: *PeerLinks, node_id: u16, realm: u16, open_bytes: []const u8) ?Stream {
        const now = quic.c.currentTime();
        const link = self.readyLink(node_id, now) orelse return null;

        const patched = self.patchRealm(open_bytes, realm) orelse {
            self.refused += 1;
            return null;
        };

        const stream: Stream = .{
            .node_id = node_id,
            .epoch = link.epoch,
            .stream_id = link.next_stream_id,
        };
        link.next_stream_id += 4;
        // 不带 fin：这条流后面还有 DATA。
        if (!self.write(link, stream.stream_id, patched, false, now)) return null;
        return stream;
    }

    /// 在一条已经开好的会话流上继续写一帧。
    ///
    /// **不打 realm 补丁**：DATA 帧只有 4 字节头，没有那两个保留字节可用。接收侧
    /// 也不需要——它按流定位会话，realm 在 OPEN 那一刻就已经记住了。
    ///
    /// 世代失配即返回 false：链路重连之后那条流在新连接上并不存在，继续往里写
    /// 只会在一条陌生的流上拼出半段字节流。
    pub fn sendOn(self: *PeerLinks, stream: Stream, frame_bytes: []const u8, is_last: bool) bool {
        const now = quic.c.currentTime();
        const link = self.linkFor(stream.node_id) orelse {
            self.refused += 1;
            return false;
        };
        if (link.state != .ready or link.epoch != stream.epoch) {
            self.refused += 1;
            return false;
        }
        return self.write(link, stream.stream_id, frame_bytes, is_last, now);
    }

    /// 作废一条会话流：让对面立刻知道这段字节流不完整。
    ///
    /// 用 RESET_STREAM 而不是 fin：fin 的含义是"完整结束"，对面会把半段当成整段
    /// 继续投给客户端。世代失配时什么也不做——那条流所在的连接已经没了。
    pub fn resetSession(self: *PeerLinks, stream: Stream) void {
        const link = self.linkFor(stream.node_id) orelse return;
        if (link.state != .ready or link.epoch != stream.epoch) return;
        const cnx_handle = link.cnx orelse return;
        var conn = QUICConnection.fromRaw(cnx_handle);
        conn.closeStream(stream.stream_id);
    }

    /// 把一段字节写进这条链路的某条流；失败即让链路进退避。
    fn write(self: *PeerLinks, link: *Link, stream_id: u64, bytes: []const u8, is_last: bool, now: u64) bool {
        const cnx_handle = link.cnx orelse {
            self.refused += 1;
            return false;
        };
        var conn = QUICConnection.fromRaw(cnx_handle);
        conn.streamWrite(stream_id, bytes, is_last) catch |write_err| {
            err_handler.reportError(.transport, "Failed to write to peer link", write_err);
            // 写失败说明这条链路已经不可用，让它进退避而不是继续往里灌。
            self.fail(link, now);
            self.refused += 1;
            return false;
        };
        self.sent += 1;
        return true;
    }

    /// 取一条就绪的链路；没就绪时顺手发起建连并计一次拒绝。
    fn readyLink(self: *PeerLinks, node_id: u16, now: u64) ?*Link {
        const link = self.linkFor(node_id) orelse {
            self.refused += 1;
            return null;
        };
        if (link.state != .ready) {
            self.ensureConnecting(link, now);
            self.refused += 1;
            return null;
        }
        return link;
    }

    /// 周期性推进退避中的链路。
    ///
    /// 由 Worker 的后端轮询定时器调用。没有它，一条进入退避的链路只能等下一次投递
    /// 来唤醒——而那次投递必然失败一回，等于每个退避周期至少损失一帧。
    pub fn poll(self: *PeerLinks, now: u64) void {
        for (self.links) |*link| {
            if (link.node_id == 0) continue;
            if (link.state != .backoff) continue;
            self.ensureConnecting(link, now);
        }
    }

    // ------------------------------------------------------------------------
    // 内部
    // ------------------------------------------------------------------------

    /// 找到或占用一个槽位；表满时返回 null。
    fn linkFor(self: *PeerLinks, node_id: u16) ?*Link {
        var free: ?*Link = null;
        for (self.links) |*link| {
            if (link.node_id == node_id) return link;
            if (link.node_id == 0 and free == null) free = link;
        }
        const slot = free orelse {
            std.log.warn("[PEER] no free peer link slot for node {}", .{node_id});
            return null;
        };
        slot.* = .{ .node_id = node_id };
        return slot;
    }

    /// 把 realm 打进 OPEN 头保留的那两字节。
    ///
    /// 原帧字节是借用的（指向接收池槽位或别人的缓冲），不能就地改——就地改会污染
    /// 同一帧到别的目标的那几次投递。
    fn patchRealm(self: *PeerLinks, frame_bytes: []const u8, realm: u16) ?[]const u8 {
        // OPEN 头是 8 字节，group/route_key 在偏移 6、7（见 FrameHeader.encode）。
        if (frame_bytes.len < protocol.frame.OPEN_HEADER_SIZE) return null;
        if (frame_bytes.len > self.scratch.len) {
            std.log.warn("[PEER] frame too large for peer link: {} bytes", .{frame_bytes.len});
            return null;
        }
        @memcpy(self.scratch[0..frame_bytes.len], frame_bytes);
        self.scratch[6] = @intCast(realm >> 8);
        self.scratch[7] = @intCast(realm & 0xFF);
        return self.scratch[0..frame_bytes.len];
    }

    /// 在状态机允许时发起建连。
    fn ensureConnecting(self: *PeerLinks, link: *Link, now: u64) void {
        switch (link.state) {
            .ready, .connecting => return,
            .backoff => if (now < link.retry_at) return,
            .idle => {},
        }

        const address = self.peerAddress(link.node_id) orelse {
            // membership 里还没有这个节点（或它已经离开）。算一次失败进退避，
            // 而不是每帧都去查一遍成员表。
            self.fail(link, now);
            return;
        };

        const client = self.acquireClient() catch {
            self.fail(link, now);
            return;
        };

        link.state = .connecting;
        link.cnx = client.connectAddress(address, peer_server_name, null) catch {
            self.fail(link, now);
            return;
        };
    }

    /// 建连/连接失败：安排指数退避。
    fn fail(self: *PeerLinks, link: *Link, now: u64) void {
        _ = self;
        link.cnx = null;
        link.failure_count +|= 1;
        const shift: u6 = @intCast(@min(link.failure_count - 1, 8));
        link.retry_at = now + @min(backoff_base_us << shift, backoff_max_us);
        link.state = .backoff;
    }

    fn acquireClient(self: *PeerLinks) !*AsyncClient {
        if (self.client) |*client| return client;
        self.client = try AsyncClient.init(self.allocator, self.client_config, self.event_loop);
        const client = &self.client.?;
        client.setCallbacks(self, onConnected, null, onClose);
        client.start();
        return client;
    }

    /// 对等节点的集群端口地址。
    ///
    /// membership 给的是 gossip 通告地址，复用它的 IP 换成集群端口——与 forward 隧道
    /// 复用同一个假设（集群同构，全集群同一个端口）。
    fn peerAddress(self: *PeerLinks, node_id: u16) ?foundation.net.Address {
        const view = self.coordinator.membershipView() orelse return null;
        const member = view.lookup(node_id) orelse return null;
        if (!member.isForwardable()) return null;
        return foundation.net.withPort(member.address, self.config.peer_port);
    }

    fn findByCnx(self: *PeerLinks, cnx: quic.c.QuicCnx) ?*Link {
        for (self.links) |*link| {
            if (link.cnx == cnx) return link;
        }
        return null;
    }

    fn onConnected(ctx: ?*anyopaque, conn: *QUICConnection) void {
        const self: *PeerLinks = @ptrCast(@alignCast(ctx.?));
        const link = self.findByCnx(conn.inner) orelse return;
        link.state = .ready;
        link.failure_count = 0;
        link.retry_at = 0;
        // 世代前进：此前开的会话流属于上一条连接，在这条连接上并不存在。
        link.epoch +%= 1;
        std.log.info("[PEER] link to node {} is ready", .{link.node_id});
    }

    fn onClose(ctx: ?*anyopaque, conn: *QUICConnection, event: quic.c.CallbackEvent) void {
        _ = event;
        const self: *PeerLinks = @ptrCast(@alignCast(ctx.?));
        const link = self.findByCnx(conn.inner) orelse return;
        std.log.info("[PEER] link to node {} closed", .{link.node_id});
        // 无论此前是否就绪都要进退避：留在 ready/connecting 会让状态永久停滞，
        // 此后每次建连尝试都被误判为"已在进行中"。
        self.fail(link, quic.c.currentTime());
    }
};

/// 连集群端口时用的 SNI。
///
/// 对面**不**从它解析 realm（集群监听器没有 realm 概念，realm 走帧头），
/// 但 TLS 要求客户端给一个 server_name，而且证书校验会核对它。
/// 因此集群 CA 签发的节点证书必须把这个名字放进 SAN。
pub const peer_server_name = "lyune-cluster";

// ============================================================================
// 测试
// ============================================================================

test "patching realm rewrites only the two reserved bytes" {
    const allocator = std.testing.allocator;

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var coordinator = try control.Coordinator.init(std.testing.io, allocator, .{
        .node_id = 1,
        .advertise_address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 0),
        .forward_address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 0),
        .worker_count = 1,
        .handoff_queue_capacity = 4,
    });
    defer coordinator.deinit();

    var links = try PeerLinks.init(allocator, &loop, &coordinator, .{}, .{ .peer_port = 7948 });
    defer links.deinit();

    // 一帧 `.peer` OPEN，group/route_key 都是 0（客户端/后端连接上它们是保留字节）。
    var frame_buf: [64]u8 = undefined;
    var encoder = codec.FrameEncoder.init(&frame_buf);
    const original = try encoder.encodeOpen(.peer, .{}, .none, protocol.frame.Flags.last(), "body");

    const patched = links.patchRealm(original, 0x0709).?;

    // realm 落在偏移 6、7。
    try std.testing.expectEqual(@as(u8, 0x07), patched[6]);
    try std.testing.expectEqual(@as(u8, 0x09), patched[7]);
    // 解回来就是发送侧填进去的那个 realm。
    const reparsed = try codec.parseExactFrame(patched);
    try std.testing.expectEqual(@as(u16, 0x0709), reparsed.header.realmHint().?);

    // 其余每一个字节都不能动——尤其 body_len 与 flags，改了就是分帧错位。
    for (original, patched, 0..) |before, after, i| {
        if (i == 6 or i == 7) continue;
        try std.testing.expectEqual(before, after);
    }

    // 关键：原帧没有被就地改写。同一帧要投给多个节点，就地改会污染后续几次投递。
    try std.testing.expectEqual(@as(u8, 0), original[6]);
    try std.testing.expectEqual(@as(u8, 0), original[7]);
}

test "delivery to an unknown node is refused, not queued" {
    const allocator = std.testing.allocator;

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var coordinator = try control.Coordinator.init(std.testing.io, allocator, .{
        .node_id = 1,
        .advertise_address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 0),
        .forward_address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 0),
        .worker_count = 1,
        .handoff_queue_capacity = 4,
    });
    defer coordinator.deinit();

    var links = try PeerLinks.init(allocator, &loop, &coordinator, .{}, .{ .peer_port = 7948 });
    defer links.deinit();

    var frame_buf: [64]u8 = undefined;
    var encoder = codec.FrameEncoder.init(&frame_buf);
    const frame_bytes = try encoder.encodeOpen(.peer, .{}, .none, protocol.frame.Flags.last(), "body");

    // 集群没启用，membership 视图为空 → 查不到地址。
    //
    // 必须返回 false 而不是排队：排队意味着后端以为消息在路上，而它可能永远发不出去。
    // 返回 false 让扇出侧把这个目标回报为不可达，后端才会转离线存储。
    try std.testing.expect(!links.send(7, 0, frame_bytes));
    try std.testing.expectEqual(@as(u64, 1), links.refused);
    try std.testing.expectEqual(@as(u64, 0), links.sent);

    // 失败已经登记成退避，而不是每帧都重查成员表。
    const link = links.linkFor(7).?;
    try std.testing.expectEqual(LinkState.backoff, link.state);
    try std.testing.expect(link.retry_at > 0);
}

test "a session stream is refused once its link is no longer the one it was opened on" {
    const allocator = std.testing.allocator;

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var coordinator = try control.Coordinator.init(std.testing.io, allocator, .{
        .node_id = 1,
        .advertise_address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 0),
        .forward_address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 0),
        .worker_count = 1,
        .handoff_queue_capacity = 4,
    });
    defer coordinator.deinit();

    var links = try PeerLinks.init(allocator, &loop, &coordinator, .{}, .{ .peer_port = 7948 });
    defer links.deinit();

    // 链路没就绪 → 开不出会话流，且这一次被计入拒绝而不是静默排队。
    try std.testing.expect(links.beginSession(7, 0, "\x00\x00\x00\x00") == null);
    try std.testing.expect(links.refused > 0);

    // 伪造一条"曾经就绪过、后来重连了"的链路：世代已经前进，当初那条流号在新连接上
    // 并不存在。继续往里写会在一条陌生的流上拼出半段字节流，所以必须拒。
    const link = links.linkFor(7).?;
    link.state = .ready;
    link.epoch = 2;
    try std.testing.expect(!links.sendOn(.{ .node_id = 7, .epoch = 1, .stream_id = 0 }, "data", false));
}

test "the link table refuses new peers instead of evicting a live one" {
    const allocator = std.testing.allocator;

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var coordinator = try control.Coordinator.init(std.testing.io, allocator, .{
        .node_id = 1,
        .advertise_address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 0),
        .forward_address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 0),
        .worker_count = 1,
        .handoff_queue_capacity = 4,
    });
    defer coordinator.deinit();

    var links = try PeerLinks.init(allocator, &loop, &coordinator, .{}, .{ .peer_port = 7948, .max_links = 2 });
    defer links.deinit();

    // 占满两个槽位，且同一个 node_id 复用同一条链路。
    const first = links.linkFor(11).?;
    try std.testing.expect(links.linkFor(11).? == first);
    _ = links.linkFor(12).?;

    // 满了之后拒绝新节点。挤掉一条在用的链路会让两个节点互相踢，
    // 表现成周期性的投递失败——比明确拒绝难查得多。
    try std.testing.expect(links.linkFor(13) == null);
    try std.testing.expectEqual(@as(u16, 11), first.node_id);
}
