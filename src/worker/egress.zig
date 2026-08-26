//! 后端回程出口
//!
//! 下行的分派判据是**网关自己的表**，不是帧内容（设计文档 §7.2）：
//!
//! - 后端流在认证等待表里 → 认证响应，累积后判定
//! - 后端流在回程映射里   → 某个客户端请求的响应，原样字节写回，不解析
//! - 后端主动开的流       → `.peer` / `.multicast` 推送的载体，要分帧解析
//! - 以上都不是           → 孤儿响应（客户端早已断开、条目已回收），丢弃
//!
//! 顺序不能反过来由帧内容决定，否则后端可以把一个数据响应伪装成认证成功。
//!
//! ## 为什么推送这一条要解析
//!
//! §1.2 说下行不解析。推送是那条规则的例外，而例外的判据仍然是网关自己的表
//! （`peer_initiated`：这条流是后端开的），不是帧里的某个字段。要解析是因为投递
//! 目标写在 body 前缀里——不读它就不知道该发给谁。
//!
//! ## 一次性推送与流式推送
//!
//! `.peer` / `.multicast` 的目标列表只出现在 OPEN 帧上（目标是流级属性，同
//! `dest_kind`）。所以两种形态的差别只有一处：
//!
//! - OPEN 带 `eof` → 一次性推送，读列表、扇出、结束，不留任何状态
//! - OPEN + DATA×N → 流式推送，OPEN 时把成员集合**冻结**进一个会话，后续 DATA
//!   沿会话续传（见本文件的"流式推送"一节与 push_session.zig）
//!
//! 流式的每一跳都用"它所在的那条流"标识会话，线格式里没有任何新增字段。代价是
//! 目标数必须有上限：在网关里把一条流复制 N 份，出口带宽就乘以 N。
//!
//! ## 错误处理与上行不同
//!
//! 上行的编码违规会关掉整条客户端连接。下行不能这么做：一条后端连接承载着所有
//! 客户端的请求，为一个畸形推送杀掉它等于让全体客户端的在途请求一起失败。
//! 因此这里的策略一律是"记日志 + 丢弃这条推送流"。后端是配置指定且经过认证的，
//! 畸形推送更可能是版本不匹配而不是攻击。

const std = @import("std");

const foundation = @import("../foundation/mod.zig");
const err_handler = foundation.err;
const RealmId = foundation.realm.RealmId;
const protocol = @import("../protocol/mod.zig");
const codec = protocol.codec;
const framing = protocol.framing;
const body = protocol.body;
const frame = protocol.frame;
const quic = @import("../quic/mod.zig");
const QUICConnection = quic.connection.Connection;
const backend = @import("../backend/mod.zig");
const BackendTransport = backend.BackendTransport;
const TransportRecv = backend.transport.TransportRecv;
const connection = @import("connection.zig");
const ConnectionContext = connection.ConnectionContext;
const inflight = @import("inflight.zig");
const peer_link = @import("peer_link.zig");
const push_session = @import("push_session.zig");
const GatewayWorker = @import("worker.zig").GatewayWorker;

/// 单个 Worker 允许的并发后端推送流数量。
///
/// 每条正在重组的推送流都占着一份残帧缓冲（最坏一帧 64KB）。没有上限的话，
/// 一个只发半帧就不管了的后端能把 Worker 的内存吃干。
pub const max_push_streams: usize = 256;

/// 下行出口状态：推送流的重组缓冲 + 投递回报的复用编码缓冲。
///
/// 线程私有，每个 Worker 一份。
pub const Egress = struct {
    allocator: std.mem.Allocator,
    /// 后端主动流的跨轮残帧，按后端流的复合键存。
    ///
    /// 后端接收池按固定大小的槽位切片，一个 64KB 的推送帧会分成几十个分片到达，
    /// 因此下行也需要一份分帧状态——上行那套按客户端流存，这套按后端流存。
    ///
    /// 键里带 transport 实例身份：句柄只在单个实例内唯一，只用句柄做键会让两个后端的
    /// 推送分片被拼进同一份重组缓冲，解出来的是一帧谁都没发过的垃圾。
    pushes: std.AutoHashMap(inflight.StreamKey, framing.Spill),
    /// 投递回报的编码缓冲。
    ///
    /// 启动期一次分配、之后复用：回报最坏是一整帧（8191 个不可达目标），放栈上
    /// 会炸栈，每次现分配又违背运行期零分配。回报是逐个目标增量写进来的，
    /// 因此直接在这块缓冲上就地拼，不需要第二块缓冲和一次拷贝。
    report_buf: []u8,
    /// 进行中的流式推送会话（设计文档 §5.3）。
    sessions: push_session.Table,

    pub fn init(allocator: std.mem.Allocator, worker_id: u8) !Egress {
        const report_buf = try allocator.alloc(u8, frame.DATA_HEADER_SIZE + frame.MAX_BODY_SIZE);
        errdefer allocator.free(report_buf);
        return .{
            .allocator = allocator,
            .pushes = std.AutoHashMap(inflight.StreamKey, framing.Spill).init(allocator),
            .report_buf = report_buf,
            .sessions = try push_session.Table.init(allocator, worker_id),
        };
    }

    pub fn deinit(self: *Egress) void {
        var it = self.pushes.valueIterator();
        while (it.next()) |spill| spill.deinit(self.allocator);
        self.pushes.deinit();
        self.allocator.free(self.report_buf);
        self.sessions.deinit();
    }

    /// 丢弃一条推送流的重组状态。
    fn dropPush(self: *Egress, key: inflight.StreamKey) void {
        if (self.pushes.fetchRemove(key)) |removed| {
            var spill = removed.value;
            spill.deinit(self.allocator);
        }
    }
};

/// 可以被去重记账的节点编号上限。
///
/// 去重不是优化而是**正确性**：同一份帧发两次给同一个位置，那个位置会把它投给同一批
/// 连接两次。编号超出这个范围的节点因此被判为不可投递（记 warn + 回报不可达），
/// 而不是"不去重照样发"。1024 与 `cluster.max_nodes` 的默认值一致。
const max_routable_nodes: usize = 1024;

/// 一次扇出里需要转投的位置集合。
///
/// 它就是设计文档 §8.5 的"目标集合函数"的运行期形态：**策略只决定这个集合有多大，
/// 不决定怎么送。** 亲和模式下每个目标往里加一个位置，广播模式下一次加满；两种模式
/// 之后走的是同一条 `flush`。刻意不做成两条代码路径——它们的正确性不变量不同
/// （亲和要强制重定向、广播不要），做成两套实现的话运维配错就是静默的消息丢失。
///
/// 用定长数组而不是位集合：`[256]` + `[1024]` 各两份是 2.5KB 栈空间，一次 memset
/// 的代价对一次扇出可以忽略，换来的是没有任何位运算需要读者验证。
const RouteSet = struct {
    /// 本节点其他 Worker，下标即 worker_id。
    worker_pending: [256]bool = @splat(false),
    worker_accepted: [256]bool = @splat(false),
    /// 其他节点，下标即 node_id。
    node_pending: [max_routable_nodes]bool = @splat(false),
    node_accepted: [max_routable_nodes]bool = @splat(false),
    /// 实际发出的转投次数（去重之后）。
    sent: usize = 0,
    /// 只在本节点内转投，永不发给别的节点。
    ///
    /// 对等节点送进来的帧用这个模式，它是**防环的第二道**：跨节点一跳 + 节点内一跳，
    /// 总跳数被结构性地限死在 2。没有它，两个节点的选址视图短暂不一致时就能让一帧
    /// 在两个节点之间来回弹。
    local_only: bool = false,

    /// 记下一个待转投的位置；就是本 Worker 时什么也不做。
    fn mark(self: *RouteSet, worker: *GatewayWorker, home: foundation.placement.Location) void {
        if (home.node_id != worker.placement.self.node_id) {
            if (self.local_only) return;
            if (home.node_id < max_routable_nodes) self.node_pending[home.node_id] = true;
            return;
        }
        if (home.worker_id != worker.placement.self.worker_id) {
            self.worker_pending[home.worker_id] = true;
        }
    }

    /// 记下一个目标的全部候选位置。
    ///
    /// 稳定期就是一个 home；成员刚变过且这个键漂移了就是两个（§8.5 的双查）。
    /// 多发的那一份不会造成重复投递：一条连接只存在于一个位置上，另一个位置查不到
    /// 索引就什么也不做——这与广播策略下"查不到是正常情形"是同一件事。
    fn markHome(self: *RouteSet, worker: *GatewayWorker, realm: RealmId, dest_id: u64) void {
        for (worker.placement.candidates(realm, dest_id).slice()) |home| self.mark(worker, home);
    }

    /// 记下本节点所有其他 Worker，以及（非 local_only 时）所有其他节点。
    fn markAll(self: *RouteSet, worker: *GatewayWorker) void {
        var worker_id: u8 = 0;
        while (worker_id < worker.placement.worker_count) : (worker_id += 1) {
            if (worker_id != worker.placement.self.worker_id) self.worker_pending[worker_id] = true;
        }
        if (self.local_only) return;
        for (worker.placement.nodes) |node_id| {
            if (node_id == worker.placement.self.node_id) continue;
            if (node_id < max_routable_nodes) self.node_pending[node_id] = true;
        }
    }

    /// 把这一帧发给集合里的每个位置，每个位置只发一次。
    fn flush(self: *RouteSet, worker: *GatewayWorker, realm: RealmId, bytes: []const u8) void {
        for (self.worker_pending, 0..) |pending, worker_id| {
            if (!pending) continue;
            worker.coordinator.messageRouter().deliver(@intCast(worker_id), bytes, realm, 0) catch |err| {
                // 必须可观测：静默丢弃会表现成"某些设备偶发收不到推送"，
                // 而那是最难定位的一类故障。
                std.log.warn("[ROUTE] app message handoff to worker {} failed: {}", .{ worker_id, err });
                continue;
            };
            self.worker_accepted[worker_id] = true;
            self.sent += 1;
        }

        for (self.node_pending, 0..) |pending, node_id| {
            if (!pending) continue;
            // 跨节点走对等网关节点的 QUIC 链路（设计文档 §8.5）。链路不可用时
            // `send` 返回 false，这个节点上的目标随后会被回报为不可达——**不静默丢弃**，
            // 后端因此会把消息转去离线存储。
            const links = if (worker.peer_links) |*value| value else {
                std.log.warn("[ROUTE] cross-node delivery needs cluster.peer_* certificates; node {} unreachable", .{node_id});
                continue;
            };
            if (links.send(@intCast(node_id), realm, bytes)) {
                self.node_accepted[node_id] = true;
                self.sent += 1;
            }
        }
    }

    /// 流式会话的 OPEN 转投：与 `flush` 用同一份位置集合，但**记住发给了谁**。
    ///
    /// 后续 DATA 帧上没有目标列表，所以位置集合不能每帧重算——它在 OPEN 这一刻
    /// 就被冻结进会话里（§5.3 的"成员集合在 OPEN 时冻结"）。
    ///
    /// 同机跨 Worker 只需要记住 worker_id：那一跳的会话身份是信封里的会话号。
    /// 跨节点要记住一条流：那一跳的会话身份是对等链路上的一条专属流。
    fn flushSession(
        self: *RouteSet,
        worker: *GatewayWorker,
        session: *push_session.Session,
        bytes: []const u8,
    ) void {
        for (self.worker_pending, 0..) |pending, worker_id| {
            if (!pending) continue;
            worker.coordinator.messageRouter().deliver(@intCast(worker_id), bytes, session.realm, session.id) catch |err| {
                std.log.warn("[ROUTE] streaming handoff to worker {} failed: {}", .{ worker_id, err });
                continue;
            };
            self.worker_accepted[worker_id] = true;
            session.workers[worker_id] = true;
            self.sent += 1;
        }

        for (self.node_pending, 0..) |pending, node_id| {
            if (!pending) continue;
            const links = if (worker.peer_links) |*value| value else {
                std.log.warn("[ROUTE] cross-node streaming needs cluster.peer_* certificates; node {} unreachable", .{node_id});
                continue;
            };
            const stream = links.beginSession(@intCast(node_id), session.realm, bytes) orelse continue;
            if (!session.addNode(stream)) {
                // 后面那些节点掉出会话。不推倒已经建好的部分：那些客户端已经收到
                // 头部，把它们的流也砍掉等于让更多人拿到残缺的字节流。
                std.log.warn("[PUSH] streaming session spans more than {} nodes, node {} dropped", .{ push_session.max_nodes, node_id });
                return;
            }
            self.node_accepted[node_id] = true;
            self.sent += 1;
        }
    }

    /// 这个位置那一次转投是否被受理。
    ///
    /// 回报语义是**「本位置是否受理」而不是「是否已投递」**：给跨位置这一跳单独加 ack
    /// 并不能让端到端可靠（客户端那一跳照样会丢），只是把不可靠往后推一格。真正要
    /// "消息必达"必须靠后端离线存储 + 客户端拉取。
    fn accepted(self: *const RouteSet, worker: *GatewayWorker, home: ?foundation.placement.Location) bool {
        const location = home orelse return false;
        if (location.node_id != worker.placement.self.node_id) {
            return location.node_id < max_routable_nodes and self.node_accepted[location.node_id];
        }
        if (location.worker_id == worker.placement.self.worker_id) return false;
        return self.worker_accepted[location.worker_id];
    }

    /// 这个目标的候选位置里有任何一个受理了这一次转投。
    ///
    /// 必须与 `markHome` 用同一份候选枚举：双查窗口里连接可能还在旧 home 上，
    /// 结算时只看新 home 会把"已经送到旧 home"误报成不可达，后端于是又写一份离线，
    /// 用户拿到两条一样的消息——这比漏投更难解释。
    fn acceptedHome(self: *const RouteSet, worker: *GatewayWorker, realm: RealmId, dest_id: u64) bool {
        for (worker.placement.candidates(realm, dest_id).slice()) |home| {
            if (self.accepted(worker, home)) return true;
        }
        return false;
    }
};

/// 别的 Worker 转投过来的一条应用消息：只做本地投递，绝不再转投。
///
/// 由 worker.messageCallback 在本 Worker 线程内调用。不再转投这一点是**防环的全部
/// 机制**——不需要帧里带跳数或"已路由"标记，因为这条队列只由别的 Worker 的选路
/// 决策喂进来，而选路只会指向终点。
///
/// `realm` 来自消息本身，不从帧里读：realm 是网关按 SNI 定的（§12.3），帧是后端给的。
///
/// 一律不回报：后端那条双向流属于**发起方 Worker**，本 Worker 没有它的句柄。
/// 这与"回报语义 = 本位置是否受理"是一致的——受理与否在发起方那一侧就已经定了。
pub fn deliverHandoff(self: *GatewayWorker, realm: RealmId, session_id: u64, bytes: []const u8) void {
    if (session_id != 0) return deliverStreamingHandoff(self, realm, session_id, bytes);

    const parsed = codec.parseExactFrame(bytes) catch |err| {
        std.log.warn("[ROUTE] malformed handed-off app message: {}", .{err});
        return;
    };
    if (!parsed.header.isOpen() or !parsed.header.isLast()) {
        std.log.warn("[ROUTE] handed-off app message must be a single OPEN with eof", .{});
        return;
    }

    switch (parsed.header.dest_kind) {
        .peer => {
            const list = body.TargetList.decode(parsed.body) catch return;
            for (0..list.count) |i| _ = deliverLocalPeer(self, realm, list.get(i), bytes);
        },
        .multicast => {
            const list = body.TargetList.decode(parsed.body) catch return;
            for (0..list.count) |i| _ = deliverLocalGroup(self, realm, list.get(i), parsed);
        },
        .gateway => {
            const ctrl = parsed.header.controlType() orelse return;
            switch (ctrl) {
                .kick_off => kickAll(self, null, realm, 0, decodeTokens(parsed.body) orelse return, bytes, false),
                .join_group, .leave_group => applyGroupBinding(self, realm, ctrl, parsed.body),
                else => std.log.warn("[ROUTE] control type 0x{x} is not routable", .{@intFromEnum(ctrl)}),
            }
        },
        // 转投的只可能是投递指令。`.service` 到了这里说明选路侧出了 bug。
        .service => std.log.warn("[ROUTE] a .service frame was handed off, which should be impossible", .{}),
    }
}

/// 这个 `conn_token` 指向的连接是否就在本 Worker 上。
fn isLocal(self: *GatewayWorker, token: connection.ConnToken) bool {
    return token.node_id == self.placement.self.node_id and
        token.worker_id == self.placement.self.worker_id;
}

/// 对等网关节点送进来的一次投递（设计文档 §8.5 的跨节点那一半）。
///
/// 由 ingress 在校验过"这条连接是对等节点、帧是带 eof 的 `.peer`/`.multicast` OPEN"
/// 之后调用。与 `deliverHandoff` 的唯一区别是**允许一次节点内转投**：
///
/// ```
/// 节点 A ──跨节点一跳──> 节点 B 的任意 Worker ──节点内一跳──> home Worker ──> 连接
/// ```
///
/// 中间那一跳跑不掉：A 的 QUIC 连接落在 B 的哪个 Worker 由 B 的内核 reuseport 决定，
/// 与目标的 home 无关。而节点内转投过去的帧走 `deliverHandoff`，那条路**不再转投**
/// ——所以总跳数被结构性地限死在 2，不需要跳数字段。
///
/// 一律不回报：后端那条双向流在**节点 A** 上，本节点没有它的句柄。
pub fn deliverFromPeer(self: *GatewayWorker, realm: RealmId, bytes: []const u8) void {
    const parsed = codec.parseExactFrame(bytes) catch |err| {
        std.log.warn("[PEER] malformed peer delivery: {}", .{err});
        return;
    };
    const list = body.TargetList.decode(parsed.body) catch |err| {
        std.log.warn("[PEER] malformed target list from peer node: {}", .{err});
        return;
    };

    var routes = RouteSet{ .local_only = true };
    switch (parsed.header.dest_kind) {
        .peer => {
            // 选址是纯函数，所以本节点能独立算出目标该在哪个 Worker，
            // 不需要 A 把它算出来的位置塞进线格式（这正是 §8.5 那条前提的价值）。
            if (self.placement.strategy == .broadcast) {
                routes.markAll(self);
            } else {
                for (0..list.count) |i| routes.markHome(self, realm, list.get(i));
            }
            routes.flush(self, realm, bytes);
            for (0..list.count) |i| {
                const dest_id = list.get(i);
                if (self.placement.isHome(realm, dest_id)) _ = deliverLocalPeer(self, realm, dest_id, bytes);
            }
        },
        .multicast => {
            // 组成员的落点与 group_id 无关，所以本节点内必须问过每个 Worker。
            routes.markAll(self);
            routes.flush(self, realm, bytes);
            for (0..list.count) |i| _ = deliverLocalGroup(self, realm, list.get(i), parsed);
        },
        // ingress 已经把这两种拒掉了；走到这里说明调用方绕过了校验。
        .gateway, .service => std.log.warn("[PEER] unexpected dest_kind from a peer node", .{}),
    }

    std.log.info("[PEER] realm={} kind={s} targets={} routed={}", .{
        realm,
        @tagName(parsed.header.dest_kind),
        list.count,
        routes.sent,
    });
}

/// 解出一个 conn_token 列表；畸形则记日志返回 null。
fn decodeTokens(payload: []const u8) ?body.TargetList {
    return body.TargetList.decode(payload) catch |err| {
        std.log.warn("[ROUTE] malformed conn_token list: {}", .{err});
        return null;
    };
}

/// 投递回报的增量编码器。
/// 直接写进 `Egress.report_buf`：先把 dest_id 逐个落在 body 位置上，最后回填
/// count 与 DATA 帧头。这样省掉"先攒一个 u64 数组再编码"里的第二块 64KB 缓冲
/// 和那一次拷贝。
const ReportBuilder = struct {
    buf: []u8,
    count: usize = 0,

    /// dest_id 区起点：DATA 帧头 + count 字段。
    const list_offset: usize = frame.DATA_HEADER_SIZE + 2;

    fn add(self: *ReportBuilder, dest_id: u64) void {
        // 满了就截断。回报是尽力而为的诊断信息，为它把一次成功的扇出判失败不值得；
        // 而能触发截断的前提是一帧里塞了 8191 个目标且全部不可达。
        if (self.count >= body.max_targets) return;
        const offset = list_offset + self.count * body.dest_id_size;
        std.mem.writeInt(u64, self.buf[offset..][0..body.dest_id_size], dest_id, .big);
        self.count += 1;
    }

    /// 回填 count 与帧头，返回可直接写出的完整 DATA 帧。
    fn finish(self: *ReportBuilder) []const u8 {
        const body_len = 2 + self.count * body.dest_id_size;
        std.mem.writeInt(u16, self.buf[frame.DATA_HEADER_SIZE..][0..2], @intCast(self.count), .big);
        const header = frame.FrameHeader.initData(frame.Flags.last(), @intCast(body_len));
        // buf 是启动期按最大帧长分配的，写 4 字节帧头不可能失败。
        _ = header.encode(self.buf[0..frame.DATA_HEADER_SIZE]) catch unreachable;
        return self.buf[0 .. frame.DATA_HEADER_SIZE + body_len];
    }
};

/// 一条推送流的分帧分派上下文。
const PushDispatcher = struct {
    worker: *GatewayWorker,
    transport: BackendTransport,
    /// 推送来源 transport 所属的隔离域，来自注册表键而不是帧内容。
    realm: RealmId,
    /// 这条后端推送流的复合键；流式会话就是按它定位的。
    key: inflight.StreamKey,

    fn onFrame(self: *PushDispatcher, parsed: codec.Frame) bool {
        return dispatchPush(self.worker, self.transport, self.realm, self.key, parsed);
    }
};

/// 后端主动开的流上来了数据：重组成完整帧，按目的地投递。
///
/// 由 worker.drainTransport 在 `event.peer_initiated` 时调用；`realm` 由调用方从
/// 注册表键上取——推送只能投给注册这条 transport 的那个 realm 里的连接，帧里没有
/// 任何字段能改变它（设计文档 §12.2）。
pub fn handlePush(self: *GatewayWorker, transport: BackendTransport, realm: RealmId, event: TransportRecv) void {
    const eg = &self.egress;
    // 句柄只在这个 transport 实例内部唯一，重组缓冲必须按复合键存。
    const key = inflight.StreamKey{ .transport = transport.id(), .stream = event.stream_id };

    // 已有残帧就接着用；没有就借栈上的空壳，帧边界对齐时不碰表也不分配。
    var fresh_spill: framing.Spill = .{ .items = &.{}, .capacity = 0 };
    const existing = eg.pushes.getPtr(key);
    if (existing == null and eg.pushes.count() >= max_push_streams) {
        std.log.warn("[PUSH] too many concurrent push streams, dropping backend_stream={}", .{event.stream_id});
        return;
    }
    const spill = existing orelse &fresh_spill;

    var dispatcher = PushDispatcher{
        .worker = self,
        .transport = transport,
        .realm = realm,
        .key = key,
    };

    const drained = framing.drainFrames(
        PushDispatcher,
        &dispatcher,
        PushDispatcher.onFrame,
        spill,
        self.allocator,
        event.data,
        codec.MAX_FRAME_SIZE,
    );

    // 先把缓冲状态落回表：栈上那份残帧不落盘就会随本函数返回丢失。
    if (existing == null) {
        if (fresh_spill.items.len > 0) {
            eg.pushes.put(key, fresh_spill) catch |err| {
                fresh_spill.deinit(self.allocator);
                err_handler.reportError(.session, "Failed to keep partial push frame", err);
                return;
            };
        } else {
            fresh_spill.deinit(self.allocator);
        }
    } else if (spill.items.len == 0) {
        eg.dropPush(key);
    }

    drained catch |err| {
        // 只丢这条推送流，不动后端连接：那条连接上还有其他客户端的在途请求。
        std.log.warn("[PUSH] framing violation on backend_stream={}: {}", .{ event.stream_id, err });
        eg.dropPush(key);
        return;
    };

    if (event.is_fin) {
        eg.dropPush(key);
        // 后端把推送流关了却没发过 eof：这个会话的尾巴永远不会来，就地作废，
        // 否则客户端会一直等下去。
        if (self.egress.sessions.findByOrigin(key)) |session| abortSession(self, session);
    }
}

/// 分派一个完整的推送帧；返回 false 停止分帧。
fn dispatchPush(
    self: *GatewayWorker,
    transport: BackendTransport,
    realm: RealmId,
    key: inflight.StreamKey,
    parsed: codec.Frame,
) bool {
    const header = parsed.header;
    const backend_stream = key.stream;

    // 先看这条后端流上有没有在进行中的流式会话：DATA 帧上没有目的地，去向只能从
    // 会话里查。这也顺带消掉了帧走私——后续帧即使伪造 8 字节的 OPEN 帧头，
    // 也改不了已经冻结的成员集合。
    if (self.egress.sessions.findByOrigin(key)) |session| {
        if (header.isOpen()) {
            std.log.warn("[PUSH] a second OPEN on a live push session: backend_stream={}", .{backend_stream});
            abortSession(self, session);
            return false;
        }
        writeSessionFrame(self, session, parsed);
        return true;
    }

    if (!header.isOpen()) {
        // 推送流的首帧必须是 OPEN。走到这里说明后端在一条网关从未见过 OPEN 的流上
        // 发了 DATA，或者在 eof 之后继续发。
        std.log.warn("[PUSH] non-OPEN frame on backend_stream={}", .{backend_stream});
        return false;
    }

    switch (header.dest_kind) {
        .peer => {},
        .gateway => return dispatchBackendControl(self, transport, realm, backend_stream, parsed),
        .multicast => return dispatchMulticast(self, transport, realm, key, parsed),
        // 下行寻址 `.service` 没有意义：网关不是后端的客户端，后端要调别的服务
        // 应该自己发起，不该借这条隧道。
        .service => {
            std.log.warn("[PUSH] backend addressed a service on the downlink: backend_stream={}", .{backend_stream});
            return false;
        },
    }

    // OPEN 没带 eof = 流式推送：冻结成员集合，后续 DATA 沿会话续传（§5.3）。
    if (!header.isLast()) return openStreamingPush(self, transport, realm, key, parsed);

    const list = body.TargetList.decode(parsed.body) catch |err| {
        std.log.warn("[PUSH] malformed target list on backend_stream={}: {}", .{ backend_stream, err });
        return false;
    };

    fanOut(self, transport, realm, backend_stream, list, parsed.bytes, header.flags.report);
    return true;
}

/// 后端 → 网关的控制交换（设计文档 §7.2）。
///
/// 这是 `.gateway` 在下行方向唯一被允许的用途：后端请求网关对某些连接执行一个动作。
/// 它与"网关不是后端的客户端"不矛盾——后端不是在借隧道调别的服务，而是在指挥网关
/// 自己。语法与客户端的控制交换完全相同（`.gateway` + `route_key = ControlType`），
/// **但白名单不同**：这正是 §1.5「语法对称，权限不对称」。
///
/// - 客户端能发：`heartbeat` / `ping` / `disconnect` / `auth_request`
/// - 后端能发：`kick_off` / `join_group` / `leave_group`
///
/// 这条通道让后端能命令网关断开任意连接、把任意连接放进任意组，因此它的安全性完全
/// 依赖网关 ↔ 后端的双向认证（§10.1 的 mTLS）。在 mTLS 落地之前，任何能连上后端
/// 端口的东西都能冒充后端。
fn dispatchBackendControl(
    self: *GatewayWorker,
    transport: BackendTransport,
    realm: RealmId,
    backend_stream: u64,
    parsed: codec.Frame,
) bool {
    const ctrl = parsed.header.controlType() orelse {
        std.log.warn("[CTRL] backend sent an unknown control type: backend_stream={}", .{backend_stream});
        return false;
    };
    switch (ctrl) {
        .kick_off, .join_group, .leave_group => {},
        else => {
            // 白名单之外一律拒绝。控制类型是开放空间，但"后端能指挥网关做什么"
            // 必须是封闭集合，否则新增一个客户端方向的控制类型就顺带给了后端一项权限。
            std.log.warn("[CTRL] control type 0x{x} is not allowed from a backend: backend_stream={}", .{ @intFromEnum(ctrl), backend_stream });
            return false;
        },
    }
    if (!parsed.header.isLast()) {
        std.log.warn("[CTRL] backend control exchange must be one-shot: backend_stream={}", .{backend_stream});
        return false;
    }

    if (ctrl == .join_group or ctrl == .leave_group) {
        return dispatchGroupBinding(self, realm, backend_stream, ctrl, parsed);
    }

    const list = body.TargetList.decode(parsed.body) catch |err| {
        std.log.warn("[KICK] malformed target list on backend_stream={}: {}", .{ backend_stream, err });
        return false;
    };

    kickAll(self, transport, realm, backend_stream, list, parsed.bytes, parsed.header.flags.report);
    return true;
}

/// 组播成员变更：本 Worker 上的连接就地处理，别的位置转投过去。
///
/// 与 kick 一样按 `conn_token` 定位而不是选址函数——token 自带 (节点, Worker)，
/// 所以这里连"算 home"都不需要，更不需要广播。
fn dispatchGroupBinding(
    self: *GatewayWorker,
    realm: RealmId,
    backend_stream: u64,
    ctrl: frame.ControlType,
    parsed: codec.Frame,
) bool {
    const binding = body.GroupBinding.decode(parsed.body) catch |err| {
        std.log.warn("[GROUP] malformed group binding on backend_stream={}: {}", .{ backend_stream, err });
        return false;
    };

    var routes = RouteSet{};
    var applied: usize = 0;
    for (0..binding.members.count) |i| {
        const token = connection.ConnToken.decode(binding.members.get(i));
        if (isLocal(self, token)) {
            if (applyGroupChange(self, realm, ctrl, binding.group_id, token)) applied += 1;
        } else {
            routes.mark(self, .{ .node_id = token.node_id, .worker_id = token.worker_id });
        }
    }
    routes.flush(self, realm, parsed.bytes);

    std.log.info("[GROUP] backend_stream={} realm={} ctrl=0x{x} group={} members={} applied={} routed={}", .{
        backend_stream,
        realm,
        @intFromEnum(ctrl),
        binding.group_id,
        binding.members.count,
        applied,
        routes.sent,
    });
    return true;
}

/// 在本 Worker 上执行一条组成员变更；返回是否真的作用到了一条连接。
fn applyGroupChange(
    self: *GatewayWorker,
    realm: RealmId,
    ctrl: frame.ControlType,
    group_id: u64,
    token: connection.ConnToken,
) bool {
    const ctx = self.conn_manager.byToken(token) orelse return false;

    // 授权校验：只能作用于**发起方所属 realm** 里的连接。少了这一道，realm A 的后端
    // 拿一个猜中的 token 就能把 realm B 的用户塞进自己的组，从而收走那个组的全部广播。
    if (ctx.realm != realm) {
        std.log.warn("[GROUP] cross-realm membership change refused: from realm={} target realm={}", .{ realm, ctx.realm });
        return false;
    }

    if (ctrl == .join_group) {
        self.conn_manager.joinGroup(ctx.cnx_handle, group_id) catch |err| {
            std.log.warn("[GROUP] join refused: group={} err={}", .{ group_id, err });
            return false;
        };
    } else {
        self.conn_manager.leaveGroup(ctx.cnx_handle, group_id);
    }
    return true;
}

/// 转投过来的组成员变更：解出 binding 后逐条就地执行。
fn applyGroupBinding(self: *GatewayWorker, realm: RealmId, ctrl: frame.ControlType, payload: []const u8) void {
    const binding = body.GroupBinding.decode(payload) catch |err| {
        std.log.warn("[GROUP] malformed handed-off group binding: {}", .{err});
        return;
    };
    for (0..binding.members.count) |i| {
        _ = applyGroupChange(self, realm, ctrl, binding.group_id, connection.ConnToken.decode(binding.members.get(i)));
    }
}

/// 逐个执行 kick，并按需回报没踢到的目标。
///
/// 回报对 kick 比对推送更重要：推送丢了是消息没到，业务层能补；kick 没生效是安全
/// 动作静默失效，被踢的人还在线，而后端会以为自己踢成功了。
///
/// `transport` 为 null 表示这是别的 Worker 转投过来的一批，此时没有可回写的后端流
/// ——发起方那一侧已经按"是否受理"结算过回报了。
fn kickAll(
    self: *GatewayWorker,
    transport: ?BackendTransport,
    realm: RealmId,
    backend_stream: u64,
    list: body.TargetList,
    bytes: []const u8,
    want_report: bool,
) void {
    var report = ReportBuilder{ .buf = self.egress.report_buf };
    var routes = RouteSet{};
    var kicked: usize = 0;

    // 先把不在本 Worker 的目标转投出去，再按原序结算——回报必须与目标列表同序，
    // 而转投的成败要在结算之前就已知。
    //
    // token 自带 (节点, Worker)，所以 kick 的寻址是精确的：既不需要算 home，
    // 也不需要广播。这是 §8.4「两跳都不知道」的破解口——kick 的前提是连接已经
    // 认证过了，那一刻网关完全知道"我在哪"，只要在 `AuthContext` 里说出来就行。
    for (0..list.count) |i| {
        const token = connection.ConnToken.decode(list.get(i));
        if (isLocal(self, token)) continue;
        routes.mark(self, .{ .node_id = token.node_id, .worker_id = token.worker_id });
    }
    routes.flush(self, realm, bytes);

    for (0..list.count) |i| {
        const raw = list.get(i);
        const token = connection.ConnToken.decode(raw);
        const done = if (isLocal(self, token))
            kickOne(self, realm, token)
        else
            routes.accepted(self, .{ .node_id = token.node_id, .worker_id = token.worker_id });
        if (done) {
            kicked += 1;
        } else if (want_report) {
            report.add(raw);
        }
    }

    std.log.info("[KICK] backend_stream={} realm={} targets={} kicked={} routed={} missed={}", .{
        backend_stream,
        realm,
        list.count,
        kicked,
        routes.sent,
        report.count,
    });

    if (!want_report) return;
    const target = transport orelse return;
    const data = report.finish();
    _ = target.sendStream(.{}, backend_stream, data, true) catch |err| {
        err_handler.reportError(.session, "Failed to write kick report", err);
    };
}

/// 踢掉一条连接；返回是否真的踢到了。
fn kickOne(self: *GatewayWorker, realm: RealmId, token: connection.ConnToken) bool {
    // 查不到有三种情形，都归为"没踢到"：
    // 1. token 指向别的节点/Worker——需要跨 Worker/跨节点投递通路，尚未建（§8.5 第一层）
    // 2. 连接已经关了
    // 3. 槽位已被复用（generation 失配）
    // 三者对后端的含义相同（这条 kick 没生效），因此不细分，但都必须回报。
    const ctx = self.conn_manager.byToken(token) orelse return false;

    // 授权校验：kick 只能作用于**发起方所属 realm** 里的连接。少了这一道，
    // realm A 的后端拿一个猜中的 token 就能踢掉 realm B 的用户。
    // byToken 刻意不管这件事——定位与授权失败时的处置不同，混在一起会看不清。
    if (ctx.realm != realm) {
        std.log.warn("[KICK] cross-realm kick refused: from realm={} target realm={}", .{ realm, ctx.realm });
        return false;
    }

    // 顺序是有意的：**先吊销，再通知，最后关闭。**
    //
    // 吊销是本地状态改动，一定生效；写帧和关连接都可能失败或在竞态里丢掉。这样即使
    // 通知没送到、连接一时还没断，它也已经什么都做不了了——数据帧过不了准入门禁
    // （§10.2），也不再可被 `.peer` 寻址。
    ctx.authenticated = false;
    ctx.auth_expires_at = 0;
    // 通道也一起收走：datagram 的热路径上没有授权查找，所以吊销必须落到通道表上，
    // 否则这条连接在断开前的那段时间里还能往组里灌状态包（§6.1）。
    ctx.clearChannels();
    self.conn_manager.bindDest(ctx.cnx_handle, 0);

    var buf: [128]u8 = undefined;
    var encoder = codec.FrameEncoder.init(&buf);
    if (encoder.encodeKickOff("kicked")) |notice| {
        var conn = QUICConnection.fromRaw(ctx.cnx_handle);
        conn.streamWrite(ctx.nextPushStream(), notice, true) catch |err| {
            err_handler.reportError(.session, "Failed to notify a kicked client", err);
        };
    } else |err| {
        err_handler.reportError(.session, "Failed to encode kick_off", err);
    }

    // 带错误码关闭：上面那个通知帧可能在关闭竞态里送不到，而错误码一定随
    // CONNECTION_CLOSE 到达，客户端靠它区分"该重新认证"和"网关下线了"。
    var closing = QUICConnection.fromRaw(ctx.cnx_handle);
    closing.closeWithError(@intFromEnum(frame.AppError.kicked));
    return true;
}

/// 把整帧原样投给每个目标的每条在线连接，并按需回报不可达的目标。
///
/// 转发的是 `bytes`（含帧头与目标列表前缀），不剥离——剥离会改变 `body_len`，
/// 迫使网关为每个目标重新编码一次帧头（设计文档 §5.3）。接收方按同样规则跳过前缀。
///
/// 扇出的真实成本是 1 次读 + N 次写：picoquic 每次写都会把负载拷进该连接的发送
/// 队列，因为每条 QUIC 连接有独立的加密上下文，密文无法共享。"零拷贝"这个性质
/// 只对单目标投递成立（§8.2）。
///
/// 目标查找只在 `realm` 内进行：后端只能推给自己所属 realm 的连接，同号的别人的
/// 用户不在这条链上，因此不可能收到。
///
/// ## 两段式，因为 dest 索引是每 Worker 一份的
///
/// 1. 先算出所有需要转投的位置并各转投一次（去重是必须的：同一份帧发两次给同一个
///    Worker，那个 Worker 会把它投给同一批连接两次）
/// 2. 再按**目标列表原有顺序**逐个投递/结算回报
///
/// 顺序是"先转投、后本地"而不是反过来，只为让第二段能一次成型：回报必须与目标列表
/// 同序（后端按下标对应自己的目标），而转投的成败要在结算之前就已知。
fn fanOut(
    self: *GatewayWorker,
    transport: BackendTransport,
    realm: RealmId,
    backend_stream: u64,
    list: body.TargetList,
    bytes: []const u8,
    want_report: bool,
) void {
    var report = ReportBuilder{ .buf = self.egress.report_buf };
    var routes = RouteSet{};
    var delivered: usize = 0;

    // 第一段：算出目标集合并转投。广播策略下没有单一 home，一次加满。
    if (self.placement.strategy == .broadcast) {
        routes.markAll(self);
    } else {
        for (0..list.count) |i| routes.markHome(self, realm, list.get(i));
    }
    routes.flush(self, realm, bytes);

    // 第二段：按原序投递与结算。
    for (0..list.count) |i| {
        const dest_id = list.get(i);
        var reached = false;
        if (self.placement.isHome(realm, dest_id)) {
            const count = deliverLocalPeer(self, realm, dest_id, bytes);
            delivered += count;
            reached = count > 0;
        }
        if (!reached) reached = routes.acceptedHome(self, realm, dest_id);
        // "不可达"= 一条都没投出去、也没有被任何位置受理。有一条成功就不算——后端要的
        // 信号是"该不该转离线存储"，而不是"多端里有几端收到了"，后者属于业务层的已读游标。
        if (!reached and want_report) report.add(dest_id);
    }

    std.log.info("[PUSH] backend_stream={} realm={} targets={} delivered={} routed={} unreachable={}", .{
        backend_stream,
        realm,
        list.count,
        delivered,
        routes.sent,
        report.count,
    });

    if (!want_report) return;

    // 回报写在后端自己开的那条双向流的回程方向上：一个带 eof 的 DATA 帧。
    // 它不需要 OPEN——目的地是"这次交换的发起方"，由流本身确定。
    const data = report.finish();
    _ = transport.sendStream(.{}, backend_stream, data, true) catch |err| {
        err_handler.reportError(.session, "Failed to write delivery report", err);
    };
}

/// 把整帧投给本 Worker 上绑定了这个 `dest_id` 的每条连接，返回写成功的条数。
fn deliverLocalPeer(self: *GatewayWorker, realm: RealmId, dest_id: u64, bytes: []const u8) usize {
    var it = self.conn_manager.destConnections(realm, dest_id);
    var count: usize = 0;
    while (it.next()) |target| {
        if (pushToClient(target, bytes)) count += 1;
    }
    return count;
}

/// 把整帧投给本 Worker 上属于这个组播组的每条连接，返回投出去的条数。
///
/// 帧头带 `unreliable` 时改走不可靠通路（设计文档 §6）：投的不再是整帧，而是帧里那段
/// 负载，形态是 QUIC DATAGRAM。判据放在这里而不是各个调用点，是为了让**三条入口
/// （后端直推、同机交接、对等节点）自动一致**——标志位跟着帧走，谁都不用记得判它。
fn deliverLocalGroup(self: *GatewayWorker, realm: RealmId, group_id: u64, parsed: codec.Frame) usize {
    if (parsed.header.flags.unreliable) {
        return deliverLocalGroupDatagram(self, realm, group_id, groupPayload(parsed), null);
    }
    var it = self.conn_manager.groupConnections(realm, group_id);
    var count: usize = 0;
    while (it.next()) |target| {
        if (pushToClient(target, parsed.bytes)) count += 1;
    }
    return count;
}

/// `.multicast` 帧里目标列表之后那一段负载。
///
/// 调用方已经解过一次列表，这里再解一次只是读 2 字节 count；换来的是本函数不需要
/// 多一个必须与帧保持一致的参数。列表畸形在这里不可达（调用方先解的），
/// 保守返回空负载而不是崩。
fn groupPayload(parsed: codec.Frame) []const u8 {
    const list = body.TargetList.decode(parsed.body) catch return &.{};
    return parsed.body[list.prefixLen()..];
}

/// 把一段负载以 datagram 投给本 Worker 上这个组的成员，返回投出去的条数。
///
/// `skip` 是发起方自己的连接（客户端上行时非 null）：把状态包回显给发送者是纯粹的浪费。
fn deliverLocalGroupDatagram(
    self: *GatewayWorker,
    realm: RealmId,
    group_id: u64,
    payload: []const u8,
    skip: ?quic.c.QuicCnx,
) usize {
    if (payload.len + protocol.datagram.header_size > self.datagram_out_buf.len) {
        // 负载超过本端通告的上限。只可能来自"后端推了一个超大 unreliable 组播"或
        // 对端节点配了更大的上限，两者都该看见。
        std.log.warn("[DGRAM] payload of {} bytes exceeds the datagram limit", .{payload.len});
        return 0;
    }

    // 负载对所有成员相同，只有通道号不同：拷一次负载，之后逐个改第 2 个字节。
    const out = self.datagram_out_buf[0 .. protocol.datagram.header_size + payload.len];
    out[0] = @intFromEnum(frame.FrameType.datagram);
    @memcpy(out[protocol.datagram.header_size..], payload);

    var it = self.conn_manager.groupConnections(realm, group_id);
    var count: usize = 0;
    while (it.next()) |target| {
        if (skip) |sender| {
            if (target.cnx_handle == sender) continue;
        }
        // 只投给绑过通道的成员：绑定既是授权，也是"我要不可靠投递"这个意愿的表达。
        // 没绑的跳过，而**不是**降级成可靠推送——降级会让 60Hz 的状态流在那条连接上
        // 堆成队头阻塞，正是这条通路存在理由的反面。
        const channel = target.channelFor(group_id) orelse continue;
        out[1] = channel;
        var conn = QUICConnection.fromRaw(target.cnx_handle);
        conn.sendDatagram(out) catch {
            // 逐包路径上不记日志（会把磁盘写满），也不算错误：不可靠通路上发不出去
            // 与路上丢了对接收方是同一件事。
            self.datagrams_dropped +%= 1;
            continue;
        };
        count += 1;
    }
    return count;
}

/// 客户端上行的一个 datagram：按它绑定的组扇出（设计文档 §6）。
///
/// ## 为什么要先重编成一个 `.multicast` 帧
///
/// 组成员散落在本位置、同机其他 Worker、其他节点上（成员的落点由各自的 `dest_id`
/// 决定，与 `group_id` 无关）。把负载装进一个带 `unreliable` 标志的 `.multicast` 帧，
/// 不可靠投递就**原封不动复用了整套可靠扇出的选路机制**：`RouteSet` 一行不用改，
/// 跨节点也不需要新的线格式、新的配置、新的回调。
///
/// 代价是一次 ≤ `max_datagram_frame_size` 的 memcpy。另写一条不可靠专用的选路会得到
/// 两份必须同步演化的正确性不变量，那才是真正贵的东西。
///
/// ## 跨节点那一跳是可靠有序的
///
/// 对等链路上走的是普通 `.multicast` 帧（可靠流），收方节点再在本地落成 datagram。
/// 这不是妥协不彻底：**丢包发生在最后一公里，不在机架内部**。用可靠链路换来的是
/// 零新增线格式、零新增配置、零新增回调路径。
pub fn fanOutUnreliable(
    self: *GatewayWorker,
    sender: *ConnectionContext,
    group_id: u64,
    payload: []const u8,
) void {
    const realm = sender.realm;

    // 先投本位置：负载借用的是 picoquic 的接收缓冲，而下面重编帧用的是另一块缓冲，
    // 两者不冲突。
    _ = deliverLocalGroupDatagram(self, realm, group_id, payload, sender.cnx_handle);

    const bytes = encodeUnreliableGroupFrame(self, group_id, payload) orelse {
        self.datagrams_dropped +%= 1;
        return;
    };

    // 组成员的落点与 group_id 无关，所以必须问过每个位置（同一次性 `.multicast`）。
    var routes = RouteSet{};
    routes.markAll(self);
    routes.flush(self, realm, bytes);
}

/// 把一段 datagram 负载装进一个带 `unreliable` 的单目标 `.multicast` OPEN 帧。
fn encodeUnreliableGroupFrame(self: *GatewayWorker, group_id: u64, payload: []const u8) ?[]const u8 {
    const buf = self.datagram_frame_buf;
    const prefix = body.TargetList.byteSize(1);
    if (buf.len < frame.OPEN_HEADER_SIZE + prefix + payload.len) {
        std.log.warn("[DGRAM] payload of {} bytes does not fit a multicast frame", .{payload.len});
        return null;
    }

    // body = 组标识前缀 + 负载，就地拼在帧缓冲的 body 位置上。
    const body_start = frame.OPEN_HEADER_SIZE;
    _ = body.TargetList.encode(buf[body_start..], &.{group_id}) catch return null;
    @memcpy(buf[body_start + prefix ..][0..payload.len], payload);

    const body_len: u16 = @intCast(prefix + payload.len);
    const header = frame.FrameHeader.initOpen(.multicast, .{}, .{ .eof = true, .unreliable = true }, body_len);
    _ = header.encode(buf[0..frame.OPEN_HEADER_SIZE]) catch return null;
    return buf[0 .. body_start + body_len];
}

/// `.multicast` 推送：按组播组扇出（设计文档 §8）。
///
/// ## 为什么它总是广播给所有位置，不看配置的选路策略
///
/// 组成员的落点由**各自的 `dest_id`** 决定，与 `group_id` 无关——一个协作会话的
/// 参与者是不同的账号，`hash(realm, dest_id)` 会把他们散布到各处。所以
/// `hash(realm, group_id)` 算出来的位置对"成员在哪"毫无预测力，亲和在这里没有意义。
///
/// 这不是缺陷，反而是 `.multicast` 相对批量 `.peer` 的**真正**价值所在：
///
/// - 批量 `.peer` 的跨位置成本是 O(目标数)——每个 `dest_id` 各算一次 home
/// - `.multicast` 的跨位置成本是 O(位置数)——**与组成员数无关**
///
/// 一个 5000 人的直播间，批量 `.peer` 要在帧里塞 40KB 的 id 列表并算 5000 次 home；
/// `.multicast` 只是 8 字节组标识 × (节点数 × Worker 数) 次投递指令。
///
/// 因此设计文档里"`.multicast` 的语义前提是成员共节点（亲和）"这条**是错的**，
/// 已经修正：它不需要亲和，只需要每个位置都能查自己的本地组成员表。
fn dispatchMulticast(
    self: *GatewayWorker,
    transport: BackendTransport,
    realm: RealmId,
    key: inflight.StreamKey,
    parsed: codec.Frame,
) bool {
    const backend_stream = key.stream;

    // OPEN 没带 eof = 流式组播。与 `.peer` 走同一条会话路径：组播只是"目标条目是
    // 组标识而不是 dest_id"，冻结成员集合、按会话续传这两件事完全一样。
    if (!parsed.header.isLast()) return openStreamingPush(self, transport, realm, key, parsed);

    // 目标列表与 `.peer` 同形，只是条目是组标识而不是 dest_id。共用一种前缀让两条
    // 路径的编解码、截断校验、投递回报完全一致，也让"一帧发给多个组"免费得到支持。
    const list = body.TargetList.decode(parsed.body) catch |err| {
        std.log.warn("[MCAST] malformed group list on backend_stream={}: {}", .{ backend_stream, err });
        return false;
    };

    var report = ReportBuilder{ .buf = self.egress.report_buf };
    var routes = RouteSet{};
    var delivered: usize = 0;

    for (0..list.count) |i| {
        const group_id = list.get(i);
        const local = deliverLocalGroup(self, realm, group_id, parsed);
        delivered += local;
        // 回报的含义只能是"本位置一个成员都没有"。别的位置有没有成员，发起方无从得知
        // ——这正是组播省下 O(成员数) 的代价。
        if (local == 0 and parsed.header.flags.report) report.add(group_id);
    }

    routes.markAll(self);
    routes.flush(self, realm, parsed.bytes);

    std.log.info("[MCAST] backend_stream={} realm={} groups={} delivered={} routed={}", .{
        backend_stream,
        realm,
        list.count,
        delivered,
        routes.sent,
    });

    if (!parsed.header.flags.report) return true;
    const data = report.finish();
    _ = transport.sendStream(.{}, backend_stream, data, true) catch |err| {
        err_handler.reportError(.session, "Failed to write multicast report", err);
    };
    return true;
}

// ============================================================================
// 流式推送（设计文档 §5.3）
// ============================================================================
//
// 一次性推送（OPEN 带 eof）与流式推送（OPEN + DATA×N）的区别只有一个：**后续 DATA
// 帧上没有目标列表**（目标是流级属性，只在 OPEN 上声明）。所以网关必须在 OPEN 那一刻
// 把成员集合冻结进一个会话，后续每一帧都照着它投。
//
// 每一跳的会话身份都是"它所在的那条流"，线格式里没有任何新增字段——四条腿的形态、
// 各自为什么这么选，见 push_session.zig 的文件注释。
//
// **成员集合在 OPEN 时冻结**：会话中途新连上来的设备不接这条流。它没收到头部，
// 把尾巴发给它就是一段残缺的字节流，正确的补偿路径是后端的离线存储。

/// 别的 Worker 交接过来的一帧流式推送。
///
/// 空载荷是**作废信号**：发起方那一侧的会话异常终止了，本 Worker 要把自己这一段
/// 也重置掉。用长度而不是新加一个信封字段，因为一帧应用消息不可能是 0 字节
/// （最短的 DATA 帧也有 4 字节帧头）。
fn deliverStreamingHandoff(self: *GatewayWorker, realm: RealmId, session_id: u64, bytes: []const u8) void {
    if (bytes.len == 0) {
        const session = self.egress.sessions.findById(session_id) orelse return;
        abortSession(self, session);
        return;
    }

    const parsed = codec.parseExactFrame(bytes) catch |err| {
        std.log.warn("[PUSH] malformed handed-off streaming frame: {}", .{err});
        return;
    };

    if (parsed.header.isOpen()) {
        if (self.egress.sessions.findById(session_id) != null) {
            std.log.warn("[PUSH] duplicate streaming session {} handed off", .{session_id});
            return;
        }
        const session = self.egress.sessions.open(session_id, realm, null, quic.c.currentTime()) orelse {
            std.log.warn("[PUSH] too many streaming sessions on worker {}, session {} dropped", .{ self.worker_id, session_id });
            return;
        };
        var reached: [push_session.max_list_targets]bool = @splat(false);
        const attached = attachSessionTargets(self, session, parsed, &reached) orelse {
            self.egress.sessions.close(session);
            return;
        };
        // 本 Worker 一个目标都没有是常态（dest 索引每 Worker 一份），此时不留条目
        // ——留着只会占额度，而后续 DATA 查不到会话本来就什么也不做。
        if (attached == 0) self.egress.sessions.close(session);
        return;
    }

    // DATA：查不到会话说明本 Worker 在这个会话里没有目标，与一次性投递"查不到索引
    // 就什么也不做"是同一件事，不是错误。
    const session = self.egress.sessions.findById(session_id) orelse return;
    writeSessionFrame(self, session, parsed);
}

/// 对等节点在一条链路流上开始了一个流式会话（设计文档 §8.5 的跨节点那一半）。
///
/// 与一次性投递同理，允许**一次节点内转投**、之后不再转投，所以总跳数仍然被结构性地
/// 限死在 2，不需要跳数字段。
///
/// 会话号由本节点重新发：对面那条流的编号是它的内部记账，本节点的交接信封要用自己的。
/// 返回新会话号；开不出来返回 null。
pub fn beginPeerSession(self: *GatewayWorker, realm: RealmId, parsed: codec.Frame) ?u64 {
    switch (parsed.header.dest_kind) {
        .peer, .multicast => {},
        // ingress 已经把这两种拒掉了；走到这里说明调用方绕过了校验。
        .gateway, .service => return null,
    }

    // 先校验，再开会话、再转投：反过来的话超限是在附着阶段才发现的，而那时 OPEN
    // 已经发到本节点其他 Worker 去了，只能再补一轮作废信号。
    const list = decodeStreamingTargets(parsed) orelse return null;

    const session = self.egress.sessions.open(
        self.egress.sessions.nextId(),
        realm,
        null,
        quic.c.currentTime(),
    ) orelse {
        std.log.warn("[PEER] too many streaming sessions, refusing a peer session", .{});
        return null;
    };

    var routes = RouteSet{ .local_only = true };
    if (parsed.header.dest_kind == .multicast or self.placement.strategy == .broadcast) {
        // 组成员的落点与 group_id 无关，所以本节点内必须问过每个 Worker。
        routes.markAll(self);
    } else {
        // 选址是纯函数，所以本节点能独立算出目标该在哪个 Worker。
        for (0..list.count) |i| routes.markHome(self, realm, list.get(i));
    }
    routes.flushSession(self, session, parsed.bytes);

    var reached: [push_session.max_list_targets]bool = @splat(false);
    const attached = attachSessionTargets(self, session, parsed, &reached) orelse {
        abortSession(self, session);
        return null;
    };

    std.log.info("[PEER] streaming session {} realm={} kind={s} locals={} routed={}", .{
        session.id,
        realm,
        @tagName(parsed.header.dest_kind),
        attached,
        routes.sent,
    });
    return session.id;
}

/// 对等节点在会话流上续传的一帧。
pub fn continuePeerSession(self: *GatewayWorker, session_id: u64, parsed: codec.Frame) void {
    const session = self.egress.sessions.findById(session_id) orelse return;
    writeSessionFrame(self, session, parsed);
}

/// 按会话号异常终止一个会话；查不到就什么也不做。
pub fn abortSessionById(self: *GatewayWorker, session_id: u64) void {
    const session = self.egress.sessions.findById(session_id) orelse return;
    abortSession(self, session);
}

/// 兜底回收静默超时的会话。由 Worker 的周期定时器调用。
///
/// 它兜的是"后端既不发 eof 也不关流"这一种。没有它，那些会话会一直占着会话表的
/// 额度和客户端的推送流，而客户端则一直等一段永远不来的尾巴。
pub fn purgeExpiredSessions(self: *GatewayWorker, now: u64) void {
    // 每轮最多扫一遍表：`abortSession` 会释放槽位，所以循环一定收敛，
    // 但显式限次让"表被写坏"退化成一次跳过而不是死循环。
    for (0..push_session.max_sessions) |_| {
        const session = self.egress.sessions.expired(now) orelse return;
        std.log.warn("[PUSH] streaming session {} idle for too long", .{session.id});
        abortSession(self, session);
    }
}

/// 流式推送的 OPEN：冻结成员集合，为每个目标开一条专属流。
///
/// 回报在**这一刻**结算完：可达性此刻就已经定了（成员集合已冻结），而后续 DATA 帧上
/// 没有目标列表，再也没有第二次结算的机会。
fn openStreamingPush(
    self: *GatewayWorker,
    transport: BackendTransport,
    realm: RealmId,
    key: inflight.StreamKey,
    parsed: codec.Frame,
) bool {
    const list = body.TargetList.decode(parsed.body) catch |err| {
        std.log.warn("[PUSH] malformed streaming target list on backend_stream={}: {}", .{ key.stream, err });
        return false;
    };
    // 在开会话、转投任何一帧**之前**就把超限的拒掉：等到附着阶段才发现，OPEN 已经
    // 发到别的位置去了，只能再补一轮作废信号。
    //
    // 这一道是后端**能控制**的（列表是它编的），所以硬拒而不是截断成前 N 个
    // ——截断会让后端以为全都发出去了。
    if (list.count > push_session.max_list_targets) {
        std.log.warn("[PUSH] a streaming push may address at most {} targets, got {}: backend_stream={}", .{
            push_session.max_list_targets,
            list.count,
            key.stream,
        });
        return false;
    }

    const session = self.egress.sessions.open(
        self.egress.sessions.nextId(),
        realm,
        key,
        quic.c.currentTime(),
    ) orelse {
        std.log.warn("[PUSH] too many concurrent streaming sessions, refusing backend_stream={}", .{key.stream});
        return false;
    };

    // 位置集合与一次性推送用同一套判据（§8.5），只是结果被冻结进会话而不是用完就扔。
    var routes = RouteSet{};
    if (parsed.header.dest_kind == .multicast or self.placement.strategy == .broadcast) {
        routes.markAll(self);
    } else {
        for (0..list.count) |i| routes.markHome(self, realm, list.get(i));
    }
    routes.flushSession(self, session, parsed.bytes);

    var reached: [push_session.max_list_targets]bool = @splat(false);
    const attached = attachSessionTargets(self, session, parsed, &reached) orelse {
        abortSession(self, session);
        return false;
    };

    std.log.info("[PUSH] streaming session {} opened: backend_stream={} realm={} kind={s} targets={} locals={} routed={}", .{
        session.id,
        key.stream,
        realm,
        @tagName(parsed.header.dest_kind),
        list.count,
        attached,
        routes.sent,
    });

    if (!parsed.header.flags.report) return true;

    var report = ReportBuilder{ .buf = self.egress.report_buf };
    for (0..list.count) |i| {
        if (reached[i]) continue;
        const target = list.get(i);
        // `.peer` 的回报要算上"被别的位置受理"；`.multicast` 不能——组成员在别的位置
        // 有没有人，发起方无从得知（这正是组播省下 O(成员数) 的代价）。
        if (parsed.header.dest_kind == .peer and routes.acceptedHome(self, realm, target)) continue;
        report.add(target);
    }

    // 回报带 fin 写在回程方向上。QUIC 的两个方向各自独立收尾，所以这不会妨碍后端
    // 继续在同一条流上发 DATA。
    const data = report.finish();
    _ = transport.sendStream(.{}, key.stream, data, true) catch |err| {
        err_handler.reportError(.session, "Failed to write streaming delivery report", err);
    };
    return true;
}

/// 把会话的一帧续传投给所有冻结在里面的位置与本地目标。
fn writeSessionFrame(self: *GatewayWorker, session: *push_session.Session, parsed: codec.Frame) void {
    const is_last = parsed.header.isLast();
    const bytes = parsed.bytes;

    for (session.workers, 0..) |accepted, worker_id| {
        if (!accepted) continue;
        self.coordinator.messageRouter().deliver(@intCast(worker_id), bytes, session.realm, session.id) catch |err| {
            std.log.warn("[PUSH] streaming continuation to worker {} failed: {}", .{ worker_id, err });
        };
    }

    if (self.peer_links) |*links| {
        for (session.remoteNodes()) |stream| {
            if (!links.sendOn(stream, bytes, is_last)) {
                std.log.warn("[PUSH] streaming continuation to node {} failed", .{stream.node_id});
            }
        }
    }

    var written: usize = 0;
    for (session.localTargets()) |target| {
        // token 带 generation：连接中途断开、槽位被复用时这里必定失配，
        // 那个目标就自然掉出会话——而不是把这一帧写进另一个用户的连接。
        const ctx = self.conn_manager.byToken(target.token) orelse continue;
        var conn = QUICConnection.fromRaw(ctx.cnx_handle);
        conn.streamWrite(target.stream_id, bytes, is_last) catch |err| {
            err_handler.reportError(.session, "Failed to continue a streaming push", err);
            continue;
        };
        written += 1;
    }

    session.last_active = quic.c.currentTime();
    if (is_last) {
        std.log.info("[PUSH] streaming session {} finished: locals={} nodes={}", .{ session.id, written, session.node_len });
        self.egress.sessions.close(session);
    }
}

/// 一次附着尝试的结果。
const Attach = enum {
    attached,
    /// 这一条没附上（写失败、拿不到 token），但还可以试下一条。
    skipped,
    /// 本位置的连接数到顶了，不必再试。
    full,
};

/// 解出流式推送的目标列表并校验它的规模；不合法则记日志返回 null。
///
/// 每个位置都要独立校验一遍，不能只信发起方：对等节点送来的帧是**另一个节点**编的，
/// 而它可能跑着不同版本的上限。
fn decodeStreamingTargets(parsed: codec.Frame) ?body.TargetList {
    const list = body.TargetList.decode(parsed.body) catch |err| {
        std.log.warn("[PUSH] malformed streaming target list: {}", .{err});
        return null;
    };
    if (list.count > push_session.max_list_targets) {
        std.log.warn("[PUSH] a streaming push may address at most {} targets, got {}", .{
            push_session.max_list_targets,
            list.count,
        });
        return null;
    }
    return list;
}

/// 冻结本位置的成员集合：为每个在线的目标连接开一条专属推送流并写入 OPEN 帧。
///
/// 返回本位置附上的连接数；目标列表本身不合法时返回 null（调用方据此拒掉整个会话）。
fn attachSessionTargets(
    self: *GatewayWorker,
    session: *push_session.Session,
    parsed: codec.Frame,
    reached: *[push_session.max_list_targets]bool,
) ?usize {
    const list = decodeStreamingTargets(parsed) orelse return null;

    var attached: usize = 0;
    for (0..list.count) |i| {
        const count = switch (parsed.header.dest_kind) {
            .peer => attachDest(self, session, list.get(i), parsed.bytes),
            .multicast => attachGroup(self, session, list.get(i), parsed.bytes),
            .gateway, .service => return null,
        };
        reached[i] = count > 0;
        attached += count;
    }
    return attached;
}

/// 把这个 `dest_id` 名下本 Worker 的每条连接附进会话。
fn attachDest(self: *GatewayWorker, session: *push_session.Session, dest_id: u64, bytes: []const u8) usize {
    var it = self.conn_manager.destConnections(session.realm, dest_id);
    var count: usize = 0;
    while (it.next()) |target| switch (attachOne(self, session, target, bytes)) {
        .attached => count += 1,
        .skipped => {},
        .full => break,
    };
    return count;
}

/// 把这个组里本 Worker 的每条成员连接附进会话。
fn attachGroup(self: *GatewayWorker, session: *push_session.Session, group_id: u64, bytes: []const u8) usize {
    var it = self.conn_manager.groupConnections(session.realm, group_id);
    var count: usize = 0;
    while (it.next()) |target| switch (attachOne(self, session, target, bytes)) {
        .attached => count += 1,
        .skipped => {},
        .full => break,
    };
    return count;
}

/// 给一条连接开一条专属推送流并写入首帧。
fn attachOne(
    self: *GatewayWorker,
    session: *push_session.Session,
    target: *ConnectionContext,
    bytes: []const u8,
) Attach {
    if (session.local_len >= push_session.max_local_targets) {
        // 不推倒已经附上的那些：它们已经收到头部，把它们的流也砍掉等于让更多人
        // 拿到残缺的字节流。这一道超限是多设备放大造成的，网关只能被动接受。
        std.log.warn("[PUSH] streaming session {} hit the {}-connection cap at this position", .{
            session.id,
            push_session.max_local_targets,
        });
        return .full;
    }

    const token = self.conn_manager.tokenFor(target.cnx_handle) orelse return .skipped;
    const stream_id = target.nextPushStream();
    var conn = QUICConnection.fromRaw(target.cnx_handle);
    // 不带 fin：这条流后面还有 DATA。
    conn.streamWrite(stream_id, bytes, false) catch |err| {
        err_handler.reportError(.session, "Failed to open a streaming push stream", err);
        return .skipped;
    };
    return if (session.addLocal(.{ .token = token, .stream_id = stream_id })) .attached else .full;
}

/// 异常终止一个会话：把所有下游流重置掉。
///
/// **重置而不是 fin**：fin 的含义是"完整结束"，客户端会把半个文件当成整个文件收下，
/// 而它没有任何方式发现自己被截断了。RESET_STREAM 才是"这一段作废"。
///
/// 同机其他 Worker 收不到 RESET——它们持有自己的会话。所以给它们发一条空载荷的
/// 交接消息当作废信号；跨节点那一跳靠重置对等链路上那条流，对面按兜底回收收尾。
fn abortSession(self: *GatewayWorker, session: *push_session.Session) void {
    for (session.localTargets()) |target| {
        const ctx = self.conn_manager.byToken(target.token) orelse continue;
        var conn = QUICConnection.fromRaw(ctx.cnx_handle);
        conn.closeStream(target.stream_id);
    }

    for (session.workers, 0..) |accepted, worker_id| {
        if (!accepted) continue;
        self.coordinator.messageRouter().deliver(@intCast(worker_id), &.{}, session.realm, session.id) catch |err| {
            std.log.warn("[PUSH] failed to tell worker {} that session {} is void: {}", .{ worker_id, session.id, err });
        };
    }

    if (self.peer_links) |*links| {
        for (session.remoteNodes()) |stream| links.resetSession(stream);
    }

    std.log.warn("[PUSH] streaming session {} aborted", .{session.id});
    self.egress.sessions.close(session);
}

/// 在一条客户端连接上主动开流并推送整帧。
///
/// 每次推送开一条新的 server-initiated 流（设计文档 §7.4）。这是对客户端 SDK 的
/// 硬要求：它必须能接收服务端发起的流，而不是只在自己开的流上读。
///
/// 返回是否写成功，用来判定投递回报里的"不可达"。
fn pushToClient(target: *ConnectionContext, bytes: []const u8) bool {
    const stream_id = target.nextPushStream();
    var conn = QUICConnection.fromRaw(target.cnx_handle);
    conn.streamWrite(stream_id, bytes, true) catch |err| {
        err_handler.reportError(.session, "Failed to push to client", err);
        return false;
    };
    return true;
}

// ============================================================================
// 测试
// ============================================================================

test "ReportBuilder emits a DATA frame that decodes back to the unreachable list" {
    const allocator = std.testing.allocator;
    const buf = try allocator.alloc(u8, frame.DATA_HEADER_SIZE + frame.MAX_BODY_SIZE);
    defer allocator.free(buf);

    var report = ReportBuilder{ .buf = buf };
    report.add(1);
    report.add(0xDEAD_BEEF_CAFE_BABE);
    report.add(3);

    const data = report.finish();
    const parsed = try codec.parseExactFrame(data);
    try std.testing.expectEqual(frame.FrameType.data, parsed.header.frame_type);
    // 带 eof：回报就是这条流回程方向的全部内容。
    try std.testing.expect(parsed.header.isLast());

    const list = try body.TargetList.decode(parsed.body);
    try std.testing.expectEqual(@as(u16, 3), list.count);
    try std.testing.expectEqual(@as(u64, 1), list.get(0));
    try std.testing.expectEqual(@as(u64, 0xDEAD_BEEF_CAFE_BABE), list.get(1));
    try std.testing.expectEqual(@as(u64, 3), list.get(2));
}

test "an empty report is still a well-formed frame" {
    // 全部投递成功时也要能编出一个合法的空回报——后端靠"收到回报"判断扇出结束。
    const allocator = std.testing.allocator;
    const buf = try allocator.alloc(u8, frame.DATA_HEADER_SIZE + frame.MAX_BODY_SIZE);
    defer allocator.free(buf);

    var report = ReportBuilder{ .buf = buf };
    const data = report.finish();

    const parsed = try codec.parseExactFrame(data);
    const list = try body.TargetList.decode(parsed.body);
    try std.testing.expectEqual(@as(u16, 0), list.count);
}

test "ReportBuilder truncates instead of overflowing its buffer" {
    const allocator = std.testing.allocator;
    const buf = try allocator.alloc(u8, frame.DATA_HEADER_SIZE + frame.MAX_BODY_SIZE);
    defer allocator.free(buf);

    var report = ReportBuilder{ .buf = buf };
    for (0..body.max_targets + 100) |i| report.add(@intCast(i + 1));

    try std.testing.expectEqual(body.max_targets, report.count);
    // 截断后仍然是一个能解出来的合法帧，而不是一段越界写坏的内存。
    const parsed = try codec.parseExactFrame(report.finish());
    const list = try body.TargetList.decode(parsed.body);
    try std.testing.expectEqual(@as(u16, @intCast(body.max_targets)), list.count);
}
