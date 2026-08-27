//! 客户端上行入口
//!
//! 一条 QUIC 流上的字节 -> 完整帧 -> 按帧类型与目的地分派。本文件是网关数据面的
//! 上行半边，回程半边在 worker.zig 的 drainTransport 里，两边通过
//! inflight.Tables 里的映射对接。
//!
//! ## 一条 QUIC 流 = 一次交换
//!
//! 首帧是 OPEN，声明目的地；后续是 DATA，只带长度；末帧带 eof。网关的动作
//! 因此收敛成三条，没有模式分支：
//!
//! - OPEN → 开一条后端流并登记回程映射
//! - DATA → 往同一条追加
//! - eof  → fin
//!
//! 旧协议用帧头里的 `mode` 区分"一帧一请求"和"多帧一请求"，于是有两条几乎
//! 平行的转发路径。新协议把它变成"一次交换有几帧"，两条路径合并成一条。
//!
//! ## 与 protocol 层的分界
//!
//! protocol 只描述帧长什么样、怎么切。"控制交换就地回、业务交换转给后端、
//! 越权的目的地拒绝"是网关策略，依赖认证配置、路由注册表和在途表，都是
//! Worker 的状态。所以切帧在 protocol，分派在这里。
//!
//! ## 错误分级
//!
//! 判据是"字节流本身还可信吗"（设计文档 §7.5）：
//!
//! - **协议违规**（分帧错误、未定义取值、保留位非 0、越权目的地、eof 后又来帧）
//!   → 关闭整条连接。同一个坏编码器产出的其他流同样不可信。
//! - **业务失败**（路由不存在、配额满、未认证、后端不可用）
//!   → 在该流上回一个错误帧并 fin，其他流不受影响。
//!
//! 两者都不发 RESET_STREAM：它只中止发送方向，客户端仍可继续发送，违规会反复
//! 触发；而 reset 会丢弃尚未送达的数据，"先回错误帧再 reset"里错误帧很可能
//! 根本收不到。

const std = @import("std");

const foundation = @import("../foundation/mod.zig");
const err_handler = foundation.err;
const protocol = @import("../protocol/mod.zig");
const codec = protocol.codec;
const framing = protocol.framing;
const AppError = protocol.frame.AppError;
const quic = @import("../quic/mod.zig");
const QUICConnection = quic.connection.Connection;
const backend_mod = @import("../backend/mod.zig");
const ScopedRoute = backend_mod.ScopedRoute;
const connection = @import("connection.zig");
const ConnectionContext = connection.ConnectionContext;
const Exchange = connection.Exchange;
const BackendStream = connection.BackendStream;
const egress = @import("egress.zig");
const GatewayWorker = @import("worker.zig").GatewayWorker;

/// 单条客户端连接允许的并发交换数量。
///
/// 每次进行中的交换都占着一条后端 QUIC 流和一条在途映射。没有这道限制，
/// 单个客户端只要不断开新流就能吃满 Worker 的在途表和后端的流配额。
pub const max_exchanges_per_connection: usize = 64;

/// 单帧分派的结果。
pub const FrameOutcome = enum {
    /// 继续处理本次回调里剩下的帧。
    continue_stream,
    /// 停止分帧，但不额外清理（连接已被标记关闭）。
    stop_stream,
    /// 停止分帧，并在循环外关闭整条连接。
    close_connection,
};

/// 一条客户端流的分帧分派上下文。
///
/// framing.drainFrames 是 comptime 泛型的，把这三样打包传进去就没有虚函数
/// 调用，逐帧分派可以被内联。
const FrameDispatcher = struct {
    worker: *GatewayWorker,
    ctx: *ConnectionContext,
    stream_id: u64,
    /// 分帧循环里判定了协议违规，由调用方在循环外关闭连接。
    violation: bool = false,

    /// 逐帧分派；返回 false 让分帧循环立即停止。
    ///
    /// 清理动作一律不在这里做：解出的帧指向 spill 缓冲，循环期间释放它就是
    /// use-after-free，因此只置位，等 drainFrames 返回后再处理。
    fn onFrame(self: *FrameDispatcher, parsed: codec.Frame) bool {
        switch (dispatchFrame(self.worker, self.ctx, self.stream_id, parsed)) {
            .continue_stream => return true,
            .stop_stream => return false,
            .close_connection => {
                self.violation = true;
                return false;
            },
        }
    }
};

/// 流数据到达：把字节切成完整帧，逐帧分派。
///
/// 由 ServerDriver 作为函数指针注册（见 GatewayWorker.run），因此签名必须与
/// driver 的回调类型一致。
///
/// 拿不到 ctx 说明这条连接没在管理器里（例如 drain 期间刚被拒绝），直接丢弃。
///
/// 残帧缓冲是懒创建的：只有一次回调没带来整帧时才写进 ctx。帧边界对齐的
/// 常态下全程零拷贝、零分配，也不碰那张表——这是热路径的性能前提。
pub fn handleStreamData(ud: ?*anyopaque, conn: *QUICConnection, stream_id: u64, data: []const u8, is_fin: bool) void {
    const self = GatewayWorker.castSelf(ud);
    const ctx = self.conn_manager.get(conn) orelse return;

    var dispatcher = FrameDispatcher{ .worker = self, .ctx = ctx, .stream_id = stream_id };

    // 已有残帧就接着用那份缓冲；没有就借栈上的空壳，避免无谓的表操作。
    var fresh_spill: framing.Spill = .{ .items = &.{}, .capacity = 0 };
    const existing = ctx.frameSpill(stream_id);
    const spill = existing orelse &fresh_spill;

    const drained = framing.drainFrames(
        FrameDispatcher,
        &dispatcher,
        FrameDispatcher.onFrame,
        spill,
        self.allocator,
        data,
        codec.MAX_FRAME_SIZE,
    );

    // 先把缓冲状态落回 ctx：栈上那份残帧不落盘就会随本函数返回丢失，
    // 而后续清理必须在 drainFrames 返回之后才能碰它。
    if (existing == null) {
        if (fresh_spill.items.len > 0) {
            ctx.storeFrameSpill(stream_id, fresh_spill) catch |err| {
                fresh_spill.deinit(self.allocator);
                err_handler.reportError(.session, "Failed to keep partial frame", err);
                // 残帧存不下就再也拼不回这条字节流，后续字节会被当成帧头解析。
                closeConnection(ctx, .protocol_violation);
                return;
            };
        } else {
            fresh_spill.deinit(self.allocator);
        }
    } else if (spill.items.len == 0) {
        ctx.dropFrameSpill(stream_id);
    }

    drained catch |err| {
        // 分帧违规：字节流已经失去边界，任何续读都是猜测。同一个编码器产出的
        // 其他流同样不可信，所以关整条连接而不是只弃这一条流。
        std.log.warn("[STREAM] framing violation on stream {}: {}", .{ stream_id, err });
        closeConnection(ctx, .protocol_violation);
        return;
    };

    if (dispatcher.violation) {
        closeConnection(ctx, .protocol_violation);
        return;
    }

    if (is_fin) finishClientStream(self, ctx, stream_id);

    // 关闭连接推迟到分帧循环之外：循环里分派的帧指向 spill 缓冲，
    // 连接一旦销毁，后续迭代就会读到已释放内存。
    if (ctx.close_requested) {
        var closing = QUICConnection.fromRaw(ctx.cnx_handle);
        closing.close();
    }
}

/// 分派一个完整帧。
///
/// 先看这条流有没有在进行中的交换，再决定这一帧的含义——目的地是流级属性，
/// 只在 OPEN 上声明，所以 DATA 的去向只能从交换状态里查。这也顺带消掉了帧走私：
/// 后续帧即使伪造 8 字节的 OPEN 帧头，也改不了已经定型的投递目标。
pub fn dispatchFrame(self: *GatewayWorker, ctx: *ConnectionContext, stream_id: u64, parsed: codec.Frame) FrameOutcome {
    if (ctx.exchange(stream_id)) |active| {
        // eof 之后这条流上不该再有帧。这是无歧义的编码器错误：网关这边条目还在，
        // 说明它确实见过这次交换的结束标记。
        if (active.completed) {
            std.log.warn("[STREAM] frame after eof on stream {}", .{stream_id});
            return .close_connection;
        }
        // 一条流一次交换。交换还没结束就又来 OPEN，说明对端在复用流；
        // 放行会让同一条客户端流上挂两条后端流，响应交错回来无法区分。
        if (parsed.header.isOpen()) {
            std.log.warn("[STREAM] a second OPEN on live stream {}", .{stream_id});
            return .close_connection;
        }
        // 对等节点的会话流：这一帧是流式推送的续传，沿会话投递（设计文档 §5.3）。
        if (active.push_session != 0) return continueSessionFrame(self, active, parsed);
        return appendToExchange(self, ctx, stream_id, active, parsed);
    }

    if (parsed.header.isOpen()) return openExchange(self, ctx, stream_id, parsed);

    // 查不到交换的 DATA 帧一律丢弃，**不**升级为协议违规。
    //
    // 看起来这违反了"首帧必须是 OPEN"，但网关无法区分两种情形：客户端真的先发了
    // DATA，还是这次交换刚刚被业务级理由拒掉（配额满、路由不存在）而没有留条目。
    // 后者是正常运行中会发生的——客户端收到错误帧时，后面的分片早就在路上了。
    // 既然分不清，就不能升级：否则一次配额拒绝会顺带杀掉整条连接。
    //
    // 丢弃是安全的：这一帧已经被完整解析，帧边界没有丢失，也没有任何字节被转发。
    std.log.warn("[STREAM] DATA frame with no live exchange on stream {}", .{stream_id});
    return .continue_stream;
}

/// OPEN 帧：按目的地开一次新交换。
fn openExchange(self: *GatewayWorker, ctx: *ConnectionContext, stream_id: u64, parsed: codec.Frame) FrameOutcome {
    // 对等网关节点走完全不同的一套白名单：它只能投递，不能请求。
    if (ctx.peer_node) return openPeerNodeExchange(self, ctx, stream_id, parsed);

    switch (parsed.header.dest_kind) {
        // 客户端无权直接寻址其他客户端（设计文档 §5.4）。可靠广播必须走
        // "客户端 → 后端 → 网关 → N 个客户端"两跳，否则落库、反垃圾、定序
        // 这些业务逻辑全被绕过。越权是编码器在故意构造，按协议违规处理。
        .peer, .multicast => {
            std.log.warn("[STREAM] client tried to address {s} on stream {}", .{ @tagName(parsed.header.dest_kind), stream_id });
            return .close_connection;
        },
        .gateway, .service => {},
    }

    // 每次被接纳的交换都要占一个条目，条目要等 QUIC FIN 才清理。控制交换也算——
    // 否则客户端只要在新流上发心跳而从不关流，就能让这张表无界增长。
    if (ctx.exchangeCount() >= max_exchanges_per_connection) {
        std.log.warn("[STREAM] too many concurrent exchanges on one connection, rejecting stream={}", .{stream_id});
        self.replyControl(ctx.cnx_handle, stream_id, .gateway_error, "too many concurrent exchanges");
        return .continue_stream;
    }

    if (parsed.header.dest_kind == .gateway) return openGatewayExchange(self, ctx, stream_id, parsed);
    return openServiceExchange(self, ctx, stream_id, parsed);
}

/// 对等网关节点发来的一次投递（设计文档 §8.5 的跨节点那一半）。
///
/// ## 权限与客户端正好相反
///
/// 对等节点**只能**发 `.peer` / `.multicast`——它存在的唯一目的就是"把这一帧投给
/// 你节点上的这些目标"。反过来 `.service` 与 `.gateway` 一律拒：
///
/// - `.service`：借这条链路调别的后端等于绕过本节点的路由与配额，而它自己有后端。
/// - `.gateway`：控制交换（kick / 组成员变更）的权威在**后端**，不在别的网关节点。
///   放开它就等于任何一个节点都能指挥全集群，攻击面从"一个节点"扩大到"任意节点"。
///
/// ## realm 从帧头来，这里是唯一的例外
///
/// 对等节点连接的 SNI 不代表任何 realm（它是集群监听器），所以 realm 只能来自
/// `realmHint()`——即发送方节点按**它自己那条后端连接的注册表键**填进去的值。
/// 这不违反"realm 不从帧内容读"：那条规则防的是**不受信的对端**自称 realm，
/// 而对等节点持有集群 CA 签发的证书，它本来就持有所有 realm 的连接。
///
/// ## 一次性与流式都支持
///
/// 一次性投递（OPEN 带 eof）就地扇出、不留状态；流式投递（OPEN + DATA×N）在本节点
/// 开一个会话，**这条链路流就是它的身份**（设计文档 §5.3）。
fn openPeerNodeExchange(self: *GatewayWorker, ctx: *ConnectionContext, stream_id: u64, parsed: codec.Frame) FrameOutcome {
    switch (parsed.header.dest_kind) {
        .peer, .multicast => {},
        .gateway, .service => {
            std.log.warn("[PEER] a peer node may not address {s}: stream={}", .{ @tagName(parsed.header.dest_kind), stream_id });
            return .close_connection;
        },
    }

    // realmHint 对 `.peer` / `.multicast` 的 OPEN 恒非 null，上面的 switch 已经保证了。
    const realm = parsed.header.realmHint() orelse return .close_connection;

    if (!parsed.header.isLast()) return openPeerSession(self, ctx, stream_id, realm, parsed);

    egress.deliverFromPeer(self, realm, parsed.bytes);

    // 不登记交换：这一帧已经处理完，这条流上不会再有内容，留条目只会占额度。
    return .continue_stream;
}

/// 对等节点开了一个流式会话：登记"这条流 → 这个会话"，后续 DATA 才找得回来。
fn openPeerSession(
    self: *GatewayWorker,
    ctx: *ConnectionContext,
    stream_id: u64,
    realm: u16,
    parsed: codec.Frame,
) FrameOutcome {
    // 流式会话要留条目，因此也要受这条连接的并发上限约束——否则对等节点只要不断
    // 开新流就能让这张表无界增长。
    if (ctx.exchangeCount() >= max_exchanges_per_connection) {
        std.log.warn("[PEER] too many concurrent sessions on one peer link, refusing stream={}", .{stream_id});
        return .continue_stream;
    }

    const session_id = egress.beginPeerSession(self, realm, parsed) orelse return .continue_stream;
    ctx.openExchange(stream_id, .{ .push_session = session_id }) catch |err| {
        err_handler.reportError(.session, "Failed to track a peer streaming session", err);
        // 条目登记不上，后续 DATA 就再也对不上会话，这个会话只能就地作废
        // ——留着它等于让客户端收一段永远等不到尾巴的字节流。
        egress.abortSessionById(self, session_id);
        return .continue_stream;
    };
    return .continue_stream;
}

/// 会话流上的 DATA 帧：沿会话续传。
fn continueSessionFrame(self: *GatewayWorker, active: *Exchange, parsed: codec.Frame) FrameOutcome {
    egress.continuePeerSession(self, active.push_session, parsed);
    if (parsed.header.isLast()) {
        // 会话已经在 egress 那侧收尾。条目留着当"这条流用过了"的凭据，等 QUIC FIN
        // 时清理；会话号清零，免得收尾路径再去作废一个已经正常结束的会话。
        active.push_session = 0;
        active.completed = true;
    }
    return .continue_stream;
}

/// 与网关自身的交换：心跳、认证、断开等控制操作。
fn openGatewayExchange(self: *GatewayWorker, ctx: *ConnectionContext, stream_id: u64, parsed: codec.Frame) FrameOutcome {
    // 流式控制交换（例如客户端持续上报遥测）协议上是允许的（设计文档 §5.1），
    // 但网关侧还没有消费方。明确拒绝而不是把首帧当成完整请求处理——后者会让
    // 客户端以为上报成功了。
    if (!parsed.header.isLast()) {
        std.log.warn("[CTRL] streaming control exchange is not supported yet: stream={}", .{stream_id});
        self.replyControl(ctx.cnx_handle, stream_id, .gateway_error, "streaming control exchange not supported");
        return .continue_stream;
    }

    // 记账在处理之前：handleControlFrame 可能置位 close_requested，此后不该再
    // 往这条连接的表里写东西。
    ctx.openExchange(stream_id, .{ .completed = true }) catch |err| {
        err_handler.reportError(.session, "Failed to track control exchange", err);
        self.replyControl(ctx.cnx_handle, stream_id, .gateway_error, "gateway busy");
        return .continue_stream;
    };

    self.handleControlFrame(ctx, stream_id, parsed);
    return if (ctx.close_requested) .stop_stream else .continue_stream;
}

/// 与后端服务的交换：开一条后端流，登记回程映射。
///
/// 一次性交换（OPEN 直接带 eof）与流式交换走同一条路径，区别只在开流时是否
/// 顺带 fin、以及要不要留住句柄给后续 DATA 用。
fn openServiceExchange(self: *GatewayWorker, ctx: *ConnectionContext, stream_id: u64, parsed: codec.Frame) FrameOutcome {
    const header = parsed.header;
    const now = quic.c.currentTime();

    // 接入门禁只在 OPEN 上检查。这是**准入**而不是逐帧授权：交换一旦放行，
    // 后续 DATA 骑的就是已经过门禁的那次交换，不必重复判定。
    //
    // 判据是"已认证且未过期"。只看 authenticated 的话，token 过期与账号吊销
    // 都无法反映到已经建立的连接上（设计文档 §10.2）。
    if (self.auth_policy.required and !ctx.isAdmitted(now)) {
        std.log.warn("[AUTH] rejecting exchange, admission not valid: stream={}", .{stream_id});
        self.replyControl(ctx.cnx_handle, stream_id, .gateway_error, "authentication required");
        return .continue_stream;
    }

    // 传输路径（direct/relay）由服务端注册关系决定，客户端只指定 group + route_key。
    // realm 由网关从这条连接的 SNI 解析后补上：客户端拿不到跨 realm 的键，因此
    // 也无法把请求投进别人的后端（设计文档 §12.2）。
    const scope = ScopedRoute.scoped(ctx.realm, header.routeId().?);
    const transport = self.findTransport(scope) orelse {
        std.log.warn("[ROUTE] route not found: realm={} group=0x{x} route=0x{x}", .{ ctx.realm, header.group, header.route_key });
        self.replyControl(ctx.cnx_handle, stream_id, .gateway_error, "route not found");
        return .continue_stream;
    };

    // 两个拒绝理由分开报：运维要能区分"整机在途满了"（扩容/查后端慢）和
    // "这个 realm 超了它的公平份额"（找接入方），两者的处置完全不同（§12.4）。
    switch (self.inflight.reserveRoute(ctx.realm, now)) {
        .ok => {},
        .table_full => {
            std.log.warn("[ROUTE] in-flight request table full, rejecting stream={}", .{stream_id});
            self.replyControl(ctx.cnx_handle, stream_id, .gateway_error, "too many in-flight requests");
            return .continue_stream;
        },
        .realm_over_share => {
            std.log.warn("[ROUTE] realm over in-flight share: realm={} stream={}", .{ ctx.realm, stream_id });
            self.replyControl(ctx.cnx_handle, stream_id, .gateway_error, "realm in-flight quota exceeded");
            return .continue_stream;
        },
    }

    const is_last = header.isLast();
    const handle = transport.sendStream(scope.route, null, parsed.bytes, is_last) catch |err| {
        err_handler.reportError(.session, "Failed to open backend stream", err);
        self.replyControl(ctx.cnx_handle, stream_id, .gateway_error, "backend unavailable");
        return .continue_stream;
    };

    const backend: BackendStream = .{
        .key = .{ .transport = transport.id(), .stream = handle },
        .scope = scope,
    };

    self.inflight.openRoute(backend.key, .{
        .client_cnx = ctx.cnx_handle,
        .client_stream_id = stream_id,
        .realm = ctx.realm,
        .last_active_at = now,
    }) catch |err| {
        // 登记不上回程映射，后端的响应就找不回客户端。当场把后端流收尾，
        // 否则它会一直等一个永远不来的 eof。
        self.finishBackendStream(backend);
        err_handler.reportError(.session, "Failed to track in-flight request", err);
        self.replyControl(ctx.cnx_handle, stream_id, .gateway_error, "gateway busy");
        return .continue_stream;
    };

    // 一次性交换不留句柄：后端流已经随首帧 fin，条目只用来拒绝这条流上的后续帧。
    ctx.openExchange(stream_id, .{
        .backend = if (is_last) null else backend,
        .completed = is_last,
    }) catch |err| {
        self.finishBackendStream(backend);
        self.inflight.closeRoute(backend.key);
        err_handler.reportError(.session, "Failed to track exchange", err);
        self.replyControl(ctx.cnx_handle, stream_id, .gateway_error, "gateway busy");
        return .continue_stream;
    };

    std.log.info("[ROUTE] client_stream={} -> backend_stream={} realm={} group=0x{x} route=0x{x} single={}", .{ stream_id, handle, ctx.realm, header.group, header.route_key, is_last });
    return .continue_stream;
}

/// DATA 帧：沿同一条后端流追加，末帧顺带 fin。
///
/// 路由键不从帧里取——DATA 没有路由键，目的地在 OPEN 时就定型了。因此一条流的
/// 前后半段必定落到同一个后端。
fn appendToExchange(
    self: *GatewayWorker,
    ctx: *ConnectionContext,
    stream_id: u64,
    active: *Exchange,
    parsed: codec.Frame,
) FrameOutcome {
    const backend = active.backend orelse {
        // 走不到：进行中的交换只可能是 `.service` 的，而它必定带句柄
        // （`.gateway` 交换在 OPEN 时就已经结束）。留一条日志而不是 unreachable
        // ——将来放开流式控制交换时，这里会明确报出来而不是崩在生产环境。
        std.log.warn("[STREAM] live exchange without a backend stream: stream={}", .{stream_id});
        self.replyControl(ctx.cnx_handle, stream_id, .gateway_error, "unsupported exchange continuation");
        ctx.closeExchange(stream_id);
        return .continue_stream;
    };

    const transport = self.transport_registry.find(backend.scope) orelse {
        // transport 中途消失（配置重载/后端摘除）。后端已经收到前半段，
        // 继续发只会拼出一条残缺的字节流，因此这次交换就地作废。
        std.log.warn("[STREAM] transport disappeared mid-exchange: stream={}", .{stream_id});
        self.inflight.closeRoute(backend.key);
        ctx.closeExchange(stream_id);
        self.replyControl(ctx.cnx_handle, stream_id, .gateway_error, "backend unavailable");
        return .continue_stream;
    };

    // 映射可能已经因真实空闲而被周期回收；先判定再发送，不能把一帧交给后端后才
    // 发现响应无处可回。完整 DATA 被接纳即算上行活动，发送失败路径会立即删映射。
    if (!self.inflight.touchRoute(backend.key, quic.c.currentTime())) {
        std.log.warn("[STREAM] in-flight route expired mid-exchange: stream={}", .{stream_id});
        self.finishBackendStream(backend);
        ctx.closeExchange(stream_id);
        self.replyControl(ctx.cnx_handle, stream_id, .gateway_error, "request expired");
        return .continue_stream;
    }

    const is_last = parsed.header.isLast();
    _ = transport.sendStream(backend.scope.route, backend.key.stream, parsed.bytes, is_last) catch |err| {
        err_handler.reportError(.session, "Failed to append to backend stream", err);
        self.finishBackendStream(backend);
        self.inflight.closeRoute(backend.key);
        ctx.closeExchange(stream_id);
        self.replyControl(ctx.cnx_handle, stream_id, .gateway_error, "backend unavailable");
        return .continue_stream;
    };

    if (is_last) {
        // 交换结束但条目留着：它是"这条流已经用过了"的凭据，等 QUIC FIN 时清理。
        // 回程映射不能删——后端的响应还没回来。
        active.backend = null;
        active.completed = true;
    }
    return .continue_stream;
}

/// 客户端关闭了这条流（QUIC FIN）。
///
/// 残帧还在说明客户端发了半个帧就关流，那半个帧只能丢弃。
/// 交换也要收尾：客户端可能没来得及发 eof 就把流关了，此时后端流还等着结束标记。
pub fn finishClientStream(self: *GatewayWorker, ctx: *ConnectionContext, stream_id: u64) void {
    if (ctx.frameSpill(stream_id)) |spill| {
        if (spill.items.len > 0) {
            std.log.warn("[STREAM] stream {} ended with {} bytes of a partial frame", .{ stream_id, spill.items.len });
        }
        ctx.dropFrameSpill(stream_id);
    }
    if (ctx.exchange(stream_id)) |active| {
        if (active.backend) |backend| self.finishBackendStream(backend);
        // 会话流被 FIN 掉却没发过 eof：尾巴永远不会来，就地作废，
        // 否则下游客户端会一直等下去。
        if (active.push_session != 0) egress.abortSessionById(self, active.push_session);
        ctx.closeExchange(stream_id);
    }
}

// ============================================================================
// 不可靠通路（设计文档 §6）
// ============================================================================

/// 收到一个 datagram。
///
/// 由 ServerDriver 作为函数指针注册（见 GatewayWorker.run），因此签名必须与 driver 的
/// 回调类型一致。**只在面向客户端的监听器上注册**：集群链路那一跳走的是可靠
/// `.multicast` 帧，由收方节点在本地再落成 datagram。
///
/// ## 热路径上没有授权查找
///
/// 组授权在 `bind_channel` 那一刻查过一次（§6.1），之后就塌缩成一次数组下标读取。
/// 剩下的只有一次**准入有效性**判定（`isAdmitted`）——它不是授权查找，而是"这条连接
/// 此刻还算不算在线"，两次加载加一次比较。**不能省**：省了它，一条 token 已过期的
/// 连接就能继续往房间里灌状态包，而它已经开不出任何交换了。
///
/// 吊销准入的路径还必须顺手 `clearChannels`（见 `egress.kickOne`），否则被踢的连接在
/// 断开前的那段时间里仍然持有通道。
///
/// ## 一切异常都是丢弃 + 计数，绝不关连接
///
/// 不可靠通路上一个坏包不代表对端的编码器坏了（它可能是被中间设备截断的），而关连接
/// 会把一次丢包放大成一次掉线。逐包记日志会在 60Hz × N 个玩家下把磁盘写满，所以
/// 可观测性靠计数器而不是日志。
pub fn handleDatagram(ud: ?*anyopaque, conn: *QUICConnection, data: []const u8) void {
    const self = GatewayWorker.castSelf(ud);
    self.datagrams_in +%= 1;

    const ctx = self.conn_manager.get(conn) orelse {
        self.datagrams_dropped +%= 1;
        return;
    };
    if (self.auth_policy.required and !ctx.isAdmitted(quic.c.currentTime())) {
        self.datagrams_dropped +%= 1;
        return;
    }

    const parsed = protocol.datagram.decode(data) catch {
        self.datagrams_dropped +%= 1;
        return;
    };

    // 通道没绑有两种情形：客户端抢跑（绑定请求还在路上），或者绑定已经被吊销。
    // 两者都只该丢这一包。
    const group_id = ctx.channelGroup(parsed.channel) orelse {
        self.datagrams_dropped +%= 1;
        return;
    };

    egress.fanOutUnreliable(self, ctx, group_id, parsed.payload);
}

/// 一次绑定请求的判定结果。
///
/// 把"决定"与"回执"分开是为了让判定可测：回执要往一条真实的 QUIC 连接上写，而绑定
/// **授权**这件事恰恰是最需要用例钉住的部分（放开它就是一次越权）。
pub const BindOutcome = enum {
    bound,
    malformed,
    not_admitted,
    not_a_member,
};

/// `bind_channel`：把一个 datagram 通道绑到一个组播组（设计文档 §6.1）。
///
/// ## 授权判据是"已经是该组的成员"
///
/// 而成员关系只能由后端的 `join_group` 建立（§7.2）。所以网关在这里做的是一次真实的
/// 本地判断，而不是采信客户端的自述——这与 §5.4「客户端无权直接寻址其他客户端」是
/// 一致的：客户端能不可靠地发给这个组，前提是**后端已经把它放进了这个组**。
///
/// 设计文档原先在 §6.1 里还列了绑到 `.peer` 的形态，那一半过不了这道判据：网关对
/// "这个客户端能不能不可靠地寻址那个账号"没有任何本地依据，临时发明一个就正好是
/// §5.4 要防的越权。需要 1:1 不可靠通路时让后端建一个两人组。
///
/// ## 成功的回执是把同一个控制类型回一遍
///
/// 不新增"绑定成功"控制类型：客户端发 `bind_channel`、网关回 `bind_channel`，含义就是
/// "按你说的办了"，而失败走 `gateway_error`。多一个类型就多一处两边都要实现的分支。
pub fn bindChannel(self: *GatewayWorker, ctx: *ConnectionContext, stream_id: u64, parsed: codec.Frame) void {
    switch (resolveBind(self, ctx, parsed)) {
        .bound => self.replyControl(ctx.cnx_handle, stream_id, .bind_channel, parsed.body),
        .malformed => {
            std.log.warn("[CHAN] malformed channel binding on stream {}", .{stream_id});
            self.replyControl(ctx.cnx_handle, stream_id, .gateway_error, "malformed channel binding");
        },
        .not_admitted => self.replyControl(ctx.cnx_handle, stream_id, .gateway_error, "authentication required"),
        .not_a_member => {
            std.log.warn("[CHAN] bind refused, not a member: realm={} stream={}", .{ ctx.realm, stream_id });
            self.replyControl(ctx.cnx_handle, stream_id, .gateway_error, "not a member of that group");
        },
    }
}

/// 判定并（在通过时）落实一次绑定。
pub fn resolveBind(self: *GatewayWorker, ctx: *ConnectionContext, parsed: codec.Frame) BindOutcome {
    // 门禁与 `.service` 交换同一道：未认证的连接不该拿到任何投递能力。
    if (self.auth_policy.required and !ctx.isAdmitted(quic.c.currentTime())) return .not_admitted;

    const binding = protocol.body.ChannelBinding.decode(parsed.body) catch return .malformed;
    if (!self.conn_manager.isGroupMember(ctx.cnx_handle, binding.group_id)) return .not_a_member;

    ctx.bindChannel(binding.channel, binding.group_id);
    return .bound;
}

/// `unbind_channel`：解除一个通道的绑定。
///
/// 不校验成员关系，也不校验这个通道当初绑过什么：解绑只会收窄能力，任何时候都安全。
pub fn unbindChannel(self: *GatewayWorker, ctx: *ConnectionContext, stream_id: u64, parsed: codec.Frame) void {
    const channel = protocol.body.decodeChannel(parsed.body) catch |err| {
        std.log.warn("[CHAN] malformed unbind on stream {}: {}", .{ stream_id, err });
        self.replyControl(ctx.cnx_handle, stream_id, .gateway_error, "malformed channel number");
        return;
    };
    ctx.unbindChannel(channel);
    self.replyControl(ctx.cnx_handle, stream_id, .unbind_channel, parsed.body);
}

/// 关闭整条连接（协议违规）。
///
/// 带上应用层错误码，客户端才能区分"网关正常下线"和"我发出的字节被判违规"
/// ——后者需要修客户端，前者只需要重连。
fn closeConnection(ctx: *ConnectionContext, code: AppError) void {
    var conn = QUICConnection.fromRaw(ctx.cnx_handle);
    conn.closeWithError(@intFromEnum(code));
}
