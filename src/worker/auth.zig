//! 接入认证
//!
//! 网关不解析 token：`auth_request` 的 body 被原样转发给配置指定的后端认证服务，
//! 由它返回 auth_success / auth_failure。
//!
//! 这样做的理由是职责边界：token 的签发、校验、吊销都是业务逻辑，放进网关就意味着
//! 网关要跟着业务的认证方案一起改。网关只需要知道"这条连接过了没有"。
//!
//! 但两个方向上各有一段**网关自有的定长前缀**（设计文档 §10.3），它们不违反上面
//! 那条边界——网关只碰自己的字段，token 的形态依然完全不可见：
//!
//! - 请求方向 `AuthContext{realm, conn_token}`：告诉后端"这是哪个 realm 的、
//!   哪一条连接"。`conn_token` 是后端之后精确 kick 这条连接的唯一依据（§7.2）；
//!   没有它，后端只能按 `dest_id` 踢掉一个账号的全部设备。
//! - 响应方向 `AuthGrant{dest_id, ttl_seconds}`：告诉网关准入到什么程度。
//!   `dest_id` 让 `.peer` 投递能找到这条连接，**只能由认证服务下发**，采信客户端
//!   声明的值等于允许任何人冒领别人的消息。TTL 让准入状态有生命周期，没有它
//!   token 过期与账号吊销都无法反映到已经建立的连接上。
//!
//! 等待期间的状态放在 inflight.Tables 里（与普通请求共用同一套上限与回收），
//! 本文件只负责委托、累积响应、判定结果这三步。

const std = @import("std");

const foundation = @import("../foundation/mod.zig");
const err_handler = foundation.err;
const io = @import("../io/mod.zig");
const protocol = @import("../protocol/mod.zig");
const quic = @import("../quic/mod.zig");
const QUICConnection = quic.connection.Connection;
const backend = @import("../backend/mod.zig");
const RouteId = backend.RouteId;
const connection = @import("connection.zig");
const ConnectionContext = connection.ConnectionContext;
const inflight = @import("inflight.zig");
const GatewayWorker = @import("worker.zig").GatewayWorker;

/// 接入认证策略（由配置装配）。
pub const Policy = struct {
    /// true 时未认证连接的数据帧一律拒绝，只放行控制帧。
    required: bool = false,
    /// 认证服务的完整路由键（Group + RouteKey）；null 表示未配置认证服务。
    route: ?RouteId = null,
};

/// 认证服务响应的判定结果。
pub const Result = enum { success, failure, invalid };

/// 判定结果 + 成功时从响应前缀里解出的准入信息。
///
/// 分成两个字段而不是带载荷的 union，是为了让 `result` 保持可直接比较——
/// 调用方与测试都只关心"成功/失败/非法"这三个分支，grant 只在成功时有意义。
pub const Verdict = struct {
    result: Result,
    grant: protocol.body.AuthGrant = .{},
};

/// 把 `AuthContext` 前缀 + 客户端原样 body 重编成一个 auth_request 帧。
///
/// 就地拼装：前缀写在帧头之后，客户端 body 紧跟其后，最后回填帧头。全程只用这一块
/// 缓冲、只拷一次（客户端 body 那一次无法避免——插了前缀，长度变了）。
fn buildAuthRequest(
    scratch: []u8,
    context: protocol.body.AuthContext,
    client_body: []const u8,
) protocol.frame.FrameError![]const u8 {
    const header_size = protocol.frame.OPEN_HEADER_SIZE;
    const prefix = protocol.body.AuthContext.SIZE;
    const body_len = prefix + client_body.len;
    if (body_len > protocol.frame.MAX_BODY_SIZE) return error.BodyTooLarge;
    if (scratch.len < header_size + body_len) return error.BufferTooSmall;

    try context.encode(scratch[header_size..][0..prefix]);
    @memcpy(scratch[header_size + prefix ..][0..client_body.len], client_body);
    const header = protocol.frame.FrameHeader.initControl(.auth_request, @intCast(body_len));
    _ = try header.encode(scratch[0..header_size]);
    return scratch[0 .. header_size + body_len];
}

/// 把认证请求转发给后端认证服务，网关不解析 token。
///
/// 认证路由键是全局配置（一个 `(group, route_key)`），但查表时会带上这条连接的
/// realm：每个 realm 必须在同一个路由键上注册自己的认证服务，于是"各接入方用自己的
/// 认证体系"是自动成立的，不需要 per-realm 的策略配置（设计文档 §12）。
/// 某个 realm 没注册认证服务时这里会查不到，连接就认证不过——失败关闭。
///
/// 转发的不是原帧，而是"`AuthContext` 前缀 + 客户端原样 body"重编出的帧。前缀里的
/// `conn_token` 是后端之后精确 kick 这条连接的唯一依据（§7.2）。这仍然不违反"网关
/// 不解析 token"：网关只写自己的定长前缀，客户端那段字节一个都不看。
pub fn delegateAuth(self: *GatewayWorker, ctx: *ConnectionContext, client_stream_id: u64, parsed: protocol.codec.Frame) void {
    const route = self.auth_policy.route orelse {
        self.replyControl(ctx.cnx_handle, client_stream_id, .auth_failure, "authentication not configured");
        return;
    };
    const scope = backend.ScopedRoute.scoped(ctx.realm, route);
    const transport = self.findTransport(scope) orelse {
        self.replyControl(ctx.cnx_handle, client_stream_id, .auth_failure, "authentication service unavailable");
        return;
    };
    // 走不到 null：ctx 就是从管理器里取出来的。用 orelse 而不是 .? 是因为一旦真的
    // 发生（将来有人改了调用路径），回一个认证失败远比崩掉整个 Worker 好。
    const token = self.conn_manager.tokenFor(ctx.cnx_handle) orelse {
        self.replyControl(ctx.cnx_handle, client_stream_id, .auth_failure, "connection not registered");
        return;
    };
    const forwarded = buildAuthRequest(
        self.auth_scratch,
        .{ .realm = ctx.realm, .conn_token = token.encode() },
        parsed.body,
    ) catch |err| {
        // 唯一现实原因是客户端的认证 body 已经贴着 64KB 上限，插不进 10 字节前缀。
        std.log.warn("[AUTH] cannot frame auth request: {}", .{err});
        self.replyControl(ctx.cnx_handle, client_stream_id, .auth_failure, "authentication payload too large");
        return;
    };
    const now = quic.c.currentTime();
    // 两个拒绝理由分开报，理由同 ingress 的 reserveRoute。认证被挡住的表现是
    // "整个 realm 谁都登录不上"，因此这条日志必须能一眼看出是配额还是表满。
    switch (self.inflight.reserveAuth(ctx.realm, now)) {
        .ok => {},
        .table_full => {
            std.log.warn("[AUTH] pending auth table full, rejecting stream={}", .{client_stream_id});
            self.replyControl(ctx.cnx_handle, client_stream_id, .auth_failure, "authentication service busy");
            return;
        },
        .realm_over_share => {
            std.log.warn("[AUTH] realm over pending-auth share: realm={} stream={}", .{ ctx.realm, client_stream_id });
            self.replyControl(ctx.cnx_handle, client_stream_id, .auth_failure, "realm authentication quota exceeded");
            return;
        },
    }
    const backend_stream_id = transport.send(scope.route, forwarded) catch |err| {
        err_handler.reportError(.session, "Failed to forward auth request", err);
        self.replyControl(ctx.cnx_handle, client_stream_id, .auth_failure, "authentication service unavailable");
        return;
    };
    self.inflight.trackAuth(.{ .transport = transport.id(), .stream = backend_stream_id }, .{
        .client_cnx = ctx.cnx_handle,
        .client_stream_id = client_stream_id,
        .realm = ctx.realm,
        .buffer = .{ .items = &.{}, .capacity = 0 },
        .created_at = now,
    }) catch |err| {
        err_handler.reportError(.session, "Failed to track pending auth request", err);
        return;
    };
    std.log.info("[AUTH] delegated: client_stream={} -> backend_stream={} realm={} group=0x{x} route=0x{x}", .{ client_stream_id, backend_stream_id, ctx.realm, route.group, route.route_key });
}

/// 累积认证服务的响应分片，收到 fin 后解码并更新连接认证状态。
///
/// 认证响应必须攒齐再判定：只看第一个分片可能把一个截断的 auth_success
/// 当成认证通过。
pub fn collectAuthResponse(self: *GatewayWorker, key: inflight.StreamKey, data: []const u8, is_fin: bool) void {
    const pending = self.inflight.authPtr(key) orelse return;
    pending.buffer.appendSlice(self.allocator, data) catch |err| {
        err_handler.reportError(.session, "Failed to buffer auth response", err);
        var entry = self.inflight.takeAuth(key).?;
        entry.buffer.deinit(self.allocator);
        return;
    };
    if (!is_fin) return;

    var entry = self.inflight.takeAuth(key).?;
    defer entry.buffer.deinit(self.allocator);
    completeAuth(self, &entry);
}

/// 根据认证服务返回的帧标记连接状态，并把响应原样回给客户端。
fn completeAuth(self: *GatewayWorker, auth: *const inflight.PendingAuth) void {
    // 等待认证结果期间连接可能已经关闭
    const ctx = self.conn_manager.getByHandle(auth.client_cnx) orelse {
        std.log.warn("[AUTH] connection closed before auth completed", .{});
        return;
    };

    const response = auth.buffer.items;
    const verdict = classify(response);
    switch (verdict.result) {
        .success => {
            // 亲和策略下，认证成功这一刻才第一次知道 dest_id，也才第一次能判断这条连接
            // 在不在它该在的位置上。不在就必须赶走——留在错位置继续服务，后续按
            // hash 定向转发的推送会漏掉它，而漏掉的表现是消息静默丢失（§8.5 策略 B）。
            if (redirectIfNotHome(self, ctx, auth, verdict.grant.dest_id, response)) return;

            ctx.authenticated = true;
            ctx.auth_expires_at = expiryFrom(verdict.grant.ttl_seconds);
            // 绑定寻址标识：这一步之后 .peer 投递才能找到这条连接。
            // dest_id 只来自认证服务，客户端声明的任何字段都不参与；它只在本连接的
            // realm 内唯一，realm 由 ConnectionManager 从连接上下文自己取。
            self.conn_manager.bindDest(auth.client_cnx, verdict.grant.dest_id);
            std.log.info("[AUTH] success: stream={} realm={} dest_id={} ttl={}s", .{
                auth.client_stream_id,
                ctx.realm,
                verdict.grant.dest_id,
                verdict.grant.ttl_seconds,
            });
        },
        .failure => std.log.info("[AUTH] failure: stream={}", .{auth.client_stream_id}),
        .invalid => {
            std.log.warn("[AUTH] invalid response from auth service", .{});
            self.replyControl(auth.client_cnx, auth.client_stream_id, .auth_failure, "invalid auth service response");
            return;
        },
    }

    var conn = QUICConnection.fromRaw(auth.client_cnx);
    conn.streamWrite(auth.client_stream_id, response, true) catch |err| {
        err_handler.reportError(.session, "Failed to write auth response to client", err);
    };
}

/// 认证成功后判断这条连接是否在它该在的节点上；不在就发重定向并关闭，返回 true。
///
/// ## 为什么必须强制，不能"就在本地先服务着"
///
/// 亲和的不变量是「每条带 `dest_id` 的活连接都在 `hash(realm, dest_id)` 算出的位置
/// 上」。只要有一条连接违反它，`hash` 就不可信——别的节点算出 B、把推送发过去，
/// 而真正的连接躺在 A 上，消息静默丢失。所以这里不绑定 `dest_id`、不置 `authenticated`：
/// 即使关闭在竞态里慢了一步，这条连接也已经既不可寻址、也发不了数据帧。
///
/// ## 顺序：先回认证响应，再回重定向
///
/// 客户端需要知道"凭据是有效的，只是地方不对"。反过来先关连接，SDK 只能看到一次
/// 失败的认证，会去做无谓的重新登录。
///
/// 拿不到 home 地址（membership 里没有它、或本节点用的是临时端口）时**不重定向**，
/// 退化成就地服务并记一条 warn：宁可牺牲一次亲和，也不能把一个错地址交给客户端。
fn redirectIfNotHome(
    self: *GatewayWorker,
    ctx: *ConnectionContext,
    auth: *const inflight.PendingAuth,
    dest_id: u64,
    response: []const u8,
) bool {
    if (dest_id == 0) return false;
    // 双查窗口里新旧两个位置都算 home（见 placement.isHomeNode）：此刻本节点的视图
    // 可能比别人新也可能比别人旧，按一份不稳定的视图重定向会让客户端来回弹。
    if (self.placement.isHomeNode(ctx.realm, dest_id)) return false;

    return redirectToHome(self, ctx, dest_id, .{
        .stream_id = auth.client_stream_id,
        .bytes = response,
    });
}

/// 把一条连接赶到它的 home 节点：发一个 redirect 帧，再带 `redirected` 错误码关闭。
///
/// `pre` 非 null 时先在指定流上写一段字节并 fin（认证路径用它把认证响应发出去，
/// 客户端重连时才能直接复用拿到的 `dest_id` 与有效期）。**顺序是有意的**：先确认
/// 目标地址可拨，再写任何东西——拨不出地址时这一次重定向根本不该开始，连接留在
/// 本节点比被关掉好。
///
/// pub 是给漂移巡检用的（`worker.rehomeDrifted`）：认证时判一次不够。连接是长寿的
/// （IM 客户端挂几小时很正常），而它的 home 会因为**别人**扩容而漂走；那时必须再赶
/// 一次，否则这条连接会永久收不到推送，且没有任何报错提示（§8.5）。
pub fn redirectToHome(
    self: *GatewayWorker,
    ctx: *ConnectionContext,
    dest_id: u64,
    pre: ?struct { stream_id: u64, bytes: []const u8 },
) bool {
    const home = self.placement.home(ctx.realm, dest_id) orelse return false;
    if (home.node_id == self.placement.self.node_id) return false;

    var address_buf: [64]u8 = undefined;
    const address = homeAddress(self, home.node_id, &address_buf) orelse {
        std.log.warn("[PLACE] cannot redirect dest_id={} to node {}: no dialable address", .{ dest_id, home.node_id });
        return false;
    };

    if (pre) |first| {
        var conn = QUICConnection.fromRaw(ctx.cnx_handle);
        conn.streamWrite(first.stream_id, first.bytes, true) catch |err| {
            err_handler.reportError(.session, "Failed to write auth response before redirect", err);
        };
    }

    const hint = io.cid.placementHint(home.node_id, home.worker_id);
    var body_buf: [128]u8 = undefined;
    var frame_buf: [256]u8 = undefined;
    const redirect = blk: {
        const body_len = protocol.body.RedirectHint.encode(&body_buf, &hint, address) catch |err| {
            err_handler.reportError(.session, "Failed to encode redirect body", err);
            break :blk null;
        };
        var encoder = protocol.codec.FrameEncoder.init(&frame_buf);
        break :blk encoder.encodeRedirect(body_buf[0..body_len]) catch |err| {
            err_handler.reportError(.session, "Failed to encode redirect frame", err);
            break :blk null;
        };
    };
    if (redirect) |data| {
        var pushing = QUICConnection.fromRaw(ctx.cnx_handle);
        pushing.streamWrite(ctx.nextPushStream(), data, true) catch |err| {
            err_handler.reportError(.session, "Failed to send redirect", err);
        };
    }

    std.log.info("[PLACE] redirecting dest_id={} realm={} to node {} worker {} at {s}", .{
        dest_id,
        ctx.realm,
        home.node_id,
        home.worker_id,
        address,
    });

    // 带错误码关闭：重定向帧可能在关闭竞态里送不到，而错误码一定随 CONNECTION_CLOSE
    // 到达。客户端靠它区分"换地址重连，凭据还有效"和"该重新认证"。
    var closing = QUICConnection.fromRaw(ctx.cnx_handle);
    closing.closeWithError(@intFromEnum(protocol.frame.AppError.redirected));
    return true;
}

/// 把 home 节点的 gossip 地址换成客户端可拨的服务地址。
///
/// 集群同构假设：所有节点用同一个客户端服务端口，与 `forward_port` 是集群级配置
/// 同一个前提。端口为 0（临时端口）时返回 null。
fn homeAddress(self: *GatewayWorker, node_id: u16, buf: []u8) ?[]const u8 {
    if (self.client_port == 0) return null;
    const view = self.coordinator.membershipView() orelse return null;
    const member = view.lookup(node_id) orelse return null;
    const dialable = foundation.net.withPort(member.address, self.client_port);
    return foundation.net.writeDialString(dialable, buf) catch null;
}

/// TTL 秒数换算成绝对失效时刻；0 表示不过期。
///
/// 饱和加法而不是普通加法：ttl 来自后端，u32 上限对应约 136 年，正常配置下不会
/// 溢出，但一个畸形的大值不该把失效时刻绕回到过去（那会让连接立刻不可用，
/// 而原因极难定位）。
fn expiryFrom(ttl_seconds: u32) u64 {
    if (ttl_seconds == 0) return 0;
    return quic.c.currentTime() +| (@as(u64, ttl_seconds) * std.time.us_per_s);
}

/// 校验认证服务返回的必须是一个完整的 auth_success / auth_failure 控制帧，
/// 并在成功时解出网关自有的准入前缀（设计文档 §10.3）。
///
/// 长度必须精确等于帧长（由 parseExactFrame 保证）：多一个字节就说明这不是
/// 单一的认证响应，不能凭它给连接打上已认证标记。
///
/// `auth_success` 的 body 短于前缀长度一律判 invalid。宁可拒绝也不能把一个截断的
/// 响应当成"认证通过且不可寻址且永不过期"——那会让一次网络截断变成静默降级。
pub fn classify(data: []const u8) Verdict {
    const parsed = protocol.codec.parseExactFrame(data) catch return .{ .result = .invalid };
    const ctrl = parsed.header.controlType() orelse return .{ .result = .invalid };
    return switch (ctrl) {
        .auth_success => blk: {
            const grant = protocol.body.AuthGrant.decode(parsed.body) catch {
                std.log.warn("[AUTH] auth_success without a complete grant prefix", .{});
                break :blk .{ .result = .invalid };
            };
            break :blk .{ .result = .success, .grant = grant };
        },
        .auth_failure => .{ .result = .failure },
        else => .{ .result = .invalid },
    };
}

/// 拼一个带准入前缀的 auth_success body（认证服务本该这么发）。
fn testGrantBody(buf: []u8, grant: protocol.body.AuthGrant, tail: []const u8) []const u8 {
    grant.encode(buf) catch unreachable;
    @memcpy(buf[protocol.body.AuthGrant.SIZE..][0..tail.len], tail);
    return buf[0 .. protocol.body.AuthGrant.SIZE + tail.len];
}

test "buildAuthRequest prefixes the gateway context without touching the client body" {
    const allocator = std.testing.allocator;
    const scratch = try allocator.alloc(u8, protocol.frame.OPEN_HEADER_SIZE + protocol.frame.MAX_BODY_SIZE);
    defer allocator.free(scratch);

    const context: protocol.body.AuthContext = .{ .realm = 9, .conn_token = 0x0102_0304_0506_0708 };
    const frame_bytes = try buildAuthRequest(scratch, context, "opaque-token");

    const parsed = try protocol.codec.parseExactFrame(frame_bytes);
    try std.testing.expectEqual(protocol.frame.ControlType.auth_request, parsed.header.controlType().?);
    // 控制交换是一次性的，重编出来的帧必须仍然带 eof。
    try std.testing.expect(parsed.header.isLast());

    const decoded = try protocol.body.AuthContext.decode(parsed.body);
    try std.testing.expectEqual(context.realm, decoded.realm);
    try std.testing.expectEqual(context.conn_token, decoded.conn_token);
    // 客户端那段字节原样落在前缀之后。
    try std.testing.expectEqualStrings("opaque-token", parsed.body[protocol.body.AuthContext.SIZE..]);
}

test "an auth body that leaves no room for the prefix is refused" {
    // 唯一现实的失败原因：客户端的认证 body 已经贴着 64KB 上限，插不进 10 字节前缀。
    // 这里必须报错而不是截断——截断会把一个残缺的 token 交给认证服务。
    const allocator = std.testing.allocator;
    const scratch = try allocator.alloc(u8, protocol.frame.OPEN_HEADER_SIZE + protocol.frame.MAX_BODY_SIZE);
    defer allocator.free(scratch);
    const oversized = try allocator.alloc(u8, protocol.frame.MAX_BODY_SIZE);
    defer allocator.free(oversized);
    @memset(oversized, 'x');

    try std.testing.expectError(
        error.BodyTooLarge,
        buildAuthRequest(scratch, .{ .realm = 1, .conn_token = 1 }, oversized),
    );
}

test "classify accepts only whole auth control frames" {
    var buf: [256]u8 = undefined;
    var encoder = protocol.codec.FrameEncoder.init(&buf);

    var body_buf: [64]u8 = undefined;
    const grant_body = testGrantBody(&body_buf, .{ .dest_id = 0xABCD, .ttl_seconds = 900 }, "user-1");

    const ok_frame = try encoder.encodeAuthSuccess(grant_body);
    const ok = classify(ok_frame);
    try std.testing.expectEqual(Result.success, ok.result);
    try std.testing.expectEqual(@as(u64, 0xABCD), ok.grant.dest_id);
    try std.testing.expectEqual(@as(u32, 900), ok.grant.ttl_seconds);

    const fail_frame = try encoder.encodeAuthFailure("bad token");
    try std.testing.expectEqual(Result.failure, classify(fail_frame).result);

    // 认证之外的控制帧不能被当成认证结果。
    const heartbeat = try encoder.encodeHeartbeat();
    try std.testing.expectEqual(Result.invalid, classify(heartbeat).result);

    try std.testing.expectEqual(Result.invalid, classify("not a frame").result);
}

test "an auth_success without a complete grant prefix is invalid" {
    // 关键回归：截断的成功响应不能降级成"通过但不可寻址、永不过期"。
    var buf: [256]u8 = undefined;
    var encoder = protocol.codec.FrameEncoder.init(&buf);

    const truncated = try encoder.encodeAuthSuccess("short");
    try std.testing.expectEqual(Result.invalid, classify(truncated).result);

    // 恰好等于前缀长度、没有 opaque 尾部是合法的。
    var body_buf: [protocol.body.AuthGrant.SIZE]u8 = undefined;
    const exact = testGrantBody(&body_buf, .{ .dest_id = 1, .ttl_seconds = 0 }, "");
    const frame_data = try encoder.encodeAuthSuccess(exact);
    const verdict = classify(frame_data);
    try std.testing.expectEqual(Result.success, verdict.result);
    try std.testing.expectEqual(@as(u32, 0), verdict.grant.ttl_seconds);
}

test "classify rejects a frame with trailing bytes" {
    var buf: [256]u8 = undefined;
    var encoder = protocol.codec.FrameEncoder.init(&buf);

    var body_buf: [64]u8 = undefined;
    const grant_body = testGrantBody(&body_buf, .{ .dest_id = 1, .ttl_seconds = 1 }, "user-1");
    const ok_frame = try encoder.encodeAuthSuccess(grant_body);

    var padded: [256]u8 = undefined;
    @memcpy(padded[0..ok_frame.len], ok_frame);
    padded[ok_frame.len] = 0xFF;

    // 长度不匹配必须判为 invalid：否则尾随字节里可以藏第二帧，
    // 而连接却按第一帧的结果被标记为已认证。
    try std.testing.expectEqual(Result.invalid, classify(padded[0 .. ok_frame.len + 1]).result);
}

test "a zero TTL means no expiry, a non-zero one lands in the future" {
    try std.testing.expectEqual(@as(u64, 0), expiryFrom(0));

    const before = quic.c.currentTime();
    const expiry = expiryFrom(60);
    try std.testing.expect(expiry >= before + 60 * std.time.us_per_s);

    // 畸形的大 ttl 不能把失效时刻绕回过去。
    try std.testing.expect(expiryFrom(std.math.maxInt(u32)) > before);
}
