//! 连接级生命周期事件
//!
//! Gateway 只报告它能权威观察到的事实：某个 `conn_token` 在认证后上线，或因连接关闭、
//! kick、准入过期而下线。`dest_id` 的多设备聚合、last_seen 与用户级在线状态全部属于
//! Reactor；本模块不保存 presence 表，也不判断“用户整体是否在线”。

const std = @import("std");

const foundation = @import("../foundation/mod.zig");
const protocol = @import("../protocol/mod.zig");
const backend = @import("../backend/mod.zig");
const quic = @import("../quic/mod.zig");
const connection = @import("connection.zig");
const ConnectionContext = connection.ConnectionContext;
const GatewayWorker = @import("worker.zig").GatewayWorker;

const Event = protocol.body.SessionLifecycle;
const EventKind = enum { online, offline };

/// 必须明显短于 Reactor 的 presence lease（默认 45 秒），给调度抖动与一次丢失留余量。
pub const refresh_interval_us: u64 = 15 * std.time.us_per_s;

pub fn publishOnline(self: *GatewayWorker, ctx: *ConnectionContext) void {
    publish(self, ctx, .online, .authenticated);
}

pub fn publishOffline(self: *GatewayWorker, ctx: *ConnectionContext, reason: Event.Reason) void {
    if (!ctx.authenticated) return;
    publish(self, ctx, .offline, reason);
}

/// 到期才重发连接级 online。它是租约续期，不是用户级 presence 聚合。
pub fn refreshOnline(self: *GatewayWorker, ctx: *ConnectionContext, now: u64) void {
    if (!ctx.authenticated) return;
    if (now -| ctx.lifecycle_refreshed_at < refresh_interval_us) return;
    publish(self, ctx, .online, .lease_refresh);
}

/// 发布下线事件并清除本地准入状态。重复调用是幂等的：第一次会把 authenticated 清零，
/// 后续调用不再产生重复 offline。
pub fn revokeAdmission(self: *GatewayWorker, ctx: *ConnectionContext, reason: Event.Reason) void {
    publishOffline(self, ctx, reason);
    ctx.authenticated = false;
    ctx.auth_expires_at = 0;
    ctx.clearChannels();
    self.conn_manager.bindDest(ctx.session_handle, 0);
}

fn publish(self: *GatewayWorker, ctx: *ConnectionContext, kind: EventKind, reason: Event.Reason) void {
    const route = self.auth_policy.lifecycle_route orelse return;
    const now = quic.c.currentTime();
    if (kind == .online) ctx.lifecycle_refreshed_at = now;
    ctx.lifecycle_sequence +%= 1;
    if (ctx.lifecycle_sequence == 0) ctx.lifecycle_sequence = 1;
    const token = self.conn_manager.tokenFor(ctx.session_handle) orelse {
        std.log.warn("[LIFECYCLE] connection has no token", .{});
        return;
    };
    const scope = backend.ScopedRoute.scoped(ctx.realm, route);
    const transport = self.findTransport(scope) orelse {
        std.log.warn("[LIFECYCLE] route unavailable: realm={} group=0x{x} route=0x{x}", .{ ctx.realm, route.group, route.route_key });
        return;
    };

    switch (self.inflight.reserveRoute(ctx.realm, now)) {
        .ok => {},
        .table_full => {
            std.log.warn("[LIFECYCLE] in-flight table full", .{});
            return;
        },
        .realm_over_share => {
            std.log.warn("[LIFECYCLE] realm {} is over its in-flight share", .{ctx.realm});
            return;
        },
    }

    var body_buf: [Event.SIZE]u8 = undefined;
    (Event{
        .realm = ctx.realm,
        .conn_token = token.encode(),
        .dest_id = ctx.dest_id,
        .connected_at = ctx.connected_at,
        .occurred_at = foundation.time.timestampSeconds(),
        .sequence = ctx.lifecycle_sequence,
        .reason = reason,
    }).encode(&body_buf) catch unreachable;

    const control_type: protocol.frame.ControlType = switch (kind) {
        .online => .session_online,
        .offline => .session_offline,
    };
    var frame_buf: [protocol.frame.OPEN_HEADER_SIZE + Event.SIZE]u8 = undefined;
    var encoder = protocol.codec.FrameEncoder.init(&frame_buf);
    const frame_bytes = encoder.encodeOpen(
        .gateway,
        protocol.frame.RouteId.init(0, @intFromEnum(control_type)),
        .none,
        protocol.frame.Flags.last(),
        &body_buf,
    ) catch |err| {
        std.log.warn("[LIFECYCLE] cannot encode event: {}", .{err});
        return;
    };

    const stream_id = transport.send(scope.route, frame_bytes) catch |err| {
        std.log.warn("[LIFECYCLE] cannot send event: {}", .{err});
        return;
    };
    const key = @import("inflight.zig").StreamKey{ .transport = transport.id(), .stream = stream_id };
    self.inflight.openRoute(key, .{
        .target = .discard,
        .realm = ctx.realm,
        .last_active_at = now,
    }) catch |err| {
        std.log.warn("[LIFECYCLE] cannot track event completion: {}", .{err});
        return;
    };

    std.log.info("[LIFECYCLE] {s}: realm={} dest_id={} conn_token={} sequence={}", .{
        @tagName(kind),
        ctx.realm,
        ctx.dest_id,
        token.encode(),
        ctx.lifecycle_sequence,
    });
}
