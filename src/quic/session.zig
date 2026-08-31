//! Raw QUIC 到传输无关客户端会话契约的适配器。
//!
//! picoquic 指针与具体 API 只停留在本文件；Worker 的认证、Exchange、路由和推送
//! 只看到 `session.TransportSession`。

const client_session = @import("../session/mod.zig");
const TransportSession = client_session.TransportSession;
const quic_c = @import("c.zig");
const QUICConnection = @import("connection.zig").Connection;

pub fn init(cnx: quic_c.QuicCnx) TransportSession {
    return TransportSession.init(.raw_quic, @ptrCast(cnx), &vtable, @intFromPtr(cnx));
}

const vtable: TransportSession.VTable = .{
    .claim_inbound_exchange = claimInboundExchange,
    .write = write,
    .send_ephemeral = sendEphemeral,
    .reset_send = resetSend,
    .stop_receive = stopReceive,
    .discard = discard,
    .close = close,
};

fn raw(ptr: *anyopaque) quic_c.QuicCnx {
    return @ptrCast(@alignCast(ptr));
}

fn claimInboundExchange(_: *anyopaque, _: u64) bool {
    // QUIC 自己维护 stream 状态并禁止 stream id 复用。
    return true;
}

fn write(ptr: *anyopaque, stream_id: u64, data: []const u8, is_fin: bool) TransportSession.Error!void {
    var conn = QUICConnection.fromRaw(raw(ptr));
    conn.streamWrite(stream_id, data, is_fin) catch return error.StreamWriteFailed;
}

fn sendEphemeral(ptr: *anyopaque, data: []const u8) TransportSession.Error!void {
    var conn = QUICConnection.fromRaw(raw(ptr));
    conn.sendDatagram(data) catch return error.EphemeralSendFailed;
}

fn resetSend(ptr: *anyopaque, stream_id: u64, app_error_code: u64) void {
    _ = quic_c.c.picoquic_reset_stream(raw(ptr), stream_id, @intCast(app_error_code));
}

fn stopReceive(ptr: *anyopaque, stream_id: u64, app_error_code: u64) void {
    _ = quic_c.c.picoquic_stop_sending(raw(ptr), stream_id, @intCast(app_error_code));
}

fn discard(ptr: *anyopaque, stream_id: u64, app_error_code: u64) void {
    _ = quic_c.c.picoquic_discard_stream(raw(ptr), stream_id, @intCast(app_error_code));
}

fn close(ptr: *anyopaque, app_error_code: u64) void {
    var conn = QUICConnection.fromRaw(raw(ptr));
    conn.closeWithError(app_error_code);
}

test "Raw QUIC session preserves callback identity" {
    const std = @import("std");
    const cnx: quic_c.QuicCnx = @ptrFromInt(0x1000);
    var transport = init(cnx);
    try std.testing.expectEqual(client_session.transport.Kind.raw_quic, transport.kind());
    try std.testing.expectEqual(@as(?usize, 0x1000), transport.callbackKey());
}
