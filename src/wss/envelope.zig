//! WSS binding 的逻辑流信封。
//!
//! QUIC 已经原生提供 stream id、FIN、RESET_STREAM、STOP_SENDING 与 DATAGRAM；
//! WebSocket 没有。WSS 因此在每个 binary message 内放一个固定 20 字节信封，把这些
//! 传输事件显式化。`payload` 中的 Lyune OPEN/DATA 字节完全沿用 Raw QUIC binding。

const std = @import("std");
const protocol = @import("../protocol/mod.zig");

pub const version: u8 = 1;
pub const header_size: usize = 20;
pub const max_payload_size: usize = protocol.frame.MAX_FRAME_SIZE;
pub const max_record_size: usize = header_size + max_payload_size;

pub const RecordType = enum(u8) {
    /// 一段 logical stream 数据；`fin` 结束发送方的方向。
    stream = 0x01,
    /// 异常终止发送方的方向，对应 QUIC RESET_STREAM。
    reset = 0x02,
    /// 请求对端停止发送，对应 QUIC STOP_SENDING。
    stop = 0x03,
    /// 尽力而为、可在拥塞前丢弃的临时消息，对应 QUIC DATAGRAM 的业务语义。
    ephemeral = 0x04,

    fn decode(raw: u8) Error!RecordType {
        return switch (raw) {
            0x01 => .stream,
            0x02 => .reset,
            0x03 => .stop,
            0x04 => .ephemeral,
            else => error.UnknownRecordType,
        };
    }
};

pub const Flags = packed struct(u8) {
    fin: bool = false,
    reserved: u7 = 0,
};

pub const Record = struct {
    record_type: RecordType,
    fin: bool = false,
    stream_id: u64 = 0,
    app_error_code: u32 = 0,
    payload: []const u8 = &.{},

    /// 客户端只能发起 QUIC 语义下的 client-initiated bidi id：0、4、8……。
    pub fn isClientInitiated(self: Record) bool {
        return self.record_type != .ephemeral and self.stream_id & 0x03 == 0;
    }

    /// Gateway 主动推送使用 server-initiated bidi id：1、5、9……。
    pub fn isServerInitiated(self: Record) bool {
        return self.record_type != .ephemeral and self.stream_id & 0x03 == 1;
    }
};

pub const Error = error{
    Truncated,
    TrailingBytes,
    UnsupportedVersion,
    UnknownRecordType,
    ReservedBitsSet,
    PayloadTooLarge,
    InvalidStreamRecord,
    InvalidControlRecord,
    InvalidEphemeralRecord,
};

/// 把一条完整 WebSocket binary message 解成一条 record。
///
/// 函数不分配内存；返回的 payload 直接借用 `bytes`。一条 message 不允许拼接多条
/// record，避免半条成功、半条失败时出现含糊的处理边界。
pub fn decode(bytes: []const u8) Error!Record {
    if (bytes.len < header_size) return error.Truncated;
    if (bytes[0] != version) return error.UnsupportedVersion;
    const record_type = try RecordType.decode(bytes[1]);
    const flags: Flags = @bitCast(bytes[2]);
    if (flags.reserved != 0 or bytes[3] != 0) return error.ReservedBitsSet;

    const stream_id = std.mem.readInt(u64, bytes[4..12], .big);
    const app_error_code = std.mem.readInt(u32, bytes[12..16], .big);
    const payload_len: usize = std.mem.readInt(u32, bytes[16..20], .big);
    if (payload_len > max_payload_size) return error.PayloadTooLarge;
    const total = std.math.add(usize, header_size, payload_len) catch return error.PayloadTooLarge;
    if (bytes.len < total) return error.Truncated;
    if (bytes.len != total) return error.TrailingBytes;

    const record: Record = .{
        .record_type = record_type,
        .fin = flags.fin,
        .stream_id = stream_id,
        .app_error_code = app_error_code,
        .payload = bytes[header_size..total],
    };
    try validate(record);
    return record;
}

/// 写入固定头并返回整条 record 的目标切片。调用者提供 payload，因此无运行期分配。
pub fn encode(out: []u8, record: Record) Error![]u8 {
    var header: [header_size]u8 = undefined;
    try encodeHeader(&header, record);
    const total = header_size + record.payload.len;
    if (out.len < total) return error.Truncated;
    @memcpy(out[0..header_size], &header);
    @memcpy(out[header_size..total], record.payload);
    return out[0..total];
}

/// 只编码固定头，供有界环形队列直接分段拷贝，避免为一条最大 64KiB record 再准备
/// 一份同样大的临时连续缓冲。
pub fn encodeHeader(out: *[header_size]u8, record: Record) Error!void {
    try validate(record);
    if (record.payload.len > max_payload_size) return error.PayloadTooLarge;
    out[0] = version;
    out[1] = @intFromEnum(record.record_type);
    out[2] = @bitCast(Flags{ .fin = record.fin });
    out[3] = 0;
    std.mem.writeInt(u64, out[4..12], record.stream_id, .big);
    std.mem.writeInt(u32, out[12..16], record.app_error_code, .big);
    std.mem.writeInt(u32, out[16..20], @intCast(record.payload.len), .big);
}

pub fn validate(record: Record) Error!void {
    switch (record.record_type) {
        .stream => {
            if (record.app_error_code != 0) return error.InvalidStreamRecord;
        },
        .reset, .stop => {
            if (record.fin or record.payload.len != 0) return error.InvalidControlRecord;
        },
        .ephemeral => {
            if (record.fin or record.stream_id != 0 or record.app_error_code != 0) {
                return error.InvalidEphemeralRecord;
            }
        },
    }
}

test "envelope round trips every transport event" {
    const records = [_]Record{
        .{ .record_type = .stream, .stream_id = 4, .payload = "open" },
        .{ .record_type = .stream, .fin = true, .stream_id = 4, .payload = "data" },
        .{ .record_type = .reset, .stream_id = 8, .app_error_code = 17 },
        .{ .record_type = .stop, .stream_id = 12, .app_error_code = 23 },
        .{ .record_type = .ephemeral, .payload = "typing" },
    };
    var storage: [max_record_size]u8 = undefined;
    for (records) |record| {
        const encoded = try encode(&storage, record);
        const actual = try decode(encoded);
        try std.testing.expectEqual(record.record_type, actual.record_type);
        try std.testing.expectEqual(record.fin, actual.fin);
        try std.testing.expectEqual(record.stream_id, actual.stream_id);
        try std.testing.expectEqual(record.app_error_code, actual.app_error_code);
        try std.testing.expectEqualSlices(u8, record.payload, actual.payload);
    }
}

test "envelope preserves QUIC bidi direction numbering" {
    const client = Record{ .record_type = .stream, .stream_id = 8 };
    const server = Record{ .record_type = .stream, .stream_id = 9 };
    try std.testing.expect(client.isClientInitiated());
    try std.testing.expect(!client.isServerInitiated());
    try std.testing.expect(server.isServerInitiated());
    try std.testing.expect(!server.isClientInitiated());
}

test "envelope rejects ambiguous or non-canonical records" {
    var storage: [header_size + 4]u8 = undefined;
    const valid = try encode(&storage, .{ .record_type = .stream, .stream_id = 0, .payload = "x" });

    var bad = storage;
    bad[0] = version + 1;
    try std.testing.expectError(error.UnsupportedVersion, decode(bad[0..valid.len]));
    bad = storage;
    bad[2] = 0x80;
    try std.testing.expectError(error.ReservedBitsSet, decode(bad[0..valid.len]));
    try std.testing.expectError(error.TrailingBytes, decode(storage[0 .. valid.len + 1]));
    try std.testing.expectError(error.InvalidControlRecord, encode(&storage, .{
        .record_type = .reset,
        .fin = true,
        .stream_id = 4,
    }));
    try std.testing.expectError(error.InvalidEphemeralRecord, encode(&storage, .{
        .record_type = .ephemeral,
        .stream_id = 4,
    }));
}
