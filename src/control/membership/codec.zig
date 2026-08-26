//! gossip 消息编解码
//!
//! 线路格式（v1，全部大端）：
//! ```
//! ┌───────┬─────────┬──────┬────────────┬─────────┬────────────┬───────┬────────┐
//! │ magic │ version │ type │ sender     │ seq     │ target     │ count │ flags │ events │
//! │ 2B    │ 1B      │ 1B   │ 2B NodeId  │ 4B      │ 2B NodeId  │ 1B    │ 1B    │ 变长   │
//! └───────┴─────────┴──────┴────────────┴─────────┴────────────┴───────┴───────┴────────┘
//! ```
//! 每条 event（成员状态快照，搭载式 gossip 的最小单元）：
//! ```
//! ┌────────────┬────────┬─────────────┬────────┬────────────┬───────┐
//! │ node_id 2B │ 状态1B │ incarnation │ 族 1B  │ 地址 4/16B │ 端口2B│
//! │            │        │ 4B          │ (4|6)  │            │       │
//! └────────────┴────────┴─────────────┴────────┴────────────┴───────┘
//! ```
//! 解码是严格的：magic/version/类型/状态/地址族/长度任何一项不符都拒绝整条消息，
//! 且不允许尾部有多余字节。协议消息来自网络，必须按不可信输入对待。
//! v1 报文尾部追加 HMAC-SHA256 标签；发送只用 current secret，接收可回退 previous secret，
//! 以支持不中断轮换。重放检测属于 SWIM 状态机而非本 codec。

const std = @import("std");
const membership = @import("mod.zig");
const crypto = @import("crypto.zig");
const foundation = @import("../../foundation/mod.zig");
const net = foundation.net;

/// 魔数 "LM"（Lyune Membership），与 CID 魔数 "LY"、帧协议区分开。
pub const magic: u16 = 0x4c4d;
/// 首次发布的 membership 线路格式版本。
pub const version: u8 = 1;
/// 单条消息编码后的体积上限：控制在典型 MTU 内，避免 IP 分片。
pub const max_message_size: usize = 1400;
/// HMAC-SHA256 标签长度。
pub const auth_tag_size: usize = crypto.mac_size;
/// 认证消息的最小密钥长度，阻止误配空密钥或过短密钥。
pub const min_secret_size: usize = 16;
/// 单条消息允许搭载的 event 数上限（解码侧的硬边界，防恶意 count）。
pub const max_events: usize = 16;

/// 消息头固定长度：magic(2) + version(1) + type(1) + sender(2) + seq(4) + target(2) + count(1) + flags(1)。
pub const header_size: usize = 14;

/// 全量同步请求消息，不携带成员事件。
pub const sync_request_flag: u8 = 1 << 0;
/// 全量同步响应仍有后续分片。
pub const sync_more_flag: u8 = 1 << 1;
/// 单条 event 编码后的最大长度：node_id(2) + status(1) + incarnation(4) + family(1) + ip6(16) + port(2)。
pub const max_event_size: usize = 26;

/// 消息类型。
pub const MessageType = enum(u8) {
    /// 直接探测：期待对方回 ack（seq 原样带回）。
    ping = 1,
    /// 探测应答。sender 字段是 ack 的逻辑发出者（间接探测转发时不变）。
    ack = 2,
    /// 间接探测请求：请求接收方代替自己 ping target（SWIM 的 k 委托探测）。
    ping_req = 3,
    /// anti-entropy 全量视图请求或分片响应。
    sync = 4,
};

/// 一条成员状态事件：搭载式 gossip 传播的最小单元。
/// 自带地址，因此新成员可以完全通过 gossip 被集群学习到。
pub const Event = struct {
    node_id: membership.NodeId,
    status: membership.NodeStatus,
    incarnation: u32,
    address: net.Address,
};

/// 解码后的完整消息。events 用内联定长数组存储，无堆分配。
pub const Message = struct {
    type: MessageType,
    /// 消息的逻辑发送者。
    sender: membership.NodeId,
    /// 探测序号：ack 必须原样带回发起方 ping 的 seq，用于匹配在途探测。
    seq: u32,
    /// ping_req 的探测目标；sync 的会话目标；其余类型恒为 0。
    target: membership.NodeId = 0,
    /// anti-entropy 请求/响应及分片标志。
    flags: u8 = 0,
    events_buf: [max_events]Event = undefined,
    events_len: u8 = 0,

    /// 有效的搭载事件切片。
    pub fn events(self: *const Message) []const Event {
        return self.events_buf[0..self.events_len];
    }
};

/// 编码阶段的容量与事件数边界错误。
pub const EncodeError = error{ BufferTooSmall, TooManyEvents };

/// 严格解码与认证可能返回的协议错误。
pub const DecodeError = error{
    MessageTooShort,
    BadMagic,
    BadVersion,
    BadMessageType,
    BadStatus,
    BadAddressFamily,
    BadFlags,
    MissingAuthTag,
    InvalidAuthTag,
    SecretTooShort,
    TooManyEvents,
    /// 消息尾部存在未消费字节：视为损坏/伪造，整条拒绝。
    TrailingBytes,
};

/// 把消息头 + 搭载事件编码进 out 缓冲区，返回写入的切片。
/// out 至少给 max_message_size 即可容纳任何合法消息。
pub fn encode(
    message_type: MessageType,
    sender: membership.NodeId,
    seq: u32,
    target: membership.NodeId,
    events: []const Event,
    out: []u8,
) EncodeError![]u8 {
    return encodeWithFlags(message_type, sender, seq, target, events, out, 0);
}

/// 编码带 anti-entropy flags 的消息。
pub fn encodeWithFlags(
    message_type: MessageType,
    sender: membership.NodeId,
    seq: u32,
    target: membership.NodeId,
    events: []const Event,
    out: []u8,
    flags: u8,
) EncodeError![]u8 {
    if (events.len > max_events) return error.TooManyEvents;
    if (out.len < header_size + events.len * max_event_size) return error.BufferTooSmall;

    std.mem.writeInt(u16, out[0..2], magic, .big);
    out[2] = version;
    out[3] = @intFromEnum(message_type);
    std.mem.writeInt(u16, out[4..6], sender, .big);
    std.mem.writeInt(u32, out[6..10], seq, .big);
    std.mem.writeInt(u16, out[10..12], target, .big);
    out[12] = @intCast(events.len);
    out[13] = flags;

    var offset: usize = header_size;
    for (events) |event| {
        std.mem.writeInt(u16, out[offset..][0..2], event.node_id, .big);
        out[offset + 2] = @intFromEnum(event.status);
        std.mem.writeInt(u32, out[offset + 3 ..][0..4], event.incarnation, .big);
        offset += 7;
        switch (event.address) {
            .ip4 => |ip4| {
                out[offset] = 4;
                @memcpy(out[offset + 1 ..][0..4], &ip4.bytes);
                std.mem.writeInt(u16, out[offset + 5 ..][0..2], ip4.port, .big);
                offset += 7;
            },
            .ip6 => |ip6| {
                out[offset] = 6;
                @memcpy(out[offset + 1 ..][0..16], &ip6.bytes);
                std.mem.writeInt(u16, out[offset + 17 ..][0..2], ip6.port, .big);
                offset += 19;
            },
        }
    }
    return out[0..offset];
}

/// 使用预共享密钥编码消息。认证标签追加在完整 v1 报文之后。
pub fn encodeAuthenticated(
    message_type: MessageType,
    sender: membership.NodeId,
    seq: u32,
    target: membership.NodeId,
    events: []const Event,
    out: []u8,
    secret: []const u8,
) (EncodeError || error{SecretTooShort})![]u8 {
    return encodeAuthenticatedWithFlags(message_type, sender, seq, target, events, out, secret, 0);
}

/// 使用预共享密钥编码带 flags 的消息。
pub fn encodeAuthenticatedWithFlags(
    message_type: MessageType,
    sender: membership.NodeId,
    seq: u32,
    target: membership.NodeId,
    events: []const Event,
    out: []u8,
    secret: []const u8,
    flags: u8,
) (EncodeError || error{SecretTooShort})![]u8 {
    if (secret.len < min_secret_size) return error.SecretTooShort;
    if (out.len < auth_tag_size) return error.BufferTooSmall;
    const payload = try encodeWithFlags(message_type, sender, seq, target, events, out[0 .. out.len - auth_tag_size], flags);
    const tag = crypto.mac(secret, payload);
    @memcpy(out[payload.len..][0..auth_tag_size], &tag);
    return out[0 .. payload.len + auth_tag_size];
}

/// 严格解码一条消息。任何格式异常都返回错误，调用方应丢弃并计数。
pub fn decode(bytes: []const u8) DecodeError!Message {
    if (bytes.len < header_size) return error.MessageTooShort;
    if (std.mem.readInt(u16, bytes[0..2], .big) != magic) return error.BadMagic;
    if (bytes[2] != version) return error.BadVersion;

    var message: Message = .{
        .type = std.enums.fromInt(MessageType, bytes[3]) orelse return error.BadMessageType,
        .sender = std.mem.readInt(u16, bytes[4..6], .big),
        .seq = std.mem.readInt(u32, bytes[6..10], .big),
        .target = std.mem.readInt(u16, bytes[10..12], .big),
        .flags = bytes[13],
    };
    if (message.flags & ~(sync_request_flag | sync_more_flag) != 0) return error.BadFlags;
    const event_count = bytes[12];
    if (event_count > max_events) return error.TooManyEvents;

    var offset: usize = header_size;
    for (0..event_count) |index| {
        // 每个 event 前 7 字节定长，之后按地址族变长。
        if (bytes.len < offset + 8) return error.MessageTooShort;
        const node_id = std.mem.readInt(u16, bytes[offset..][0..2], .big);
        const status = std.enums.fromInt(membership.NodeStatus, bytes[offset + 2]) orelse return error.BadStatus;
        const incarnation = std.mem.readInt(u32, bytes[offset + 3 ..][0..4], .big);
        const family = bytes[offset + 7];
        offset += 8;

        const address: net.Address = switch (family) {
            4 => blk: {
                if (bytes.len < offset + 6) return error.MessageTooShort;
                const addr = net.initIp4(
                    bytes[offset..][0..4].*,
                    std.mem.readInt(u16, bytes[offset + 4 ..][0..2], .big),
                );
                offset += 6;
                break :blk addr;
            },
            6 => blk: {
                if (bytes.len < offset + 18) return error.MessageTooShort;
                const addr = net.initIp6(
                    bytes[offset..][0..16].*,
                    std.mem.readInt(u16, bytes[offset + 16 ..][0..2], .big),
                );
                offset += 18;
                break :blk addr;
            },
            else => return error.BadAddressFamily,
        };

        message.events_buf[index] = .{
            .node_id = node_id,
            .status = status,
            .incarnation = incarnation,
            .address = address,
        };
        message.events_len += 1;
    }

    if (offset != bytes.len) return error.TrailingBytes;
    return message;
}

/// 校验并解码带 HMAC-SHA256 标签的消息。
pub fn decodeAuthenticated(bytes: []const u8, secret: []const u8) (DecodeError || error{SecretTooShort})!Message {
    if (secret.len < min_secret_size) return error.SecretTooShort;
    if (bytes.len <= auth_tag_size) return error.MissingAuthTag;
    const payload_len = bytes.len - auth_tag_size;
    const expected: *const [auth_tag_size]u8 = @ptrCast(bytes[payload_len..].ptr);
    if (!crypto.verify(secret, bytes[0..payload_len], expected)) return error.InvalidAuthTag;
    return decode(bytes[0..payload_len]);
}

/// 使用 current/previous 双密钥验证，支持不中断服务的预共享密钥轮换。
pub fn decodeAuthenticatedWithFallback(bytes: []const u8, current: []const u8, previous: []const u8) (DecodeError || error{SecretTooShort})!Message {
    return decodeAuthenticated(bytes, current) catch |err| switch (err) {
        error.InvalidAuthTag => if (previous.len == 0) error.InvalidAuthTag else decodeAuthenticated(bytes, previous),
        else => err,
    };
}

test "encode/decode roundtrip with mixed address families" {
    const events = [_]Event{
        .{ .node_id = 7, .status = .alive, .incarnation = 3, .address = net.initIp4(.{ 10, 0, 0, 7 }, 7946) },
        .{ .node_id = 9, .status = .suspect, .incarnation = 1, .address = net.initIp6(.{0xfd} ++ .{0} ** 14 ++ .{9}, 7947) },
    };
    var buf: [max_message_size]u8 = undefined;
    const encoded = try encode(.ping_req, 42, 12345, 9, &events, &buf);
    const decoded = try decode(encoded);

    try std.testing.expectEqual(MessageType.ping_req, decoded.type);
    try std.testing.expectEqual(@as(membership.NodeId, 42), decoded.sender);
    try std.testing.expectEqual(@as(u32, 12345), decoded.seq);
    try std.testing.expectEqual(@as(membership.NodeId, 9), decoded.target);
    try std.testing.expectEqual(@as(usize, 2), decoded.events().len);
    try std.testing.expectEqual(membership.NodeStatus.suspect, decoded.events()[1].status);
    try std.testing.expect(std.meta.eql(events[0].address, decoded.events()[0].address));
    try std.testing.expect(std.meta.eql(events[1].address, decoded.events()[1].address));
}

test "decode rejects malformed inputs" {
    var buf: [max_message_size]u8 = undefined;
    const encoded = try encode(.ping, 1, 1, 0, &.{}, &buf);

    // 逐类破坏：魔数、版本、类型、截断、尾部脏字节。
    var bad = buf;
    bad[0] ^= 0xff;
    try std.testing.expectError(error.BadMagic, decode(bad[0..encoded.len]));

    bad = buf;
    bad[2] = version + 1;
    try std.testing.expectError(error.BadVersion, decode(bad[0..encoded.len]));

    bad = buf;
    bad[3] = 0xee;
    try std.testing.expectError(error.BadMessageType, decode(bad[0..encoded.len]));

    try std.testing.expectError(error.MessageTooShort, decode(encoded[0 .. header_size - 1]));
    try std.testing.expectError(error.TrailingBytes, decode(buf[0 .. encoded.len + 1]));
}

test "authenticated messages reject tampering, wrong keys, and missing tags" {
    const secret = "0123456789abcdef";
    var buf: [max_message_size]u8 = undefined;
    const encoded = try encodeAuthenticated(.ping, 1, 7, 0, &.{}, &buf, secret);
    _ = try decodeAuthenticated(encoded, secret);

    var tampered = buf;
    tampered[6] ^= 1;
    try std.testing.expectError(error.InvalidAuthTag, decodeAuthenticated(tampered[0..encoded.len], secret));
    try std.testing.expectError(error.InvalidAuthTag, decodeAuthenticated(encoded, "fedcba9876543210"));
    _ = try decodeAuthenticatedWithFallback(encoded, "fedcba9876543210", secret);
    try std.testing.expectError(error.MissingAuthTag, decodeAuthenticated(encoded[0..header_size], secret));
    try std.testing.expectError(error.SecretTooShort, encodeAuthenticated(.ping, 1, 1, 0, &.{}, &buf, "short"));
}

test "decode never crashes on random bytes (fuzz)" {
    // 确定性 fuzz：解码器面对任意字节流只允许返回错误，绝不允许崩溃/越界。
    var prng = std.Random.DefaultPrng.init(0xdead_beef);
    const random = prng.random();
    var buf: [256]u8 = undefined;
    for (0..20_000) |_| {
        const len = random.intRangeAtMost(usize, 0, buf.len);
        random.bytes(buf[0..len]);
        _ = decode(buf[0..len]) catch continue;
    }
}
