//! 不可靠通路的 datagram 编解码（设计文档 §6）
//!
//! 面向多人游戏的状态同步。可靠有序流会因队头阻塞产生延迟尖刺：丢一个包，后面
//! 已到达的状态也得等重传。QUIC DATAGRAM（RFC 9221）没有这个问题。
//!
//! ## 为什么单独一个文件而不并进 codec.zig
//!
//! datagram **不经过分帧路径**，两条路径的前提完全不同：
//!
//! - 流上的字节需要重组：一次回调可能带来半帧，因此有 `body_len`、残帧缓冲、
//!   `drainFrames` 那一整套。
//! - datagram 本身就是完整单元：QUIC 直接给出长度，不会跨回调被切开，因此
//!   **没有 `body_len`**（长度就是 `data.len - 2`），也没有残帧状态。
//!
//! 混进 codec.zig 就得在每个分帧入口判一次"这是不是 datagram"，而
//! `FrameHeader.encode/decode` 反过来必须拒绝 datagram（`error.DatagramOnStream`）
//! ——两套规则彼此排斥，放在一起只会让两边都要读另一边的注释才敢改。
//!
//! ## 2 字节头
//!
//! ```
//! 偏移  长度  字段
//! 0     1     frame_type = 0x02 (DATAGRAM)
//! 1     1     channel
//! ```
//!
//! 20 字节负载的开销从旧协议的 16 字节（44%）降到 2 字节（9%）。
//!
//! 保留 `frame_type` 而不是直接用 1 字节通道号，是为了让 datagram 与流帧共享
//! 同一个类型空间：将来要在不可靠通路上加第二种形态（例如带序号的状态帧），
//! 判据仍然是第一个字节，而不是"看它从哪个 API 进来的"。

const std = @import("std");

const frame = @import("frame.zig");
const FrameError = frame.FrameError;

/// 头长度：`frame_type` + `channel`。
pub const header_size: usize = frame.DATAGRAM_HEADER_SIZE;

/// 一条连接上可绑定的通道数上限。
///
/// 通道表是每连接一份的定长数组，所以这个数直接乘在连接数上。取 8 是因为通道的
/// 用途是"这条连接参与的实时会话"——一个玩家同时在几个房间里做状态同步，个位数
/// 就够；而它同时也是通道号的取值上限，超出即畸形。
pub const max_channels: usize = 8;

/// 一个解出来的 datagram。
pub const Datagram = struct {
    channel: u8,
    /// 状态负载。**指向调用方的缓冲**，不拷贝——热路径上零拷贝的前提。
    payload: []const u8,
};

/// 解析一个收到的 datagram。
///
/// 三种拒绝都归为畸形，调用方应当丢弃并计数，**不要**因此关闭连接：不可靠通路上
/// 一个坏包不代表对端的编码器坏了（它可能是被中间设备截断的），而关连接会把一次
/// 丢包放大成一次掉线。
pub fn decode(bytes: []const u8) FrameError!Datagram {
    if (bytes.len < header_size) return error.BufferTooSmall;
    if (bytes[0] != @intFromEnum(frame.FrameType.datagram)) return error.UnknownFrameType;
    const channel = bytes[1];
    if (channel >= max_channels) return error.InvalidChannel;
    return .{ .channel = channel, .payload = bytes[header_size..] };
}

/// 编码一个 datagram 到 `buf`，返回可直接交给 QUIC 的那一段。
pub fn encode(buf: []u8, channel: u8, payload: []const u8) FrameError![]const u8 {
    if (channel >= max_channels) return error.InvalidChannel;
    if (buf.len < header_size + payload.len) return error.BufferTooSmall;
    buf[0] = @intFromEnum(frame.FrameType.datagram);
    buf[1] = channel;
    @memcpy(buf[header_size..][0..payload.len], payload);
    return buf[0 .. header_size + payload.len];
}

// ============================================================================
// 测试
// ============================================================================

test "a datagram roundtrips and keeps its payload borrowed" {
    var buf: [64]u8 = undefined;
    const encoded = try encode(&buf, 3, "state");

    try std.testing.expectEqual(@as(usize, header_size + 5), encoded.len);
    try std.testing.expectEqual(@intFromEnum(frame.FrameType.datagram), encoded[0]);

    const parsed = try decode(encoded);
    try std.testing.expectEqual(@as(u8, 3), parsed.channel);
    try std.testing.expectEqualStrings("state", parsed.payload);
    // 零拷贝：解出来的负载就指向输入缓冲里那一段。
    try std.testing.expect(parsed.payload.ptr == encoded.ptr + header_size);
}

test "an empty payload is legal" {
    // 一个只有头的 datagram 是合法的：它可以当作"我还活着"的最廉价形态。
    var buf: [8]u8 = undefined;
    const encoded = try encode(&buf, 0, "");
    const parsed = try decode(encoded);
    try std.testing.expectEqual(@as(usize, 0), parsed.payload.len);
}

test "a malformed datagram is rejected rather than reinterpreted" {
    // 短于头长。
    try std.testing.expectError(error.BufferTooSmall, decode(&[_]u8{0x02}));
    // 类型字节不是 DATAGRAM——很可能是有人把流帧塞进了不可靠通路。
    try std.testing.expectError(error.UnknownFrameType, decode(&[_]u8{ 0x00, 0x01 }));
    // 通道号越界。这一道必须在解码期做：它决定了后面能不能直接用它当数组下标。
    try std.testing.expectError(error.InvalidChannel, decode(&[_]u8{ 0x02, @intCast(max_channels) }));
    var out: [8]u8 = undefined;
    try std.testing.expectError(error.InvalidChannel, encode(&out, @intCast(max_channels), ""));
}

test "encode refuses a payload that does not fit" {
    var buf: [4]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, encode(&buf, 1, "too long"));
}
