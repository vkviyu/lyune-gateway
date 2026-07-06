//! 编解码器
//!
//! 提供帧的完整编解码功能，包括帧边界检测、流式解析等。
//!
//! ## 使用场景
//!
//! - **FrameEncoder**：构建完整帧，用于发送
//! - **FrameDecoder**：从字节流中解析帧，支持增量解析（处理 TCP/QUIC 粘包）
//!
//! ## 示例
//!
//! ```zig
//! // 编码
//! var encoder = FrameEncoder.init(&buf);
//! const frame_data = try encoder.encode(.relay_buffered, RouteKey.DEFAULT, payload);
//!
//! // 解码（增量）
//! var decoder = FrameDecoder.init(allocator);
//! defer decoder.deinit();
//! while (try decoder.feed(incoming_data)) |frame| {
//!     processFrame(frame);
//! }
//! ```

const std = @import("std");
const frame = @import("frame.zig");

const FrameHeader = frame.FrameHeader;
const TransportMode = frame.TransportMode;
const ControlType = frame.ControlType;
const Flags = frame.Flags;
const HEADER_SIZE = frame.HEADER_SIZE;
const MAGIC = frame.MAGIC;

// ============================================================================
// 常量
// ============================================================================

/// 最大帧大小（16MB）
pub const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

/// 最大 Body 大小
pub const MAX_BODY_SIZE: u32 = MAX_FRAME_SIZE - HEADER_SIZE;

// ============================================================================
// 编码器
// ============================================================================

/// 帧编码器
///
/// 用于将消息编码为完整的帧数据。
pub const FrameEncoder = struct {
    buf: []u8,
    seq_counter: u32 = 0,

    pub fn init(buf: []u8) FrameEncoder {
        return .{ .buf = buf };
    }

    /// 编码完整帧
    ///
    /// @param mode 传输模式
    /// @param route_key 路由标识
    /// @param body 消息体
    /// @return 编码后的完整帧数据
    pub fn encode(
        self: *FrameEncoder,
        mode: TransportMode,
        route_key: u8,
        body: []const u8,
    ) ![]const u8 {
        return self.encodeWithFlags(mode, route_key, .{}, body);
    }

    /// 编码完整帧（带自定义标志）
    pub fn encodeWithFlags(
        self: *FrameEncoder,
        mode: TransportMode,
        route_key: u8,
        flags: Flags,
        body: []const u8,
    ) ![]const u8 {
        if (body.len > MAX_BODY_SIZE) return error.BodyTooLarge;

        const total_size = HEADER_SIZE + body.len;
        if (self.buf.len < total_size) return error.BufferTooSmall;

        // 构建帧头
        const header = FrameHeader{
            .mode = mode,
            .route_key = route_key,
            .flags = flags,
            .seq = self.nextSeq(),
            .body_len = @intCast(body.len),
        };

        // 写入帧头
        try header.encode(self.buf[0..HEADER_SIZE]);

        // 写入 Body
        if (body.len > 0) {
            @memcpy(self.buf[HEADER_SIZE..][0..body.len], body);
        }

        return self.buf[0..total_size];
    }

    /// 编码控制帧（无 Body）
    pub fn encodeControl(self: *FrameEncoder) ![]const u8 {
        return self.encodeWithFlags(.control, 0, .{}, &.{});
    }

    /// 编码流式首包
    pub fn encodeStreamStart(
        self: *FrameEncoder,
        route_key: u8,
        body: []const u8,
    ) ![]const u8 {
        return self.encodeWithFlags(.streaming, route_key, Flags.streamStart(), body);
    }

    /// 编码流式中间包
    pub fn encodeStreamMiddle(
        self: *FrameEncoder,
        route_key: u8,
        body: []const u8,
    ) ![]const u8 {
        return self.encodeWithFlags(.streaming, route_key, Flags.streamMiddle(), body);
    }

    /// 编码流式末包
    pub fn encodeStreamEnd(
        self: *FrameEncoder,
        route_key: u8,
        body: []const u8,
    ) ![]const u8 {
        return self.encodeWithFlags(.streaming, route_key, Flags.streamEnd(), body);
    }

    fn nextSeq(self: *FrameEncoder) u32 {
        const seq = self.seq_counter;
        self.seq_counter +%= 1;
        return seq;
    }

    // =========================================================================
    // 控制帧编码方法
    // =========================================================================

    /// 编码控制帧
    ///
    /// @param ctrl_type 控制帧类型
    /// @param body 消息体（可选）
    /// @return 编码后的完整帧数据
    pub fn encodeControlFrame(
        self: *FrameEncoder,
        ctrl_type: ControlType,
        body: []const u8,
    ) ![]const u8 {
        return self.encodeWithFlags(
            .control,
            @intFromEnum(ctrl_type),
            .{},
            body,
        );
    }

    /// 编码心跳请求
    pub fn encodeHeartbeat(self: *FrameEncoder) ![]const u8 {
        return self.encodeControlFrame(.heartbeat, &.{});
    }

    /// 编码心跳响应
    pub fn encodeHeartbeatAck(self: *FrameEncoder) ![]const u8 {
        return self.encodeControlFrame(.heartbeat_ack, &.{});
    }

    /// 编码 Ping 请求
    pub fn encodePing(self: *FrameEncoder, payload: []const u8) ![]const u8 {
        return self.encodeControlFrame(.ping, payload);
    }

    /// 编码 Pong 响应
    pub fn encodePong(self: *FrameEncoder, payload: []const u8) ![]const u8 {
        return self.encodeControlFrame(.pong, payload);
    }

    /// 编码认证请求（Client → Gateway）
    pub fn encodeAuthRequest(self: *FrameEncoder, token: []const u8) ![]const u8 {
        return self.encodeControlFrame(.auth_request, token);
    }

    /// 编码认证成功响应（Gateway → Client）
    pub fn encodeAuthSuccess(self: *FrameEncoder, user_info: []const u8) ![]const u8 {
        return self.encodeControlFrame(.auth_success, user_info);
    }

    /// 编码认证失败响应（Gateway → Client）
    pub fn encodeAuthFailure(self: *FrameEncoder, reason: []const u8) ![]const u8 {
        return self.encodeControlFrame(.auth_failure, reason);
    }

    /// 编码踢下线通知（Gateway → Client）
    pub fn encodeKickOff(self: *FrameEncoder, reason: []const u8) ![]const u8 {
        return self.encodeControlFrame(.kick_off, reason);
    }

    /// 编码客户端主动断开（Client → Gateway）
    pub fn encodeDisconnect(self: *FrameEncoder) ![]const u8 {
        return self.encodeControlFrame(.disconnect, &.{});
    }

    /// 编码强制关闭连接（Gateway → Client）
    pub fn encodeForceClose(self: *FrameEncoder, reason: []const u8) ![]const u8 {
        return self.encodeControlFrame(.force_close, reason);
    }

    /// 编码网关错误（Gateway → Client）
    pub fn encodeGatewayError(self: *FrameEncoder, error_info: []const u8) ![]const u8 {
        return self.encodeControlFrame(.gateway_error, error_info);
    }
};

// ============================================================================
// 解码器
// ============================================================================

/// 解码后的帧
pub const Frame = struct {
    header: FrameHeader,
    body: []const u8,
};

/// 帧解码器
///
/// 支持增量解析，处理数据流中的帧边界问题。
pub const FrameDecoder = struct {
    allocator: std.mem.Allocator,
    buffer: std.ArrayList(u8),
    state: State = .reading_header,
    current_header: ?FrameHeader = null,

    const State = enum {
        reading_header,
        reading_body,
    };

    pub fn init(allocator: std.mem.Allocator) FrameDecoder {
        return .{
            .allocator = allocator,
            .buffer = .{},
        };
    }

    pub fn deinit(self: *FrameDecoder) void {
        self.buffer.deinit(self.allocator);
    }

    /// 重置解码器状态
    pub fn reset(self: *FrameDecoder) void {
        self.buffer.clearRetainingCapacity();
        self.state = .reading_header;
        self.current_header = null;
    }

    /// 喂入数据，尝试解析帧
    ///
    /// @param data 新收到的数据
    /// @return 解析出的帧，或 null（数据不完整）
    pub fn feed(self: *FrameDecoder, data: []const u8) !?Frame {
        try self.buffer.appendSlice(self.allocator, data);
        return self.tryParse();
    }

    /// 尝试从缓冲区解析一个完整帧
    fn tryParse(self: *FrameDecoder) !?Frame {
        const buf = self.buffer.items;

        switch (self.state) {
            .reading_header => {
                if (buf.len < HEADER_SIZE) return null;

                const header = FrameHeader.decode(buf[0..HEADER_SIZE]) catch |err| {
                    // 解析失败，丢弃第一个字节，尝试重新同步
                    _ = self.buffer.orderedRemove(0);
                    return err;
                };

                // 验证 Body 大小
                if (header.body_len > MAX_BODY_SIZE) {
                    self.reset();
                    return error.BodyTooLarge;
                }

                self.current_header = header;
                self.state = .reading_body;

                // 立即尝试读取 Body
                return self.tryParse();
            },

            .reading_body => {
                const header = self.current_header orelse unreachable;
                const total_size = HEADER_SIZE + header.body_len;

                if (buf.len < total_size) return null;

                // 提取 Body
                const body = buf[HEADER_SIZE..total_size];

                // 构建 Frame
                const result = Frame{
                    .header = header,
                    .body = body,
                };

                // 移除已解析的数据
                // 注意：这里返回的 body 指向 buffer 内部，调用者需要在下次 feed 前处理完
                const remaining = buf[total_size..];
                @memcpy(self.buffer.items[0..remaining.len], remaining);
                self.buffer.shrinkRetainingCapacity(remaining.len);

                // 重置状态
                self.state = .reading_header;
                self.current_header = null;

                return result;
            },
        }
    }

    /// 获取缓冲区中待处理的数据量
    pub fn pending(self: *FrameDecoder) usize {
        return self.buffer.items.len;
    }
};

// ============================================================================
// 快捷函数
// ============================================================================

/// 快速解析帧头（不创建解码器）
pub fn parseHeader(data: []const u8) !FrameHeader {
    return FrameHeader.decode(data);
}

/// 检查数据是否以有效的帧魔数开头
pub fn startsWithMagic(data: []const u8) bool {
    if (data.len < 2) return false;
    const magic = std.mem.readInt(u16, data[0..2], .big);
    return magic == MAGIC;
}

// ============================================================================
// 测试
// ============================================================================

test "FrameEncoder basic encode" {
    var buf: [1024]u8 = undefined;
    var encoder = FrameEncoder.init(&buf);

    const payload = "Hello, World!";
    const frame_data = try encoder.encode(.relay_buffered, 0, payload);

    try std.testing.expectEqual(HEADER_SIZE + payload.len, frame_data.len);

    // 验证可以解码
    const header = try FrameHeader.decode(frame_data[0..HEADER_SIZE]);
    try std.testing.expectEqual(TransportMode.relay_buffered, header.mode);
    try std.testing.expectEqual(payload.len, header.body_len);
}

test "FrameDecoder incremental parse" {
    const allocator = std.testing.allocator;

    // 编码一个帧
    var encode_buf: [1024]u8 = undefined;
    var encoder = FrameEncoder.init(&encode_buf);
    const frame_data = try encoder.encode(.relay_buffered, 0, "Test");

    // 增量解码
    var decoder = FrameDecoder.init(allocator);
    defer decoder.deinit();

    // 分两次喂入数据
    const split_point = 10;
    _ = try decoder.feed(frame_data[0..split_point]);
    try std.testing.expectEqual(@as(?Frame, null), try decoder.feed(&.{}));

    const parsed = try decoder.feed(frame_data[split_point..]);
    try std.testing.expect(parsed != null);
    try std.testing.expectEqualStrings("Test", parsed.?.body);
}

test "FrameEncoder control frame encode/decode roundtrip" {
    const allocator = std.testing.allocator;
    var buf: [1024]u8 = undefined;
    var encoder = FrameEncoder.init(&buf);

    // 测试认证请求帧
    const token = "my-secret-token-123";
    const auth_frame = try encoder.encodeAuthRequest(token);

    var decoder = FrameDecoder.init(allocator);
    defer decoder.deinit();

    const parsed = try decoder.feed(auth_frame);
    try std.testing.expect(parsed != null);

    const header = parsed.?.header;
    try std.testing.expectEqual(TransportMode.control, header.mode);
    try std.testing.expectEqual(ControlType.auth_request, header.controlType().?);
    try std.testing.expectEqualStrings(token, parsed.?.body);
}

test "FrameEncoder heartbeat encode" {
    var buf: [1024]u8 = undefined;
    var encoder = FrameEncoder.init(&buf);

    // 心跳请求（无 body）
    const heartbeat_frame = try encoder.encodeHeartbeat();
    const header = try FrameHeader.decode(heartbeat_frame[0..HEADER_SIZE]);

    try std.testing.expectEqual(TransportMode.control, header.mode);
    try std.testing.expectEqual(ControlType.heartbeat, header.controlType().?);
    try std.testing.expectEqual(@as(u32, 0), header.body_len);

    // 心跳响应（无 body）
    const heartbeat_ack_frame = try encoder.encodeHeartbeatAck();
    const ack_header = try FrameHeader.decode(heartbeat_ack_frame[0..HEADER_SIZE]);

    try std.testing.expectEqual(ControlType.heartbeat_ack, ack_header.controlType().?);
}

test "FrameEncoder kick off encode" {
    var buf: [1024]u8 = undefined;
    var encoder = FrameEncoder.init(&buf);

    const reason = "duplicate_login";
    const kick_frame = try encoder.encodeKickOff(reason);
    const header = try FrameHeader.decode(kick_frame[0..HEADER_SIZE]);

    try std.testing.expectEqual(TransportMode.control, header.mode);
    try std.testing.expectEqual(ControlType.kick_off, header.controlType().?);
    try std.testing.expectEqual(@as(u32, reason.len), header.body_len);

    // 验证 body 内容
    try std.testing.expectEqualStrings(reason, kick_frame[HEADER_SIZE..]);
}

test "FrameEncoder all control frame types" {
    var buf: [1024]u8 = undefined;
    var encoder = FrameEncoder.init(&buf);

    // 测试所有控制帧编码方法都能正常工作
    _ = try encoder.encodeHeartbeat();
    _ = try encoder.encodeHeartbeatAck();
    _ = try encoder.encodePing("ping-payload");
    _ = try encoder.encodePong("pong-payload");
    _ = try encoder.encodeAuthRequest("token");
    _ = try encoder.encodeAuthSuccess("user-info");
    _ = try encoder.encodeAuthFailure("invalid token");
    _ = try encoder.encodeKickOff("reason");
    _ = try encoder.encodeDisconnect();
    _ = try encoder.encodeForceClose("error");
    _ = try encoder.encodeGatewayError("internal error");
}
