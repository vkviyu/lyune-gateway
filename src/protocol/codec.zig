//! 编解码器
//!
//! 提供帧的完整编解码功能，包括帧边界检测、就地逐帧扫描等。
//!
//! ## 使用场景
//!
//! - **FrameEncoder**：构建完整帧，用于发送
//! - **FrameScanner**：在一段字节上就地逐帧推进，处理 QUIC 一次回调里
//!   多帧/半帧混在一起的情况；不分配、不拷贝
//! - **parseExactFrame**：缓冲里确知只有一帧时的快捷校验
//!
//! ## 示例
//!
//! ```zig
//! // 一次性交换：一个带 eof 的 OPEN 就是全部
//! var encoder = FrameEncoder.init(&buf);
//! const once = try encoder.encodeOpen(.service, route, .required, Flags.last(), payload);
//!
//! // 流式交换：OPEN + N × DATA，末帧带 eof
//! const head = try encoder.encodeOpen(.service, route, .required, .{}, first_chunk);
//! const tail = try encoder.encodeData(Flags.last(), last_chunk);
//!
//! // 就地扫描（零拷贝）
//! var scanner = FrameScanner{ .data = incoming };
//! while (try scanner.next()) |f| processFrame(f);
//! const leftover = scanner.remainder(); // 不足一帧的尾部，由调用方暂存
//! ```

const std = @import("std");
const frame = @import("frame.zig");

const FrameHeader = frame.FrameHeader;
const FrameType = frame.FrameType;
const DestKind = frame.DestKind;
const ControlType = frame.ControlType;
const RouteId = frame.RouteId;
const Flags = frame.Flags;
const ResponseMode = frame.ResponseMode;

// ============================================================================
// 常量
// ============================================================================

/// 单帧总长上限（帧头 + Body）。
pub const MAX_FRAME_SIZE: usize = frame.MAX_FRAME_SIZE;

/// 单帧 Body 上限。
pub const MAX_BODY_SIZE: usize = frame.MAX_BODY_SIZE;

// ============================================================================
// 编码器
// ============================================================================

/// 帧编码器
///
/// 把帧头与 Body 拼进调用方给的缓冲，返回其中的完整帧切片。不持有内存、
/// 不跨调用保留状态——每次编码都覆盖同一段缓冲，返回的切片在下一次编码前有效。
pub const FrameEncoder = struct {
    buf: []u8,

    pub fn init(buf: []u8) FrameEncoder {
        return .{ .buf = buf };
    }

    /// 编码一次交换的首帧（OPEN）。
    pub fn encodeOpen(
        self: *FrameEncoder,
        dest_kind: DestKind,
        route: RouteId,
        response_mode: ResponseMode,
        flags: Flags,
        body: []const u8,
    ) frame.FrameError![]const u8 {
        if (body.len > MAX_BODY_SIZE) return error.BodyTooLarge;
        return self.write(FrameHeader.initOpen(dest_kind, route, response_mode, flags, @intCast(body.len)), body);
    }

    /// 编码同一次交换的后续帧（DATA）。
    pub fn encodeData(
        self: *FrameEncoder,
        flags: Flags,
        body: []const u8,
    ) frame.FrameError![]const u8 {
        if (body.len > MAX_BODY_SIZE) return error.BodyTooLarge;
        return self.write(FrameHeader.initData(flags, @intCast(body.len)), body);
    }

    fn write(self: *FrameEncoder, header: FrameHeader, body: []const u8) frame.FrameError![]const u8 {
        const header_size = try header.encode(self.buf);
        const total = header_size + body.len;
        if (self.buf.len < total) return error.BufferTooSmall;
        if (body.len > 0) {
            @memcpy(self.buf[header_size..][0..body.len], body);
        }
        return self.buf[0..total];
    }

    // =========================================================================
    // 控制帧编码方法
    // =========================================================================

    /// 编码一个与网关的控制交换。
    ///
    /// 控制交换目前都是一次性的，所以是单个带 `eof` 的 OPEN 帧。
    pub fn encodeControlFrame(
        self: *FrameEncoder,
        ctrl_type: ControlType,
        body: []const u8,
    ) frame.FrameError![]const u8 {
        return self.encodeOpen(.gateway, RouteId.init(0, @intFromEnum(ctrl_type)), .none, Flags.last(), body);
    }

    /// 编码心跳请求
    pub fn encodeHeartbeat(self: *FrameEncoder) frame.FrameError![]const u8 {
        return self.encodeControlFrame(.heartbeat, &.{});
    }

    /// 编码心跳响应
    pub fn encodeHeartbeatAck(self: *FrameEncoder) frame.FrameError![]const u8 {
        return self.encodeControlFrame(.heartbeat_ack, &.{});
    }

    /// 编码 Ping 请求
    pub fn encodePing(self: *FrameEncoder, payload: []const u8) frame.FrameError![]const u8 {
        return self.encodeControlFrame(.ping, payload);
    }

    /// 编码 Pong 响应
    pub fn encodePong(self: *FrameEncoder, payload: []const u8) frame.FrameError![]const u8 {
        return self.encodeControlFrame(.pong, payload);
    }

    /// 编码认证请求（Client → Gateway）
    pub fn encodeAuthRequest(self: *FrameEncoder, token: []const u8) frame.FrameError![]const u8 {
        return self.encodeControlFrame(.auth_request, token);
    }

    /// 编码认证成功响应（认证服务 → 网关 → 客户端）
    ///
    /// body 必须以 `body.AuthGrant` 的 12 字节前缀开头（设计文档 §10.3）：网关要从
    /// 里面读 `dest_id` 与 TTL。前缀之后可以跟任意不透明数据，网关不解析，原样透传。
    pub fn encodeAuthSuccess(self: *FrameEncoder, granted_body: []const u8) frame.FrameError![]const u8 {
        return self.encodeControlFrame(.auth_success, granted_body);
    }

    /// 编码认证失败响应（Gateway → Client）
    pub fn encodeAuthFailure(self: *FrameEncoder, reason: []const u8) frame.FrameError![]const u8 {
        return self.encodeControlFrame(.auth_failure, reason);
    }

    /// 编码踢下线通知（Gateway → Client）
    pub fn encodeKickOff(self: *FrameEncoder, reason: []const u8) frame.FrameError![]const u8 {
        return self.encodeControlFrame(.kick_off, reason);
    }

    /// 编码客户端主动断开（Client → Gateway）
    pub fn encodeDisconnect(self: *FrameEncoder) frame.FrameError![]const u8 {
        return self.encodeControlFrame(.disconnect, &.{});
    }

    /// 编码强制关闭连接（Gateway → Client）
    pub fn encodeForceClose(self: *FrameEncoder, reason: []const u8) frame.FrameError![]const u8 {
        return self.encodeControlFrame(.force_close, reason);
    }

    /// 编码重定向（Gateway → Client）
    ///
    /// body 必须是 `body.RedirectHint` 的编码形态。这一帧发出之后网关会立刻关闭连接
    /// ——重定向是强制的，不是建议（理由见设计文档 §8.5 策略 B）。
    pub fn encodeRedirect(self: *FrameEncoder, hint_body: []const u8) frame.FrameError![]const u8 {
        return self.encodeControlFrame(.redirect, hint_body);
    }

    /// 编码组播加组（Backend → Gateway）
    ///
    /// body 必须是 `body.GroupBinding` 的编码形态。网关自己不产生它，这个方向给
    /// 测试与后端 SDK 用。
    pub fn encodeJoinGroup(self: *FrameEncoder, binding_body: []const u8) frame.FrameError![]const u8 {
        return self.encodeControlFrame(.join_group, binding_body);
    }

    /// 编码组播退组（Backend → Gateway）
    pub fn encodeLeaveGroup(self: *FrameEncoder, binding_body: []const u8) frame.FrameError![]const u8 {
        return self.encodeControlFrame(.leave_group, binding_body);
    }

    /// 编码网关错误（Gateway → Client）
    pub fn encodeGatewayError(self: *FrameEncoder, error_info: []const u8) frame.FrameError![]const u8 {
        return self.encodeControlFrame(.gateway_error, error_info);
    }
};

// ============================================================================
// 解码器
// ============================================================================

/// 解码后的帧视图。
///
/// 三个字段都是对输入缓冲的借用，不拥有内存：`bytes` 是完整帧（帧头 + Body），
/// 网关转发时按原样透传；`body` 是其中的 Body 部分，本地处理控制帧时用。
pub const Frame = struct {
    header: FrameHeader,
    body: []const u8,
    bytes: []const u8,
};

/// 就地帧扫描器
///
/// 在一段连续字节上逐帧推进。不持有内存、不分配、不拷贝：解出的 Frame
/// 指向输入切片内部，只在输入仍然有效期间可用。
///
/// QUIC 只保证流内字节有序，一次回调可能带来多帧、半帧或几帧加半帧，
/// 因此扫描到不足一帧时返回 null，并把尾部通过 `remainder()` 交还调用方。
pub const FrameScanner = struct {
    data: []const u8,
    offset: usize = 0,
    /// 单帧允许的最大总长度（帧头 + Body）。
    ///
    /// 在帧头刚解出时就据此拒绝，而不是等字节真的攒到那么多——否则一个声明了
    /// 超大 Body 的帧头就能让网关为它预留缓冲。
    max_frame_size: usize = MAX_FRAME_SIZE,

    /// 取下一个完整帧；剩余字节不足一帧时返回 null。
    ///
    /// 只要拿到第一个字节就先校验 `frame_type`：帧头是变长的，不先定型连"还差
    /// 多少字节"都算不出来。这也让未定义的帧类型在第一个字节上就被拒绝，
    /// 而不是等整个帧头到齐。
    ///
    /// 解析失败一律返回错误，不做任何重同步。旧协议靠魔数重找边界，那反而
    /// 给了帧走私的机会——Body 里的任意字节都可能被当成下一帧的起点。
    /// 字节流一旦失去边界就不可信，调用方应当关闭整条连接（见设计文档 §7.5）。
    pub fn next(self: *FrameScanner) frame.FrameError!?Frame {
        const rest = self.data[self.offset..];
        if (rest.len == 0) return null;

        const frame_type = try FrameType.decode(rest[0]);
        if (frame_type == .datagram) return error.DatagramOnStream;

        const header_size = frame_type.headerSize();
        if (rest.len < header_size) return null;

        const header = try FrameHeader.decode(rest[0..header_size]);
        const total = header.frameSize();
        if (total > self.max_frame_size) return error.FrameTooLarge;
        if (rest.len < total) return null;

        self.offset += total;
        return .{
            .header = header,
            .body = rest[header_size..total],
            .bytes = rest[0..total],
        };
    }

    /// 尚未构成完整帧的尾部字节。
    pub fn remainder(self: FrameScanner) []const u8 {
        return self.data[self.offset..];
    }
};

// ============================================================================
// 快捷函数
// ============================================================================

/// 快速解析帧头（不创建扫描器）。
///
/// 帧头变长，`data` 必须至少覆盖完整帧头，否则返回 `BufferTooSmall`。
pub fn parseHeader(data: []const u8) frame.FrameError!FrameHeader {
    return FrameHeader.decode(data);
}

/// 解析恰好包含一个完整帧的缓冲区，零拷贝返回帧视图。
///
/// 尾随任何多余字节都会被拒绝。调用方按帧头选路并做鉴权，随后把整段缓冲
/// 原样转给后端；若允许尾随字节，对端就能在合法帧后追加第二帧，
/// 让它以第一帧的路由与授权身份被执行。
///
/// 需要处理"一段字节里有多帧或半帧"时用 FrameScanner，本函数只适用于
/// 调用方已确知缓冲里恰好一帧的场景（例如后端返回的认证响应）。
pub fn parseExactFrame(data: []const u8) frame.FrameError!Frame {
    const header = try FrameHeader.decode(data);
    const total = header.frameSize();
    if (data.len != total) return error.FrameLengthMismatch;
    return .{ .header = header, .body = data[header.headerSize()..], .bytes = data };
}

// ============================================================================
// 测试
// ============================================================================

const OPEN_HEADER_SIZE = frame.OPEN_HEADER_SIZE;
const DATA_HEADER_SIZE = frame.DATA_HEADER_SIZE;

test "FrameEncoder emits an OPEN frame that decodes back" {
    var buf: [1024]u8 = undefined;
    var encoder = FrameEncoder.init(&buf);

    const payload = "Hello, World!";
    const frame_data = try encoder.encodeOpen(.service, RouteId.init(0x01, 0), .required, Flags.last(), payload);

    try std.testing.expectEqual(OPEN_HEADER_SIZE + payload.len, frame_data.len);

    const parsed = try parseExactFrame(frame_data);
    try std.testing.expectEqual(DestKind.service, parsed.header.dest_kind);
    try std.testing.expectEqual(RouteId.init(0x01, 0), parsed.header.routeId().?);
    try std.testing.expect(parsed.header.isLast());
    try std.testing.expectEqualStrings(payload, parsed.body);
}

test "FrameEncoder emits a DATA frame with the short header" {
    var buf: [1024]u8 = undefined;
    var encoder = FrameEncoder.init(&buf);

    const frame_data = try encoder.encodeData(.{}, "chunk");
    // DATA 不重复声明目的地，所以比 OPEN 少 4 个字节——流式交换里每一帧都省这 4 字节。
    try std.testing.expectEqual(DATA_HEADER_SIZE + "chunk".len, frame_data.len);

    const parsed = try parseExactFrame(frame_data);
    try std.testing.expectEqual(FrameType.data, parsed.header.frame_type);
    try std.testing.expectEqualStrings("chunk", parsed.body);
}

test "FrameScanner yields every whole frame and keeps the trailing partial" {
    var stream: [1024]u8 = undefined;
    var encode_buf: [512]u8 = undefined;
    var encoder = FrameEncoder.init(&encode_buf);

    const first = try encoder.encodeOpen(.service, RouteId.init(0x01, 0), .required, .{}, "one");
    const first_len = first.len;
    @memcpy(stream[0..first_len], first);

    const second = try encoder.encodeData(.{}, "second-body");
    const second_len = second.len;
    @memcpy(stream[first_len..][0..second_len], second);

    // 尾部再放半个帧头，模拟一次回调里"两帧 + 半帧"。
    const total = first_len + second_len;
    const partial_len = DATA_HEADER_SIZE - 1;
    @memcpy(stream[total..][0..partial_len], second[0..partial_len]);

    var scanner = FrameScanner{ .data = stream[0 .. total + partial_len] };

    const frame_one = (try scanner.next()).?;
    try std.testing.expectEqualStrings("one", frame_one.body);
    try std.testing.expectEqual(first_len, frame_one.bytes.len);
    try std.testing.expectEqual(FrameType.open, frame_one.header.frame_type);

    const frame_two = (try scanner.next()).?;
    try std.testing.expectEqualStrings("second-body", frame_two.body);
    try std.testing.expectEqual(FrameType.data, frame_two.header.frame_type);

    try std.testing.expectEqual(@as(?Frame, null), try scanner.next());
    try std.testing.expectEqual(@as(usize, partial_len), scanner.remainder().len);
}

test "FrameScanner rejects a malformed header instead of resyncing" {
    // 帧走私防线：解析失败必须报错，不能跳过垃圾字节继续找边界，
    // 否则 Body 里的任意字节都可能被当成下一帧的起点。
    var garbage: [16]u8 = @splat(0xAB);
    var scanner = FrameScanner{ .data = &garbage };
    try std.testing.expectError(error.UnknownFrameType, scanner.next());
}

test "FrameScanner rejects an unknown frame type from the very first byte" {
    // 变长帧头的一个附带收益：不必等帧头到齐就能判违规。
    var one_byte = [_]u8{0x55};
    var scanner = FrameScanner{ .data = &one_byte };
    try std.testing.expectError(error.UnknownFrameType, scanner.next());
}

test "FrameScanner needs a full header before deciding" {
    var buf: [1024]u8 = undefined;
    var encoder = FrameEncoder.init(&buf);
    const frame_data = try encoder.encodeOpen(.service, RouteId.init(0x01, 0), .required, Flags.last(), "Test");

    var scanner = FrameScanner{ .data = frame_data[0 .. OPEN_HEADER_SIZE - 1] };
    try std.testing.expectEqual(@as(?Frame, null), try scanner.next());
    try std.testing.expectEqual(OPEN_HEADER_SIZE - 1, scanner.remainder().len);
}

test "FrameEncoder control frame encode/decode roundtrip" {
    var buf: [1024]u8 = undefined;
    var encoder = FrameEncoder.init(&buf);

    const token = "my-secret-token-123";
    const auth_frame = try encoder.encodeAuthRequest(token);

    const parsed = try parseExactFrame(auth_frame);

    try std.testing.expectEqual(DestKind.gateway, parsed.header.dest_kind);
    try std.testing.expectEqual(ControlType.auth_request, parsed.header.controlType().?);
    try std.testing.expectEqualStrings(token, parsed.body);
    try std.testing.expectEqual(auth_frame.len, parsed.bytes.len);
}

test "parseExactFrame rejects trailing bytes" {
    var buf: [1024]u8 = undefined;
    var encoder = FrameEncoder.init(&buf);
    const heartbeat = try encoder.encodeHeartbeat();

    var padded: [64]u8 = undefined;
    @memcpy(padded[0..heartbeat.len], heartbeat);
    padded[heartbeat.len] = 0x00;

    try std.testing.expectError(error.FrameLengthMismatch, parseExactFrame(padded[0 .. heartbeat.len + 1]));
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

test "FrameEncoder refuses a body that does not fit the buffer" {
    var buf: [OPEN_HEADER_SIZE + 2]u8 = undefined;
    var encoder = FrameEncoder.init(&buf);
    try std.testing.expectError(
        error.BufferTooSmall,
        encoder.encodeOpen(.service, RouteId.init(1, 1), .required, .{}, "too long for this buffer"),
    );
}
