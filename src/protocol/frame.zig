//! 帧格式定义
//!
//! 本模块定义了 QUIC 网关的应用层帧格式。
//! 设计理念：网关只关心"怎么传"，不关心"传什么"。
//!
//! ## 设计原则
//!
//! 1. **传输模式**（TransportMode）：决定数据如何处理（缓冲/流式/控制）
//! 2. **路由标识**（RouteKey）：决定数据发往哪个后端（支持中间件分发）
//! 3. **业务无关**：不在帧头定义具体消息类型，业务语义由 Body 承载
//!
//! ## 帧结构
//!
//! ```
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                        Frame Header (16 bytes)                       │
//! ├──────────┬──────────┬──────────┬──────────┬──────────┬──────────────┤
//! │ Magic    │ Version  │ Mode     │ RouteKey │ Flags    │ Reserved     │
//! │ (2B)     │ (1B)     │ (1B)     │ (1B)     │ (1B)     │ (2B)         │
//! ├──────────┴──────────┴──────────┴──────────┴──────────┴──────────────┤
//! │                          Sequence (4B)                               │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                        Body Length (4B)                              │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```

const std = @import("std");

// ============================================================================
// 常量
// ============================================================================

/// 魔数：用于快速识别有效帧
pub const MAGIC: u16 = 0xFEFE;

/// 协议版本
pub const VERSION: u8 = 3;

/// 帧头大小（字节）
pub const HEADER_SIZE: usize = 16;

// ============================================================================
// 传输模式
// ============================================================================

/// 传输模式
///
/// 决定了 Worker 应该使用哪种方式处理该帧。
/// 这是网关核心关注的字段。
///
/// ## 编码规则
///
/// 高 4 位表示传输路径，低 4 位表示传输方式：
/// - 路径：0x0_ = 中继（relay），0x1_ = 直连（direct），0xF_ = 控制
/// - 方式：0x_0 = 缓冲（buffered），0x_1 = 流式（streaming）
///
/// ## 传输路径说明
///
/// - **中继模式**：消息通过消息中间件（如 NATS）转发到后端服务
/// - **直连模式**：网关通过服务发现直接连接后端服务器转发
///
pub const TransportMode = enum(u8) {
    /// 中继 + 缓冲模式
    ///
    /// 适用场景：普通消息（IM、RPC）、小型文件
    /// 处理方式：完整接收后通过消息中间件转发
    relay_buffered = 0x00,

    /// 中继 + 流式模式
    ///
    /// 适用场景：需要通过中间件分发的流式数据
    /// 处理方式：流式分片通过消息中间件转发
    relay_streaming = 0x01,

    /// 直连 + 缓冲模式
    ///
    /// 适用场景：需要低延迟的完整消息传输
    /// 处理方式：完整接收后直连后端服务器转发
    direct_buffered = 0x10,

    /// 直连 + 流式模式
    ///
    /// 适用场景：AI 流式响应、实时音视频、大文件分块
    /// 处理方式：收到即转发，直连后端服务器
    direct_streaming = 0x11,

    /// 控制帧
    ///
    /// 适用场景：心跳、ACK、连接控制
    /// 处理方式：网关本地处理，不转发给后端
    control = 0xFF,

    _,

    /// 是否为中继模式（通过消息中间件转发）
    pub fn isRelay(self: TransportMode) bool {
        const v = @intFromEnum(self);
        return v != 0xFF and (v & 0xF0) == 0x00;
    }

    /// 是否为直连模式（直接连接后端服务器）
    pub fn isDirect(self: TransportMode) bool {
        return (@intFromEnum(self) & 0xF0) == 0x10;
    }

    /// 是否为流式传输
    pub fn isStreaming(self: TransportMode) bool {
        const v = @intFromEnum(self);
        return v != 0xFF and (v & 0x0F) == 0x01;
    }

    /// 是否为缓冲传输
    pub fn isBuffered(self: TransportMode) bool {
        const v = @intFromEnum(self);
        return v != 0xFF and (v & 0x0F) == 0x00;
    }

    /// 是否为控制帧
    pub fn isControl(self: TransportMode) bool {
        return self == .control;
    }
};

// ============================================================================
// 路由标识
// ============================================================================

/// 路由标识（RouteKey）
///
/// 作为服务标识使用，具体值的业务含义由配置文件定义：
/// - **直连模式**：作为服务发现的 key，网关查询对应后端地址
/// - **中继模式**：作为消息中间件的 topic/queue 标识
/// - **控制模式**：复用为 ControlType（见 ControlType 定义）
///
/// ## 设计说明
///
/// RouteKey 是一个 u8 值（0-255），网关本身不预定义具体含义，
/// 而是通过配置文件将数值映射到具体的服务名或 topic 名。
/// 例如：
/// - 0x01 → "ai-service"（服务发现 key）
/// - 0x02 → "im.messages"（NATS topic）
///
/// 这样设计的好处是网关代码无需修改，只需更新配置即可扩展服务。

// ============================================================================
// 控制帧类型
// ============================================================================

/// 控制帧类型
///
/// 当 TransportMode == .control 时，route_key 字段的语义变为 ControlType。
/// 用于区分网关层面需要处理的不同控制操作。
///
/// ## 类型分区
///
/// | 范围        | 类别         | 说明                           |
/// |-------------|--------------|--------------------------------|
/// | 0x00 - 0x0F | 心跳类       | heartbeat, ping/pong           |
/// | 0x10 - 0x1F | 认证类       | auth_request, auth_response    |
/// | 0x20 - 0x2F | 连接控制类   | kick_off, disconnect           |
/// | 0x30 - 0x3F | 会话类       | session_resume                 |
/// | 0xF0 - 0xFF | 系统类       | error, maintenance             |
pub const ControlType = enum(u8) {
    // =========================================================================
    // 心跳类 (0x00 - 0x0F)
    // =========================================================================

    /// 心跳请求（Client → Gateway）
    heartbeat = 0x00,
    /// 心跳响应（Gateway → Client）
    heartbeat_ack = 0x01,
    /// Ping 请求（延迟测量）
    ping = 0x02,
    /// Pong 响应
    pong = 0x03,

    // =========================================================================
    // 认证类 (0x10 - 0x1F)
    // =========================================================================

    /// 认证请求（Client → Gateway，Body 携带 Token）
    auth_request = 0x10,
    /// 认证成功响应（Gateway → Client）
    auth_success = 0x11,
    /// 认证失败响应（Gateway → Client，Body 携带错误信息）
    auth_failure = 0x12,

    // =========================================================================
    // 连接控制类 (0x20 - 0x2F)
    // =========================================================================

    /// 踢下线（Gateway → Client，Body 携带原因）
    kick_off = 0x20,
    /// 客户端主动断开（Client → Gateway）
    disconnect = 0x21,
    /// 强制关闭连接（Gateway → Client，用于异常情况）
    force_close = 0x22,

    // =========================================================================
    // 会话类 (0x30 - 0x3F)
    // =========================================================================

    /// 会话恢复请求（Client → Gateway）
    session_resume = 0x30,
    /// 会话恢复成功（Gateway → Client）
    session_resume_ack = 0x31,
    /// 会话恢复失败（Gateway → Client）
    session_resume_fail = 0x32,

    // =========================================================================
    // 系统类 (0xF0 - 0xFF)
    // =========================================================================

    /// 网关错误（Gateway → Client）
    gateway_error = 0xF0,
    /// 服务维护通知（Gateway → Client）
    maintenance = 0xF1,

    /// 允许未定义的值（向前兼容）
    _,

    /// 判断是否为心跳类
    pub fn isHeartbeat(self: ControlType) bool {
        const v = @intFromEnum(self);
        return v <= 0x0F;
    }

    /// 判断是否为认证类
    pub fn isAuth(self: ControlType) bool {
        const v = @intFromEnum(self);
        return v >= 0x10 and v <= 0x1F;
    }

    /// 判断是否为连接控制类
    pub fn isConnectionControl(self: ControlType) bool {
        const v = @intFromEnum(self);
        return v >= 0x20 and v <= 0x2F;
    }

    /// 判断是否为会话类
    pub fn isSession(self: ControlType) bool {
        const v = @intFromEnum(self);
        return v >= 0x30 and v <= 0x3F;
    }

    /// 判断是否为系统类
    pub fn isSystem(self: ControlType) bool {
        const v = @intFromEnum(self);
        return v >= 0xF0;
    }
};

// ============================================================================
// 标志位
// ============================================================================

/// 帧标志位
pub const Flags = packed struct(u8) {
    /// 是否压缩 Body
    compressed: bool = false,
    /// 是否加密 Body
    encrypted: bool = false,
    /// 是否需要 ACK 确认
    need_ack: bool = false,
    /// 流式模式：首包标志 (Start of Frame)
    sof: bool = false,
    /// 流式模式：末包标志 (End of Frame)
    eof: bool = false,
    /// 保留位
    _reserved: u3 = 0,

    pub fn default() Flags {
        return .{};
    }

    pub fn withAck() Flags {
        return .{ .need_ack = true };
    }

    pub fn streamStart() Flags {
        return .{ .sof = true };
    }

    pub fn streamMiddle() Flags {
        return .{};
    }

    pub fn streamEnd() Flags {
        return .{ .eof = true };
    }

    pub fn streamSingle() Flags {
        return .{ .sof = true, .eof = true };
    }
};

// ============================================================================
// 帧头
// ============================================================================

/// 帧头结构体
pub const FrameHeader = struct {
    magic: u16 = MAGIC,
    version: u8 = VERSION,
    mode: TransportMode = .relay_buffered,
    route_key: u8 = 0x00,
    flags: Flags = .{},
    seq: u32 = 0,
    body_len: u32 = 0,

    /// 序列化到缓冲区（大端序）
    pub fn encode(self: FrameHeader, buf: []u8) !void {
        if (buf.len < HEADER_SIZE) return error.BufferTooSmall;

        std.mem.writeInt(u16, buf[0..2], self.magic, .big);
        buf[2] = self.version;
        buf[3] = @intFromEnum(self.mode);
        buf[4] = self.route_key;
        buf[5] = @as(u8, @bitCast(self.flags));
        buf[6] = 0;
        buf[7] = 0;
        std.mem.writeInt(u32, buf[8..12], self.seq, .big);
        std.mem.writeInt(u32, buf[12..16], self.body_len, .big);
    }

    /// 从缓冲区解析（大端序）
    pub fn decode(buf: []const u8) !FrameHeader {
        if (buf.len < HEADER_SIZE) return error.BufferTooSmall;

        const magic = std.mem.readInt(u16, buf[0..2], .big);
        if (magic != MAGIC) return error.InvalidMagic;

        const version = buf[2];
        if (version > VERSION) return error.UnsupportedVersion;

        return .{
            .magic = magic,
            .version = version,
            .mode = @enumFromInt(buf[3]),
            .route_key = buf[4],
            .flags = @bitCast(buf[5]),
            .seq = std.mem.readInt(u32, buf[8..12], .big),
            .body_len = std.mem.readInt(u32, buf[12..16], .big),
        };
    }

    /// 是否为中继模式
    pub fn isRelay(self: FrameHeader) bool {
        return self.mode.isRelay();
    }

    /// 是否为直连模式
    pub fn isDirect(self: FrameHeader) bool {
        return self.mode.isDirect();
    }

    /// 是否为流式传输
    pub fn isStreaming(self: FrameHeader) bool {
        return self.mode.isStreaming();
    }

    /// 是否为缓冲传输
    pub fn isBuffered(self: FrameHeader) bool {
        return self.mode.isBuffered();
    }

    /// 是否为控制帧
    pub fn isControl(self: FrameHeader) bool {
        return self.mode.isControl();
    }

    /// 是否为流式首包
    pub fn isStreamStart(self: FrameHeader) bool {
        return self.mode.isStreaming() and self.flags.sof;
    }

    /// 是否为流式末包
    pub fn isStreamEnd(self: FrameHeader) bool {
        return self.mode.isStreaming() and self.flags.eof;
    }

    pub fn frameSize(self: FrameHeader) usize {
        return HEADER_SIZE + self.body_len;
    }

    /// 获取控制帧类型
    ///
    /// 当 mode == .control 时，route_key 字段的语义为 ControlType。
    /// 其他模式下返回 null。
    pub fn controlType(self: FrameHeader) ?ControlType {
        if (self.mode != .control) return null;
        return @enumFromInt(self.route_key);
    }

    /// 创建控制帧头
    ///
    /// 快捷方法，用于创建指定类型的控制帧头。
    /// route_key 字段会被设置为 ctrl_type 的值。
    pub fn initControl(ctrl_type: ControlType, body_len: u32) FrameHeader {
        return .{
            .mode = .control,
            .route_key = @intFromEnum(ctrl_type),
            .body_len = body_len,
        };
    }

    /// 创建带序列号的控制帧头
    pub fn initControlWithSeq(ctrl_type: ControlType, seq: u32, body_len: u32) FrameHeader {
        return .{
            .mode = .control,
            .route_key = @intFromEnum(ctrl_type),
            .seq = seq,
            .body_len = body_len,
        };
    }
};

// ============================================================================
// 错误类型
// ============================================================================

pub const FrameError = error{
    BufferTooSmall,
    InvalidMagic,
    UnsupportedVersion,
    BodyTooLarge,
};

// ============================================================================
// 测试
// ============================================================================

test "FrameHeader encode/decode roundtrip" {
    const original = FrameHeader{
        .mode = .relay_buffered,
        .route_key = 0x01,
        .flags = .{ .need_ack = true },
        .seq = 12345,
        .body_len = 1024,
    };

    var buf: [HEADER_SIZE]u8 = undefined;
    try original.encode(&buf);

    const decoded = try FrameHeader.decode(&buf);

    try std.testing.expectEqual(original.magic, decoded.magic);
    try std.testing.expectEqual(original.mode, decoded.mode);
    try std.testing.expectEqual(original.route_key, decoded.route_key);
    try std.testing.expectEqual(original.seq, decoded.seq);
    try std.testing.expectEqual(original.body_len, decoded.body_len);
}

test "TransportMode helper methods" {
    // 中继 + 缓冲
    try std.testing.expect(TransportMode.relay_buffered.isRelay());
    try std.testing.expect(TransportMode.relay_buffered.isBuffered());
    try std.testing.expect(!TransportMode.relay_buffered.isDirect());
    try std.testing.expect(!TransportMode.relay_buffered.isStreaming());
    try std.testing.expect(!TransportMode.relay_buffered.isControl());

    // 中继 + 流式
    try std.testing.expect(TransportMode.relay_streaming.isRelay());
    try std.testing.expect(TransportMode.relay_streaming.isStreaming());
    try std.testing.expect(!TransportMode.relay_streaming.isDirect());
    try std.testing.expect(!TransportMode.relay_streaming.isBuffered());

    // 直连 + 缓冲
    try std.testing.expect(TransportMode.direct_buffered.isDirect());
    try std.testing.expect(TransportMode.direct_buffered.isBuffered());
    try std.testing.expect(!TransportMode.direct_buffered.isRelay());
    try std.testing.expect(!TransportMode.direct_buffered.isStreaming());

    // 直连 + 流式
    try std.testing.expect(TransportMode.direct_streaming.isDirect());
    try std.testing.expect(TransportMode.direct_streaming.isStreaming());
    try std.testing.expect(!TransportMode.direct_streaming.isRelay());
    try std.testing.expect(!TransportMode.direct_streaming.isBuffered());

    // 控制帧
    try std.testing.expect(TransportMode.control.isControl());
    try std.testing.expect(!TransportMode.control.isRelay());
    try std.testing.expect(!TransportMode.control.isDirect());
    try std.testing.expect(!TransportMode.control.isStreaming());
    try std.testing.expect(!TransportMode.control.isBuffered());
}

test "FrameHeader mode helpers" {
    const relay_buf = FrameHeader{ .mode = .relay_buffered };
    try std.testing.expect(relay_buf.isRelay());
    try std.testing.expect(relay_buf.isBuffered());

    const direct_stream = FrameHeader{ .mode = .direct_streaming };
    try std.testing.expect(direct_stream.isDirect());
    try std.testing.expect(direct_stream.isStreaming());

    const control = FrameHeader{ .mode = .control };
    try std.testing.expect(control.isControl());
}

test "ControlType category detection" {
    // 心跳类
    try std.testing.expect(ControlType.heartbeat.isHeartbeat());
    try std.testing.expect(ControlType.heartbeat_ack.isHeartbeat());
    try std.testing.expect(ControlType.ping.isHeartbeat());
    try std.testing.expect(ControlType.pong.isHeartbeat());
    try std.testing.expect(!ControlType.heartbeat.isAuth());

    // 认证类
    try std.testing.expect(ControlType.auth_request.isAuth());
    try std.testing.expect(ControlType.auth_success.isAuth());
    try std.testing.expect(ControlType.auth_failure.isAuth());
    try std.testing.expect(!ControlType.auth_request.isHeartbeat());

    // 连接控制类
    try std.testing.expect(ControlType.kick_off.isConnectionControl());
    try std.testing.expect(ControlType.disconnect.isConnectionControl());
    try std.testing.expect(ControlType.force_close.isConnectionControl());
    try std.testing.expect(!ControlType.kick_off.isAuth());

    // 会话类
    try std.testing.expect(ControlType.session_resume.isSession());
    try std.testing.expect(ControlType.session_resume_ack.isSession());
    try std.testing.expect(ControlType.session_resume_fail.isSession());

    // 系统类
    try std.testing.expect(ControlType.gateway_error.isSystem());
    try std.testing.expect(ControlType.maintenance.isSystem());
}

test "FrameHeader controlType for control frames" {
    // 控制帧应该能获取 ControlType
    const control_header = FrameHeader.initControl(.auth_request, 100);
    try std.testing.expectEqual(TransportMode.control, control_header.mode);
    try std.testing.expectEqual(ControlType.auth_request, control_header.controlType().?);
    try std.testing.expectEqual(@as(u32, 100), control_header.body_len);

    // 非控制帧应该返回 null
    const relay_header = FrameHeader{ .mode = .relay_buffered };
    try std.testing.expectEqual(@as(?ControlType, null), relay_header.controlType());

    const direct_header = FrameHeader{ .mode = .direct_streaming };
    try std.testing.expectEqual(@as(?ControlType, null), direct_header.controlType());
}

test "FrameHeader initControlWithSeq" {
    const header = FrameHeader.initControlWithSeq(.kick_off, 12345, 50);
    try std.testing.expectEqual(TransportMode.control, header.mode);
    try std.testing.expectEqual(ControlType.kick_off, header.controlType().?);
    try std.testing.expectEqual(@as(u32, 12345), header.seq);
    try std.testing.expectEqual(@as(u32, 50), header.body_len);
}
