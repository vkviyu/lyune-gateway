//! 消息类型定义
//!
//! 按功能域划分消息类型，每个域保留一定的扩展空间。
//!
//! ## 消息类型分区
//!
//! | 范围        | 域           | 说明                           |
//! |-------------|--------------|--------------------------------|
//! | 0x00 - 0x0F | 控制消息     | 心跳、ACK、Ping/Pong           |
//! | 0x10 - 0x1F | 连接管理     | 认证、会话控制                 |
//! | 0x20 - 0x3F | IM 消息      | 文本、图片、语音、群聊         |
//! | 0x40 - 0x5F | 流式消息     | AI 响应、实时流                |
//! | 0x60 - 0x7F | 通知消息     | 推送、事件通知                 |
//! | 0x80 - 0x9F | RPC 消息     | 通用 RPC 请求/响应             |
//! | 0xA0 - 0xEF | 业务扩展     | 预留给具体业务扩展             |
//! | 0xF0 - 0xFF | 系统消息     | 错误、踢下线、维护通知         |

const std = @import("std");

/// 消息类型枚举
pub const MsgType = enum(u8) {
    // =========================================================================
    // 控制消息 (0x00 - 0x0F)
    // =========================================================================

    /// 心跳请求
    heartbeat = 0x00,
    /// 心跳响应
    heartbeat_ack = 0x01,
    /// 通用 ACK 确认
    ack = 0x02,
    /// Ping (延迟测量)
    ping = 0x03,
    /// Pong (延迟响应)
    pong = 0x04,

    // =========================================================================
    // 连接管理 (0x10 - 0x1F)
    // =========================================================================

    /// 认证请求（携带 Token）
    auth_request = 0x10,
    /// 认证响应
    auth_response = 0x11,
    /// 主动断开连接
    disconnect = 0x12,
    /// 会话恢复请求
    session_resume = 0x13,
    /// 会话恢复响应
    session_resume_ack = 0x14,

    // =========================================================================
    // IM 消息 (0x20 - 0x3F) - 使用 Buffered 模式
    // =========================================================================

    /// 文本消息
    chat_text = 0x20,
    /// 图片消息
    chat_image = 0x21,
    /// 语音消息
    chat_voice = 0x22,
    /// 视频消息
    chat_video = 0x23,
    /// 文件消息
    chat_file = 0x24,
    /// 位置消息
    chat_location = 0x25,
    /// 自定义消息（JSON 扩展）
    chat_custom = 0x2F,

    /// 群聊消息
    group_message = 0x30,
    /// 群通知（成员变动等）
    group_notification = 0x31,
    /// 群公告
    group_announcement = 0x32,

    /// 消息已读回执
    read_receipt = 0x38,
    /// 消息撤回
    message_recall = 0x39,
    /// 正在输入
    typing_indicator = 0x3A,

    // =========================================================================
    // 流式消息 (0x40 - 0x5F) - 使用 Streaming 模式
    // =========================================================================

    /// AI/LLM 流式响应
    ai_stream = 0x40,
    /// 实时语音流
    voice_stream = 0x41,
    /// 实时视频流
    video_stream = 0x42,
    /// 文件分块传输
    file_chunk = 0x43,
    /// 屏幕共享流
    screen_share = 0x44,
    /// 通用数据流
    data_stream = 0x4F,

    // =========================================================================
    // 通知消息 (0x60 - 0x7F)
    // =========================================================================

    /// 推送通知
    push_notification = 0x60,
    /// 好友请求
    friend_request = 0x61,
    /// 好友请求响应
    friend_response = 0x62,
    /// 系统通知
    system_notification = 0x63,
    /// 在线状态变更
    presence_update = 0x64,

    // =========================================================================
    // RPC 消息 (0x80 - 0x9F)
    // =========================================================================

    /// RPC 请求
    rpc_request = 0x80,
    /// RPC 响应
    rpc_response = 0x81,
    /// RPC 错误
    rpc_error = 0x82,
    /// 双向流 RPC
    rpc_stream = 0x83,

    // =========================================================================
    // 业务扩展 (0xA0 - 0xEF) - 预留
    // =========================================================================

    // 这部分留给具体业务自定义

    // =========================================================================
    // 系统消息 (0xF0 - 0xFF)
    // =========================================================================

    /// 被踢下线
    kick_off = 0xF0,
    /// 服务维护通知
    maintenance = 0xF1,
    /// 服务端错误
    server_error = 0xFE,
    /// 未知类型（用于解析容错）
    unknown = 0xFF,

    /// 允许未定义的值（向前兼容）
    _,

    // ========================================================================
    // 辅助方法
    // ========================================================================

    /// 判断是否为控制消息
    pub fn isControl(self: MsgType) bool {
        const v = @intFromEnum(self);
        return v <= 0x0F;
    }

    /// 判断是否为需要流式处理的消息
    pub fn isStreaming(self: MsgType) bool {
        const v = @intFromEnum(self);
        return v >= 0x40 and v <= 0x5F;
    }

    /// 判断是否为 IM 消息
    pub fn isIM(self: MsgType) bool {
        const v = @intFromEnum(self);
        return v >= 0x20 and v <= 0x3F;
    }

    /// 判断是否为 RPC 消息
    pub fn isRPC(self: MsgType) bool {
        const v = @intFromEnum(self);
        return v >= 0x80 and v <= 0x9F;
    }

    /// 判断是否为系统消息
    pub fn isSystem(self: MsgType) bool {
        const v = @intFromEnum(self);
        return v >= 0xF0;
    }

    /// 获取消息类型的人类可读名称
    pub fn name(self: MsgType) []const u8 {
        return @tagName(self);
    }
};

// ============================================================================
// 消息体结构定义
// ============================================================================

/// 认证请求体
pub const AuthRequest = struct {
    /// 认证 Token
    token: []const u8,
    /// 客户端类型
    client_type: ClientType = .unknown,
    /// 客户端版本
    client_version: []const u8 = "",
    /// 设备 ID
    device_id: []const u8 = "",
};

/// 认证响应体
pub const AuthResponse = struct {
    /// 是否成功
    success: bool,
    /// 用户 ID（成功时返回）
    user_id: u64 = 0,
    /// 错误码（失败时返回）
    error_code: u16 = 0,
    /// 错误信息
    error_message: []const u8 = "",
};

/// 客户端类型
pub const ClientType = enum(u8) {
    unknown = 0,
    ios = 1,
    android = 2,
    web = 3,
    desktop_windows = 4,
    desktop_macos = 5,
    desktop_linux = 6,
    mini_program = 7,
    _,
};

/// 踢下线原因
pub const KickOffReason = enum(u8) {
    /// 其他设备登录
    other_device_login = 1,
    /// 账号被禁用
    account_disabled = 2,
    /// 强制下线（管理员操作）
    force_logout = 3,
    /// Token 过期
    token_expired = 4,
    _,
};

// ============================================================================
// 测试
// ============================================================================

test "MsgType category detection" {
    try std.testing.expect(MsgType.heartbeat.isControl());
    try std.testing.expect(!MsgType.heartbeat.isStreaming());

    try std.testing.expect(MsgType.chat_text.isIM());
    try std.testing.expect(!MsgType.chat_text.isStreaming());

    try std.testing.expect(MsgType.ai_stream.isStreaming());
    try std.testing.expect(!MsgType.ai_stream.isIM());

    try std.testing.expect(MsgType.rpc_request.isRPC());

    try std.testing.expect(MsgType.server_error.isSystem());
}
