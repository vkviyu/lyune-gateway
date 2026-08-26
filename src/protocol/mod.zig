//! 协议层模块
//!
//! 定义帧格式、消息类型和编解码逻辑。

// 帧格式
pub const codec = @import("codec.zig");
pub const frame = @import("frame.zig");
pub const framing = @import("framing.zig");

// 不可靠通路（QUIC DATAGRAM）
pub const datagram = @import("datagram.zig");

// 网关会解析的 Body 结构（准入结果、目标列表）
pub const body = @import("body.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
