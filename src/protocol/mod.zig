//! 协议层模块
//!
//! 定义帧格式、消息类型和编解码逻辑。

// 消息类型定义
pub const MsgType = @import("message.zig").MsgType;

// 帧格式
pub const frame = @import("frame.zig");
pub const FrameHeader = frame.FrameHeader;
pub const Flags = frame.Flags;
pub const MAGIC = frame.MAGIC;
pub const HEADER_SIZE = frame.HEADER_SIZE;
pub const VERSION = frame.VERSION;

// 以下模块尚未实现完整功能
pub const codec = @import("codec.zig");
pub const handler = @import("handler.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
