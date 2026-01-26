//! 协议层模块
//!
//! 定义帧格式、消息类型和编解码逻辑。

// 帧格式
pub const codec = @import("codec.zig");
pub const frame = @import("frame.zig");
pub const handler = @import("handler.zig");

// 以下模块尚未实现完整功能
test {
    @import("std").testing.refAllDecls(@This());
}
