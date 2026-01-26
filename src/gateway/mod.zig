//! 网关核心模块
//!
//! 提供 QUIC 网关服务器、连接管理、会话管理和消息路由功能。

pub const connection = @import("connection.zig");
pub const router = @import("router.zig");
pub const session = @import("session.zig");
pub const worker = @import("worker.zig");

// 以下模块尚未实现完整功能
test {
    @import("std").testing.refAllDecls(@This());
}
