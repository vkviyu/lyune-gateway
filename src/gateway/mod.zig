//! 网关核心模块
//!
//! 提供 QUIC 网关服务器、连接管理、会话管理和消息路由功能。

pub const ConnectionManager = @import("connection.zig").ConnectionManager;
pub const ConnectionContext = @import("connection.zig").ConnectionContext;
pub const GatewayWorker = @import("worker.zig").GatewayWorker;
// 以下模块尚未实现完整功能
pub const session = @import("session.zig");
pub const router = @import("router.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
