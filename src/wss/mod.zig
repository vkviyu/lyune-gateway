//! Lyune Protocol v2 的 WSS binding。
//!
//! 本目录只处理浏览器侧的 TLS/TCP/WebSocket 接入；Worker、Exchange、认证与路由
//! 仍通过 `TransportSession` 共享同一套业务实现。协议拆成两层，避免把 RFC 6455 的
//! 分片/控制帧状态与 Lyune logical stream 状态揉在一起：
//!
//!   WebSocket binary message -> envelope record -> 原有 Lyune OPEN/DATA bytes

pub const envelope = @import("envelope.zig");
pub const listener = @import("listener.zig");
pub const output_queue = @import("output_queue.zig");
pub const tls = @import("tls.zig");
pub const websocket = @import("websocket.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
