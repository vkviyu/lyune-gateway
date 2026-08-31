//! 客户端接入会话契约。
//!
//! 这一层位于具体 binding（Raw QUIC / WSS）与 Worker 业务状态之间：
//!
//! - `SessionHandle` 是 Worker-local、带代次的稳定会话身份；
//! - `TransportSession` 是认证、Exchange、推送和关闭所需的最小 I/O 能力。
//! - `Handler` / `Acceptor` 是 binding 与 Worker 之间的事件、生命周期端口。
//!
//! binding 与 Worker 都依赖本模块，彼此不反向导入。新增客户端传输时应在这里扩展
//! 会话能力，并在自己的 binding 内实现，不应把 socket/TLS/picoquic 对象泄漏进 Worker。

pub const handle = @import("handle.zig");
pub const transport = @import("transport.zig");
pub const binding = @import("binding.zig");

pub const SessionHandle = handle.SessionHandle;
pub const TransportSession = transport.TransportSession;
pub const StreamControl = binding.StreamControl;
pub const Handler = binding.Handler;
pub const Acceptor = binding.Acceptor;

test {
    @import("std").testing.refAllDecls(@This());
}
