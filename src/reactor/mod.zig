//! reactor —— 事件反应堆组件层
//!
//! 采用 Reactor 模式：监听 io 层的 UDP/定时器事件，驱动 quic 协议状态机，
//! 再把连接/流事件回调给上层。它把「协议」与「I/O」粘成一个可运行的收发闭环。
//!   - server：服务端反应堆（组装 Endpoint + IoLoop，驱动收包→处理→发包→定时器）；
//!   - client：客户端反应堆（网关主动连接后端）。

pub const client = @import("client.zig");
pub const server = @import("server.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
