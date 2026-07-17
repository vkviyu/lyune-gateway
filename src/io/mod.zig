//! io —— I/O 与内核态分流组件层
//!
//! 汇集与「数据包怎么进出、怎么在 Worker 间落位」相关的底层能力：
//!   - loop：基于 libxev 的事件循环 + UDP 收发；
//!   - reuseport：Linux 内核态 reuseport 分类器；
//!   - cid：服务端 Connection ID 编解码（Worker 归属）；
//!   - handoff：误分流时的本地跨 Worker 包交接。

pub const loop = @import("loop.zig");
pub const reuseport = @import("reuseport.zig");
pub const cid = @import("cid.zig");
pub const handoff = @import("handoff.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
