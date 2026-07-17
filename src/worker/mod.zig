//! worker —— 数据面 per-core 组件层
//!
//! 每个 Worker 独占一个事件循环、一套 picoquic 上下文与连接表，是网关承载业务流量的
//! 核心。对外暴露 GatewayWorker（运行实体）与 connection（连接上下文/管理）。

pub const GatewayWorker = @import("worker.zig").GatewayWorker;
pub const connection = @import("connection.zig");

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("worker.zig");
}
