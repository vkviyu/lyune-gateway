//! worker —— 数据面 per-core 组件层
//!
//! 每个 Worker 独占一个事件循环、一套 picoquic 上下文与连接表，是网关承载业务流量的
//! 核心。按"谁拥有状态"分成几个文件：
//!
//!   - worker.zig     —— GatewayWorker 本体：装配、生命周期、优雅停机、后端回程分派
//!   - ingress.zig    —— 客户端上行：分帧、按目的地分派、交换状态与错误分级
//!   - egress.zig     —— 后端下行：接纳后端主动流、`.peer` / `.multicast` 扇出、跨位置转投
//!   - peer_link.zig  —— 节点间应用层投递的出站链路（对等网关节点，mTLS）
//!   - inflight.zig   —— 在途请求表：回程映射与认证等待表，含上限与三条回收路径
//!   - auth.zig       —— 接入认证：委托给后端认证服务，解析准入结果
//!   - connection.zig —— 会话上下文、定容槽位池、`dest_id` / 组播成员索引
//!
//! 上行在 ingress、下行在 egress，两边通过 inflight 里的映射对接；worker.zig 只负责
//! 把回程事件按归属分给三条路径（认证响应 / 请求响应 / 后端推送）。

pub const GatewayWorker = @import("worker.zig").GatewayWorker;
pub const PeerListener = @import("worker.zig").PeerListener;
pub const connection = @import("connection.zig");
pub const ingress = @import("ingress.zig");
pub const egress = @import("egress.zig");
pub const peer_link = @import("peer_link.zig");
pub const inflight = @import("inflight.zig");
pub const auth = @import("auth.zig");

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("worker.zig");
}
