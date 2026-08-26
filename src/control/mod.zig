//! control —— 进程级控制面组件层
//!
//! 负责节点/Worker 生命周期，是数据面之上的「装配与治理」层：
//!   - coordinator：节点与 Worker 状态机、本地包交接器的持有者；
//!   - membership：集群成员发现与故障检测（SWIM），见 docs/cluster_design.md §5。
//!
//! 后端实例寻址不属于本层，由各 BackendTransport 实现内部处理。

pub const coordinator = @import("coordinator.zig");
pub const membership = @import("membership/mod.zig");

pub const Coordinator = coordinator.Coordinator;

test {
    @import("std").testing.refAllDecls(@This());
    _ = membership;
}
