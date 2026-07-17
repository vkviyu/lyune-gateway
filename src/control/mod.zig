//! control —— 进程级控制面组件层
//!
//! 负责节点/Worker 生命周期与服务发现，是数据面之上的「装配与治理」层：
//!   - coordinator：节点与 Worker 状态机、本地包交接器的持有者；
//!   - discovery：可替换的服务发现 provider 接口与静态实现。

pub const coordinator = @import("coordinator.zig");
pub const discovery = @import("discovery.zig");

pub const Coordinator = coordinator.Coordinator;
pub const ServiceDiscovery = discovery.ServiceDiscovery;

test {
    @import("std").testing.refAllDecls(@This());
}
