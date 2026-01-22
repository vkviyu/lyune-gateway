//! 集群功能模块
//!
//! 提供服务发现、网关协调和连接迁移功能。

// 连接迁移（包含线程间包转发队列）
pub const migration = @import("migration.zig");
pub const Cluster = migration.Cluster;
pub const PacketQueue = migration.PacketQueue;
pub const ForwardPacket = migration.ForwardPacket;

// 以下模块尚未实现完整功能
pub const discovery = @import("discovery.zig");
pub const coordinator = @import("coordinator.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
