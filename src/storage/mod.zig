//! 存储适配模块
//!
//! 提供 Redis 客户端和路由表操作功能。

// 以下模块尚未实现完整功能
pub const redis = @import("redis.zig");
pub const route_table = @import("route_table.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
