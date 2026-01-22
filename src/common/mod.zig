//! 公共工具模块
//!
//! 提供配置加载、日志、监控指标和错误定义等通用功能。

// 以下模块尚未实现完整功能
pub const config = @import("config.zig");
pub const log = @import("log.zig");
pub const metrics = @import("metrics.zig");
pub const err = @import("error.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
