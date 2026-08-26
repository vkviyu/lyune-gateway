//! app —— 应用装配层
//!
//! 位于所有组件之上，负责"加载配置 → 组装组件 → 运行"这条启动链路。
//! main.zig 只做命令行解析，真正的启动逻辑集中在这里。

const std = @import("std");

const foundation = @import("../foundation/mod.zig");

pub const config = @import("config.zig");
pub const bootstrap = @import("bootstrap.zig");
pub const reload = @import("reload.zig");

/// 加载配置文件、装配运行期配置并启动网关，直到事件循环结束。
pub fn serve(io: std.Io, allocator: std.mem.Allocator, config_path: []const u8) !void {
    var loaded = foundation.config.load(io, allocator, config_path) catch |err| {
        std.log.err("Failed to load configuration '{s}': {}", .{ config_path, err });
        return err;
    };
    defer loaded.deinit(allocator);

    var runtime = try config.prepare(allocator, loaded.parsed.value);
    defer runtime.deinit(allocator);

    // 路径要往下传：热加载靠重读同一个文件实现（见 app/reload.zig）。
    try bootstrap.run(io, allocator, &runtime, config_path);
}

test {
    std.testing.refAllDecls(@This());
}
