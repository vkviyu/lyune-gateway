//! Lyune Gateway 进程入口
//!
//! 只负责命令行解析，随后把控制权交给 app 装配层。

const std = @import("std");

const app = @import("app/mod.zig");

const DEFAULT_CONFIG_PATH = "config/gateway.json";

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();

    // 跳过程序名 `lyune_gateway`
    _ = args.skip();

    // args.next() 本身不负责按照空格、逗号或其他符号分割命令行
    // 它只是从操作系统已经准备好的参数数组中，依次取出下一个参数
    const cmd = args.next() orelse {
        printUsage();
        return;
    };
    if (!std.mem.eql(u8, cmd, "server")) {
        std.log.err("Unknown command: {s}", .{cmd});
        printUsage();
        return;
    }

    var config_path: []const u8 = DEFAULT_CONFIG_PATH;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--config")) {
            config_path = args.next() orelse return error.MissingConfigPath;
        } else {
            std.log.err("Unknown option: {s}", .{arg});
            printUsage();
            return;
        }
    }

    try app.serve(init.io, allocator, config_path);
}

fn printUsage() void {
    std.debug.print(
        \\Lyune Gateway
        \\
        \\Usage:
        \\  lyune_gateway server [--config PATH]
        \\
        \\Default configuration: config/gateway.json
        \\
    , .{});
}

test {
    std.testing.refAllDecls(@This());
    _ = app;
}
