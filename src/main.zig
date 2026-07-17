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

    _ = args.skip();
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
