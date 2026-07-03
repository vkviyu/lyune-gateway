const std = @import("std");
const builtin = @import("builtin");

const gateway = @import("gateway/mod.zig");


pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len > 1) {
        const cmd = args[1];
        if (std.mem.eql(u8, cmd, "server")) {
            var threads: ?usize = null;

            var i: usize = 2;
            while (i < args.len) : (i += 1) {
                const arg = args[i];
                if (std.mem.eql(u8, arg, "--threads")) {
                    if (i + 1 < args.len) {
                        threads = std.fmt.parseInt(usize, args[i + 1], 10) catch null;
                        i += 1;
                    }
                }
            }

            try runServer(allocator, threads);
        } else {
            printUsage();
        }
    } else {
        printUsage();
    }
}

fn printUsage() void {
    std.debug.print(
        \\Lyune Gateway - High Performance IM Gateway
        \\
        \\Usage:
        \\  lyune-gateway server [--threads N]  - 启动 QUIC 服务端
        \\
        \\需要先生成测试证书:
        \\  openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
        \\    -days 365 -nodes -subj "/CN=localhost"
        \\
    , .{});
}

/// QUIC 服务端
fn runServer(allocator: std.mem.Allocator, threads: ?usize) !void {
    const num_threads = threads orelse std.Thread.getCpuCount() catch 1;
    std.log.info("Starting Gateway on port 8443 (libxev: {s}) with {} threads...", .{ @tagName(builtin.os.tag), num_threads });

    if (num_threads <= 1) {
        try runSingleWorker(allocator, 0);
    } else {
        // 多线程模式：Thread-per-Core
        const handles = try allocator.alloc(std.Thread, num_threads);
        defer allocator.free(handles);

        for (handles, 0..) |*handle, i| {
            // 每个线程运行一个独立的 GatewayWorker
            handle.* = try std.Thread.spawn(.{}, runSingleWorker, .{ allocator, @as(u8, @intCast(i)) });
        }

        for (handles) |t| {
            t.join();
        }
    }
}

/// 运行单个 Worker 实例
fn runSingleWorker(allocator: std.mem.Allocator, thread_id: u8) !void {
    var worker = gateway.worker.GatewayWorker.init(allocator, .{
        .cert_file = "server.crt",
        .key_file = "server.key",
        .bind_address = .{ 0, 0, 0, 0 },
        .bind_port = 4433,
        .base = .{
            .alpn = "lyune-im",
            .max_connections = 10000,
            .idle_timeout_ms = 30000,
        },
    }, thread_id) catch |err| {
        std.log.err("Failed to create gateway worker: {}", .{err});
        std.log.err("Make sure server.crt and server.key exist.", .{});
        return err;
    };
    defer worker.deinit();

    try worker.run();
}

test {
    _ = @import("./mq/direct.zig");
}
