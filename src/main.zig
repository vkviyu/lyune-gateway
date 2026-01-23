const std = @import("std");
const xev = @import("xev");
const builtin = @import("builtin");
const quic = @import("quic/mod.zig"); // 注意这里路径可能需要根据你的实际情况调整
const gateway = @import("gateway/mod.zig");
const protocol = @import("protocol/mod.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}).init;
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
        } else if (std.mem.eql(u8, cmd, "client")) {
            try runClient(allocator);
        } else if (std.mem.eql(u8, cmd, "xev-demo")) {
            try runXevDemo();
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
        \\  lyune-gateway client                - 运行 QUIC 客户端示例 (Blocking)
        \\  lyune-gateway xev-demo              - 运行 libxev 演示
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

/// 运行单个 Worker 实例 (原 Server)
fn runSingleWorker(allocator: std.mem.Allocator, thread_id: u8) !void {
    // 使用 GatewayWorker 而不是 Server
    // 确保 gateway/mod.zig 中导出了 GatewayWorker
    var worker = gateway.GatewayWorker.init(allocator, .{
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

    // 启动 Worker (阻塞直到停止)
    // Worker 内部会初始化 ServerDriver 并驱动事件循环
    try worker.run();
}

/// QUIC 客户端示例
/// 注意：这是用于测试的同步阻塞客户端 (基于 quic/client.zig)，
/// 不是 Gateway 内部使用的异步客户端 (driver/client.zig)。
fn runClient(allocator: std.mem.Allocator) !void {
    std.log.info("Connecting to QUIC server at localhost:8443...", .{});

    // 假设 quic.zig 导出了同步 Client (原 Client 封装)
    var client = quic.Client.init(allocator, .{
        .base = .{ .alpn = "lyune-gateway", .root_cert_file = "server.crt" },
    }) catch |err| {
        std.log.err("Failed to create client: {}", .{err});
        return err;
    };
    defer client.deinit();

    const conn = client.connect("127.0.0.1", 8443, "localhost") catch |err| {
        std.log.err("Failed to connect: {}", .{err});
        return err;
    };

    std.log.info("Connected! Connection ID: {x}", .{conn.getConnectionIdBytes()});

    var response_buf: [4096]u8 = undefined;

    // 1. 分配实体内存（在栈上开辟 4096 字节）
    var buffer_memory: [4096]u8 = undefined;

    // 2. 创建指向这块内存的切片
    // FrameEncoder.init 需要的是 []u8，我们可以通过取地址符 & 将数组转为切片
    var encoder = protocol.codec.FrameEncoder.init(&buffer_memory);

    // 3. 编码
    // 这里的 "Hello..." 会被写入到 buffer_memory 中
    const data = try encoder.encode(protocol.frame.TransportMode.direct_buffered, 0x01, "Hello from Client!");

    // 发送 hello 并等待回响
    const response = client.sendAndReceive(data, &response_buf) catch |err| {
        std.log.err("Failed to send/receive: {}", .{err});
        return err;
    };

    std.log.info("Received response: {s}", .{response});
}

/// libxev 演示 (保持不变，用于测试环境)
fn runXevDemo() !void {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var c: xev.Completion = undefined;

    std.debug.print("Lyune Gateway is running on OS: {s}\n", .{@tagName(builtin.os.tag)});
    std.debug.print("Starting a 1ms timer...\n", .{});

    loop.timer(&c, 1, null, (struct {
        fn callback(
            _: ?*anyopaque,
            _: *xev.Loop,
            _: *xev.Completion,
            r: xev.Result,
        ) xev.CallbackAction {
            std.debug.print("Timer fired! Result: {}\n", .{r});
            return .disarm;
        }
    }.callback));

    try loop.run(.until_done);
    std.debug.print("Loop finished.\n", .{});
}
