const std = @import("std");
const xev = @import("xev");
const builtin = @import("builtin");
const quic = @import("quic.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}).init;
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len > 1) {
        const cmd = args[1];
        if (std.mem.eql(u8, cmd, "server")) {
            // 检查是否有 --legacy 参数
            const use_legacy = args.len > 2 and std.mem.eql(u8, args[2], "--legacy");
            try runServer(allocator, use_legacy);
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
        \\  lyune-gateway server [--legacy]  - 启动 QUIC 服务端
        \\                                     默认使用 libxev 高性能事件循环
        \\                                     --legacy 使用 picoquic 原生循环
        \\  lyune-gateway client             - 运行 QUIC 客户端示例
        \\  lyune-gateway xev-demo           - 运行 libxev 演示
        \\
        \\需要先生成测试证书:
        \\  openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
        \\    -days 365 -nodes -subj "/CN=localhost"
        \\
    , .{});
}

/// QUIC 服务端示例
fn runServer(allocator: std.mem.Allocator, use_legacy: bool) !void {
    if (use_legacy) {
        std.log.info("Starting QUIC server on port 4433 (legacy mode: picoquic event loop)...", .{});
    } else {
        std.log.info("Starting QUIC server on port 4433 (libxev: {s})...", .{@tagName(builtin.os.tag)});
    }

    var server = quic.Server.init(allocator, .{
        .cert_file = "server.crt",
        .key_file = "server.key",
        .port = 4433,
        .base = .{
            .alpn = "lyune-im",
            .max_connections = 1000,
        },
    }) catch |err| {
        std.log.err("Failed to create server: {}", .{err});
        std.log.err("Make sure server.crt and server.key exist.", .{});
        std.log.err("Generate with: openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj \"/CN=localhost\"", .{});
        return err;
    };
    defer server.deinit();

    // 设置连接回调
    server.onConnection(struct {
        fn callback(conn: *quic.Connection) void {
            const cid = conn.getConnectionIdBytes();
            std.log.info("New connection: {x}", .{cid});
        }
    }.callback);

    // 设置数据接收回调
    server.onStreamData(struct {
        fn callback(conn: *quic.Connection, stream_id: u64, data: []const u8, is_fin: bool) void {
            std.log.info("Stream {}: received {} bytes, fin={}", .{ stream_id, data.len, is_fin });

            if (data.len > 0) {
                std.log.info("Data: {s}", .{data});

                // Echo 回复
                const response = "Hello from Lyune Gateway!";
                conn.streamWrite(stream_id, response, true) catch |err| {
                    std.log.err("Failed to send response: {}", .{err});
                };
            }
        }
    }.callback);

    // 设置断开回调
    server.onConnectionClose(struct {
        fn callback(conn: *quic.Connection) void {
            const cid = conn.getConnectionIdBytes();
            std.log.info("Connection closed: {x}", .{cid});
        }
    }.callback);

    std.log.info("Server ready, waiting for connections...", .{});

    // 根据参数选择事件循环
    if (use_legacy) {
        try server.run();
    } else {
        try server.runWithXev();
    }
}

/// QUIC 客户端示例
fn runClient(allocator: std.mem.Allocator) !void {
    std.log.info("Connecting to QUIC server at localhost:4433...", .{});

    var client = quic.Client.init(allocator, .{
        .server_host = "localhost",
        .server_port = 4433,
        .base = .{
            .alpn = "lyune-im",
        },
    }) catch |err| {
        std.log.err("Failed to create client: {}", .{err});
        return err;
    };
    defer client.deinit();

    // 连接到服务器
    const conn = client.connect() catch |err| {
        std.log.err("Failed to connect: {}", .{err});
        return err;
    };

    std.log.info("Connected! Connection ID: {x}", .{conn.getConnectionIdBytes()});

    // 发送请求并等待响应
    var response_buf: [4096]u8 = undefined;
    const response = client.sendAndReceive("Hello, Server!", &response_buf) catch |err| {
        std.log.err("Failed to send/receive: {}", .{err});
        return err;
    };

    std.log.info("Received response: {s}", .{response});
}

/// libxev 演示
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
