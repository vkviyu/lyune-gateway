//! app/bootstrap —— 进程与 Worker 编排（组合根）
//!
//! 这是各组件的「组装点」：创建 Coordinator、reuseport socket 组，拉起多 Worker 线程，
//! 并把 foundation / io / backend / control / worker 组件拼装成一个运行中的网关。
//! 除装配外不含业务逻辑，业务逻辑都在各自组件内部。

const std = @import("std");
const builtin = @import("builtin");

const backend = @import("../backend/mod.zig");
const control = @import("../control/mod.zig");
const foundation = @import("../foundation/mod.zig");
const io = @import("../io/mod.zig");
const quic = @import("../quic/mod.zig");
const worker_rt = @import("../worker/mod.zig");
const RuntimeConfig = @import("config.zig").RuntimeConfig;

/// Worker 启动同步闸门。
///
/// 多 Worker 模式下，主线程会先把整组 reuseport socket 建好、attach 好分类器，再一次性
/// 放行所有 Worker。若中途某个线程 spawn 失败，则以 run_workers=false 广播，让已就绪的
/// 线程直接退出，避免"socket 已交出但 Worker 没起来"导致 socket index 错位。
const WorkerStartGate = struct {
    io: std.Io,
    /// libxev 无关的一次性事件，set 后所有 wait 返回。
    event: std.Io.Event = .unset,
    /// true 表示放行运行，false 表示启动失败需要各 Worker 退出。
    run_workers: std.atomic.Value(bool) = .init(false),

    /// Worker 线程调用：阻塞直到主线程放行，返回是否应继续运行。
    fn wait(self: *WorkerStartGate) bool {
        self.event.waitUncancelable(self.io);
        return self.run_workers.load(.acquire);
    }

    /// 主线程调用：设置结果并唤醒所有等待的 Worker。
    fn release(self: *WorkerStartGate, run_workers: bool) void {
        self.run_workers.store(run_workers, .release);
        self.event.set(self.io);
    }
};

/// 传给每个 Worker 线程的启动上下文。
const WorkerStartContext = struct {
    allocator: std.mem.Allocator,
    thread_id: u8,
    config: *const RuntimeConfig,
    /// 本 Worker 独占的 reuseport socket。
    socket_fd: std.posix.socket_t,
    gate: *WorkerStartGate,
    coordinator: *control.Coordinator,
};

/// 装配并运行网关：创建控制面，按线程数选择单/多 Worker 模式。
pub fn run(io_iface: std.Io, allocator: std.mem.Allocator, config: *const RuntimeConfig) !void {
    const backend_endpoints = [_]control.discovery.ServiceEndpoint{.{
        .id = "configured-direct-backend",
        .host = config.direct.server_host,
        .port = config.direct.server_port,
        .weight = 1,
        .state = .healthy,
    }};
    const routes = [_]control.discovery.Route{.{
        .route_key = config.direct_route_key,
        .revision = 1,
        .endpoints = &backend_endpoints,
    }};
    var static_discovery = control.discovery.StaticDiscovery.init(&routes);
    var coordinator = try control.Coordinator.init(
        io_iface,
        allocator,
        config.cluster,
        static_discovery.asDiscovery(),
    );
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    const address = config.server_quic.bind_address;
    std.log.info("Starting Gateway on {}.{}.{}.{}:{} (libxev: {s}) with {} threads...", .{
        address[0],
        address[1],
        address[2],
        address[3],
        config.server_quic.bind_port,
        @tagName(builtin.os.tag),
        config.threads,
    });

    if (config.threads <= 1) {
        return runSingleWorker(allocator, 0, config, null, &coordinator);
    }

    const sockets = try createReusePortSockets(allocator, config.server_quic, config.threads);
    var sockets_owned = true;
    defer {
        if (sockets_owned) closeSockets(sockets);
        allocator.free(sockets);
    }

    const threads = try allocator.alloc(std.Thread, config.threads);
    defer allocator.free(threads);
    const contexts = try allocator.alloc(WorkerStartContext, config.threads);
    defer allocator.free(contexts);

    var gate: WorkerStartGate = .{ .io = io_iface };
    var spawned: usize = 0;
    for (threads, contexts, 0..) |*thread, *context, i| {
        context.* = .{
            .allocator = allocator,
            .thread_id = @intCast(i),
            .config = config,
            .socket_fd = sockets[i],
            .gate = &gate,
            .coordinator = &coordinator,
        };
        thread.* = std.Thread.spawn(.{}, runGatedWorker, .{context}) catch |err| {
            gate.release(false);
            for (threads[0..spawned]) |started_thread| started_thread.join();
            return err;
        };
        spawned += 1;
    }

    sockets_owned = false;
    gate.release(true);
    for (threads) |thread| thread.join();
}

/// 创建一组 SO_REUSEPORT UDP socket，并把 reuseport 分类器 attach 到该组。
/// socket 下标即 worker_id，与 CID 中编码的 worker_id 严格对应；任一步失败都回滚已建 socket。
fn createReusePortSockets(allocator: std.mem.Allocator, config: quic.config.QUICConfig, count: usize) ![]std.posix.socket_t {
    const sockets = try allocator.alloc(std.posix.socket_t, count);
    var initialized: usize = 0;
    errdefer {
        closeSockets(sockets[0..initialized]);
        allocator.free(sockets);
    }

    const local_addr = foundation.net.initIp4(config.bind_address, config.bind_port);
    var storage = foundation.net.toSockAddrStorage(local_addr);
    const reuse: c_int = 1;

    for (sockets) |*fd| {
        const socket_fd = try createDatagramSocket();
        fd.* = socket_fd;
        initialized += 1;

        // 组内所有 socket 复用同一地址端口，由内核 + BPF 决定包投递给谁。
        try std.posix.setsockopt(socket_fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEPORT, std.mem.asBytes(&reuse));
        if (std.c.bind(socket_fd, @ptrCast(&storage), foundation.net.sockAddrLen(local_addr)) != 0) return error.BindFailed;
    }

    // 全部绑定完成后 attach 一次即可，内核会应用到整组。
    try io.reuseport.attach(sockets[0], @intCast(count));
    return sockets;
}

/// 创建一个非阻塞、CLOEXEC 的 UDP socket。
/// Linux 支持 SOCK_NONBLOCK|SOCK_CLOEXEC 直接创建；macOS/Darwin 不支持这些 flag，
/// 需要事后用 fcntl 分两步设置，因此这里做平台分流。
fn createDatagramSocket() !std.posix.socket_t {
    const socket_type = std.posix.SOCK.DGRAM | std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC;
    const native_type = if (builtin.os.tag.isDarwin()) std.posix.SOCK.DGRAM else socket_type;
    const socket_fd = std.c.socket(std.posix.AF.INET, native_type, 0);
    if (socket_fd < 0) return error.SocketCreateFailed;
    errdefer _ = std.c.close(socket_fd);

    if (builtin.os.tag.isDarwin()) {
        if (std.c.fcntl(socket_fd, std.posix.F.SETFD, @as(usize, std.posix.FD_CLOEXEC)) < 0) {
            return error.SetCloseOnExecFailed;
        }
        const flags = std.c.fcntl(socket_fd, std.posix.F.GETFL, @as(usize, 0));
        if (flags < 0) return error.GetSocketFlagsFailed;
        const nonblocking: c_int = @bitCast(std.posix.O{ .NONBLOCK = true });
        if (std.c.fcntl(socket_fd, std.posix.F.SETFL, flags | nonblocking) < 0) {
            return error.SetNonblockingFailed;
        }
    }
    return socket_fd;
}

fn closeSockets(sockets: []const std.posix.socket_t) void {
    for (sockets) |fd| _ = std.c.close(fd);
}

/// Worker 线程入口：先等闸门放行，再运行 Worker 主循环。
/// 任一 Worker 异常退出都直接终止整个进程——因为 reuseport socket 从组里移除会导致
/// 后续 socket index 重排，破坏 CID→Worker 的固定映射，让存量连接被错误分流。
fn runGatedWorker(context: *const WorkerStartContext) void {
    if (!context.gate.wait()) return;
    runSingleWorker(
        context.allocator,
        context.thread_id,
        context.config,
        context.socket_fd,
        context.coordinator,
    ) catch |err| {
        std.log.err("Gateway worker {} stopped: {}; terminating to preserve reuseport socket indexes", .{ context.thread_id, err });
        std.process.exit(1);
    };
}

/// 组装并运行单个 Worker：Worker 本体 + 异步 DNS + 直连后端传输。
fn runSingleWorker(allocator: std.mem.Allocator, thread_id: u8, config: *const RuntimeConfig, socket_fd: ?std.posix.socket_t, coordinator: *control.Coordinator) !void {
    const registry = backend.TransportRegistry.init();
    var worker = try worker_rt.GatewayWorker.init(
        allocator,
        config.server_quic,
        thread_id,
        registry,
        config.backend_poll_interval_ms,
        socket_fd,
        coordinator,
    );
    defer worker.deinit();

    const dns_resolver = try foundation.resolver.Cares.init(allocator, worker.event_loop);
    defer dns_resolver.deinit();

    var direct_transport = try backend.DirectTransport.init(
        allocator,
        config.direct,
        worker.event_loop,
        dns_resolver.asResolver(),
        coordinator.serviceDiscovery(),
    );
    defer direct_transport.deinit();

    worker.registerTransport(.direct, config.direct_route_key, backend.BackendTransport.init(backend.DirectTransport, &direct_transport));
    try worker.run();
}
