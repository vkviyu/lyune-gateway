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
const reload = @import("reload.zig");
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
    /// 本 Worker 独占的集群监听 socket；null 表示未启用集群链路。
    peer_socket_fd: ?std.posix.socket_t,
    gate: *WorkerStartGate,
    coordinator: *control.Coordinator,
};

/// 供信号处理器访问的活跃 Coordinator。
///
/// 信号处理器只能触碰进程级状态、不能加锁或分配，因此这里用一个原子指针
/// 把 Coordinator 暴露给它，处理器本身只调用 requestShutdown（仅翻转一个
/// 原子标志）。真正的停机序列由各 Worker 在自己线程内推进。
var active_coordinator: std.atomic.Value(?*control.Coordinator) = .init(null);

fn handleShutdownSignal(_: std.c.SIG) callconv(.c) void {
    if (active_coordinator.load(.acquire)) |coordinator| coordinator.requestShutdown();
}

/// 安装 SIGTERM/SIGINT 处理器，使进程可以被优雅停机。
///
/// 没有它，Worker 的事件循环只能靠异常退出，drain 与 left 广播在生产路径上
/// 永远不会被触发。
fn installShutdownHandlers() void {
    if (builtin.os.tag == .windows) return;
    const action: std.posix.Sigaction = .{
        .handler = .{ .handler = handleShutdownSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.TERM, &action, null);
    std.posix.sigaction(std.posix.SIG.INT, &action, null);
}

/// 装配并运行网关：创建控制面，按线程数选择单/多 Worker 模式。
pub fn run(io_iface: std.Io, allocator: std.mem.Allocator, config: *RuntimeConfig, config_path: []const u8) !void {
    // 必须在拉起任何线程之前屏蔽 SIGHUP：屏蔽字会被后续线程继承，漏掉这一步就会有
    // 别的线程抢到这个信号并按默认动作终止进程。
    reload.blockSignal();

    var coordinator = try control.Coordinator.init(io_iface, allocator, config.cluster);
    defer coordinator.deinit();
    try coordinator.start();
    defer {
        if (coordinator.state() == .running) coordinator.beginDrain() catch {};
        coordinator.stop();
    }

    // coordinator 的生命周期覆盖整个进程运行期，因此可以安全地暴露给信号处理器。
    active_coordinator.store(&coordinator, .release);
    defer active_coordinator.store(null, .release);
    installShutdownHandlers();

    // 配置热加载：只接受新增，形态与理由见 app/reload.zig。
    // 两个 defer 的 LIFO 顺序是有约束的——必须先停掉信号线程（它是两张表唯一的写者），
    // 再释放它分配的内存，而那时 Worker 也已经全部停止，不存在任何读者。
    var reloader = reload.Reloader.init(io_iface, allocator, config_path, &config.realms, &config.routes);
    defer reloader.deinit();
    const reload_thread = try reload.spawn(&reloader);
    defer reload.shutdown(&reloader, reload_thread);

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
        return runSingleWorker(allocator, 0, config, null, null, &coordinator);
    }

    const sockets = try createReusePortSockets(allocator, config.server_quic, config.threads);
    var sockets_owned = true;
    defer {
        if (sockets_owned) closeSockets(sockets);
        allocator.free(sockets);
    }

    // 集群监听器的 socket 组：与客户端那组同样按 worker_id 一一对应，端口不同。
    // 两组分开 attach 分类器，内核各自按 CID 分流，互不影响。
    const peer_sockets: ?[]std.posix.socket_t = if (config.peer_quic) |peer_config|
        try createReusePortSockets(allocator, peer_config, config.threads)
    else
        null;
    defer if (peer_sockets) |group| {
        if (sockets_owned) closeSockets(group);
        allocator.free(group);
    };

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
            .peer_socket_fd = if (peer_sockets) |group| group[i] else null,
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
        context.peer_socket_fd,
        context.coordinator,
    ) catch |err| {
        std.log.err("Gateway worker {} stopped: {}; terminating to preserve reuseport socket indexes", .{ context.thread_id, err });
        std.process.exit(1);
    };
}

/// 组装并运行单个 Worker：Worker 本体 + 异步 DNS + 直连后端传输。
fn runSingleWorker(
    allocator: std.mem.Allocator,
    thread_id: u8,
    config: *const RuntimeConfig,
    socket_fd: ?std.posix.socket_t,
    peer_socket_fd: ?std.posix.socket_t,
    coordinator: *control.Coordinator,
) !void {
    const registry = backend.TransportRegistry.init(allocator);
    var worker = try worker_rt.GatewayWorker.init(
        allocator,
        config.server_quic,
        thread_id,
        registry,
        &config.realms,
        config.backend_poll_interval_ms,
        .{ .required = config.auth_required, .route = config.auth_route },
        socket_fd,
        if (config.peer_quic) |peer_config|
            .{ .config = peer_config, .socket_fd = peer_socket_fd }
        else
            null,
        coordinator,
    );
    defer worker.deinit();

    const dns_resolver = try foundation.resolver.Cares.init(allocator, worker.event_loop);
    defer dns_resolver.deinit();

    // 每 Worker 一份的后端传输设施：一个 QUIC 客户端（1 socket / 1 picoquic 上下文 /
    // 1 定时器 / 1 份 GSO 缓冲）+ 一份共享接收槽位池。
    //
    // 它必须晚于所有 DirectTransport 销毁——那些 transport 在 deinit 里会把连接从池的
    // 索引上摘掉、把槽位还回来。下面 defer 的 LIFO 顺序正好保证了这一点：
    // transports 的 defer 注册得更晚，因此先执行。
    var backend_pool = try backend.BackendPool.init(allocator, worker.event_loop, config.backend_pool);
    defer backend_pool.deinit();
    // Worker 只用它做一件事：drain 之前问一句"池里有东西吗"，省掉空闲时 O(路由数)
    // 的无效轮询。挂载放在这里而不是 init 参数，是因为池要用 worker.event_loop。
    worker.attachBackendPool(&backend_pool);

    // 直连实例的所有权在工厂里，而不是本函数的栈上——栈上的定长数组一旦装配完就没法
    // 再加，而运行期新增的路由需要有地方放（见 backend/factory.zig）。
    //
    // 它必须早于 backend_pool 销毁：每个 transport 在 deinit 里会把连接从池的索引上
    // 摘掉、把接收槽位还回来。下面两个 defer 的 LIFO 顺序正好保证了这一点。
    var direct_factory = try backend.DirectFactory.init(
        allocator,
        worker.event_loop,
        dns_resolver.asResolver(),
        &backend_pool,
        config.direct,
        config.route_slots.len,
    );
    defer direct_factory.deinit();
    worker.attachBackendRoutes(&config.routes, &direct_factory);

    // 启动期声明的路由预建，行为与从前一致（第一次请求不必等 DNS 解析与握手）。
    // 运行期热加载进来的那些走惰性创建，见 GatewayWorker.findTransport。
    //
    // 每个 ScopedRoute（realm + 路由键）对应一个独立实例（同一 realm 下相同路由键的所有
    // 客户端都命中同一实例）；实例内部维护本服务全部后端副本的连接，而连接底下的传输
    // 设施来自上面那个共享池。
    for (config.routes.entries()) |entry| {
        const instance = try direct_factory.create(entry);
        try worker.registerTransport(.direct, entry.route, backend.BackendTransport.init(backend.DirectTransport, instance));
    }
    try worker.run();
}
