//! 进程级协调器
//!
//! Coordinator 是单个网关进程的「控制面边界」，负责三类进程级状态：
//!   1. 节点生命周期（configured → running → draining → stopped）；
//!   2. 各 Worker 生命周期（starting → running → stopped）及在跑数量；
//!   3. 持有服务发现 provider 和本地异常包交接器 LocalPacketRouter。
//!
//! 它有意「不」参与业务数据面：不转发业务包、不持有 QUIC 连接状态。多节点的注册、
//! 租约、路由下发等能力应通过替换 ServiceDiscovery provider 引入，而不是在此搬运流量。

const std = @import("std");
const discovery_mod = @import("discovery.zig");
const migration = @import("../io/handoff.zig");
const net = @import("../foundation/mod.zig").net;

/// 节点整体生命周期状态。
pub const NodeState = enum(u8) {
    /// 已构造，尚未开始服务。
    configured,
    /// 正常服务，接受新连接。
    running,
    /// 优雅下线：拒绝新连接，保留存量连接。
    draining,
    /// 已停止。
    stopped,
};

/// 单个 Worker 的生命周期状态。
pub const WorkerState = enum(u8) {
    starting,
    running,
    stopped,
};

/// 协调器配置。node_id / advertise_address 面向未来多节点场景；
/// worker_count 和 handoff_queue_capacity 决定本地交接器的规模。
pub const Config = struct {
    node_id: []const u8,
    advertise_address: net.Address,
    worker_count: u16,
    handoff_queue_capacity: usize,
};

/// 进程级控制面：管理本地 Worker 拓扑与包交接，外部 registry 语义交给 ServiceDiscovery。
pub const Coordinator = struct {
    allocator: std.mem.Allocator,
    config: Config,
    discovery: discovery_mod.ServiceDiscovery,
    /// 异常路径的本地包交接器，供各 Worker 共享。
    packet_router: migration.LocalPacketRouter,
    node_state: std.atomic.Value(NodeState) = .init(.configured),
    /// 下标即 worker_id 的状态数组。
    worker_states: []std.atomic.Value(WorkerState),
    /// 当前处于 running 的 Worker 数量。
    running_workers: std.atomic.Value(u16) = .init(0),

    pub fn init(io: std.Io, allocator: std.mem.Allocator, config: Config, discovery: discovery_mod.ServiceDiscovery) !Coordinator {
        if (config.node_id.len == 0) return error.InvalidNodeId;
        if (config.worker_count == 0 or config.worker_count > 256) return error.InvalidWorkerCount;
        if (config.handoff_queue_capacity == 0) return error.InvalidQueueCapacity;

        var packet_router = try migration.LocalPacketRouter.init(
            io,
            allocator,
            config.worker_count,
            config.handoff_queue_capacity,
        );
        errdefer packet_router.deinit();

        const worker_states = try allocator.alloc(std.atomic.Value(WorkerState), config.worker_count);
        for (worker_states) |*worker_state| worker_state.* = .init(.starting);

        return .{
            .allocator = allocator,
            .config = config,
            .discovery = discovery,
            .packet_router = packet_router,
            .worker_states = worker_states,
        };
    }

    pub fn deinit(self: *Coordinator) void {
        self.discovery.deinit();
        self.packet_router.deinit();
        self.allocator.free(self.worker_states);
        self.* = undefined;
    }

    /// 从 configured 进入 running；重复调用或状态不对返回 error.InvalidState。
    pub fn start(self: *Coordinator) !void {
        if (self.node_state.cmpxchgStrong(.configured, .running, .release, .monotonic) != null) {
            return error.InvalidState;
        }
    }

    /// 从 running 进入 draining（优雅下线）。
    pub fn beginDrain(self: *Coordinator) !void {
        if (self.node_state.cmpxchgStrong(.running, .draining, .acq_rel, .acquire) != null) {
            return error.InvalidState;
        }
    }

    /// 无条件置为 stopped，用于进程收尾。
    pub fn stop(self: *Coordinator) void {
        self.node_state.store(.stopped, .release);
    }

    pub fn state(self: *const Coordinator) NodeState {
        return self.node_state.load(.acquire);
    }

    /// 只有 running 状态才接受新连接；draining/stopped 时 Worker 会直接关掉新连接。
    pub fn acceptsNewConnections(self: *const Coordinator) bool {
        return self.state() == .running;
    }

    /// Worker 启动成功后上报，把自己从 starting 切到 running 并计数。
    pub fn workerStarted(self: *Coordinator, worker_id: u8) !void {
        const worker_state = try self.workerStatePtr(worker_id);
        if (worker_state.cmpxchgStrong(.starting, .running, .acq_rel, .acquire) != null) {
            return error.InvalidWorkerState;
        }
        _ = self.running_workers.fetchAdd(1, .release);
    }

    /// Worker 退出时上报。只有之前确实处于 running 才递减计数，避免重复扣减。
    pub fn workerStopped(self: *Coordinator, worker_id: u8) void {
        const worker_state = self.workerStatePtr(worker_id) catch return;
        const previous = worker_state.swap(.stopped, .acq_rel);
        if (previous == .running) _ = self.running_workers.fetchSub(1, .release);
    }

    pub fn runningWorkerCount(self: *const Coordinator) u16 {
        return self.running_workers.load(.acquire);
    }

    /// 供 Worker/Driver 获取共享的本地包交接器。
    pub fn packetRouter(self: *Coordinator) *migration.LocalPacketRouter {
        return &self.packet_router;
    }

    /// 供 DirectTransport 拿到服务发现句柄用于选择后端实例。
    pub fn serviceDiscovery(self: *const Coordinator) discovery_mod.ServiceDiscovery {
        return self.discovery;
    }

    /// 读取当前路由快照。
    pub fn routes(self: *const Coordinator) discovery_mod.Snapshot {
        return self.discovery.snapshot();
    }

    /// 触发一次服务发现刷新，返回是否有新快照装载。
    pub fn refreshRoutes(self: *Coordinator) !bool {
        return self.discovery.refresh();
    }

    /// 按 worker_id 取状态槽指针，越界返回错误。
    fn workerStatePtr(self: *Coordinator, worker_id: u8) !*std.atomic.Value(WorkerState) {
        if (worker_id >= self.worker_states.len) return error.InvalidWorkerId;
        return &self.worker_states[worker_id];
    }
};

test "coordinator enforces node and Worker lifecycle" {
    const routes = [_]discovery_mod.Route{};
    var static_discovery = discovery_mod.StaticDiscovery.init(&routes);
    var coordinator = try Coordinator.init(std.testing.io, std.testing.allocator, .{
        .node_id = "node-a",
        .advertise_address = net.initIp4(.{ 127, 0, 0, 1 }, 8443),
        .worker_count = 2,
        .handoff_queue_capacity = 4,
    }, static_discovery.asDiscovery());
    defer coordinator.deinit();

    try coordinator.start();
    try coordinator.workerStarted(0);
    try coordinator.workerStarted(1);
    try std.testing.expectEqual(@as(u16, 2), coordinator.runningWorkerCount());
    try std.testing.expect(coordinator.acceptsNewConnections());

    try coordinator.beginDrain();
    try std.testing.expect(!coordinator.acceptsNewConnections());
    coordinator.workerStopped(0);
    coordinator.workerStopped(1);
    try std.testing.expectEqual(@as(u16, 0), coordinator.runningWorkerCount());
    coordinator.stop();
    try std.testing.expectEqual(NodeState.stopped, coordinator.state());
}
