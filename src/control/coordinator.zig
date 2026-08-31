//! 进程级协调器
//!
//! Coordinator 是单个网关进程的「控制面边界」，负责三类进程级状态：
//!   1. 节点生命周期（configured → running → draining → stopped）；
//!   2. 各 Worker 生命周期（starting → running → stopped）及在跑数量；
//!   3. 持有本地异常包交接器、SWIM membership runner 与节点间 forward tunnel。
//!
//! 它有意「不」持有 QUIC 连接状态，也不感知后端寻址（那是各 BackendTransport 的内部实现）。
//! 集群组件只维护网关成员视图并转发误投递的原始 UDP 包，与业务 RouteId → Transport
//! 路由属于两个层级；cluster_enabled=false 时不创建额外集群 socket 或线程。

const std = @import("std");
const io_component = @import("../io/mod.zig");
const migration = io_component.handoff;
const forward = io_component.forward;
const membership = @import("membership/mod.zig");
const foundation = @import("../foundation/mod.zig");
const net = foundation.net;
const placement = foundation.placement;
const DeploymentMode = foundation.config.GatewayConfig.Cluster.DeploymentMode;

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

/// 协调器配置。node_id 同时用于 CID v1 与 membership 身份；advertise/forward
/// 地址分别绑定 gossip 和节点间转发。worker_count 与队列容量决定本地交接器规模。
pub const Config = struct {
    /// 是否启用多节点控制面。false 时不创建 gossip socket/线程。
    cluster_enabled: bool = false,
    node_id: u16,
    advertise_address: net.Address,
    forward_address: net.Address,
    worker_count: u16,
    handoff_queue_capacity: usize,
    /// 每个 Worker 的应用消息交接队列深度（见 io/handoff.zig 的 MessageRouter）。
    ///
    /// 与 `handoff_queue_capacity` 分开是因为两者的维度差两个数量级：包队列是
    /// 深队列浅槽位（2KB 槽位，吸收突发重传），应用消息队列是浅队列深槽位
    /// （64KB 槽位，低频、一轮事件循环就排空）。槽位大小**不暴露给配置**——
    /// 它由协议的单帧上限决定，调小就是静默截断。
    message_queue_capacity: usize = 16,
    /// 跨 Worker / 跨节点投递的选路策略（设计文档 §8.5 第二层）。
    ///
    /// 默认亲和：它让"投给某个 dest_id"变成纯计算，同时也让投递回报重新有意义
    /// （广播下发起方无法知道有没有别的位置命中，`unreachable` 就退化成猜测）。
    /// 代价是认证成功后可能要强制重定向一次。
    placement_strategy: placement.Strategy = .affinity,
    /// 客户端侧入口网络模型，决定是否创建 forward 隧道以及是否启用 L4 回程。
    ///
    /// 直接持有模式本身而不是两个布尔开关：能力由 DeploymentMode 的穷尽 switch
    /// 统一回答，新增模式时编译器会强制在同一处补全语义。
    deployment_mode: DeploymentMode = .direct,
    /// 每个 Worker 的回程/入口授权表容量。
    return_path_capacity: usize = 4096,
    /// 回程状态空闲超时，通常与 QUIC idle timeout 一致。
    return_path_timeout_ms: u64 = 30_000,
    /// membership gossip/forward 的当前 HMAC 预共享密钥。
    secret: []const u8 = &.{},
    /// 轮换期旧密钥，仅用于验收入站消息。
    previous_secret: []const u8 = &.{},
    /// 成员表容量上限，供控制面装配 membership 状态机。
    max_nodes: u16 = 1024,
    /// 静态种子由运行期配置解析成结构化地址，runner 启动时自动 join。
    seeds: []const membership.runner.Seed = &.{},
};

/// 进程级控制面：所有 Worker 共享的节点身份、集群关系与生命周期状态。
///
/// 它同时承载本机能力与集群能力。这不是把两件事塞在一起，而是因为三者互相依赖，
/// 拆开只会变成两个结构体互相持有指针：
///
///   - `packet_router` 是本机跨 Worker 交接器。单机模式也需要它兜底内核 reuseport
///     的误分流；同时它又是 forward 隧道收到跨节点报文后的投递出口，
///     因此不属于本机侧或集群侧任何一方独有。
///   - `forward_tunnel` 需要 `membership_runner` 才能把 node_id 解析成地址
///     （见 sendForward），也需要 `packet_router` 才能把报文交给目标 Worker。
///   - `beginDrain` 必须先广播 left 再拒绝新连接，这条顺序约束横跨两侧。
///
/// 两个可选字段只有三种合法组合，由 start() 的装配顺序保证：
///
///   单机（cluster_enabled = false）    membership = null, forward = null
///   集群 + direct                      membership 有值, forward = null
///   集群 + anycast / l4_lb             两者都有值
///
/// 「有 forward 但无 membership」不成立——隧道无法解析目标地址。forwardSender
/// 在运行期再次检查该组合，作为对装配顺序的兜底。
///
/// 线程安全：所有跨线程可见的状态都是原子的，或由内部持有的组件自己同步。
/// Worker 只借用 *Coordinator，不拥有其中任何字段。
pub const Coordinator = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    config: Config,
    /// 本机跨 Worker 包交接器，被两条路径共用：内核 reuseport 误分流的兜底转投，
    /// 以及 forward 隧道收到跨节点报文后的投递。单机模式下同样需要。
    packet_router: migration.LocalPacketRouter,
    /// 本机跨 Worker 应用消息交接器（设计文档 §8.5 第一层的节点内那一半）。
    ///
    /// 与 `packet_router` 的区别不只是尺寸：那个搬的是密文，目标 Worker 喂给
    /// picoquic 就完事；这个搬的是**已解密、已分帧的应用帧**，目标 Worker 要按
    /// `dest_kind` 重新走一遍投递逻辑。单 Worker 部署下它一次也不会被用到，但仍然
    /// 创建——让"投递通路存在"与"部署形态"解耦，避免 threads=1 与 threads>1 走
    /// 两条不同的代码路径。
    message_router: migration.MessageRouter,
    /// SWIM 协议线程的持有者；单机模式为 null。
    /// 它在数据面的唯一消费者是 sendForward（把 node_id 解析成地址并判断可达性）。
    membership_runner: ?membership.runner.Runner = null,
    /// 节点间原始 QUIC 包转发隧道；单机模式与 direct 入口模式均为 null。
    forward_tunnel: ?forward.Tunnel = null,
    node_state: std.atomic.Value(NodeState) = .init(.configured),
    /// 下标即 worker_id 的状态数组。
    worker_states: []std.atomic.Value(WorkerState),
    /// 当前处于 running 的 Worker 数量。
    running_workers: std.atomic.Value(u16) = .init(0),
    /// 是否已请求停机。由信号处理器置位，Worker 在自己线程内观察后进入 drain。
    ///
    /// 信号处理器不能做加锁、分配或阻塞操作，因此这里只翻转一个原子标志，
    /// 真正的停机序列（广播 left、拒绝新连接、等待存量、退出事件循环）
    /// 全部发生在 Worker 线程内。
    shutdown_requested: std.atomic.Value(bool) = .init(false),

    /// 构造进程控制面与本地交接器；集群启用时绑定 membership socket，但尚不启动线程。
    pub fn init(io: std.Io, allocator: std.mem.Allocator, config: Config) !Coordinator {
        // 节点 ID 必须在 1-255 之间
        if (config.node_id == 0) return error.InvalidNodeId;
        // Worker 数量必须在 1-256 之间
        if (config.worker_count == 0 or config.worker_count > 256) return error.InvalidWorkerCount;
        // 队列容量必须大于 0，且 return_path_timeout_ms 必须大于 0
        if (config.handoff_queue_capacity == 0 or config.return_path_capacity == 0 or config.return_path_timeout_ms == 0) return error.InvalidQueueCapacity;
        if (config.message_queue_capacity == 0) return error.InvalidQueueCapacity;
        // return_path_capacity 超过 u32 的最大值或 return_path_timeout_ms 超过 u64 的最大值时，返回错误
        if (config.return_path_capacity > std.math.maxInt(u32) or config.return_path_timeout_ms > std.math.maxInt(u64) / std.time.us_per_ms) return error.InvalidReturnPathConfig;

        var packet_router = try migration.LocalPacketRouter.init(
            io,
            allocator,
            config.worker_count,
            config.handoff_queue_capacity,
        );
        errdefer packet_router.deinit();

        var message_router = try migration.MessageRouter.init(
            io,
            allocator,
            config.worker_count,
            config.message_queue_capacity,
        );
        errdefer message_router.deinit();

        const worker_states = try allocator.alloc(std.atomic.Value(WorkerState), config.worker_count);
        errdefer allocator.free(worker_states);
        for (worker_states) |*worker_state| worker_state.* = .init(.starting);

        var membership_runner: ?membership.runner.Runner = null;
        if (config.cluster_enabled) {
            var seed: u64 = undefined;
            io.random(std.mem.asBytes(&seed));
            membership_runner = try membership.runner.Runner.init(allocator, io, .{
                .node_id = config.node_id,
                .address = config.advertise_address,
                .max_nodes = config.max_nodes,
                .seed = seed,
                .secret = config.secret,
                .previous_secret = config.previous_secret,
                .seeds = config.seeds,
            });
        }
        errdefer if (membership_runner) |*runner| runner.deinit();

        return .{
            .io = io,
            .allocator = allocator,
            .config = config,
            .packet_router = packet_router,
            .message_router = message_router,
            .membership_runner = membership_runner,
            .worker_states = worker_states,
        };
    }

    /// 停止并释放所有集群运行器、本地交接队列和 Worker 状态。
    pub fn deinit(self: *Coordinator) void {
        if (self.forward_tunnel) |*tunnel| tunnel.deinit();
        if (self.membership_runner) |*runner| runner.deinit();
        self.packet_router.deinit();
        self.message_router.deinit();
        self.allocator.free(self.worker_states);
        self.* = undefined;
    }

    /// 从 configured 进入 running，并启动可选的 membership 协议线程。
    /// 启动控制面：按入口模式装配 forward 隧道，再启动 membership 协议线程。
    ///
    /// 装配顺序保证了字段组合的合法性——隧道先于 membership 创建，任一步失败都
    /// 回滚到 configured 并清空已创建的隧道，因此不会留下「有隧道无成员视图」的中间态。
    pub fn start(self: *Coordinator) !void {
        if (self.node_state.cmpxchgStrong(.configured, .running, .release, .monotonic) != null) {
            return error.InvalidState;
        }
        // forward 隧道只服务「报文可能投错节点」的入口模式。direct 模式下客户端
        // 直连固定节点，不会错投，因此连 socket 和接收线程都不必创建。
        if (self.config.cluster_enabled and self.config.deployment_mode.requiresCrossNodeForward()) {
            self.forward_tunnel = forward.Tunnel.initWithPrevious(
                self.io,
                self.config.forward_address,
                self.config.node_id,
                self.config.secret,
                self.config.previous_secret,
                &self.packet_router,
            ) catch |err| {
                self.node_state.store(.configured, .release);
                return err;
            };
            self.forward_tunnel.?.start() catch |err| {
                self.forward_tunnel.?.deinit();
                self.forward_tunnel = null;
                self.node_state.store(.configured, .release);
                return err;
            };
        }
        if (self.membership_runner) |*runner| {
            runner.start() catch |err| {
                if (self.forward_tunnel) |*tunnel| tunnel.deinit();
                self.forward_tunnel = null;
                self.node_state.store(.configured, .release);
                return err;
            };
        }
    }

    /// 广播 left 后从 running 进入 draining（优雅下线）。
    ///
    /// left 的首次发送在状态切换前完成，避免其他节点仍把已拒绝新连接的节点视为 alive。
    pub fn beginDrain(self: *Coordinator) !void {
        if (self.state() != .running) return error.InvalidState;
        if (self.membership_runner) |*runner| try runner.leave();
        if (self.node_state.cmpxchgStrong(.running, .draining, .acq_rel, .acquire) != null) {
            return error.InvalidState;
        }
    }

    /// 停止 membership 线程并无条件置为 stopped，用于进程收尾。
    pub fn stop(self: *Coordinator) void {
        if (self.membership_runner) |*runner| runner.stop();
        if (self.forward_tunnel) |*tunnel| tunnel.stop();
        self.node_state.store(.stopped, .release);
    }

    /// 原子读取当前节点生命周期状态。
    pub fn state(self: *const Coordinator) NodeState {
        return self.node_state.load(.acquire);
    }

    /// 当前进程的静态 node_id，同时用于 membership 与 CID v1。
    pub fn nodeId(self: *const Coordinator) u16 {
        return self.config.node_id;
    }

    /// 只有 running 状态才接受新连接；draining/stopped 时 Worker 会直接关掉新连接。
    pub fn acceptsNewConnections(self: *const Coordinator) bool {
        return self.state() == .running;
    }

    /// 【信号安全】请求进程停机；只翻转原子标志，可从信号处理器调用。
    pub fn requestShutdown(self: *Coordinator) void {
        self.shutdown_requested.store(true, .release);
    }

    /// 是否已请求停机。Worker 在周期回调中观察它并推进 drain 流程。
    pub fn shutdownRequested(self: *const Coordinator) bool {
        return self.shutdown_requested.load(.acquire);
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

    /// 返回已成功启动且尚未停止的 Worker 数量。
    pub fn runningWorkerCount(self: *const Coordinator) u16 {
        return self.running_workers.load(.acquire);
    }

    /// 供 Worker/Driver 获取共享的本地包交接器。
    pub fn packetRouter(self: *Coordinator) *migration.LocalPacketRouter {
        return &self.packet_router;
    }

    /// 供 Worker 获取共享的本机应用消息交接器。
    pub fn messageRouter(self: *Coordinator) *migration.MessageRouter {
        return &self.message_router;
    }

    /// 本节点的 Worker 数量；选址的 Worker 级取模要用它。
    pub fn workerCount(self: *const Coordinator) u16 {
        return self.config.worker_count;
    }

    /// 配置的选路策略。
    pub fn placementStrategy(self: *const Coordinator) placement.Strategy {
        return self.config.placement_strategy;
    }

    /// 成员表容量上限；调用方按它给 `nodeSnapshot` 备缓冲。
    pub fn maxNodes(self: *const Coordinator) u16 {
        return self.config.max_nodes;
    }

    /// 把当前可投递的节点 id 抄进 `buf`，返回填充的那一段。
    ///
    /// **抄一份快照而不是让调用方实时查**：`membership.Table` 的零锁读接口是按
    /// node_id 逐个 lookup 的（遍历只允许 SWIM 线程做），而 HRW 选址需要完整的候选
    /// 集合。每个投递目标都扫一遍全表会让扇出退化成 O(目标数 × max_nodes)。
    ///
    /// 因此调用方应当在自己的周期定时器里刷新，而不是每次投递都调一次。
    /// 快照必然滞后，这正是设计文档 §8.5 记下的那个脆弱点。
    ///
    /// 本节点总是第一个：即使 membership 还没建立视图，选址也要有一个可用的候选，
    /// 否则集群启动窗口内所有推送都算不出 home。
    pub fn nodeSnapshot(self: *const Coordinator, buf: []u16) []const u16 {
        if (buf.len == 0) return buf[0..0];
        buf[0] = self.config.node_id;
        var count: usize = 1;

        const view = self.membershipView() orelse return buf[0..count];
        var node_id: u16 = 1;
        while (node_id < self.config.max_nodes and count < buf.len) : (node_id += 1) {
            if (node_id == self.config.node_id) continue;
            const member = view.lookup(node_id) orelse continue;
            if (!member.isForwardable()) continue;
            buf[count] = node_id;
            count += 1;
        }
        return buf[0..count];
    }

    /// 返回当前成员视图；单机模式未启动 membership 时返回 null。
    pub fn membershipView(self: *const Coordinator) ?*const membership.Table {
        if (self.membership_runner) |*runner| return runner.view();
        return null;
    }

    /// 返回 Worker 使用的跨节点发送接口；不具备转发能力时返回 null。
    ///
    /// 返回 null 是正常状态而非错误：单机模式与 direct 入口模式都不需要转发，
    /// 调用方（ServerDriver）拿到 null 就不建回程表，因此不必知道 deployment_mode。
    ///
    /// 两者同时判空是对装配顺序的兜底：隧道离开 membership 无法把 node_id
    /// 解析成地址，这种组合在 start() 中不会产生，但一旦出现应表现为「无转发能力」
    /// 而不是运行期崩溃。
    pub fn forwardSender(self: *Coordinator) ?forward.Sender {
        if (self.forward_tunnel == null or self.membership_runner == null) return null;
        return .{
            .ptr = self,
            .return_path_enabled = self.config.deployment_mode.requiresReturnPath(),
            .return_path_capacity = self.config.return_path_capacity,
            .return_path_timeout_us = self.config.return_path_timeout_ms * std.time.us_per_ms,
            .sendFn = sendForward,
        };
    }

    fn sendForward(ptr: *anyopaque, kind: migration.TunnelKind, node_id: u16, target_worker_id: u8, source_worker_id: u8, payload: []const u8, client_address: net.Address) !void {
        const self: *Coordinator = @ptrCast(@alignCast(ptr));
        const member = if (self.membership_runner) |*runner|
            runner.view().lookup(node_id) orelse return error.UnknownNode
        else
            return error.ClusterDisabled;
        if (!member.isForwardable()) return error.NodeUnavailable;
        const target = net.withPort(member.address, net.addressPort(self.config.forward_address));
        if (self.forward_tunnel) |*tunnel| {
            try tunnel.sendTo(target, kind, node_id, target_worker_id, source_worker_id, payload, client_address);
        } else {
            return error.ClusterDisabled;
        }
    }

    /// 按 worker_id 取状态槽指针，越界返回错误。
    fn workerStatePtr(self: *Coordinator, worker_id: u8) !*std.atomic.Value(WorkerState) {
        if (worker_id >= self.worker_states.len) return error.InvalidWorkerId;
        return &self.worker_states[worker_id];
    }
};

test "coordinator starts and drains real cluster runners" {
    var coordinator = try Coordinator.init(std.testing.io, std.testing.allocator, .{
        .cluster_enabled = true,
        .node_id = 1,
        .advertise_address = net.initIp4(.{ 127, 0, 0, 1 }, 0),
        .forward_address = net.initIp4(.{ 127, 0, 0, 1 }, 0),
        .worker_count = 1,
        .handoff_queue_capacity = 4,
        .deployment_mode = .l4_lb,
        .return_path_capacity = 8,
        .return_path_timeout_ms = 123,
        .secret = "0123456789abcdef",
    });
    defer coordinator.deinit();
    try coordinator.start();
    try std.testing.expect(coordinator.membershipView() != null);
    const sender = coordinator.forwardSender().?;
    try std.testing.expect(sender.return_path_enabled);
    try std.testing.expectEqual(@as(usize, 8), sender.return_path_capacity);
    try std.testing.expectEqual(@as(u64, 123 * std.time.us_per_ms), sender.return_path_timeout_us);
    try coordinator.beginDrain();
    try std.testing.expectEqual(NodeState.draining, coordinator.state());
    coordinator.stop();
}

test "coordinator enforces node and Worker lifecycle" {
    var coordinator = try Coordinator.init(std.testing.io, std.testing.allocator, .{
        .node_id = 1,
        .advertise_address = net.initIp4(.{ 127, 0, 0, 1 }, 7946),
        .forward_address = net.initIp4(.{ 127, 0, 0, 1 }, 7947),
        .worker_count = 2,
        .handoff_queue_capacity = 4,
    });
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
