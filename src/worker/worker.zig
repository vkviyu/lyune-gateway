//! src/worker/worker.zig
//!
//! 网关工作者 (GatewayWorker)
//!
//! 职责：装配并运行 ServerDriver、持有会话与在途状态、收割后端回程、执行优雅停机。
//! 数据面的其余两半在同目录：
//!
//!   - 上行（分帧 + 逐帧分派 + 上行转发）在 ingress.zig
//!   - 在途映射（回程表 + 认证等待表 + 回收）在 inflight.zig
//!   - 接入认证在 auth.zig
//!
//! 回程留在本文件（drainTransport）：它与上行共享 inflight 里的映射，把两边分到
//! 不同文件反而会让"插入/删除配平"这条不变量更难看清。
//!
//! 线程模型：thread-per-core。每个 Worker 独占一个 OS 线程和一条 xev 事件循环，
//! 本文件里除 running 标志与 notifyPacketHandoff 之外的所有状态都是线程私有的，
//! 因此不加锁。跨线程交互只有两条通道：coordinator 的包交接队列，以及
//! coordinator 上的原子停机标志。

const std = @import("std");

const xev = @import("xev");

const foundation = @import("../foundation/mod.zig");
const err_handler = foundation.err;
const control = @import("../control/mod.zig");
const reactor = @import("../reactor/mod.zig");
const ServerDriver = reactor.server.ServerDriver;
const protocol = @import("../protocol/mod.zig");
const backend = @import("../backend/mod.zig");
const quic = @import("../quic/mod.zig");
const QUICConfig = quic.config.QUICConfig;
const QUICConnection = quic.connection.Connection;
const QUICCallbackEvent = quic.c.CallbackEvent;
const BackendTransport = backend.BackendTransport;
const TransportRegistry = backend.TransportRegistry;
const TransportPath = backend.TransportPath;
const RouteId = backend.RouteId;
const ScopedRoute = backend.ScopedRoute;
const connection = @import("connection.zig");
const ConnectionManager = connection.ConnectionManager;
const ConnectionContext = connection.ConnectionContext;
const client_session = @import("../session/mod.zig");
const SessionHandle = client_session.SessionHandle;
const TransportSession = client_session.TransportSession;
const inflight = @import("inflight.zig");
const ingress = @import("ingress.zig");
const egress = @import("egress.zig");
const peer_link = @import("peer_link.zig");
const push_session = @import("push_session.zig");
const auth = @import("auth.zig");
const lifecycle = @import("lifecycle.zig");

const codec = protocol.codec;

/// 接入认证策略（由配置装配）。实现见 auth.zig。
pub const AuthPolicy = auth.Policy;

/// drain 等待上限：即使 QUIC 空闲超时配得很大，停机也不应无限期挂着。
const max_drain_timeout_us: u64 = 60 * std.time.us_per_s;
const metrics_interval_us: u64 = 60 * std.time.us_per_s;
/// 后端连接的主动维护周期。
///
/// DirectTransport 自己保留精确的指数退避状态；Worker 这里只需低频唤醒每条路由，
/// 让已经到达 retry_at 的连接重新发起握手。若只在真实请求到来时唤醒，后端恢复后
/// 每条路由都会先牺牲一个请求来触发重连。1 秒既把恢复延迟限定在秒级，又避免把
/// 空闲路径重新变成每 10ms 遍历全部路由。
const backend_maintenance_interval_us: u64 = std.time.us_per_s;

/// 成员变更后双查窗口的长度（微秒）。
///
/// 它要覆盖的是**别的节点也看到这次变更**所需的时间，也就是 SWIM 的收敛时间；
/// 收敛靠 gossip，轮数是 O(log N)，几十个节点下是秒级。取 30 秒是留足余量：
/// 窗口偏长的代价只是漂移的那一小部分键多发一份（不会造成重复投递，因为一条连接
/// 只存在于一个位置上，另一个位置查不到索引就什么也不做）；窗口偏短的代价是
/// 消息静默丢失。两边不对称，所以宁可长。
const placement_grace_us: u64 = 30 * std.time.us_per_s;

/// 一次轮询里最多检查多少条连接是否漂移。
///
/// 上限是为了把扩容变成涓流而不是重连风暴：HRW 下加第 N 个节点会让约 1/N 的连接漂移，
/// 8 Worker × 每 10ms 16 条 ≈ 每秒上万条，几万连接的机器数秒排空，而任何一个 10ms
/// 窗口内的重连量都很小。没有上限的话，"扩容"这个动作本身会先造成一次雪崩。
const rehome_per_tick: usize = 16;

/// 集群监听器的装配参数（设计文档 §8.5）。
///
/// 它与面向客户端的监听器**必须是两个 socket、两个 picoquic 上下文**，因为
/// `require_client_auth` 是上下文级开关：合成一个就意味着要么所有客户端都得带证书，
/// 要么对等节点根本不被要求出示证书。分开之后"对等节点"这个身份的判据变成结构性的
/// ——它是从哪个 socket 进来的。
pub const PeerListener = struct {
    /// 集群监听器的 QUIC 配置；必须已开 `require_client_auth` 与 `verify_cert`。
    config: QUICConfig,
    /// 本 Worker 独占的集群 reuseport socket；null 表示由 IoLoop 自建（单 Worker）。
    socket_fd: ?std.posix.socket_t = null,
};

pub const GatewayWorker = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    event_loop: *xev.Loop,
    worker_id: u8,
    coordinator: *control.Coordinator,
    handoff_async: xev.Async,
    handoff_completion: xev.Completion = undefined,
    /// 应用消息交接队列的唤醒句柄（设计文档 §8.5 第一层的节点内那一半）。
    ///
    /// 与 `handoff_async` 分开是因为两条队列的消费动作完全不同：包队列的项要喂给
    /// picoquic，应用消息的项要按 `dest_kind` 重走一遍投递逻辑。合成一个 Async 会
    /// 让每次唤醒都得把两条队列都排空一遍，而它们的到达节奏不相关。
    message_async: xev.Async,
    message_completion: xev.Completion = undefined,
    /// 选址视图：策略 + 本 Worker 的位置 + 集群节点快照（见 foundation/placement.zig）。
    ///
    /// `nodes` 指向 `node_snapshot`、`prev_nodes` 指向 `prev_node_snapshot`，
    /// 都由周期定时器刷新。
    placement: foundation.placement.View,
    /// 节点快照缓冲，启动期按 `max_nodes` 一次分配，运行期只被覆写。
    node_snapshot: []u16,
    /// 成员变更前那份视图的缓冲，双查用（`placement.prev_nodes` 指向它）。
    prev_node_snapshot: []u16,
    /// 每次刷新先把 coordinator 的快照读进这里，再与当前视图比对。
    ///
    /// 三份缓冲而不是两份轮换：轮换会让"本轮写入的那份"正好是 `prev_nodes` 指着的那份，
    /// 于是一次**无变更**的刷新就能把上一份视图覆盖掉——双查窗口会静默失效，
    /// 而症状是扩容期间少量消息丢失，几乎无法定位。
    snapshot_scratch: []u16,
    /// 双查窗口的截止时刻（微秒）；0 表示当前没有开着的窗口。
    placement_grace_until: u64 = 0,
    /// 漂移巡检的扫描游标（`conn_manager.slots` 的下标）。
    ///
    /// 必须留着：每轮有限额，从 0 重新开始的话后半张表永远轮不到，那些连接会一直
    /// 留在错位置上。
    rehome_cursor: usize = 0,
    /// 准入过期巡检游标；与 rehome 分开，两个低频任务互不影响推进速度。
    admission_cursor: usize = 0,
    lifecycle_cursor: usize = 0,
    /// 本节点对客户端提供服务的端口。
    ///
    /// 重定向帧要告诉客户端"去连节点 B 的哪个地址"，而 membership 给出的是 gossip
    /// 地址。集群同构（所有节点用同一个服务端口）是这里的前提，与 `forward_port`
    /// 是集群级配置同一个假设。为 0（临时端口，测试用）时不发重定向——宁可不亲和，
    /// 也不能把一个错地址交给客户端。
    client_port: u16,

    // 底层驱动器 (替代了 endpoint, io_loop, gso_buffer 等)
    server_driver: reactor.server.ServerDriver,
    /// app 装配的外部客户端监听器生命周期端口；具体实现及所有权不进入 Worker。
    /// 当前由 WSS 使用，与 Raw QUIC 共用下面同一份 conn_manager/inflight/auth/egress 状态。
    session_acceptor: ?client_session.Acceptor = null,
    /// 集群监听器；null 表示未启用节点间应用层投递链路（见 PeerListener）。
    ///
    /// 它与 `server_driver` 共用同一条事件循环与同一份 `conn_manager`——连接以
    /// `cnx` 指针为键，两个监听器的连接在同一张表里并存不冲突。区别只在**注册时**：
    /// 从这里进来的连接走 `addPeerNode`，因此带上 `peer_node` 标记。
    peer_driver: ?reactor.server.ServerDriver,
    /// 节点间应用层投递的**出站**链路；null 表示未启用集群链路。
    ///
    /// 与 `peer_driver` 是同一件事的两个方向：那个收，这个发。两边都只在
    /// `cluster.peer_*` 证书齐备时才存在。
    peer_links: ?peer_link.PeerLinks,
    /// 后端共享传输设施；由装配层在两者都建好之后挂进来（见 attachBackendPool）。
    ///
    /// Worker 只用它做一件事：drain 之前问一句"池里有东西吗"。它是**借用**，
    /// 所有权在装配层，而且必须晚于所有 transport 销毁。
    backend_pool: ?*backend.BackendPool = null,
    /// 直连路由声明目录（进程级共享，可运行期追加）；**借用**。
    ///
    /// 它与 `transport_registry` 是"声明"与"实例"的关系：注册表查不到时来这里问一句
    /// "配置里有没有声明过这条路由"，有就地建实例（见 findTransport）。
    route_catalog: ?*const backend.RouteCatalog = null,
    /// 本 Worker 的直连实例工厂与仓库；**借用**，所有权在装配层。
    ///
    /// 实例只能在本 Worker 的线程上创建——它持有绑在这条事件循环上的句柄。
    direct_factory: ?*backend.DirectFactory = null,

    // 业务组件
    conn_manager: ConnectionManager,
    transport_registry: TransportRegistry,
    /// SNI -> RealmId 的解析表（设计文档 §12）。
    ///
    /// **借用一份进程级共享的表**，不是自己的副本：它可以在运行期被追加（新接入方上线，
    /// §12.5），追加靠原子长度发布，见 foundation/realm.zig。持有指针而不是值拷贝正是
    /// 为此——值拷贝会让追加对已经启动的 Worker 不可见。
    realms: *const foundation.realm.Table,
    /// 在途请求表：后端流 -> 客户端流的回程映射，以及等待中的认证请求。
    /// 三条回收路径与上限都封在这个模块里，见 inflight.zig。
    inflight: inflight.Tables,
    /// 下行出口状态：后端主动流的重组缓冲与投递回报的复用缓冲，见 egress.zig。
    egress: egress.Egress,
    /// 转发 `auth_request` 时重编帧用的缓冲。
    ///
    /// 网关要在 body 前面插入 `AuthContext` 前缀（§10.4），长度变了就必须重编帧头。
    /// 启动期一次分配、之后复用：一帧最坏 64KB，放栈上会炸栈，每次现分配又违背
    /// 运行期零分配。认证是每条连接一次的低频路径，一块缓冲足够。
    auth_scratch: []u8,
    /// 把一个上行 datagram 重编成 `.multicast` 帧用的缓冲（设计文档 §6）。
    ///
    /// 重编一次是有意的取舍：`unreliable` 标志位让不可靠投递**复用整套可靠扇出的
    /// 选路机制**（本位置 / 同机其他 Worker / 其他节点），代价只是一次
    /// ≤ `max_datagram_frame_size` 的 memcpy。另写一条不可靠专用的选路会得到两份
    /// 必须同步演化的正确性不变量，那是真正贵的东西。
    ///
    /// 单独一块而不复用 `auth_scratch`：把不相关的功能压在同一块缓冲上，将来任何一方
    /// 改变生命周期假设都会踩到另一方。
    datagram_frame_buf: []u8,
    /// 投给客户端的那一个 datagram 的线格式缓冲。
    ///
    /// 必须与上面那块分开：一次扇出里，帧还要交给转投路径用，而本地投递会为每个成员
    /// 改写通道号——共用一块就会在转投之前把帧写坏。
    ///
    /// 每个成员的通道号可以不同，但负载相同，所以只拷一次负载、逐个改第 2 个字节。
    datagram_out_buf: []u8,
    /// 不可靠通路的可观测量（设计文档 §6）。
    ///
    /// 用计数器而不是日志：datagram 是逐包路径，60Hz × N 个玩家下逐包记日志会把磁盘
    /// 写满。但丢弃**必须**可观测——静默丢弃会表现成"某些玩家偶发卡顿"，那是最难
    /// 定位的一类故障。线程私有，因此不需要原子。
    datagrams_in: u64 = 0,
    datagrams_dropped: u64 = 0,
    auth_policy: AuthPolicy,

    // Backend receive polling timer.
    backend_timer: xev.Timer,
    backend_timer_completion: xev.Completion = undefined,
    backend_poll_interval_ms: u64,
    /// 事件循环是否仍应继续；停机时由本 Worker 线程清零。
    /// 用原子类型是为了让 pub 的 stop() 在被跨线程调用时也定义良好。
    running: std.atomic.Value(bool) = .init(false),
    /// drain 截止时刻（微秒）；0 表示尚未进入 drain。
    drain_deadline_us: u64 = 0,
    /// drain 等待上限（微秒）。
    ///
    /// 取 QUIC 空闲超时：存量连接最多再存活这么久，等满一个空闲超时即可
    /// 认为存量已自然收敛，因此不需要额外的配置项。上限见 max_drain_timeout_us。
    drain_timeout_us: u64,
    /// 上次输出线程本地资源快照的单调时钟；0 表示启动后尚未输出。
    last_metrics_at_us: u64 = 0,
    /// 上次主动推进后端重连状态机的时刻。
    last_backend_maintenance_at_us: u64 = 0,

    /// 创建 Worker 实例：建好事件循环、Driver、交接唤醒句柄与后端轮询定时器，但不启动任何东西。
    ///
    /// socket_fd 的所有权从入参那一刻就转移给本函数——包括所有失败分支，
    /// 因此每条 early return 前都要 closeSocket，否则 reuseport 组会漏 fd。
    /// 成功之后 fd 交给 ServerDriver 持有。
    pub fn init(allocator: std.mem.Allocator, config: QUICConfig, thread_id: u8, transport_registry: TransportRegistry, realms: *const foundation.realm.Table, backend_poll_interval_ms: u64, auth_policy: AuthPolicy, socket_fd: ?std.posix.socket_t, peer_listener: ?PeerListener, coordinator: *control.Coordinator) !Self {

        // GatewayWorker owns a supplied socket from entry, even if setup fails early.
        const event_loop = allocator.create(xev.Loop) catch |err| {
            closeSocket(socket_fd);
            return err;
        };
        event_loop.* = xev.Loop.init(.{}) catch {
            allocator.destroy(event_loop);
            closeSocket(socket_fd);
            return error.LoopInitFailed;
        };
        errdefer {
            event_loop.deinit();
            allocator.destroy(event_loop);
        }

        // 2. 创建 Server Driver
        // 注意：Config, ThreadID, Loop 都传给 Driver
        var server_driver = try ServerDriver.init(
            allocator,
            config,
            coordinator.nodeId(),
            thread_id,
            event_loop,
            socket_fd,
            coordinator.packetRouter(),
            coordinator.forwardSender(),
        );
        errdefer server_driver.deinit();

        // 集群监听器：socket 的所有权与客户端那条一样交给 ServerDriver，
        // 失败时的处置也一致（见上面 server_driver 那段）。
        var peer_driver: ?reactor.server.ServerDriver = null;
        if (peer_listener) |listener| {
            peer_driver = try ServerDriver.init(
                allocator,
                listener.config,
                coordinator.nodeId(),
                thread_id,
                event_loop,
                listener.socket_fd,
                coordinator.packetRouter(),
                coordinator.forwardSender(),
            );
        }
        errdefer if (peer_driver) |*driver| driver.deinit();

        // 出站链路与集群监听器共用同一份证书配置：两个方向证明的是同一个身份。
        // 拨号端口取监听端口（集群同构，全集群同一个端口）。
        var peer_links: ?peer_link.PeerLinks = null;
        if (peer_listener) |listener| {
            peer_links = try peer_link.PeerLinks.init(
                allocator,
                event_loop,
                coordinator,
                listener.config,
                .{ .peer_port = listener.config.bind_port },
            );
        }
        errdefer if (peer_links) |*links| links.deinit();

        var handoff_async = try xev.Async.init();
        errdefer handoff_async.deinit();

        var message_async = try xev.Async.init();
        errdefer message_async.deinit();

        const node_snapshot = try allocator.alloc(u16, @max(coordinator.maxNodes(), 1));
        errdefer allocator.free(node_snapshot);
        node_snapshot[0] = coordinator.nodeId();

        const prev_node_snapshot = try allocator.alloc(u16, node_snapshot.len);
        errdefer allocator.free(prev_node_snapshot);

        const snapshot_scratch = try allocator.alloc(u16, node_snapshot.len);
        errdefer allocator.free(snapshot_scratch);

        const backend_timer = xev.Timer.init() catch return error.TimerInitFailed;
        errdefer backend_timer.deinit();

        // 会话槽位池与 QUIC 层共用同一个上限，避免出现"picoquic 接了但业务层放不下"。
        var conn_manager = try ConnectionManager.init(allocator, config.base.max_connections, coordinator.nodeId(), thread_id);
        errdefer conn_manager.deinit();

        // 投递回报的编码缓冲与流式会话表在这里一次分配好，之后运行期不再申请。
        // 会话号带 worker_id，所以本节点内不会撞号（见 push_session.Table.nextId）。
        var egress_state = try egress.Egress.init(allocator, thread_id);
        errdefer egress_state.deinit();

        const auth_scratch = try allocator.alloc(u8, protocol.frame.OPEN_HEADER_SIZE + protocol.frame.MAX_BODY_SIZE);
        errdefer allocator.free(auth_scratch);

        // 一个 OPEN 帧头 + 一个单目标的组标识前缀（2 字节 count + 8 字节组标识）
        // + 一整个 datagram 负载。按 `max_datagram_frame_size` 精确定尺：那个数就是
        // 对端能发的上限，所以这块缓冲不可能不够。
        const datagram_frame_buf = try allocator.alloc(
            u8,
            protocol.frame.OPEN_HEADER_SIZE + 2 + protocol.body.dest_id_size +
                config.base.max_datagram_frame_size,
        );
        errdefer allocator.free(datagram_frame_buf);

        const datagram_out_buf = try allocator.alloc(
            u8,
            protocol.datagram.header_size + config.base.max_datagram_frame_size,
        );
        errdefer allocator.free(datagram_out_buf);

        return .{
            .allocator = allocator,
            .event_loop = event_loop,
            .worker_id = thread_id,
            .coordinator = coordinator,
            .handoff_async = handoff_async,
            .message_async = message_async,
            // 快照先只放本节点：membership 视图要等 SWIM 跑起来，而在那之前
            // 收到的推送同样必须能算出一个可用的 home。
            .placement = .{
                .strategy = coordinator.placementStrategy(),
                .self = .{ .node_id = coordinator.nodeId(), .worker_id = thread_id },
                .worker_count = coordinator.workerCount(),
                .nodes = node_snapshot[0..1],
            },
            .node_snapshot = node_snapshot,
            .prev_node_snapshot = prev_node_snapshot,
            .snapshot_scratch = snapshot_scratch,
            .client_port = config.bind_port,
            .server_driver = server_driver,
            .peer_driver = peer_driver,
            .peer_links = peer_links,
            .conn_manager = conn_manager,
            .transport_registry = transport_registry,
            .realms = realms,
            .inflight = try inflight.Tables.init(allocator),
            .egress = egress_state,
            .auth_scratch = auth_scratch,
            .datagram_frame_buf = datagram_frame_buf,
            .datagram_out_buf = datagram_out_buf,
            .auth_policy = auth_policy,
            .backend_timer = backend_timer,
            .backend_poll_interval_ms = backend_poll_interval_ms,
            .drain_timeout_us = @min(
                config.base.idle_timeout_ms *| std.time.us_per_ms,
                max_drain_timeout_us,
            ),
        };
    }

    /// 释放资源。释放顺序是有约束的，不能随意调换：
    ///
    /// 1. 先摘掉交接队列的 notifier——别的 Worker 线程持有它，摘掉之后才能保证
    ///    没有人再碰本对象的 handoff_async。
    /// 2. server_driver 必须早于 event_loop：它的 completion 都挂在这条 loop 上。
    pub fn deinit(self: *Self) void {
        self.coordinator.packetRouter().setNotifier(self.worker_id, null) catch {};
        self.coordinator.messageRouter().setNotifier(self.worker_id, null) catch {};
        self.inflight.deinit();
        self.egress.deinit();
        self.allocator.free(self.auth_scratch);
        self.allocator.free(self.datagram_frame_buf);
        self.allocator.free(self.datagram_out_buf);
        self.allocator.free(self.node_snapshot);
        self.allocator.free(self.prev_node_snapshot);
        self.allocator.free(self.snapshot_scratch);
        self.transport_registry.deinit();
        self.backend_timer.deinit();
        self.message_async.deinit();
        self.handoff_async.deinit();
        self.conn_manager.deinit();
        if (self.peer_links) |*links| links.deinit();
        if (self.peer_driver) |*driver| driver.deinit();
        self.server_driver.deinit();
        self.event_loop.deinit();
        self.allocator.destroy(self.event_loop);
    }

    /// 启动工作循环，阻塞直到事件循环被停掉（见 pollShutdown）。
    ///
    /// 启动顺序有约束：
    /// - running 必须最先置位，两个定时/唤醒回调都靠它决定 rearm 还是 disarm。
    /// - notifier 与 handoff_async.wait 必须早于 workerStarted：一旦对外宣告本
    ///   Worker 在跑，别的线程随时可能往交接队列 push 并调 notify。
    /// - setCallbacks 必须早于 server_driver.start()，否则握手完成的连接无处上报。
    pub fn run(self: *Self) !void {
        self.running.store(true, .release);
        defer self.running.store(false, .release);

        try self.coordinator.packetRouter().setNotifier(self.worker_id, .{
            .ptr = self,
            .notifyFn = notifyPacketHandoff,
        });
        defer self.coordinator.packetRouter().setNotifier(self.worker_id, null) catch {};
        self.handoff_async.wait(self.event_loop, &self.handoff_completion, Self, self, handoffCallback);

        try self.coordinator.messageRouter().setNotifier(self.worker_id, .{
            .ptr = self,
            .notifyFn = notifyMessageHandoff,
        });
        defer self.coordinator.messageRouter().setNotifier(self.worker_id, null) catch {};
        self.message_async.wait(self.event_loop, &self.message_completion, Self, self, messageCallback);

        try self.coordinator.workerStarted(self.worker_id);
        defer self.coordinator.workerStopped(self.worker_id);

        // 1. 注册业务回调到 Driver
        self.server_driver.setCallbacks(self, handleNewConnection, ingress.handleStreamData, handleConnectionClose);
        self.server_driver.setStreamControlCallback(ingress.handleStreamControl);
        // 不可靠通路只对客户端开放（设计文档 §6）。集群监听器刻意不注册它：跨节点那一跳
        // 走的是对等链路上的可靠 `.multicast` 帧，由收方节点在本地再落成 datagram。
        self.server_driver.setDatagramCallback(ingress.handleDatagram);

        // 集群监听器只有"新连接"这一个回调不同：从它进来的连接必须带上 peer_node
        // 标记。流数据与关闭两个回调完全共用——它们按 cnx 指针在同一张
        // conn_manager 里查上下文，不关心连接是从哪个监听器进来的。
        if (self.peer_driver) |*driver| {
            driver.setCallbacks(self, handlePeerConnection, ingress.handleStreamData, handleConnectionClose);
            driver.setStreamControlCallback(ingress.handleStreamControl);
        }

        // 2. 启动 Driver (非阻塞)
        self.server_driver.start();
        if (self.session_acceptor) |acceptor| try acceptor.start();
        if (self.peer_driver) |*driver| {
            driver.start();
            std.log.info("[CLUSTER] peer listener started on worker {}", .{self.worker_id});
        }
        self.resolveRegisteredTransports();
        self.scheduleBackendPoll(self.backend_poll_interval_ms);

        std.log.info("GatewayWorker loop running...", .{});

        // 3. 运行主循环 (阻塞)
        try self.event_loop.run(.until_done);
    }

    /// 停止收发：清掉 running 并把 socket 从事件循环注销。
    ///
    /// 注意它不退出事件循环——真正的 loop.stop() 在 pollShutdown 里，因为要等
    /// 存量连接 drain 完。running 用原子类型正是为了让本函数在被其他线程调用时
    /// 也定义良好（当前生产路径只由本 Worker 线程调用）。
    pub fn stop(self: *Self) void {
        self.running.store(false, .release);
        if (self.session_acceptor) |acceptor| acceptor.stopAccepting();
        self.server_driver.stop();
        if (self.peer_driver) |*driver| driver.stop();
    }

    /// 挂上后端共享传输设施。
    ///
    /// 单独一个 setter 而不是 init 参数：池要用 `worker.event_loop` 来建自己的 socket
    /// 与定时器，所以它只能在 Worker 之后诞生——init 参数会形成循环依赖。
    pub fn attachBackendPool(self: *Self, shared: *backend.BackendPool) void {
        self.backend_pool = shared;
    }

    /// 挂上与本 Worker 同线程的外部客户端监听器。所有权仍在 app；必须在 run 前调用。
    pub fn attachSessionAcceptor(self: *Self, acceptor: client_session.Acceptor) void {
        std.debug.assert(self.session_acceptor == null);
        self.session_acceptor = acceptor;
    }

    /// 生成具体客户端 binding 所需的传输无关事件端口。
    pub fn sessionHandler(self: *Self) client_session.Handler {
        return .{ .ptr = self, .vtable = &session_handler_vtable };
    }

    /// 挂上直连路由目录与实例工厂。
    ///
    /// 与 `attachBackendPool` 同理：工厂要用 `worker.event_loop`，只能在 Worker 之后诞生。
    pub fn attachBackendRoutes(self: *Self, route_catalog: *const backend.RouteCatalog, factory: *backend.DirectFactory) void {
        self.route_catalog = route_catalog;
        self.direct_factory = factory;
    }

    /// 找一条路由的 transport，注册表里没有就按目录声明就地建一个。
    ///
    /// **只在交换的起点调用**（`.service` 的 OPEN、认证委托），不能在交换中途调用：
    /// 中途查不到说明这条路由在交换进行中消失了，那是异常，就地新建一个空实例只会把
    /// 半条字节流发给一个全新的后端连接。
    ///
    /// 惰性建实例是热加载的落点（设计文档 §12.5）：信号线程只往共享目录里追加声明，
    /// 实例由第一个真正用到它的 Worker 在自己线程上创建。顺带的好处是没有那个 realm
    /// 流量的 Worker 不会为它白付一个 socket 与若干后端连接。
    pub fn findTransport(self: *Self, scope: backend.ScopedRoute) ?BackendTransport {
        if (self.transport_registry.find(scope)) |found| return found;

        const catalog = self.route_catalog orelse return null;
        const entry = catalog.find(scope) orelse return null;
        const factory = self.direct_factory orelse return null;

        const instance = factory.create(entry) catch |err| {
            std.log.warn("[ROUTE] cannot create transport for realm={} group=0x{x} route=0x{x}: {s}", .{
                scope.realm,
                entry.route.route.group,
                entry.route.route.route_key,
                @errorName(err),
            });
            return null;
        };
        const erased = BackendTransport.init(backend.DirectTransport, instance);
        self.registerTransport(.direct, scope, erased) catch |err| {
            // create 与 register 在同一 Worker 线程内紧邻发生；此时实例一定还是工厂最后
            // 一个槽位，可以安全回滚。否则一次临时登记失败会让每次重试都再泄漏一个
            // 定容槽位，最终把与故障无关的所有热加载路由一起锁死。
            factory.discardLast(instance);
            std.log.warn("[ROUTE] cannot register transport for realm={}: {s}", .{ scope.realm, @errorName(err) });
            return null;
        };
        std.log.info("[ROUTE] transport created on demand: realm={} group=0x{x} route=0x{x}", .{
            scope.realm,
            entry.route.route.group,
            entry.route.route.route_key,
        });
        return erased;
    }

    /// 观察停机请求并推进 drain。
    ///
    /// 由后端轮询定时器在本 Worker 线程内调用，因此整套停机序列都发生在
    /// 拥有这些状态的线程里——信号处理器只负责翻转一个原子标志。
    ///
    /// 顺序上先广播 left 并停止接受新连接，再等存量连接自然结束，最后才退出
    /// 事件循环；反过来会让节点在集群仍认为它健康时就停止服务。
    fn pollShutdown(self: *Self) void {
        if (!self.coordinator.shutdownRequested()) return;

        if (self.drain_deadline_us == 0) {
            // beginDrain 会广播 left 并把节点置为 draining。多 Worker 并发调用时
            // 只有第一个成功，其余返回 InvalidState，这里忽略即可。
            self.coordinator.beginDrain() catch {};
            self.drain_deadline_us = quic.c.currentTime() + self.drain_timeout_us;
            std.log.info("[SHUTDOWN] worker {} draining, up to {}ms", .{
                self.worker_id,
                self.drain_timeout_us / std.time.us_per_ms,
            });
            return;
        }

        const remaining = self.conn_manager.count();
        if (remaining > 0 and quic.c.currentTime() < self.drain_deadline_us) return;

        std.log.info("[SHUTDOWN] worker {} stopping with {} connection(s) left", .{ self.worker_id, remaining });
        self.stop();
        self.event_loop.stop();
    }

    /// 注册一个后端传输：path 决定直连还是中继，route 是 realm + 客户端帧里的
    /// group+route_key。transport 的所有权转移给 registry，由 deinit 统一释放。
    pub fn registerTransport(self: *Self, path: TransportPath, route: ScopedRoute, transport: BackendTransport) !void {
        try self.transport_registry.register(path, route, transport);
    }

    /// 对所有已注册的 transport 触发一次异步解析与建连。
    ///
    /// 在 run() 里提前做，避免第一个客户端请求还要等 DNS 与握手。结果只经
    /// onBackendReady 记日志——建连失败不影响 Worker 启动，后续请求会重试。
    fn resolveRegisteredTransports(self: *Self) void {
        self.resolvePathTransports(.direct);
        self.resolvePathTransports(.relay);
    }

    fn resolvePathTransports(self: *Self, path: TransportPath) void {
        var it = self.transport_registry.iterator(path);
        while (it.next()) |entry| {
            entry.value_ptr.resolve(entry.key_ptr.route, onBackendReady, self);
        }
    }

    /// 低频推进全部已注册 transport 的重连状态机。
    ///
    /// callback 刻意传 null：启动阶段只登记一次可观测回调；维护阶段若在 connecting
    /// 状态反复登记，会让等待列表随轮询次数增长。DirectTransport.resolve 对 ready /
    /// connecting / 尚在退避期的连接都是无副作用检查。
    fn maintainBackendConnections(self: *Self, now: u64) void {
        if (self.last_backend_maintenance_at_us != 0 and
            now -| self.last_backend_maintenance_at_us < backend_maintenance_interval_us)
        {
            return;
        }
        self.last_backend_maintenance_at_us = now;
        self.maintainPathTransports(.direct);
        self.maintainPathTransports(.relay);
    }

    fn maintainPathTransports(self: *Self, path: TransportPath) void {
        var it = self.transport_registry.iterator(path);
        while (it.next()) |entry| {
            entry.value_ptr.resolve(entry.key_ptr.route, null, null);
        }
    }

    // ========================================================================
    // 业务逻辑回调 (由 Driver 触发)
    // ========================================================================

    const session_handler_vtable: client_session.Handler.VTable = .{
        .accept = acceptTransportSession,
        .stream_data = handleSessionData,
        .control = handleSessionControl,
        .ephemeral = handleSessionEphemeral,
        .closed = handleSessionClose,
        .now_us = sessionNow,
    };

    fn workerFromSessionHandler(ptr: *anyopaque) *Self {
        return @ptrCast(@alignCast(ptr));
    }

    fn acceptTransportSession(ptr: *anyopaque, transport_session: TransportSession, server_name: ?[]const u8) anyerror!SessionHandle {
        return workerFromSessionHandler(ptr).acceptClientSession(transport_session, server_name);
    }

    fn handleSessionData(ptr: *anyopaque, handle: SessionHandle, stream_id: u64, bytes: []const u8, fin: bool) void {
        ingress.handleSessionData(workerFromSessionHandler(ptr), handle, stream_id, bytes, fin);
    }

    fn handleSessionControl(ptr: *anyopaque, handle: SessionHandle, stream_id: u64, event: client_session.StreamControl) void {
        ingress.handleSessionControl(workerFromSessionHandler(ptr), handle, stream_id, event);
    }

    fn handleSessionEphemeral(ptr: *anyopaque, handle: SessionHandle, bytes: []const u8) void {
        ingress.handleEphemeral(workerFromSessionHandler(ptr), handle, bytes);
    }

    fn handleSessionClose(ptr: *anyopaque, handle: SessionHandle) void {
        const self = workerFromSessionHandler(ptr);
        self.closeClientSession(handle, .transport_closed);
        std.log.info("[CONN] client session closed: worker={} slot={} generation={}", .{
            self.worker_id,
            handle.slot,
            handle.generation,
        });
    }

    fn sessionNow(_: *anyopaque) u64 {
        return quic.c.currentTime();
    }

    pub const AcceptSessionError = ConnectionManager.Error || error{
        NotAcceptingConnections,
        UnregisteredRealm,
    };

    /// 注册一条客户端接入会话。Raw QUIC 与 WSS 都只能经这一处决定 drain 门禁、realm
    /// 和 ConnectionManager 槽位，避免第二种传输复制出一套稍有差异的准入逻辑。
    pub fn acceptClientSession(self: *Self, transport: TransportSession, server_name: ?[]const u8) AcceptSessionError!SessionHandle {
        if (!self.coordinator.acceptsNewConnections()) return error.NotAcceptingConnections;
        const realm = self.realms.resolve(server_name) orelse return error.UnregisteredRealm;
        const ctx = try self.conn_manager.addSession(transport, realm, self);
        std.log.info("[CONN] new {s} session: worker={} slot={} generation={} realm={}", .{
            @tagName(ctx.transport.kind()),
            self.worker_id,
            ctx.session_handle.slot,
            ctx.session_handle.generation,
            realm,
        });
        return ctx.session_handle;
    }

    /// 新连接建立（握手完成）。
    ///
    /// drain 期间直接关掉：让客户端立刻去重连别的节点，比把新连接挂在一个正在
    /// 退出的进程上更好——后者会一直等到空闲超时才被动断开。
    ///
    /// realm 在这里定死。SNI 是**握手完成后**才可读的，而它由证书链背书，因此这是
    /// 唯一可信的隔离域来源——帧里的任何字段都是客户端自称的（设计文档 §12.3）。
    /// 解析不出 realm 就关连接：多 realm 部署下一个拼错的域名不该静默落进别人的
    /// 命名空间。
    ///
    /// 注册进 conn_manager 后，业务状态就以 conn.inner 这个稳定的 C 句柄为键，
    /// 因为回调传进来的 conn 包装只在本次调用期内有效。
    fn handleNewConnection(ud: ?*anyopaque, conn: *QUICConnection) void {
        const self = castSelf(ud);
        _ = self.acceptClientSession(quic.session.init(conn.inner), conn.getServerName()) catch |err| {
            // 没有上下文，这条连接的所有流数据都会被静默丢弃，不如立刻关掉：
            // 让客户端去连别的节点，而不是挂在这里等空闲超时。
            std.log.warn("[CONN] refusing connection: {s}", .{@errorName(err)});
            conn.close();
            return;
        };
    }

    /// 集群监听器上的新连接：对端已经在 TLS 层证明了自己是网关节点。
    ///
    /// 这个回调**没有 realm 解析**，而且这不是遗漏：集群监听器的 SNI 不代表任何 realm，
    /// 对等节点的每一帧自带 realm（`FrameHeader.realmHint()`）。
    ///
    /// 它也**没有身份校验代码**，同样不是遗漏：能走到这里就意味着 mTLS 握手已经完成，
    /// 而这个端口要求由私有集群 CA 签发的客户端证书（`require_client_auth`）。
    /// "握手成功"与"对端是网关节点"因此是同一件事，不需要 nonce、HMAC、防重放窗口
    /// 或时钟同步（设计文档 §8.5）。
    ///
    /// drain 期间同样拒绝：本节点正在退出，接进来的投递没有意义。
    fn handlePeerConnection(ud: ?*anyopaque, conn: *QUICConnection) void {
        const self = castSelf(ud);
        if (!self.coordinator.acceptsNewConnections()) {
            conn.close();
            return;
        }

        _ = self.conn_manager.addPeerNode(conn, self) catch |err| {
            std.log.warn("[CLUSTER] refusing peer link: {s}", .{@errorName(err)});
            conn.close();
            return;
        };
        const cid = conn.getLocalConnectionId();
        std.log.info("[CLUSTER] peer link established: {x}", .{cid.id[0..cid.id_len]});
    }

    /// 连接关闭
    fn handleConnectionClose(ud: ?*anyopaque, conn: *QUICConnection, event: QUICCallbackEvent) void {
        const self = castSelf(ud);
        const handle = self.conn_manager.handleForRawQuic(conn.inner) orelse return;
        const ctx = self.conn_manager.getByHandle(handle).?;
        const reason = ctx.offline_reason orelse switch (event) {
            .application_close => protocol.body.SessionLifecycle.Reason.application_closed,
            .stateless_reset => .stateless_reset,
            else => .transport_closed,
        };
        // picoquic 按值返回 connection id；必须让结构体副本活到格式化结束，不能从
        // 一个辅助函数返回指向其局部副本的切片（那会在关闭日志里打印栈垃圾）。
        const cid = conn.getLocalConnectionId();
        self.closeClientSession(handle, reason);
        std.log.info("[CONN] closed: {x}, reason: {s}", .{ cid.id[0..cid.id_len], @tagName(event) });
    }

    /// 收敛任意客户端传输会话。调用时底层 transport 对象必须仍然存活；本函数返回后
    /// SessionHandle 已失效，WSS listener 才可以释放 SSL/socket/队列对象。
    pub fn closeClientSession(self: *Self, handle: SessionHandle, reason: protocol.body.SessionLifecycle.Reason) void {
        const ctx = self.conn_manager.getByHandle(handle) orelse return;
        lifecycle.publishOffline(self, ctx, ctx.offline_reason orelse reason);
        self.finishOpenExchanges(ctx);
        self.inflight.purge(.{ .session = handle });
        self.conn_manager.removeSession(handle);
    }

    /// 把一条连接上还没收尾的交换逐条结束掉。
    fn finishOpenExchanges(self: *Self, ctx: *ConnectionContext) void {
        var it = ctx.inbound_exchanges.valueIterator();
        while (it.next()) |entry| {
            if (entry.backend) |stream| self.finishBackendStream(stream);
        }
    }

    /// 给后端流补一个空的 fin 分片，让它正常收尾。
    ///
    /// 尽力而为：找不到 transport 或发送失败都只记日志——此时客户端连接已经
    /// 不在了，没有人可以被通知，后端最终会自己超时。
    ///
    /// pub 是给 ingress.zig 用的：上行路径在交换作废或客户端关流时也要收尾后端流。
    pub fn finishBackendStream(self: *Self, stream: connection.BackendStream) void {
        const transport = self.transport_registry.find(stream.scope) orelse return;
        _ = transport.sendStream(stream.scope.route, stream.key.stream, &.{}, true) catch |err| {
            err_handler.reportError(.session, "Failed to finish backend stream", err);
        };
    }

    /// 后端轮询的主体：先排空响应，再做一次摊薄的过期回收。
    fn drainBackendResponses(self: *Self) bool {
        // 共享接收池一个待取槽位都没有时直接返回。
        //
        // 下面那两趟遍历是 O(路由数)，而路由数是 realm 数 × 服务数：200 条路由 ×
        // 每 10ms 一次 tick = 每秒 2 万次什么也没捞到的 `receive()`。所有后端响应
        // 都经由这一个池，所以"池空"就等价于"两条路径都没东西"，判据是精确的。
        if (self.backend_pool) |shared| {
            if (shared.idle()) {
                return self.expireInflight(quic.c.currentTime());
            }
        }

        self.drainTransportPath(.direct);
        self.drainTransportPath(.relay);

        // 已经进入接收队列的响应也是活动。先让 drainTransport 刷新对应映射，再扫描，
        // 避免一个刚在 deadline 前到达的响应因轮询顺序被误判为空闲。
        _ = self.expireInflight(quic.c.currentTime());
        return true;
    }

    /// 后端没有任何可读事件时，连接层未必能立刻知道对端进程已经消失：请求可能已被
    /// ACK，但应用响应永远不会到来。到达 inflight deadline 后必须主动结束客户端流，
    /// 而不是只删映射让客户端继续挂到自己的超时。
    fn expireInflight(self: *Self, now: u64) bool {
        if (!self.inflight.expirationDue(now)) return false;

        var expired_any = false;
        var routes: [64]inflight.ExpiredRoute = undefined;
        while (true) {
            const count = self.inflight.takeExpiredRoutes(now, &routes);
            if (count != 0) expired_any = true;
            for (routes[0..count]) |expired| {
                switch (expired.route.target) {
                    .client => |target| self.replyControl(target.session, target.stream_id, .gateway_error, "backend response timeout"),
                    .discard => {},
                }
                if (self.transport_registry.findById(expired.key.transport)) |transport| {
                    transport.invalidateStream(expired.key.stream);
                }
            }
            if (count < routes.len) break;
        }

        var auths: [64]inflight.ExpiredAuth = undefined;
        while (true) {
            const count = self.inflight.takeExpiredAuths(now, &auths);
            if (count != 0) expired_any = true;
            for (auths[0..count]) |expired| {
                var pending = expired.pending;
                if (!pending.response_suppressed) {
                    self.replyControl(pending.client_session, pending.client_stream_id, .auth_failure, "authentication backend timeout");
                }
                pending.buffer.deinit(self.allocator);
                if (self.transport_registry.findById(expired.key.transport)) |transport| {
                    transport.invalidateStream(expired.key.stream);
                }
            }
            if (count < auths.len) break;
        }

        self.inflight.refreshExpiryDeadline();
        return expired_any;
    }

    fn drainTransportPath(self: *Self, path: TransportPath) void {
        var it = self.transport_registry.iterator(path);
        while (it.next()) |entry| {
            self.drainTransport(entry.value_ptr.*, entry.key_ptr.realm);
        }
    }

    /// 排空一个 transport 的接收队列，把响应分派回对应的客户端流。
    ///
    /// 四种归属，判据全部是**网关自己的表**而不是帧内容——否则后端可以把一个数据
    /// 响应伪装成认证成功：
    ///
    /// 1. 在认证等待表里 → 认证响应，累积后判定
    /// 2. 在回程映射里   → 客户端请求的响应，原样字节写回，不解析
    /// 3. 后端主动开的流 → `.peer` / `.multicast` 推送，交给 egress 分帧投递
    /// 4. 都不是         → 孤儿响应（客户端早已断开且条目已回收），记日志丢弃
    ///
    /// 3 和 4 都查不到映射，靠 `peer_initiated` 区分。不区分的话，客户端断开高峰期的
    /// 孤儿响应会被当成畸形推送刷日志，而真正的推送会被当成孤儿静默丢弃。
    ///
    /// `realm` 来自注册表键（由 drainTransportPath 取），推送只能投给同 realm 的连接。
    fn drainTransport(self: *Self, transport: BackendTransport, realm: foundation.realm.RealmId) void {
        while (true) {
            const event = transport.receive() catch |err| {
                err_handler.reportError(.session, "Failed to receive backend response", err);
                self.failTransportRequests(transport);
                return;
            } orelse break;
            // data 是 transport 接收池槽位的借用，必须归还，否则池会被逐渐占满。
            defer transport.releaseRecv(event);

            // 句柄只在这个 transport 实例内部唯一，查表必须用带实例身份的复合键。
            const key = inflight.StreamKey{ .transport = transport.id(), .stream = event.stream_id };

            if (event.kind != .data) {
                self.handleBackendStreamControl(key, event);
                continue;
            }

            if (self.inflight.hasAuth(key)) {
                auth.collectAuthResponse(self, key, event.data, event.is_fin);
                continue;
            }

            const route = self.inflight.lookupRoute(key) orelse {
                if (event.peer_initiated) {
                    egress.handlePush(self, transport, realm, event);
                } else {
                    std.log.warn("[ROUTE] orphan backend response: backend_stream={}", .{event.stream_id});
                }
                continue;
            };

            switch (route.target) {
                .discard => {},
                .client => |target| {
                    // 客户端可能在后端响应到达前就断开。此时传输实现已经释放会话，
                    // 必须确认它仍在管理器中，否则在途表里的旧身份会命中失效资源。
                    const client_ctx = self.conn_manager.getByHandle(target.session) orelse {
                        std.log.warn("[ROUTE] client gone before backend response: backend_stream={}", .{event.stream_id});
                        self.inflight.closeRoute(key);
                        continue;
                    };

                    client_ctx.transport.write(target.stream_id, event.data, event.is_fin) catch |err| {
                        err_handler.reportError(.session, "Failed to write backend response to client", err);
                        self.inflight.closeRoute(key);
                        continue;
                    };
                },
            }

            if (event.is_fin) {
                self.inflight.closeRoute(key);
            } else {
                // 成功写回一个完整后端事件才刷新；发送失败会走上面的关闭分支。
                _ = self.inflight.touchRoute(key, quic.c.currentTime());
            }
        }
    }

    /// 后端对单条流做了异常终止。它是这个交换的局部失败，不应放大成整条后端连接
    /// 故障；同时也绝不能伪装成正常空 FIN，否则 required 请求会被误判成功。
    fn handleBackendStreamControl(self: *Self, key: inflight.StreamKey, event: backend.transport.TransportRecv) void {
        const reason = switch (event.kind) {
            .stream_reset => "backend reset stream",
            .stop_sending => "backend stopped request stream",
            .data => unreachable,
        };

        if (self.inflight.takeAuth(key)) |pending_value| {
            var pending = pending_value;
            if (!pending.response_suppressed) {
                self.replyControl(pending.client_session, pending.client_stream_id, .auth_failure, reason);
            }
            pending.buffer.deinit(self.allocator);
            return;
        }

        if (self.inflight.lookupRoute(key)) |route| {
            switch (route.target) {
                .client => |target| self.replyControl(target.session, target.stream_id, .gateway_error, reason),
                .discard => {},
            }
            self.inflight.closeRoute(key);
            return;
        }

        if (event.peer_initiated) {
            egress.abortBackendPush(self, key);
        } else {
            std.log.warn("[ROUTE] control event for orphan backend stream={}", .{event.stream_id});
        }
    }

    /// 后端连接已无法交付响应时，立即终止它影响的在途请求。
    ///
    /// 普通业务流回 gateway_error；认证流回 auth_failure。两者都经 replyControl 写入
    /// 原客户端流并带 fin，客户端因此在本轮 Worker tick 内得到明确、可重试的结果，
    /// 不再悬挂到自己的 deadline。
    fn failTransportRequests(self: *Self, transport: BackendTransport) void {
        const selector = transport.failureSelector();
        var routes: [64]inflight.Route = undefined;
        while (true) {
            const count = self.inflight.takeFailedRoutes(transport.id(), selector, &routes);
            for (routes[0..count]) |route| switch (route.target) {
                .client => |target| self.replyControl(target.session, target.stream_id, .gateway_error, "backend connection failed"),
                .discard => {},
            };
            if (count < routes.len) break;
        }

        var auths: [64]inflight.PendingAuth = undefined;
        while (true) {
            const count = self.inflight.takeFailedAuths(transport.id(), selector, &auths);
            for (auths[0..count]) |pending_value| {
                var pending = pending_value;
                if (!pending.response_suppressed) {
                    self.replyControl(pending.client_session, pending.client_stream_id, .auth_failure, "authentication backend failed");
                }
                pending.buffer.deinit(self.allocator);
            }
            if (count < auths.len) break;
        }
    }

    // ========================================================================
    // 控制帧处理
    // ========================================================================

    /// 控制帧本地处理：心跳/ping/断开由网关直接响应，认证委托给后端认证服务。
    ///
    /// disconnect 只置位 close_requested，不当场关闭连接：本函数在分帧循环里
    /// 被调用，销毁连接会让循环里后续的帧指向已释放内存。
    ///
    /// 未知控制类型回一个错误帧而不是关连接——控制类型是开放空间，用一个网关
    /// 还不认识的取值不代表对端的编码器坏了（例如客户端版本更新）。
    ///
    /// pub 是给 ingress.zig 的逐帧分派用的。
    pub fn handleControlFrame(self: *Self, ctx: *ConnectionContext, client_stream_id: u64, parsed: codec.Frame) void {
        const ctrl = parsed.header.controlType() orelse {
            self.replyControl(ctx.session_handle, client_stream_id, .gateway_error, "unknown control type");
            return;
        };

        // 控制操作的返回契约是协议的一部分，而不是由实现碰巧决定：断开只触发连接
        // 关闭，不产生应用响应；其余客户端控制操作都必须拿到明确结果。模式不匹配是
        // 一次合法编码但不可执行的请求，因此回业务错误，不升级为连接级协议违规。
        const expected_mode: protocol.frame.ResponseMode = if (ctrl == .disconnect) .none else .required;
        if (parsed.header.response_mode != expected_mode) {
            const message = if (expected_mode == .none)
                "control requires response_mode=none"
            else
                "control requires response_mode=required";
            self.replyControl(ctx.session_handle, client_stream_id, .gateway_error, message);
            return;
        }
        switch (ctrl) {
            .heartbeat => self.replyControl(ctx.session_handle, client_stream_id, .heartbeat_ack, &.{}),
            .ping => self.replyControl(ctx.session_handle, client_stream_id, .pong, parsed.body),
            .disconnect => {
                ctx.offline_reason = .client_disconnect;
                ctx.close_requested = true;
            },
            .bind_channel => ingress.bindChannel(self, ctx, client_stream_id, parsed),
            .unbind_channel => ingress.unbindChannel(self, ctx, client_stream_id, parsed),
            .auth_request => auth.delegateAuth(self, ctx, client_stream_id, parsed),
            else => {
                std.log.warn("[CTRL] unhandled control type=0x{x}", .{@intFromEnum(ctrl)});
                self.replyControl(ctx.session_handle, client_stream_id, .gateway_error, "unsupported control type");
            },
        }
    }

    /// 向客户端流回写一个控制帧（fin 结束该流）。
    ///
    /// pub 是给 ingress.zig 用的：门禁拒绝与各类上行失败都要回一个 gateway_error。
    pub fn replyControl(self: *Self, session: SessionHandle, stream_id: u64, ctrl_type: protocol.frame.ControlType, body: []const u8) void {
        const ctx = self.conn_manager.getByHandle(session) orelse return;

        var buf: [1024]u8 = undefined;
        var encoder = protocol.codec.FrameEncoder.init(&buf);
        const data = encoder.encodeControlFrame(ctrl_type, body) catch |err| {
            err_handler.reportError(.session, "Failed to encode control frame", err);
            return;
        };
        ctx.transport.write(stream_id, data, true) catch |err| {
            err_handler.reportError(.session, "Failed to write control frame to client", err);
        };
    }

    /// 成功接纳一个 `ResponseMode.none` 请求后关闭返回方向，不发送应用帧。
    ///
    /// 空 FIN 是传输层收尾，不是业务确认：它只表示认证、路由、配额检查已经通过，
    /// 请求也已交给 BackendTransport。后端是否完成业务处理不会再回到客户端。
    pub fn finishResponseWithoutPayload(self: *Self, session: SessionHandle, stream_id: u64) void {
        const ctx = self.conn_manager.getByHandle(session) orelse return;
        ctx.transport.write(stream_id, &.{}, true) catch |err| {
            err_handler.reportError(.session, "Failed to finish no-response exchange", err);
        };
    }

    /// 吊销连接准入并发布一次连接级 offline；用户级多设备聚合不在 Gateway。
    pub fn revokeAdmission(self: *Self, ctx: *ConnectionContext, reason: protocol.body.SessionLifecycle.Reason) void {
        lifecycle.revokeAdmission(self, ctx, reason);
    }

    /// 武装一次性的后端轮询定时器；每轮回调末尾自己续期。
    fn scheduleBackendPoll(self: *Self, delay_ms: u64) void {
        self.backend_timer.run(self.event_loop, &self.backend_timer_completion, delay_ms, Self, self, backendPollCallback);
    }

    /// 周期性泵：推进停机流程 + 收割后端响应，然后重新武装自己。
    ///
    /// 两次 running 检查不是冗余：第一次挡住已经停机的情况，第二次是因为
    /// pollShutdown 可能刚好在本次调用里触发了停机，此时不该再续期。
    ///
    /// 末尾判断 completion 状态是为了不把同一个 completion 重复推入 xev 的提交队列
    /// ——drainBackendResponses 路径上可能已经间接续期过了。
    fn backendPollCallback(
        ud: ?*Self,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        _ = result catch {};

        const self = ud orelse return .disarm;
        if (!self.running.load(.acquire)) return .disarm;

        self.pollShutdown();
        if (!self.running.load(.acquire)) return .disarm;

        const now = quic.c.currentTime();
        if (self.session_acceptor) |acceptor| acceptor.poll(now);
        self.logMetrics(now);
        self.maintainBackendConnections(now);
        self.refreshPlacement(now);
        self.expireAdmissions(now);
        self.refreshLifecycleLeases(now);
        self.rehomeDrifted();
        // 后端响应由独立的 UDP client + 本定时器收割，不经过面向客户端的
        // ServerDriver 收包回调。因此 streamWrite 之后必须显式驱动一次服务端
        // picoquic；否则字节会滞留到空闲连接最远 10 秒后的协议定时器。
        if (self.drainBackendResponses()) self.server_driver.flushApplicationWrites();
        // 推进退避中的对等链路。少了它，一条进入退避的链路只能等下一次跨节点投递
        // 来唤醒——而那次投递必然先失败一回，等于每个退避周期至少损失一帧。
        if (self.peer_links) |*links| links.poll(now);
        // 兜底回收静默太久的流式推送会话（后端既不发 eof 也不关流的情形）。
        egress.purgeExpiredSessions(self, now);

        if (self.backend_timer_completion.state() != .active) {
            self.scheduleBackendPoll(self.backend_poll_interval_ms);
        }
        return .disarm;
    }

    /// 每分钟一条稳定、低基数的资源快照，供 soak 与现场诊断判断状态是否在请求结束后
    /// 回到基线。它只读取当前 Worker 的线程本地计数，不需要锁，也不暴露管理端口。
    fn logMetrics(self: *Self, now: u64) void {
        if (self.last_metrics_at_us != 0 and now -| self.last_metrics_at_us < metrics_interval_us) return;
        self.last_metrics_at_us = now;

        const clients = self.conn_manager.stats();
        const pool_stats = if (self.backend_pool) |pool| pool.stats() else backend.BackendPool.Stats{
            .connections = 0,
            .recv_slots_used = 0,
            .recv_slots_capacity = 0,
            .pending_failures = 0,
        };
        std.log.info(
            "[METRICS] worker={} clients={} exchanges={} frame_spills={} inflight_routes={} inflight_auth={} backend_connections={} recv_slots={}/{} pending_backend_failures={}",
            .{
                self.conn_manager.workerId(),
                clients.connections,
                clients.exchanges,
                clients.frame_spills,
                self.inflight.routeCount(),
                self.inflight.authCount(),
                pool_stats.connections,
                pool_stats.recv_slots_used,
                pool_stats.recv_slots_capacity,
                pool_stats.pending_failures,
            },
        );
    }

    /// 后端 transport 解析/建连结果的回调，只记日志。
    ///
    /// 失败不做任何补偿：重连与退避是 transport 自己的职责（见 backend/direct.zig），
    /// 这里不需要 Worker 上下文，所以 ctx 不使用。
    fn onBackendReady(ctx: ?*anyopaque, err: ?backend.TransportError) void {
        _ = ctx;
        if (err) |e| {
            std.log.err("[BACKEND] transport connect failed: {}", .{e});
        } else {
            std.log.info("[BACKEND] transport ready", .{});
        }
    }

    /// 交接队列的唤醒回调：其他 Worker push 包后调用，通过 xev.Async 唤醒本 Worker 事件循环。
    /// 注意此函数会被别的线程调用，只能做线程安全的 async.notify。
    fn notifyPacketHandoff(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.handoff_async.notify() catch |err| {
            err_handler.reportError(.transport, "Failed to wake packet owner Worker", err);
        };
    }

    /// 被唤醒后在本 Worker 线程内执行：把交接队列里属于自己的包全部取走并处理。
    fn handoffCallback(
        ud: ?*Self,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Async.WaitError!void,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        const self = ud orelse return .disarm;
        _ = result catch |err| {
            err_handler.reportError(.transport, "Packet handoff notification failed", err);
            return if (self.running.load(.acquire)) .rearm else .disarm;
        };

        // 一次唤醒可能对应多个积压包，循环排空；notify 可能被合并，所以不能只处理一个。
        while (self.coordinator.packetRouter().pop(self.worker_id)) |packet| {
            self.server_driver.handleHandoffPacket(&packet);
        }
        return if (self.running.load(.acquire)) .rearm else .disarm;
    }

    /// 应用消息交接队列的唤醒回调；会被别的 Worker 线程调用，只做线程安全的 notify。
    fn notifyMessageHandoff(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.message_async.notify() catch |err| {
            err_handler.reportError(.transport, "Failed to wake app message target Worker", err);
        };
    }

    /// 被唤醒后在本 Worker 线程内执行：把别的 Worker 交过来的应用消息全部投递掉。
    fn messageCallback(
        ud: ?*Self,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Async.WaitError!void,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        const self = ud orelse return .disarm;
        _ = result catch |err| {
            err_handler.reportError(.transport, "App message notification failed", err);
            return if (self.running.load(.acquire)) .rearm else .disarm;
        };

        while (self.coordinator.messageRouter().pop(self.worker_id)) |message| {
            egress.deliverHandoff(self, message.realm, message.session, message.bytes());
        }
        return if (self.running.load(.acquire)) .rearm else .disarm;
    }

    /// 从 membership 抄一份节点快照，供选址使用。
    ///
    /// 在周期定时器里做而不是每次投递都做：`nodeSnapshot` 是 O(max_nodes) 的，
    /// 而扇出是 O(目标数)，两者相乘会让一次群发退化成几十万次查表。滞后是有意
    /// 接受的代价，见 foundation/placement.zig 与设计文档 §8.5。
    fn refreshPlacement(self: *Self, now: u64) void {
        const fresh = self.coordinator.nodeSnapshot(self.snapshot_scratch);
        if (!std.mem.eql(u16, self.placement.nodes, fresh)) {
            // 成员变更：把当前视图存成"上一份"，开启双查窗口。
            //
            // 窗口里又发生一次变更时**不覆盖** prev：覆盖会丢掉更早那份视图，而窗口
            // 存在的意义正是"新旧两份的并集必定包含真正的位置"。宁可让 prev 更旧一些
            // （多发一份，而多发不会造成重复投递），也不能让并集变窄。
            if (self.placement.prev_nodes.len == 0) {
                const current = self.placement.nodes;
                @memcpy(self.prev_node_snapshot[0..current.len], current);
                self.placement.prev_nodes = self.prev_node_snapshot[0..current.len];
            }
            @memcpy(self.node_snapshot[0..fresh.len], fresh);
            self.placement.nodes = self.node_snapshot[0..fresh.len];
            self.placement_grace_until = now +| placement_grace_us;
            std.log.info("[PLACE] membership changed: {} nodes, double-lookup window open", .{fresh.len});
            return;
        }

        if (self.placement.prev_nodes.len != 0 and now >= self.placement_grace_until) {
            // 窗口关闭。此后旧位置不再是 home，漂移巡检会开始把留在那里的连接赶走。
            self.placement.prev_nodes = &.{};
            std.log.info("[PLACE] double-lookup window closed", .{});
        }
    }

    /// 把漂移到错位置的连接赶回它的 home（设计文档 §8.5 的第三道）。
    ///
    /// 认证时判一次不够：连接是长寿的（IM 客户端挂几小时很正常），而它的 home 会因为
    /// **别人**扩容而漂走。有时限的双查覆盖不了这种情况——窗口一过，这条连接就永久
    /// 收不到推送，而且没有任何报错提示。所以必须让函数与现实重新对齐。
    ///
    /// 三条前置判断都不是可选的：
    /// - 广播策略下人人都是 home，"漂移"这个概念不存在；
    /// - 双查窗口内新旧两个位置都合法，此时赶人只会让客户端在两个节点之间来回弹；
    /// - 每轮限额，否则加一个节点会让 1/N 的连接同时重连，那是自己造的雪崩。
    fn rehomeDrifted(self: *Self) void {
        if (self.placement.strategy != .affinity) return;
        if (self.placement.prev_nodes.len != 0) return;

        var checked: usize = 0;
        var moved: usize = 0;
        while (checked < rehome_per_tick) : (checked += 1) {
            const live = self.conn_manager.nextLive(self.rehome_cursor) orelse {
                // 扫完一圈，下一轮从头再来。
                self.rehome_cursor = 0;
                break;
            };
            self.rehome_cursor = live.index + 1;

            const ctx = live.ctx;
            // 对等节点的连接不参与选址：它是集群内部链路，没有 dest_id 也没有 home。
            if (ctx.peer_node) continue;
            // 还没绑定标识的连接无从判断该在哪——它也还收不到推送。
            if (ctx.dest_id == 0) continue;
            if (self.placement.isHomeNode(ctx.realm, ctx.dest_id)) continue;
            if (auth.redirectToHome(self, ctx, ctx.dest_id, null)) moved += 1;
        }

        if (moved != 0) {
            std.log.info("[PLACE] re-homed {} drifted connection(s)", .{moved});
        }
    }

    /// 分批吊销已经超过认证 TTL 的连接。QUIC 连接保持打开，客户端可以原地重新认证；
    /// 但过期以后不再可寻址，也不能继续发送业务流或 datagram。
    fn expireAdmissions(self: *Self, now: u64) void {
        var checked: usize = 0;
        while (checked < rehome_per_tick) : (checked += 1) {
            const live = self.conn_manager.nextLive(self.admission_cursor) orelse {
                self.admission_cursor = 0;
                return;
            };
            self.admission_cursor = live.index + 1;
            const ctx = live.ctx;
            if (ctx.peer_node or !ctx.authenticated or ctx.auth_expires_at == 0) continue;
            if (now < ctx.auth_expires_at) continue;
            self.revokeAdmission(ctx, .admission_expired);
        }
    }

    /// 分批刷新连接级在线租约。与 TTL 巡检使用独立游标，避免连接数很大时两类扫描
    /// 互相改变进度；每 tick 固定预算，刷新成本不会形成事件循环长尾。
    fn refreshLifecycleLeases(self: *Self, now: u64) void {
        var checked: usize = 0;
        while (checked < rehome_per_tick) : (checked += 1) {
            const live = self.conn_manager.nextLive(self.lifecycle_cursor) orelse {
                self.lifecycle_cursor = 0;
                return;
            };
            self.lifecycle_cursor = live.index + 1;
            if (live.ctx.peer_node) continue;
            lifecycle.refreshOnline(self, live.ctx, now);
        }
    }

    /// init 失败路径专用：关掉尚未交给 ServerDriver 的 socket。
    fn closeSocket(socket_fd: ?std.posix.socket_t) void {
        if (socket_fd) |fd| _ = std.c.close(fd);
    }

    /// 把 Driver 回传的类型擦除上下文还原为本 Worker。
    ///
    /// ud 恒为 setCallbacks 注册的 self，为 null 只可能是装配错误。这里刻意用 `.?`
    /// 让它当场触发安全检查：静默返回会让三个回调一起空转，表现为服务器不回应，
    /// 比崩溃难定位得多。
    ///
    /// pub 是给 ingress.zig 用的：handleStreamData 已经搬到那里。
    pub inline fn castSelf(ud: ?*anyopaque) *Self {
        return @as(*Self, @ptrCast(@alignCast(ud.?)));
    }
};

/// 记录 transport 收到的每一次上行调用，用来断言"一条客户端流对应一条后端流"。
const StreamRecorder = struct {
    opened: usize = 0,
    appended: usize = 0,
    fins: usize = 0,
    last_handle: ?u64 = null,
    /// 最后一次写入的字节，用来断言投递回报的内容。
    last_data: [512]u8 = undefined,
    last_len: usize = 0,

    /// 开流时返回的固定句柄，便于断言后续分片确实沿用了它。
    const opened_handle: u64 = 0x2A;

    pub fn resolveImpl(_: *@This(), _: RouteId, _: ?backend.transport.ResolveCallback, _: ?*anyopaque) void {}

    pub fn sendStreamImpl(
        self: *@This(),
        _: RouteId,
        handle: ?u64,
        data: []const u8,
        is_fin: bool,
    ) backend.TransportError!u64 {
        if (data.len <= self.last_data.len) {
            @memcpy(self.last_data[0..data.len], data);
            self.last_len = data.len;
        }
        if (is_fin) self.fins += 1;
        if (handle) |value| {
            self.appended += 1;
            self.last_handle = value;
            return value;
        }
        self.opened += 1;
        self.last_handle = null;
        return opened_handle;
    }

    fn lastWrite(self: *const @This()) []const u8 {
        return self.last_data[0..self.last_len];
    }

    pub fn receiveImpl(_: *@This()) backend.TransportError!?backend.transport.TransportRecv {
        return null;
    }

    pub fn releaseRecvImpl(_: *@This(), _: backend.transport.TransportRecv) void {}

    pub fn closeImpl(_: *@This()) void {}
};

/// 造一个只跑上行转发路径的 Worker。
///
/// 返回的 Worker 由调用方 deinit；registry 的所有权已转移进去，不要另行释放。
fn testWorker(
    allocator: std.mem.Allocator,
    coordinator: *control.Coordinator,
    registry: TransportRegistry,
) !GatewayWorker {
    var config: QUICConfig = .{
        .cert_file = "server.crt",
        .key_file = "server.key",
        .bind_address = .{ 127, 0, 0, 1 },
        .bind_port = 0,
    };
    config.base.verify_cert = false;
    // 与面向客户端的真实监听器一致地开启不可靠通路：关掉它的话 datagram 缓冲会被按 0
    // 定尺，那些用例就会撞上一个测试专有的失败模式（§6.2）。
    config.base.max_datagram_frame_size = 1200;
    // realms 用默认表：单 realm 部署（任何 SNI 都落进 default_realm）。
    // 不建集群监听器：这些用例走的是离线分派路径，不需要真的监听。
    return GatewayWorker.init(allocator, config, 0, registry, &test_realms, 10, .{}, null, null, coordinator);
}

/// 测试用的 realm 表：槽位为空 + fallback = default_realm，即单域部署。
///
/// 必须是容器作用域的变量而不是临时值：Worker 借用的是指针，指向栈上的临时值会在
/// 构造函数返回后立刻悬垂。
var test_realms: foundation.realm.Table = .{};

/// 上行分派测试用的最小 Coordinator。
fn testCoordinator(allocator: std.mem.Allocator) !control.Coordinator {
    return testCoordinatorWithWorkers(allocator, 1);
}

/// 多 Worker 的 Coordinator，用来验证跨 Worker 转投。
fn testCoordinatorWithWorkers(allocator: std.mem.Allocator, worker_count: u16) !control.Coordinator {
    return control.Coordinator.init(std.testing.io, allocator, .{
        .node_id = 1,
        .advertise_address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 0),
        .forward_address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 0),
        .worker_count = worker_count,
        .handoff_queue_capacity = 4,
    });
}

const test_route = RouteId.init(0x11, 0x22);
/// 单 realm 部署的取值：testWorker 用默认 realms 表，任何连接都落进 default_realm。
const test_realm: foundation.realm.RealmId = foundation.realm.default_realm;
/// 注册表键：客户端帧里只有 test_route，realm 由网关补上。
const test_scope = ScopedRoute.scoped(test_realm, test_route);

fn testDetachedContext(allocator: std.mem.Allocator, raw_handle: usize, realm: foundation.realm.RealmId) ConnectionContext {
    return ConnectionContext.init(
        allocator,
        .{ .slot = 0, .generation = 1 },
        quic.session.init(@ptrFromInt(raw_handle)),
        realm,
    );
}

// 一次交换的接线回归测试。
//
// 关键不变量是"客户端一条流 = 后端一条流"：OPEN 开流，DATA 沿同一句柄追加，
// 只有 eof 才 fin。任何一环接错，后端拿到的都是拼不起来的字节流，
// 而这种错误在单元测试之外要等真实流式业务上线才会暴露。
test "one exchange rides one backend stream and finishes on eof" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    // 伪造连接上下文：本用例只走上行转发，不会解引用这个句柄。
    var ctx = testDetachedContext(allocator, 0x1000, test_realm);
    defer ctx.deinit();

    const client_stream: u64 = 4;
    var buf: [128]u8 = undefined;
    var encoder = codec.FrameEncoder.init(&buf);

    const open = try encoder.encodeOpen(.service, test_route, .required, .{}, "head");
    try std.testing.expectEqual(
        ingress.FrameOutcome.continue_stream,
        ingress.dispatchFrame(&worker, &ctx, client_stream, try codec.parseExactFrame(open)),
    );
    try std.testing.expectEqual(@as(usize, 1), recorder.opened);
    try std.testing.expectEqual(@as(usize, 0), recorder.fins);
    try std.testing.expectEqual(StreamRecorder.opened_handle, ctx.inboundExchange(client_stream).?.backend.?.key.stream);

    const middle = try encoder.encodeData(.{}, "body");
    _ = ingress.dispatchFrame(&worker, &ctx, client_stream, try codec.parseExactFrame(middle));
    try std.testing.expectEqual(@as(usize, 1), recorder.opened);
    try std.testing.expectEqual(@as(usize, 1), recorder.appended);
    try std.testing.expectEqual(@as(?u64, StreamRecorder.opened_handle), recorder.last_handle);
    try std.testing.expectEqual(@as(usize, 0), recorder.fins);

    const end = try encoder.encodeData(protocol.frame.Flags.last(), "tail");
    _ = ingress.dispatchFrame(&worker, &ctx, client_stream, try codec.parseExactFrame(end));
    try std.testing.expectEqual(@as(usize, 2), recorder.appended);
    try std.testing.expectEqual(@as(usize, 1), recorder.fins);

    // eof 之后句柄就该丢掉（后端流已 fin），但条目留着当"这条流用过了"的凭据；
    // 回程映射也要留着等后端响应，且只登记一次。
    const finished = ctx.inboundExchange(client_stream).?;
    try std.testing.expect(finished.input_complete);
    try std.testing.expect(finished.backend == null);
    try std.testing.expectEqual(@as(u32, 1), worker.inflight.routeCount());
}

// eof 之后这条流上又来帧：无歧义的编码器错误，必须关整条连接。
test "a frame after eof closes the connection" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    var ctx = testDetachedContext(allocator, 0x1000, test_realm);
    defer ctx.deinit();

    var buf: [128]u8 = undefined;
    var encoder = codec.FrameEncoder.init(&buf);

    // 一次性交换：OPEN 直接带 eof，开流并 fin。
    const once = try encoder.encodeOpen(.service, test_route, .required, protocol.frame.Flags.last(), "only");
    _ = ingress.dispatchFrame(&worker, &ctx, 4, try codec.parseExactFrame(once));
    try std.testing.expectEqual(@as(usize, 1), recorder.opened);
    try std.testing.expectEqual(@as(usize, 1), recorder.fins);

    const extra = try encoder.encodeData(.{}, "after-eof");
    try std.testing.expectEqual(
        ingress.FrameOutcome.close_connection,
        ingress.dispatchFrame(&worker, &ctx, 4, try codec.parseExactFrame(extra)),
    );
}

// 一条流上两次 OPEN：放行会让同一条客户端流挂两条后端流，响应交错回来无法区分。
test "a second OPEN on a live stream closes the connection" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    var ctx = testDetachedContext(allocator, 0x1000, test_realm);
    defer ctx.deinit();

    var buf: [128]u8 = undefined;
    var encoder = codec.FrameEncoder.init(&buf);

    const first = try encoder.encodeOpen(.service, test_route, .required, .{}, "head");
    _ = ingress.dispatchFrame(&worker, &ctx, 4, try codec.parseExactFrame(first));
    try std.testing.expectEqual(@as(usize, 1), recorder.opened);

    const second = try encoder.encodeOpen(.service, test_route, .required, .{}, "again");
    try std.testing.expectEqual(
        ingress.FrameOutcome.close_connection,
        ingress.dispatchFrame(&worker, &ctx, 4, try codec.parseExactFrame(second)),
    );
    // 第二次 OPEN 不得开出第二条后端流。
    try std.testing.expectEqual(@as(usize, 1), recorder.opened);
}

// 客户端寻址 .peer / .multicast 是越权：可靠广播必须经过后端，
// 否则落库、反垃圾、定序这些业务逻辑全被绕过。
test "a client may not address peers or multicast groups" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    var ctx = testDetachedContext(allocator, 0x1000, test_realm);
    defer ctx.deinit();

    var buf: [128]u8 = undefined;
    var encoder = codec.FrameEncoder.init(&buf);

    inline for ([_]protocol.frame.DestKind{ .peer, .multicast }, 0..) |dest, i| {
        const frame_data = try encoder.encodeOpen(dest, test_route, .required, protocol.frame.Flags.last(), "blast");
        try std.testing.expectEqual(
            ingress.FrameOutcome.close_connection,
            ingress.dispatchFrame(&worker, &ctx, 4 + i * 4, try codec.parseExactFrame(frame_data)),
        );
    }
    try std.testing.expectEqual(@as(usize, 0), recorder.opened);
}

// 查不到交换的 DATA 帧只能丢弃，不能升级为协议违规。
//
// 网关分不清"客户端真的先发了 DATA"和"这次交换刚被业务级理由拒掉、条目没留"，
// 而后者在正常运行中就会发生（客户端收到错误帧时后面的分片早在路上）。
// 升级会让一次配额拒绝顺带杀掉整条连接。
test "a DATA frame with no live exchange is dropped, not escalated" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    var ctx = testDetachedContext(allocator, 0x1000, test_realm);
    defer ctx.deinit();

    var buf: [128]u8 = undefined;
    var encoder = codec.FrameEncoder.init(&buf);
    const orphan = try encoder.encodeData(.{}, "orphan");

    try std.testing.expectEqual(
        ingress.FrameOutcome.continue_stream,
        ingress.dispatchFrame(&worker, &ctx, 8, try codec.parseExactFrame(orphan)),
    );
    try std.testing.expectEqual(@as(usize, 0), recorder.opened);
    try std.testing.expectEqual(@as(usize, 0), recorder.appended);
    try std.testing.expect(ctx.inboundExchange(8) == null);
    try std.testing.expectEqual(@as(u32, 0), worker.inflight.routeCount());
}

// 控制交换（`.gateway`）就地处理，不碰后端，但仍要留下交换记录。
//
// 记录是必要的：没有它，客户端可以在一条流上塞两个 auth_request。
test "a control exchange is handled locally and still leaves a record" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    var ctx = testDetachedContext(allocator, 0x1000, test_realm);
    defer ctx.deinit();

    var buf: [128]u8 = undefined;
    var encoder = codec.FrameEncoder.init(&buf);
    const heartbeat = try encoder.encodeHeartbeat();

    try std.testing.expectEqual(
        ingress.FrameOutcome.continue_stream,
        ingress.dispatchFrame(&worker, &ctx, 4, try codec.parseExactFrame(heartbeat)),
    );
    try std.testing.expectEqual(@as(usize, 0), recorder.opened);
    try std.testing.expect(ctx.inboundExchange(4).?.input_complete);
    try std.testing.expect(ctx.inboundExchange(4).?.backend == null);

    // 同一条流上再来一个控制交换必须被判违规。
    const again = try encoder.encodeHeartbeat();
    try std.testing.expectEqual(
        ingress.FrameOutcome.close_connection,
        ingress.dispatchFrame(&worker, &ctx, 4, try codec.parseExactFrame(again)),
    );
}

// 路由不存在是业务失败：回错误帧，连接与其他流不受影响，也不留交换条目。
test "an unknown route fails the exchange without touching the connection" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    var ctx = testDetachedContext(allocator, 0x1000, test_realm);
    defer ctx.deinit();

    var buf: [128]u8 = undefined;
    var encoder = codec.FrameEncoder.init(&buf);
    const stray = try encoder.encodeOpen(.service, RouteId.init(0x99, 0x99), .required, protocol.frame.Flags.last(), "nowhere");

    try std.testing.expectEqual(
        ingress.FrameOutcome.continue_stream,
        ingress.dispatchFrame(&worker, &ctx, 4, try codec.parseExactFrame(stray)),
    );
    try std.testing.expectEqual(@as(usize, 0), recorder.opened);
    // 不留条目：后续分片会走"查不到交换"那条丢弃路径，而不是被判违规。
    try std.testing.expect(ctx.inboundExchange(4) == null);
}

/// 拼一个后端主动发起的 `.peer` 推送帧：目标列表前缀 + 负载。
fn testPushFrame(
    frame_buf: []u8,
    body_buf: []u8,
    targets: []const u64,
    payload: []const u8,
    flags: protocol.frame.Flags,
) ![]const u8 {
    const list_len = try protocol.body.TargetList.encode(body_buf, targets);
    @memcpy(body_buf[list_len..][0..payload.len], payload);

    var encoder = codec.FrameEncoder.init(frame_buf);
    return encoder.encodeOpen(.peer, .{}, .none, flags, body_buf[0 .. list_len + payload.len]);
}

/// 拼一个后端 → 网关的控制帧：目标列表就是 conn_token 列表。
///
/// 线格式与客户端方向的控制帧完全相同（`.gateway` + `route_key = ControlType`）——
/// 语法对称，权限不对称（§1.5）。这里手工编帧头而不用 `encodeControlFrame`，
/// 只为了能控制 `report` 位。
fn testControlFrame(
    frame_buf: []u8,
    body_buf: []u8,
    ctrl: protocol.frame.ControlType,
    targets: []const u128,
    flags: protocol.frame.Flags,
) ![]const u8 {
    const list_len = try protocol.body.TokenList.encode(body_buf, targets);
    var header = protocol.frame.FrameHeader.initControl(ctrl, @intCast(list_len));
    header.flags = flags;

    const header_size = protocol.frame.OPEN_HEADER_SIZE;
    _ = try header.encode(frame_buf[0..header_size]);
    @memcpy(frame_buf[header_size..][0..list_len], body_buf[0..list_len]);
    return frame_buf[0 .. header_size + list_len];
}

/// 后端主动流上的一个事件。`peer_initiated` 是"推送"与"孤儿响应"的判据。
fn testPushEvent(backend_stream: u64, data: []const u8) backend.transport.TransportRecv {
    return .{
        .stream_id = backend_stream,
        .data = data,
        .is_fin = true,
        .peer_initiated = true,
    };
}

/// 后端主动流上的一个**流还没结束**的事件：流式推送的每一跳都是这个形态。
///
/// 与 `testPushEvent` 的差别只有 is_fin。它很关键：带 fin 的事件意味着后端把流关了，
/// 会话会就地作废。
fn testStreamEvent(backend_stream: u64, data: []const u8) backend.transport.TransportRecv {
    return .{
        .stream_id = backend_stream,
        .data = data,
        .is_fin = false,
        .peer_initiated = true,
    };
}

// 投递回报的端到端回归：目标全都不在线时，网关必须在后端那条流上回写不可达列表。
//
// 这是后端触发离线存储的唯一信号。漏了它，离线消息会静默丢失——而且只在收件人
// 恰好不在线时发生，是最难在测试环境复现的一类问题。
test "a push to offline targets reports them back on the backend stream" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));
    const transport = BackendTransport.init(StreamRecorder, &recorder);

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    var frame_buf: [256]u8 = undefined;
    var body_buf: [128]u8 = undefined;
    const push = try testPushFrame(
        &frame_buf,
        &body_buf,
        &[_]u64{ 11, 22 },
        "hello",
        .{ .eof = true, .report = true },
    );

    const backend_stream: u64 = 0x5;
    egress.handlePush(&worker, transport, test_realm, testPushEvent(backend_stream, push));

    // 没有任何连接绑定过 11 / 22，因此两个都不可达，回报写在同一条后端流上。
    try std.testing.expectEqual(@as(usize, 1), recorder.appended);
    try std.testing.expectEqual(@as(?u64, backend_stream), recorder.last_handle);

    const report = try codec.parseExactFrame(recorder.lastWrite());
    try std.testing.expectEqual(protocol.frame.FrameType.data, report.header.frame_type);
    const unreachable_list = try protocol.body.TargetList.decode(report.body);
    try std.testing.expectEqual(@as(u16, 2), unreachable_list.count);
    try std.testing.expectEqual(@as(u64, 11), unreachable_list.get(0));
    try std.testing.expectEqual(@as(u64, 22), unreachable_list.get(1));
}

// 不置 report 位就不该有任何回程写入——游戏状态广播这类场景靠它省掉回程带宽。
test "a push without the report flag writes nothing back" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));
    const transport = BackendTransport.init(StreamRecorder, &recorder);

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    var frame_buf: [256]u8 = undefined;
    var body_buf: [128]u8 = undefined;
    const push = try testPushFrame(&frame_buf, &body_buf, &[_]u64{7}, "hi", .{ .eof = true });

    egress.handlePush(&worker, transport, test_realm, testPushEvent(0x9, push));

    try std.testing.expectEqual(@as(usize, 0), recorder.appended);
    try std.testing.expectEqual(@as(usize, 0), recorder.opened);
}

// 流式推送：OPEN 不带 eof 时冻结成员集合，后续 DATA 沿会话续传（设计文档 §5.3）。
//
// 这里钉住三件事：会话确实建起来了、回报在 OPEN 那一刻就结算完（后续 DATA 上没有
// 目标列表，再没有第二次结算的机会）、带 eof 的续传帧把会话收掉。
test "a streaming push settles its report at OPEN and closes the session on eof" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));
    const transport = BackendTransport.init(StreamRecorder, &recorder);

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    var frame_buf: [256]u8 = undefined;
    var body_buf: [128]u8 = undefined;
    const head = try testPushFrame(&frame_buf, &body_buf, &[_]u64{7}, "head", .{ .report = true });

    const backend_stream: u64 = 0xD;
    egress.handlePush(&worker, transport, test_realm, testStreamEvent(backend_stream, head));

    // 目标 7 没有任何连接，所以回报就在 OPEN 这一刻写回后端流。
    try std.testing.expectEqual(@as(usize, 1), recorder.appended);
    const report = try codec.parseExactFrame(recorder.lastWrite());
    const unreachable_list = try protocol.body.TargetList.decode(report.body);
    try std.testing.expectEqual(@as(u16, 1), unreachable_list.count);
    try std.testing.expectEqual(@as(u64, 7), unreachable_list.get(0));

    // 会话留在表里等后续 DATA。
    try std.testing.expectEqual(@as(usize, 1), worker.egress.sessions.liveCount());

    var data_buf: [64]u8 = undefined;
    var data_encoder = codec.FrameEncoder.init(&data_buf);
    const tail = try data_encoder.encodeData(protocol.frame.Flags.last(), "tail");
    egress.handlePush(&worker, transport, test_realm, testStreamEvent(backend_stream, tail));

    // eof 之后会话被回收，而且回报不写第二遍。
    try std.testing.expectEqual(@as(usize, 0), worker.egress.sessions.liveCount());
    try std.testing.expectEqual(@as(usize, 1), recorder.appended);
}

// 目标数超过上限的流式推送整个被拒，不留会话、不投一帧。
//
// 这一道是后端能控制的（列表是它编的），所以必须硬拒：截断成前 N 个会让后端以为
// 全都发出去了。放行则意味着一条流在网关里被复制几十份，出口带宽跟着乘几十倍。
test "a streaming push beyond the target cap is refused outright" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));
    const transport = BackendTransport.init(StreamRecorder, &recorder);

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    var targets: [push_session.max_list_targets + 1]u64 = undefined;
    for (&targets, 0..) |*target, i| target.* = i + 1;

    var frame_buf: [512]u8 = undefined;
    var body_buf: [512]u8 = undefined;
    const head = try testPushFrame(&frame_buf, &body_buf, &targets, "head", .{ .report = true });

    egress.handlePush(&worker, transport, test_realm, testStreamEvent(0xE, head));

    try std.testing.expectEqual(@as(usize, 0), worker.egress.sessions.liveCount());
    try std.testing.expectEqual(@as(usize, 0), recorder.appended);
}

// 后端把推送流关了却从没发过 eof：会话必须就地作废。
//
// 留着它等于让下游客户端一直等一段永远不来的尾巴，而客户端没有任何方式发现这件事。
test "a push stream that ends without eof voids its session" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));
    const transport = BackendTransport.init(StreamRecorder, &recorder);

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    var frame_buf: [256]u8 = undefined;
    var body_buf: [128]u8 = undefined;
    const head = try testPushFrame(&frame_buf, &body_buf, &[_]u64{7}, "head", .{});

    // 带 fin 的事件 = 后端关了这条流。
    egress.handlePush(&worker, transport, test_realm, testPushEvent(0xF, head));

    try std.testing.expectEqual(@as(usize, 0), worker.egress.sessions.liveCount());
}

// 后端 → 网关的 kick：踢不到的目标必须回报，不能让后端以为踢成功了。
//
// 这是 kick 与推送的分水岭：推送丢了是消息没到，业务层能补；kick 没生效是安全动作
// 静默失效，被踢的人还在线。
test "a kick reports every target it could not reach" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));
    const transport = BackendTransport.init(StreamRecorder, &recorder);

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    // 两个 token：一个指向别的节点（跨节点通路尚未建），一个槽位号根本不存在。
    const elsewhere = connection.ConnToken{ .node_id = 99, .worker_id = 0, .slot = 0, .generation = 1 };
    const stale = connection.ConnToken{ .node_id = 1, .worker_id = 0, .slot = 4096, .generation = 1 };

    var frame_buf: [256]u8 = undefined;
    var body_buf: [128]u8 = undefined;
    const kick = try testControlFrame(
        &frame_buf,
        &body_buf,
        .kick_off,
        &[_]u128{ elsewhere.encode(), stale.encode() },
        .{ .eof = true, .report = true },
    );

    const backend_stream: u64 = 0x21;
    egress.handlePush(&worker, transport, test_realm, testPushEvent(backend_stream, kick));

    try std.testing.expectEqual(@as(usize, 1), recorder.appended);
    try std.testing.expectEqual(@as(?u64, backend_stream), recorder.last_handle);

    const report = try codec.parseExactFrame(recorder.lastWrite());
    const missed = try protocol.body.TokenList.decode(report.body);
    try std.testing.expectEqual(@as(u16, 2), missed.count);
    try std.testing.expectEqual(elsewhere.encode(), missed.get(0));
    try std.testing.expectEqual(stale.encode(), missed.get(1));
}

// 后端能指挥网关做什么必须是封闭集合：白名单之外的控制类型一律拒绝。
//
// 否则将来给客户端方向新增一个控制类型，就顺带把它变成了后端的一项权限。
test "a control type outside the backend whitelist is refused" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));
    const transport = BackendTransport.init(StreamRecorder, &recorder);

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    var frame_buf: [256]u8 = undefined;
    var body_buf: [128]u8 = undefined;
    // disconnect 是客户端方向的控制类型，后端不该能用它。
    const forged = try testControlFrame(
        &frame_buf,
        &body_buf,
        .disconnect,
        &[_]u128{1},
        .{ .eof = true, .report = true },
    );

    egress.handlePush(&worker, transport, test_realm, testPushEvent(0x25, forged));

    // 连回报都不该写：这一帧整体无效，不是"目标不可达"。
    try std.testing.expectEqual(@as(usize, 0), recorder.appended);
    try std.testing.expectEqual(@as(usize, 0), recorder.opened);
}

// 跨 realm 的 kick 必须被拒，且目标连接的准入状态一个字节都不能动。
//
// 这是 §12.2 在 kick 路径上的落点：token 只定位、不授权，realm 要单独比对。少了这一
// 道，realm A 的后端拿一个猜中的 token 就能踢掉 realm B 的用户。
test "a kick from another realm is refused and leaves the target admitted" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));
    const transport = BackendTransport.init(StreamRecorder, &recorder);

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    // 目标连接属于 realm 7；本用例不会解引用这个句柄——kick 在 realm 校验处就返回了。
    const victim_realm: foundation.realm.RealmId = 7;
    var victim = QUICConnection{ .inner = @ptrFromInt(0x1000) };
    const ctx = try worker.conn_manager.add(&victim, victim_realm, &worker);
    ctx.authenticated = true;
    worker.conn_manager.bindDest(ctx.session_handle, 42);

    const token = worker.conn_manager.tokenFor(ctx.session_handle).?;

    var frame_buf: [256]u8 = undefined;
    var body_buf: [128]u8 = undefined;
    const kick = try testControlFrame(
        &frame_buf,
        &body_buf,
        .kick_off,
        &[_]u128{token.encode()},
        .{ .eof = true, .report = true },
    );

    // 从 realm 0 的后端发来（test_realm），目标在 realm 7。
    egress.handlePush(&worker, transport, test_realm, testPushEvent(0x29, kick));

    // 回报成"没踢到"。
    const report = try codec.parseExactFrame(recorder.lastWrite());
    const missed = try protocol.body.TokenList.decode(report.body);
    try std.testing.expectEqual(@as(u16, 1), missed.count);
    try std.testing.expectEqual(token.encode(), missed.get(0));

    // 关键断言：目标仍然被准入、仍然可被本 realm 寻址。
    try std.testing.expect(ctx.authenticated);
    try std.testing.expectEqual(@as(u64, 42), ctx.dest_id);
    try std.testing.expectEqual(@as(usize, 1), worker.conn_manager.destCount(victim_realm, 42));
}

// 后端在下行寻址 .service 没有意义，必须被拒而不是当成推送。
test "a backend push addressed at a service is rejected" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));
    const transport = BackendTransport.init(StreamRecorder, &recorder);

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    var frame_buf: [256]u8 = undefined;
    var encoder = codec.FrameEncoder.init(&frame_buf);
    const push = try encoder.encodeOpen(.service, test_route, .required, protocol.frame.Flags.last(), "nope");

    egress.handlePush(&worker, transport, test_realm, testPushEvent(0x11, push));

    try std.testing.expectEqual(@as(usize, 0), recorder.appended);
    try std.testing.expectEqual(@as(usize, 0), recorder.opened);
}

/// 拼一个 `.multicast` 推送帧：目标列表的条目是组标识。
fn testMulticastFrame(
    frame_buf: []u8,
    body_buf: []u8,
    groups: []const u64,
    payload: []const u8,
    flags: protocol.frame.Flags,
) ![]const u8 {
    const list_len = try protocol.body.TargetList.encode(body_buf, groups);
    @memcpy(body_buf[list_len..][0..payload.len], payload);

    var encoder = codec.FrameEncoder.init(frame_buf);
    return encoder.encodeOpen(.multicast, .{}, .none, flags, body_buf[0 .. list_len + payload.len]);
}

/// 拼一个后端 → 网关的组成员变更帧。
fn testGroupFrame(
    frame_buf: []u8,
    body_buf: []u8,
    ctrl: protocol.frame.ControlType,
    group_id: u64,
    members: []const u128,
) ![]const u8 {
    const body_len = try protocol.body.GroupBinding.encode(body_buf, group_id, members);
    var header = protocol.frame.FrameHeader.initControl(ctrl, @intCast(body_len));

    const header_size = protocol.frame.OPEN_HEADER_SIZE;
    _ = try header.encode(frame_buf[0..header_size]);
    @memcpy(frame_buf[header_size..][0..body_len], body_buf[0..body_len]);
    return frame_buf[0 .. header_size + body_len];
}

// 组播的成员权威在后端：join 只能由后端 → 网关的控制交换驱动，网关自己没有判据。
test "a backend can put a connection into a multicast group" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));
    const transport = BackendTransport.init(StreamRecorder, &recorder);

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    var member = QUICConnection{ .inner = @ptrFromInt(0x1000) };
    const member_ctx = try worker.conn_manager.add(&member, test_realm, &worker);
    const token = worker.conn_manager.tokenFor(member_ctx.session_handle).?;

    var frame_buf: [256]u8 = undefined;
    var body_buf: [128]u8 = undefined;
    const join = try testGroupFrame(&frame_buf, &body_buf, .join_group, 777, &[_]u128{token.encode()});
    egress.handlePush(&worker, transport, test_realm, testPushEvent(0x31, join));
    try std.testing.expectEqual(@as(usize, 1), worker.conn_manager.groupCount(test_realm, 777));

    const leave = try testGroupFrame(&frame_buf, &body_buf, .leave_group, 777, &[_]u128{token.encode()});
    egress.handlePush(&worker, transport, test_realm, testPushEvent(0x35, leave));
    try std.testing.expectEqual(@as(usize, 0), worker.conn_manager.groupCount(test_realm, 777));
}

// 与 kick 同源的授权洞：realm A 的后端不能把 realm B 的连接塞进自己的组，
// 否则它就能收走那个组的全部广播。
test "a cross-realm group join is refused" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));
    const transport = BackendTransport.init(StreamRecorder, &recorder);

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    const victim_realm: foundation.realm.RealmId = 7;
    var victim = QUICConnection{ .inner = @ptrFromInt(0x1000) };
    const victim_ctx = try worker.conn_manager.add(&victim, victim_realm, &worker);
    const token = worker.conn_manager.tokenFor(victim_ctx.session_handle).?;

    var frame_buf: [256]u8 = undefined;
    var body_buf: [128]u8 = undefined;
    const join = try testGroupFrame(&frame_buf, &body_buf, .join_group, 777, &[_]u128{token.encode()});
    // 从 realm 0（test_realm）的后端发来，目标在 realm 7。
    egress.handlePush(&worker, transport, test_realm, testPushEvent(0x39, join));

    try std.testing.expectEqual(@as(usize, 0), worker.conn_manager.groupCount(test_realm, 777));
    try std.testing.expectEqual(@as(usize, 0), worker.conn_manager.groupCount(victim_realm, 777));
}

// 组播的投递回报只能表达"本位置一个成员都没有"——别的位置有没有成员，发起方无从得知。
// 这正是组播省下 O(成员数) 的代价。
test "a multicast push to an empty group reports the group back" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));
    const transport = BackendTransport.init(StreamRecorder, &recorder);

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    var frame_buf: [256]u8 = undefined;
    var body_buf: [128]u8 = undefined;
    const push = try testMulticastFrame(
        &frame_buf,
        &body_buf,
        &[_]u64{ 500, 600 },
        "state",
        .{ .eof = true, .report = true },
    );

    const backend_stream: u64 = 0x41;
    egress.handlePush(&worker, transport, test_realm, testPushEvent(backend_stream, push));

    const report = try codec.parseExactFrame(recorder.lastWrite());
    const missed = try protocol.body.TargetList.decode(report.body);
    try std.testing.expectEqual(@as(u16, 2), missed.count);
    try std.testing.expectEqual(@as(u64, 500), missed.get(0));
    try std.testing.expectEqual(@as(u64, 600), missed.get(1));
}

// 流式组播走的是与 `.peer` 完全同一条会话路径：组播只是"目标条目是组标识而不是
// dest_id"，冻结成员集合、按会话续传这两件事一模一样（§5.3）。
//
// 这里钉住"共用一条路径"这件事本身：组播的 OPEN 不带 eof 时也要建会话，而不是
// 走回一次性扇出。
test "a streaming multicast push opens a session on the same path as .peer" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));
    const transport = BackendTransport.init(StreamRecorder, &recorder);

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    var frame_buf: [256]u8 = undefined;
    var body_buf: [128]u8 = undefined;
    const head = try testMulticastFrame(&frame_buf, &body_buf, &[_]u64{500}, "state", .{ .report = true });

    const backend_stream: u64 = 0x45;
    egress.handlePush(&worker, transport, test_realm, testStreamEvent(backend_stream, head));

    try std.testing.expectEqual(@as(usize, 1), worker.egress.sessions.liveCount());

    // 组 500 在本位置一个成员都没有，所以它被回报为不可达——语义与一次性组播相同：
    // 回报只能说"本位置没有成员"，别的位置有没有，发起方无从得知。
    try std.testing.expectEqual(@as(usize, 1), recorder.appended);
    const report = try codec.parseExactFrame(recorder.lastWrite());
    const missed = try protocol.body.TargetList.decode(report.body);
    try std.testing.expectEqual(@as(u16, 1), missed.count);
    try std.testing.expectEqual(@as(u64, 500), missed.get(0));

    var data_buf: [64]u8 = undefined;
    var data_encoder = codec.FrameEncoder.init(&data_buf);
    const tail = try data_encoder.encodeData(protocol.frame.Flags.last(), "tail");
    egress.handlePush(&worker, transport, test_realm, testStreamEvent(backend_stream, tail));
    try std.testing.expectEqual(@as(usize, 0), worker.egress.sessions.liveCount());
}

// 跨 Worker 投递通路的回归：目标的 home 不是本 Worker 时，帧必须被交接出去，
// 并且回报要按"已受理"结算——而不是当成不可达让后端白转一次离线存储。
test "a push whose home is another worker is handed off, not reported unreachable" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinatorWithWorkers(allocator, 2);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));
    const transport = BackendTransport.init(StreamRecorder, &recorder);

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();
    try std.testing.expectEqual(foundation.placement.Strategy.affinity, worker.placement.strategy);

    // 找一个 home 落在 Worker 1 的 dest_id：选址是纯函数，所以这里能直接算。
    var elsewhere: u64 = 1;
    while (worker.placement.isHome(test_realm, elsewhere)) : (elsewhere += 1) {}

    var frame_buf: [256]u8 = undefined;
    var body_buf: [128]u8 = undefined;
    const push = try testPushFrame(
        &frame_buf,
        &body_buf,
        &[_]u64{elsewhere},
        "hello",
        .{ .eof = true, .report = true },
    );

    egress.handlePush(&worker, transport, test_realm, testPushEvent(0x51, push));

    // 帧进了 Worker 1 的应用消息队列，而不是被丢弃。
    const handed = coordinator.messageRouter().pop(1);
    try std.testing.expect(handed != null);
    try std.testing.expectEqual(test_realm, handed.?.realm);
    try std.testing.expectEqualSlices(u8, push, handed.?.bytes());

    // 回报里不该有它：已被 Worker 1 受理。
    const report = try codec.parseExactFrame(recorder.lastWrite());
    const missed = try protocol.body.TargetList.decode(report.body);
    try std.testing.expectEqual(@as(u16, 0), missed.count);
}

// 节点级 HRW 不能作为节点内连接目录。尤其是 WSS：TCP reuseport 在认证前已经决定
// 连接属于哪个 Worker，而认证后才知道 dest_id，也不能迁移已经建立的 TLS 状态。
// 因此即使 HRW 恰好说目标 home 是发起 Worker，也必须让其他 Worker 查自己的索引。
test "a peer push probes every local worker even when affinity home is this worker" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinatorWithWorkers(allocator, 2);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));
    const transport = BackendTransport.init(StreamRecorder, &recorder);

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    var local_home: u64 = 1;
    while (!worker.placement.isHome(test_realm, local_home)) : (local_home += 1) {}

    var frame_buf: [256]u8 = undefined;
    var body_buf: [128]u8 = undefined;
    const push = try testPushFrame(
        &frame_buf,
        &body_buf,
        &[_]u64{local_home},
        "hello",
        .{ .eof = true, .report = true },
    );

    egress.handlePush(&worker, transport, test_realm, testPushEvent(0x52, push));

    // 旧实现会因 `isHome == true` 只查 Worker 0，从而漏掉实际由 reuseport 放在
    // Worker 1 的 WSS/QUIC 连接。现在每个其他 Worker 都恰好收到一次交接。
    const handed = coordinator.messageRouter().pop(1);
    try std.testing.expect(handed != null);
    try std.testing.expectEqual(test_realm, handed.?.realm);
    try std.testing.expectEqualSlices(u8, push, handed.?.bytes());
    try std.testing.expect(coordinator.messageRouter().pop(1) == null);

    const report = try codec.parseExactFrame(recorder.lastWrite());
    const missed = try protocol.body.TargetList.decode(report.body);
    try std.testing.expectEqual(@as(u16, 0), missed.count);
}

// 转投过来的消息必须只做本地投递，绝不再转投——这是防环的全部机制。
test "a handed-off message is delivered locally and never re-routed" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinatorWithWorkers(allocator, 2);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    // 这个 dest_id 的 home 是另一个 Worker，本 Worker 上也没有它的连接。
    var elsewhere: u64 = 1;
    while (worker.placement.isHome(test_realm, elsewhere)) : (elsewhere += 1) {}

    var frame_buf: [256]u8 = undefined;
    var body_buf: [128]u8 = undefined;
    const push = try testPushFrame(&frame_buf, &body_buf, &[_]u64{elsewhere}, "hello", .{ .eof = true, .report = true });

    egress.deliverHandoff(&worker, test_realm, 0, push);

    // 既没有再转投给任何 Worker（包括自己），也没有在后端流上回写任何东西
    // ——那条流属于发起方 Worker，本 Worker 没有它的句柄。
    try std.testing.expect(coordinator.messageRouter().pop(0) == null);
    try std.testing.expect(coordinator.messageRouter().pop(1) == null);
    try std.testing.expectEqual(@as(usize, 0), recorder.appended);
}

/// 造一条"从集群监听器进来"的连接上下文。
///
/// 生产路径上 `peer_node` 只由 `addPeerNode` 置位，而那只发生在集群监听器的新连接
/// 回调里；这里直接置位是为了在不起两个真实监听端口的情况下测分派语义。
fn testPeerContext(allocator: std.mem.Allocator, handle: usize) ConnectionContext {
    var ctx = testDetachedContext(allocator, handle, test_realm);
    ctx.peer_node = true;
    return ctx;
}

/// 拼一条对等节点会发的 `.peer` 帧：realm 放在 OPEN 的保留两字节里。
fn testPeerLinkFrame(
    frame_buf: []u8,
    body_buf: []u8,
    realm: u16,
    targets: []const u64,
    payload: []const u8,
    flags: protocol.frame.Flags,
) ![]const u8 {
    const list_len = try protocol.body.TargetList.encode(body_buf, targets);
    @memcpy(body_buf[list_len..][0..payload.len], payload);

    var encoder = codec.FrameEncoder.init(frame_buf);
    const route = RouteId.init(@intCast(realm >> 8), @intCast(realm & 0xFF));
    return encoder.encodeOpen(.peer, route, .none, flags, body_buf[0 .. list_len + payload.len]);
}

// 对等节点连接的权限与客户端正好相反：它能投递，但不能请求。
//
// 这条用例锁住的是那个反转本身——一旦有人为了省事把 peer_node 的分派并回客户端
// 那条路径，`.service` 就会被放行，等于任何一个节点都能借链路调别人的后端。
test "a peer node may deliver but may not request" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var recorder = StreamRecorder{};
    var registry = TransportRegistry.init(allocator);
    try registry.register(.direct, test_scope, BackendTransport.init(StreamRecorder, &recorder));

    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();

    var ctx = testPeerContext(allocator, 0x1000);
    defer ctx.deinit();

    var frame_buf: [256]u8 = undefined;
    var body_buf: [128]u8 = undefined;

    // `.peer` 投递被接纳（目标不在线，所以只是查表落空，不写任何流）。
    const delivery = try testPeerLinkFrame(&frame_buf, &body_buf, test_realm, &[_]u64{77}, "hello", protocol.frame.Flags.last());
    try std.testing.expectEqual(
        ingress.FrameOutcome.continue_stream,
        ingress.dispatchFrame(&worker, &ctx, 4, try codec.parseExactFrame(delivery)),
    );
    // 没有登记交换：这一帧处理完这条流就结束了，留条目只会占额度。
    try std.testing.expectEqual(@as(usize, 0), ctx.inboundExchangeCount());

    // `.service` 越权：对等节点有自己的后端，借这条链路调别人的等于绕过路由与配额。
    var encoder = codec.FrameEncoder.init(&frame_buf);
    const request = try encoder.encodeOpen(.service, test_route, .required, protocol.frame.Flags.last(), "nope");
    try std.testing.expectEqual(
        ingress.FrameOutcome.close_connection,
        ingress.dispatchFrame(&worker, &ctx, 8, try codec.parseExactFrame(request)),
    );
    // 一个后端流都不该被开出去。
    try std.testing.expectEqual(@as(usize, 0), recorder.opened);

    // `.gateway` 同样越权：kick / 组成员变更的权威在后端，不在别的网关节点。
    const command = try encoder.encodeKickOff("nope");
    try std.testing.expectEqual(
        ingress.FrameOutcome.close_connection,
        ingress.dispatchFrame(&worker, &ctx, 12, try codec.parseExactFrame(command)),
    );
}

// 对等节点的 realm 取自帧头那两个保留字节，而不是连接的 SNI。
//
// 这条锁住的是隔离边界：realm 8 的投递不能落到 realm 7 的连接上，即使两者的
// dest_id 是同一个数值。
test "a peer delivery is scoped by the realm in its frame header" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var registry = TransportRegistry.init(allocator);
    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();
    _ = &registry;

    // 一条 realm 7 的连接绑定 dest_id 42。本用例不解引用这个句柄——投递会在
    // realm 不匹配时就查不到链，根本走不到 streamWrite。
    var victim = QUICConnection{ .inner = @ptrFromInt(0x2000) };
    const victim_ctx = try worker.conn_manager.add(&victim, 7, &worker);
    worker.conn_manager.bindDest(victim_ctx.session_handle, 42);
    try std.testing.expectEqual(@as(usize, 1), worker.conn_manager.destCount(7, 42));

    var ctx = testPeerContext(allocator, 0x1000);
    defer ctx.deinit();

    // 对等节点声称这是 realm 8 的投递，目标同样是 42。
    var frame_buf: [256]u8 = undefined;
    var body_buf: [128]u8 = undefined;
    const delivery = try testPeerLinkFrame(&frame_buf, &body_buf, 8, &[_]u64{42}, "hello", protocol.frame.Flags.last());
    const parsed = try codec.parseExactFrame(delivery);
    try std.testing.expectEqual(@as(u16, 8), parsed.header.realmHint().?);
    try std.testing.expectEqual(
        ingress.FrameOutcome.continue_stream,
        ingress.dispatchFrame(&worker, &ctx, 4, parsed),
    );

    // realm 7 那条连接毫发无损：realm 8 的链上一个成员都没有。
    try std.testing.expectEqual(@as(usize, 0), worker.conn_manager.destCount(8, 42));
    try std.testing.expectEqual(@as(usize, 1), worker.conn_manager.destCount(7, 42));
}

// 跨节点一跳 + 节点内一跳，总跳数被结构性地限死在 2。
test "a peer delivery may take one intra-node hop but never leaves the node again" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinatorWithWorkers(allocator, 2);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var registry = TransportRegistry.init(allocator);
    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();
    _ = &registry;

    // 挑一个 home 在 Worker 1 的 dest_id，并让选址视图里有第二个节点——
    // 若 local_only 没生效，这一帧就会被同时发给那个节点。
    var elsewhere: u64 = 1;
    while (worker.placement.isHome(test_realm, elsewhere)) : (elsewhere += 1) {}
    worker.node_snapshot[0] = 1;
    worker.node_snapshot[1] = 2;
    worker.placement.nodes = worker.node_snapshot[0..2];

    var ctx = testPeerContext(allocator, 0x1000);
    defer ctx.deinit();

    var frame_buf: [256]u8 = undefined;
    var body_buf: [128]u8 = undefined;
    const delivery = try testPeerLinkFrame(&frame_buf, &body_buf, test_realm, &[_]u64{elsewhere}, "hello", protocol.frame.Flags.last());
    _ = ingress.dispatchFrame(&worker, &ctx, 4, try codec.parseExactFrame(delivery));

    // 节点内那一跳发生了。
    const handed = coordinator.messageRouter().pop(1);
    try std.testing.expect(handed != null);
    try std.testing.expectEqual(test_realm, handed.?.realm);

    // 而它再被消费时不会又转投一次——`deliverHandoff` 只做本地投递。
    egress.deliverHandoff(&worker, handed.?.realm, handed.?.session, handed.?.bytes());
    try std.testing.expect(coordinator.messageRouter().pop(0) == null);
    try std.testing.expect(coordinator.messageRouter().pop(1) == null);
}

// 对等节点也能开流式会话：那条链路流就是会话身份（设计文档 §5.3）。
//
// 这条锁住的是"会话号走信封、不走帧"这件事：节点内转投的每一帧都带着同一个会话号，
// 而帧本身一个字节都没为它腾过位置。让目标 Worker 从帧里读会话号就等于把网关内部的
// 记账暴露成协议字段，而后端可以伪造它——伪造一个别人的会话号就能把自己的字节插进
// 别人的流。
test "a peer node streaming session carries its id in the envelope, not the frame" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinatorWithWorkers(allocator, 2);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var registry = TransportRegistry.init(allocator);
    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();
    _ = &registry;

    // 挑一个 home 在另一个 Worker 上的 dest_id，这样节点内那一跳一定发生。
    var elsewhere: u64 = 1;
    while (worker.placement.isHome(test_realm, elsewhere)) : (elsewhere += 1) {}

    var ctx = testPeerContext(allocator, 0x1100);
    defer ctx.deinit();

    var frame_buf: [256]u8 = undefined;
    var body_buf: [128]u8 = undefined;
    // OPEN 不带 eof = 流式投递。以前这是协议违规，现在它开一个会话。
    const head = try testPeerLinkFrame(&frame_buf, &body_buf, test_realm, &[_]u64{elsewhere}, "head", .{});
    try std.testing.expectEqual(
        ingress.FrameOutcome.continue_stream,
        ingress.dispatchFrame(&worker, &ctx, 4, try codec.parseExactFrame(head)),
    );

    try std.testing.expectEqual(@as(usize, 1), worker.egress.sessions.liveCount());
    const session_id = ctx.inboundExchange(4).?.push_session;
    try std.testing.expect(session_id != 0);

    const first = coordinator.messageRouter().pop(1).?;
    try std.testing.expectEqual(session_id, first.session);

    // 续传帧沿同一个会话走。DATA 帧只有 4 字节头，里面装不下也不需要装会话号。
    var data_buf: [64]u8 = undefined;
    var data_encoder = codec.FrameEncoder.init(&data_buf);
    const tail = try data_encoder.encodeData(protocol.frame.Flags.last(), "tail");
    try std.testing.expectEqual(
        ingress.FrameOutcome.continue_stream,
        ingress.dispatchFrame(&worker, &ctx, 4, try codec.parseExactFrame(tail)),
    );

    const second = coordinator.messageRouter().pop(1).?;
    try std.testing.expectEqual(session_id, second.session);

    // eof 收掉会话；条目留着当"这条流用过了"的凭据，会话号清零，免得收尾路径
    // 再去作废一个已经正常结束的会话。
    try std.testing.expectEqual(@as(usize, 0), worker.egress.sessions.liveCount());
    try std.testing.expectEqual(@as(u64, 0), ctx.inboundExchange(4).?.push_session);
    try std.testing.expect(ctx.inboundExchange(4).?.input_complete);
}

// 通道绑定的授权判据是"后端已经把你放进那个组"（设计文档 §6.1）。
//
// 这条锁住的是权限模型本身：客户端不能靠自称获得往任意组发状态包的能力。放开它就等于
// 给了 §5.4 明确禁止的那条通路一个不可靠版本——绕过后端的反垃圾与定序直接骚扰他人。
test "binding a datagram channel is refused unless the backend put you in that group" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var registry = TransportRegistry.init(allocator);
    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();
    _ = &registry;

    var conn = QUICConnection{ .inner = @ptrFromInt(0x1000) };
    const ctx = try worker.conn_manager.add(&conn, test_realm, &worker);
    ctx.authenticated = true;

    var frame_buf: [128]u8 = undefined;
    var body_buf: [16]u8 = undefined;
    const body_len = try protocol.body.ChannelBinding.encode(&body_buf, 2, 777);
    var encoder = codec.FrameEncoder.init(&frame_buf);
    const bind = try encoder.encodeControlFrame(.bind_channel, body_buf[0..body_len]);
    const parsed = try codec.parseExactFrame(bind);

    // 没进过组 → 绑定被拒。
    try std.testing.expectEqual(ingress.BindOutcome.not_a_member, ingress.resolveBind(&worker, ctx, parsed));
    try std.testing.expect(ctx.channelGroup(2) == null);

    // 后端把它放进 777（这是唯一能建立成员关系的路径），再绑就通了。
    try worker.conn_manager.joinGroup(ctx.session_handle, 777);
    try std.testing.expectEqual(ingress.BindOutcome.bound, ingress.resolveBind(&worker, ctx, parsed));
    try std.testing.expectEqual(@as(u64, 777), ctx.channelGroup(2).?);

    // 组标识变了但连接没进那个组 → 依旧被拒，而已有的绑定不受影响。
    const other_len = try protocol.body.ChannelBinding.encode(&body_buf, 5, 888);
    var other_encoder = codec.FrameEncoder.init(&frame_buf);
    const other = try other_encoder.encodeControlFrame(.bind_channel, body_buf[0..other_len]);
    try std.testing.expectEqual(
        ingress.BindOutcome.not_a_member,
        ingress.resolveBind(&worker, ctx, try codec.parseExactFrame(other)),
    );
    try std.testing.expect(ctx.channelGroup(5) == null);
    try std.testing.expectEqual(@as(u64, 777), ctx.channelGroup(2).?);
}

// 上行 datagram 的每一种拒绝都必须被计数。
//
// 逐包路径上不能记日志（60Hz × N 个玩家会把磁盘写满），所以计数器是这条路径**唯一**的
// 可观测手段。少了它，"某些玩家偶发卡顿"就没有任何入手点。
test "every rejected datagram is counted instead of vanishing" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinator(allocator);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var registry = TransportRegistry.init(allocator);
    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();
    _ = &registry;

    var conn = QUICConnection{ .inner = @ptrFromInt(0x2000) };

    // 1. 连接不在管理器里（drain 期间刚被拒的连接）。
    ingress.handleDatagram(&worker, &conn, &[_]u8{ 0x02, 0x01 });
    try std.testing.expectEqual(@as(u64, 1), worker.datagrams_in);
    try std.testing.expectEqual(@as(u64, 1), worker.datagrams_dropped);

    const ctx = try worker.conn_manager.add(&conn, test_realm, &worker);
    ctx.authenticated = true;

    // 2. 通道没绑：客户端抢跑，或者绑定已被吊销。
    ingress.handleDatagram(&worker, &conn, &[_]u8{ 0x02, 0x01 });
    try std.testing.expectEqual(@as(u64, 2), worker.datagrams_dropped);

    // 3. 头畸形（第一个字节不是 DATAGRAM）——很可能是有人把流帧塞进了不可靠通路。
    ingress.handleDatagram(&worker, &conn, &[_]u8{ 0x00, 0x01 });
    try std.testing.expectEqual(@as(u64, 3), worker.datagrams_dropped);

    // 4. 短于 2 字节头。
    ingress.handleDatagram(&worker, &conn, &[_]u8{0x02});
    try std.testing.expectEqual(@as(u64, 4), worker.datagrams_dropped);
    try std.testing.expectEqual(@as(u64, 4), worker.datagrams_in);
}

// 不可靠组播必须走遍所有位置，和一次性 `.multicast` 完全同一套选路。
//
// 这条锁住的是"标志位跟着帧走"这个设计的收益：客户端上行的 datagram 被重编成一个带
// `unreliable` 的 `.multicast` 帧之后，跨 Worker、跨节点的转投一行代码都不用改。
// 反过来说，如果哪天有人为不可靠通路另写一条选路，这条用例会先失败。
test "an uplink datagram fans out through the same routing as a reliable multicast" {
    const allocator = std.testing.allocator;

    var coordinator = try testCoordinatorWithWorkers(allocator, 2);
    defer coordinator.deinit();
    try coordinator.start();
    defer coordinator.stop();

    var registry = TransportRegistry.init(allocator);
    var worker = try testWorker(allocator, &coordinator, registry);
    defer worker.deinit();
    _ = &registry;

    var conn = QUICConnection{ .inner = @ptrFromInt(0x3000) };
    const ctx = try worker.conn_manager.add(&conn, test_realm, &worker);
    ctx.authenticated = true;
    try worker.conn_manager.joinGroup(ctx.session_handle, 555);
    ctx.bindChannel(1, 555);

    ingress.handleDatagram(&worker, &conn, &[_]u8{ 0x02, 0x01, 'x', 'y' });
    try std.testing.expectEqual(@as(u64, 0), worker.datagrams_dropped);

    // 同机另一个 Worker 收到了一条应用消息，而它是一个带 unreliable 的 `.multicast` 帧。
    const handed = coordinator.messageRouter().pop(1).?;
    try std.testing.expectEqual(test_realm, handed.realm);
    // 会话号必须是 0：不可靠投递是一次性的，不是流式会话。
    try std.testing.expectEqual(@as(u64, 0), handed.session);

    const parsed = try codec.parseExactFrame(handed.bytes());
    try std.testing.expectEqual(protocol.frame.DestKind.multicast, parsed.header.dest_kind);
    try std.testing.expect(parsed.header.flags.unreliable);
    try std.testing.expect(parsed.header.isLast());

    // body = 单个组标识 + 原始负载，负载一个字节都没被改动。
    const list = try protocol.body.TargetList.decode(parsed.body);
    try std.testing.expectEqual(@as(u16, 1), list.count);
    try std.testing.expectEqual(@as(u64, 555), list.get(0));
    try std.testing.expectEqualStrings("xy", parsed.body[list.prefixLen()..]);
}
