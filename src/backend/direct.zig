//! 直连 QUIC 传输实现
//!
//! 网关直连后端服务的 BackendTransport 实现。
//! DirectTransport 是「直连」这种传输的实现类型：每条直连路由（RouteId）
//! 对应一个独立实例，注册表维护 RouteId → 实例 的一一映射，路由语义完全落在注册表。
//! 实例内部维护「本服务各副本（不同 host:port）」的 QUIC 连接池；
//! 如何寻址、建连、复用是本实现的私事，上层不感知也不参与。
//!
//! ## 回程句柄
//!
//! send 返回的 stream 句柄由「连接 id + 连接代际 + 该连接上的 QUIC stream id」合成，
//! 保证跨后端连接和重连前后全局唯一，worker 直接用它做请求/响应回程映射。

const std = @import("std");
const xev = @import("xev");
const build_options = @import("build_options");
const foundation = @import("../foundation/mod.zig");
const quic = @import("../quic/mod.zig");
const reactor = @import("../reactor/mod.zig");

const backend_mod = @import("transport.zig");
const pool_mod = @import("pool.zig");
const BackendPool = pool_mod.BackendPool;
const BackendTransport = backend_mod.BackendTransport;
const TransportError = backend_mod.TransportError;
const ResolveCallback = backend_mod.ResolveCallback;
const TransportRecv = backend_mod.TransportRecv;
const RouteId = backend_mod.RouteId;
const protocol = @import("../protocol/mod.zig");

const Resolver = foundation.resolver.Resolver;
const ResolveHandle = foundation.resolver.ResolveHandle;
const ResolveResult = foundation.resolver.ResolveResult;
const QUICConnection = quic.connection.Connection;

// ============================================================================
// 配置
// ============================================================================

/// 后端服务的一个实例地址。
pub const Endpoint = struct {
    /// 后端主机（可以是域名，由传输内部异步 DNS 解析）
    host: [:0]const u8,
    port: u16,
};

/// 直连传输配置
pub const DirectConfig = struct {
    /// 本逻辑服务的副本列表（同一服务的多实例，不同 host:port）。
    /// 将来接 etcd/Consul 动态副本时，只替换这份列表的来源，接口不变。
    endpoints: []const Endpoint,
    /// ALPN 协议标识；与客户端侧同一个字符串，协议版本活在这里。
    alpn: [:0]const u8 = "lyune/2",
    /// 是否验证服务器证书
    verify_cert: bool = true,
    /// 根证书文件路径（可选）
    root_cert_file: ?[:0]const u8 = null,
    /// 网关向后端出示的客户端证书；与 `key_file` 同时给出才生效（设计文档 §10.1）。
    ///
    /// 有了它，"网关 ↔ 后端双向认证"这个不变量不需要任何额外状态机就成立：对端校验
    /// 失败意味着 QUIC 握手不会完成，连接永远到不了 `ready`，于是"认证失败"与
    /// "没有可用 transport"是同一件事。
    ///
    /// 它同时是后端控制通道（§7.2 的 `kick_off` / `join_group` / `leave_group`）的全部
    /// 安全依据：少了它，任何能连上后端端口的东西都能冒充后端，进而指挥网关断开任意
    /// 连接、把任意连接放进任意组。
    cert_file: ?[:0]const u8 = null,
    /// 与 `cert_file` 配对的私钥。
    key_file: ?[:0]const u8 = null,
    /// QUIC 空闲超时（毫秒）
    idle_timeout_ms: u64 = 30_000,
    /// QUIC 拥塞控制算法
    congestion_algorithm: quic.config.Config.CongestionAlgorithm = .bbr,
};

// ============================================================================
// 单后端连接
// ============================================================================

/// 单条后端连接的生命周期状态。
///
/// 用显式状态机替代 connected/connecting 两个独立 bool：后者无法表达
/// "曾经连上、现在断了、可以重连"这一状态，导致断开后 connecting 永远
/// 停在 true，此后所有建连尝试都被误判为"已在建连中"而直接返回。
const ConnState = enum {
    /// 从未建连，或上次失败后已可立即重试。
    idle,
    /// DNS 解析或 QUIC 握手进行中。
    connecting,
    /// 已就绪，可发送数据。
    ready,
    /// 建连或连接失败，需等到 retry_at 之后才允许再次尝试。
    backoff,
};

/// 重连退避的起始间隔（微秒）。
const backoff_base_us: u64 = 100 * std.time.us_per_ms;
/// 重连退避的上限间隔（微秒）。
const backoff_max_us: u64 = 30 * std.time.us_per_s;

/// 到单个后端 endpoint 的一条 QUIC 连接及其全部状态。
///
/// 由 DirectTransport 的连接池按 (host, port) 创建和复用；堆上分配，保证异步回调指针稳定。
///
/// **它不持有传输设施**：socket、picoquic 上下文、定时器、GSO 缓冲、接收槽位存储
/// 都在每 Worker 一份的 `BackendPool` 里（见 `backend/pool.zig` 的文件头）。这条连接
/// 自己只剩一个 `picoquic_cnx_t` 句柄、一段状态机和一个队列头——早先它是
/// 约 2.1 MiB + 1 fd + 1 定时器 + 1 picoquic 上下文。
const BackendConn = struct {
    transport: *DirectTransport,
    /// 连接 id，用于合成跨连接唯一的 stream 句柄
    id: u16,
    /// 这条 endpoint 连接的当前代际。
    ///
    /// 同一个 BackendConn 会在断线后建立新的 QUIC 连接，而 QUIC stream id 必须从 0
    /// 重新开始。把代际并入上层句柄后，新旧连接即使都有 stream 0 也不会发生 ABA。
    generation: u16,
    /// 本连接对应的后端 endpoint（引用配置内存，不拥有所有权）
    host: [:0]const u8,
    port: u16,

    /// 本连接的 QUIC 句柄；null 表示尚未建连或已断开。
    ///
    /// 由本结构自己持有，而不是回头问 `AsyncClient`：一个客户端上有多条连接，
    /// 它不替调用方记住"当前那条"（那个设计会让第二条连接把第一个指针变成别名，
    /// 见 `reactor/client.zig` 的 connectAddress 注释）。
    cnx: ?quic.c.QuicCnx,
    resolve_handle: ?ResolveHandle,

    /// 本连接在共享接收池上的待取队列。
    ///
    /// 存储共享、**队列不共享**：字节序与归属仍然按连接算，因此
    /// `transport.receive()` 的语义、`inflight` 的键、Worker 的 drain 循环都不用改。
    queue: pool_mod.SlotList,

    /// 当前生命周期状态。
    state: ConnState,
    /// 连续失败次数，用于指数退避。
    failure_count: u32,
    /// backoff 状态下允许再次建连的时刻（微秒）。
    retry_at: u64,

    /// 等待本连接就绪的回调（同一连接可能被多个路由的 resolve 等待）
    pending_callbacks: std.ArrayList(PendingCallback),

    /// 下一个由客户端发起的后端双向 stream id。
    /// QUIC 客户端发起的 bidi stream id 从 0 开始，每次递增 4。
    next_bidi_stream_id: u64,

    /// 池回调的转交表。
    ///
    /// 共享客户端只有一个 user_context，所以池按 cnx 指针查到本结构再经这张表转交。
    const hooks: pool_mod.ConnHooks = .{
        .on_connected = hookConnected,
        .on_stream_data = hookStreamData,
        .on_stream_control = hookStreamControl,
        .on_close = hookClose,
    };

    const PendingCallback = struct {
        callback: ResolveCallback,
        ctx: ?*anyopaque,
    };

    fn init(transport: *DirectTransport, host: [:0]const u8, port: u16, id: u16) !BackendConn {
        // 不再分配任何接收缓冲：槽位存储在每 Worker 一份的共享池里。
        return .{
            .transport = transport,
            .id = id,
            .generation = 0,
            .host = host,
            .port = port,
            .cnx = null,
            .resolve_handle = null,
            // 队列的 realm 在这里定死：它决定这条连接占用的槽位算在谁头上。
            .queue = .{ .realm = transport.realm },
            .state = .idle,
            .failure_count = 0,
            .retry_at = 0,
            .pending_callbacks = .{ .items = &.{}, .capacity = 0 },
            .next_bidi_stream_id = 0,
        };
    }

    fn deinit(self: *BackendConn) void {
        const allocator = self.transport.allocator;
        if (self.resolve_handle) |handle| {
            self.transport.resolver.cancel(handle);
            self.resolve_handle = null;
        }
        // 优雅关闭这一条连接。
        //
        // 不能指望 `AsyncClient.deinit` 代劳：客户端是**共享**的，它不持有连接列表
        // （见 reactor/client.zig）。少了这一步，后端只会看到空闲超时，而不是一个
        // 明确的 CONNECTION_CLOSE。
        self.detach();
        // 队列里没被取走的槽位要还给共享池，否则整个 Worker 的接收容量会随
        // 连接的建立/销毁单向减少。
        self.transport.pool.dropQueued(&self.queue);
        self.pending_callbacks.deinit(allocator);
        self.state = .idle;
    }

    /// 把一次回调带来的分片放进共享接收池。
    ///
    /// 容量不足时整段拒绝并返回 false：只入一半会让上层拿到被截断的字节流，
    /// 那是静默数据损坏，比明确失败糟得多。拒绝的判据有三条——共享池的剩余量、
    /// 本连接自己的公平上限（一个卡住不取的后端不能把整个 Worker 的接收容量吃干）、
    /// 以及本 realm 在争用时的公平份额（一个租户不能靠多开连接绕过前一条）。
    fn enqueueRecv(self: *BackendConn, stream_id: u64, data: []const u8, is_fin: bool) bool {
        return self.transport.pool.enqueue(
            &self.queue,
            DirectTransport.makeHandle(self.id, self.generation, stream_id),
            data,
            is_fin,
        );
    }

    /// 断开并从池的索引上摘掉自己。
    ///
    /// 只清连接，不动共享客户端——它归池所有，本连接只是它上面的一条 cnx。
    fn detach(self: *BackendConn) void {
        const cnx_handle = self.cnx orelse return;
        self.cnx = null;
        self.transport.pool.unregister(cnx_handle);
        var conn = QUICConnection.fromRaw(cnx_handle);
        conn.close();
    }

    /// 当前是否可以发送数据。
    fn isReady(self: *const BackendConn) bool {
        return self.state == .ready;
    }

    /// 在状态机允许时发起建连。
    ///
    /// 这是唯一的建连入口：resolve 与 send 路径都经由它，因此断开后只要
    /// 还有流量或 resolve 请求，连接就会按退避节奏自行恢复，不需要额外定时器。
    ///
    /// 早先这里还要处理"上次的 AsyncClient 只能在回调栈之外释放"（`needs_client_rebuild`）。
    /// 客户端改成池级共享之后那套机制整个消失了：客户端从不因单条连接断开而重建，
    /// 重连只是在同一个客户端上再开一条 cnx。
    fn ensureConnecting(self: *BackendConn, now: u64) void {
        switch (self.state) {
            .ready, .connecting => return,
            .backoff => if (now < self.retry_at) return,
            .idle => {},
        }

        self.state = .connecting;
        self.startConnect() catch |err| self.markFailed(err);
    }

    /// 标记本次建连/连接失败：安排指数退避并通知所有等待方。
    fn markFailed(self: *BackendConn, err: TransportError) void {
        self.failure_count +|= 1;
        const shift: u6 = @intCast(@min(self.failure_count - 1, 8));
        const delay = @min(backoff_base_us << shift, backoff_max_us);
        self.retry_at = quic.c.currentTime() + delay;
        self.state = .backoff;
        self.fireCallbacks(err);
    }

    /// 启动异步连接（内部使用）
    fn startConnect(self: *BackendConn) TransportError!void {
        const transport = self.transport;

        // 1. 取共享客户端（首次调用时才真正建 socket / picoquic 上下文 / 定时器）。
        //
        //    TLS 参数取自 `DirectConfig`，而它在 RuntimeConfig 里是一份模板、每条路由
        //    只替换 endpoints，因此全 Worker 一致。若哪天真要按路由配不同证书，
        //    `acquireClient` 会报 ClientConfigMismatch 而不是静默沿用第一份配置。
        _ = transport.pool.acquireClient(.{
            .base = .{
                .alpn = transport.config.alpn,
                .root_cert_file = transport.config.root_cert_file,
                .verify_cert = transport.config.verify_cert,
                .idle_timeout_ms = transport.config.idle_timeout_ms,
                .congestion_algorithm = transport.config.congestion_algorithm,
            },
            .cert_file = transport.config.cert_file,
            .key_file = transport.config.key_file,
            .bind_port = 0,
        }) catch |err| {
            return switch (err) {
                error.OutOfMemory => TransportError.OutOfMemory,
                else => TransportError.ConnectionFailed,
            };
        };

        // 2. 发起异步 DNS，解析完成后再创建 QUIC 连接。
        self.resolve_handle = transport.resolver.resolve(
            self.host,
            self.port,
            onResolved,
            self,
        ) catch |err| {
            return switch (err) {
                error.OutOfMemory => TransportError.OutOfMemory,
                error.Timeout => TransportError.Timeout,
                else => TransportError.ConnectionFailed,
            };
        };
    }

    /// 通知所有等待本连接就绪的回调并清空等待列表。
    /// 状态迁移由调用方负责（成功走 onClientConnected，失败走 markFailed）。
    fn fireCallbacks(self: *BackendConn, err: ?TransportError) void {
        for (self.pending_callbacks.items) |pending| {
            pending.callback(pending.ctx, err);
        }
        self.pending_callbacks.clearRetainingCapacity();
    }

    /// 在本连接上发送数据，返回跨连接唯一的 stream 句柄。
    ///
    /// handle 为 null 时新开一条流；否则在该句柄指向的既有流上追加。
    /// is_fin 为 true 时结束这条流，后端由此知道请求已完整。
    fn sendOn(self: *BackendConn, handle: ?u64, data: []const u8, is_fin: bool) TransportError!u64 {
        const cnx_handle = self.cnx orelse return TransportError.ConnectionFailed;

        var conn = QUICConnection.fromRaw(cnx_handle);
        if (!conn.isConnected()) return TransportError.ConnectionFailed;

        const stream_id = if (handle) |value| blk: {
            if (DirectTransport.handleConnId(value) != self.id or
                DirectTransport.handleGeneration(value) != self.generation)
            {
                return TransportError.Closed;
            }
            break :blk DirectTransport.handleStreamId(value);
        } else self.nextBidiStreamId();

        conn.streamWrite(stream_id, data, is_fin) catch return TransportError.SendFailed;
        // add_to_stream 只入 picoquic 队列；不主动驱动共享客户端的话，空闲连接上的
        // 应用数据会一直等到最远 10 秒后的 QUIC timer 才真正发出。
        self.transport.pool.flushClient();
        return DirectTransport.makeHandle(self.id, self.generation, stream_id);
    }

    fn nextBidiStreamId(self: *BackendConn) u64 {
        const stream_id = self.next_bidi_stream_id;
        self.next_bidi_stream_id += 4;
        return stream_id;
    }

    /// 与句柄高 32 位相同的连接代际键。
    fn connectionKey(self: *const BackendConn) u32 {
        return (@as(u32, self.id) << DirectTransport.generation_bits) | self.generation;
    }

    // ------------------------------------------------------------------------
    // 内部回调处理
    // ------------------------------------------------------------------------

    fn onResolved(ctx: ?*anyopaque, result: ResolveResult) void {
        const self: *BackendConn = @ptrCast(@alignCast(ctx.?));
        self.resolve_handle = null;
        if (self.transport.closed) return;

        const address = switch (result) {
            .address => |addr| addr,
            .err => |err| {
                self.fireCallbacks(switch (err) {
                    error.OutOfMemory => TransportError.OutOfMemory,
                    error.Timeout => TransportError.Timeout,
                    else => TransportError.ConnectionFailed,
                });
                return;
            },
        };

        const client = self.transport.pool.acquireClient(.{
            .base = .{
                .alpn = self.transport.config.alpn,
                .root_cert_file = self.transport.config.root_cert_file,
                .verify_cert = self.transport.config.verify_cert,
                .idle_timeout_ms = self.transport.config.idle_timeout_ms,
                .congestion_algorithm = self.transport.config.congestion_algorithm,
            },
            .cert_file = self.transport.config.cert_file,
            .key_file = self.transport.config.key_file,
            .bind_port = 0,
        }) catch {
            self.markFailed(TransportError.ConnectionFailed);
            return;
        };

        const cnx_handle = client.connectAddress(address, self.host, null) catch {
            self.markFailed(TransportError.ConnectionFailed);
            return;
        };

        // 登记到池的索引上，共享客户端的回调才能按 cnx 找回本结构。
        // 登记不上就没人能消费这条连接的事件，因此当场作废而不是留一条黑洞连接。
        self.transport.pool.register(cnx_handle, self, &hooks) catch {
            var orphan = QUICConnection.fromRaw(cnx_handle);
            orphan.close();
            self.markFailed(TransportError.ConnectionFailed);
            return;
        };
        self.cnx = cnx_handle;
    }

    fn hookConnected(ctx: *anyopaque, conn: *QUICConnection) void {
        _ = conn;
        const self: *BackendConn = @ptrCast(@alignCast(ctx));

        // 每条 QUIC 连接都有独立的流编号空间，新连接必须从客户端 bidi stream 0
        // 重新开始。代际先递增再进入 ready，使新请求的上层句柄与旧连接彻底隔离。
        // u16 回绕需要同一 endpoint 在 60 秒 inflight 窗口内完成 65536 次重连才会 ABA，
        // 远高于 100ms 起步的退避状态机在物理上可能达到的速度。
        self.generation +%= 1;
        self.next_bidi_stream_id = 0;
        self.state = .ready;
        self.failure_count = 0;
        self.retry_at = 0;
        std.log.info("[DirectTransport] connected to {s}:{}", .{ self.host, self.port });

        // 连接成功，通知所有等待方
        self.fireCallbacks(null);
    }

    fn hookStreamData(ctx: *anyopaque, conn: *QUICConnection, stream_id: u64, data: []const u8, is_fin: bool) void {
        const self: *BackendConn = @ptrCast(@alignCast(ctx));

        // 同一个 UDP 包可能连续派发多个流回调。第一段把连接废弃后，其余回调必须
        // 直接丢弃，否则会重复记录同一故障、重复关闭连接并刷屏。
        if (self.state != .ready) return;
        if (data.len == 0 and !is_fin) return;

        // 丢弃可靠流上的字节会让后续帧的长度与内容错位，属于静默数据损坏，
        // 而不只是"丢一个包"。接收池放不下时主动废弃这条连接，
        // 让上层看到明确失败，而不是继续投递残缺字节流。
        if (!self.enqueueRecv(stream_id, data, is_fin)) {
            std.log.err(
                "[DirectTransport] recv pool full for {s}:{}, dropping connection",
                .{ self.host, self.port },
            );
            self.abortConnection(conn, TransportError.ReceiveFailed);
        }
    }

    fn hookStreamControl(ctx: *anyopaque, conn: *QUICConnection, stream_id: u64, event: quic.c.CallbackEvent) void {
        const self: *BackendConn = @ptrCast(@alignCast(ctx));
        if (self.state != .ready) return;

        const kind: backend_mod.RecvKind = switch (event) {
            .stream_reset => .stream_reset,
            .stop_sending => .stop_sending,
            else => unreachable,
        };
        if (!self.transport.pool.enqueueControl(
            &self.queue,
            DirectTransport.makeHandle(self.id, self.generation, stream_id),
            kind,
        )) {
            std.log.err(
                "[DirectTransport] recv pool full for {s}:{}, dropping connection",
                .{ self.host, self.port },
            );
            self.abortConnection(conn, TransportError.ReceiveFailed);
            return;
        }

        // 后端用 STOP_SENDING 终止网关→后端这一方向；按 QUIC 约定立即 RESET_STREAM，
        // 同时仍把事件排给 Worker，让对应客户端交换得到明确失败而非等待超时。
        if (event == .stop_sending) conn.closeStream(stream_id);
    }

    /// 主动废弃当前连接：请求 QUIC 关闭并进入退避。
    /// 已入队的数据保持可读——它们是完整字节，上层仍可正常消费。
    fn abortConnection(self: *BackendConn, conn: *QUICConnection, err: TransportError) void {
        conn.close();
        // 只清句柄，不从池索引上摘：此刻仍在 picoquic 回调栈内，而池会在
        // 随后的 close 事件里自己 unregister。
        self.cnx = null;
        self.transport.signalFailure(self.connectionKey());
        self.markFailed(err);
    }

    fn hookClose(ctx: *anyopaque, conn: *QUICConnection, event: quic.c.CallbackEvent) void {
        _ = conn;
        _ = event;
        const self: *BackendConn = @ptrCast(@alignCast(ctx));

        const was_ready = self.state == .ready;
        std.log.info("[DirectTransport] connection to {s}:{} closed", .{ self.host, self.port });

        // 句柄必须就地作废：picoquic 即将释放这个 cnx，任何后续 sendOn 都是
        // use-after-free。摘索引由池在本回调返回后做。
        self.cnx = null;

        // 无论此前是否就绪，都必须离开 ready/connecting 并安排退避，
        // 否则状态会永久停滞、此后所有建连尝试都被误判为"已在进行中"。
        if (was_ready) self.transport.signalFailure(self.connectionKey());
        self.markFailed(if (was_ready) TransportError.Closed else TransportError.ConnectionFailed);
    }
};

// ============================================================================
// 直连传输实现
// ============================================================================

pub const DirectTransport = struct {
    const Self = @This();

    /// 后端流句柄布局：`connection id:16 | generation:16 | QUIC stream id:32`。
    ///
    /// connection id 定位 endpoint 槽位；generation 区分该槽位先后建立的 QUIC
    /// 连接；低 32 位保留连接内流号。默认 128 条在途流距离 2^30 条双向流上限极远。
    const stream_id_bits: u6 = 32;
    const generation_bits: u6 = 16;

    allocator: std.mem.Allocator,
    config: DirectConfig,
    event_loop: *xev.Loop,
    resolver: Resolver,
    /// 本实例服务的隔离域。
    ///
    /// 一个实例对应注册表里一个 `ScopedRoute(realm, group, route_key)`，所以 realm 是
    /// 实例级常量。它只有一个用途：给共享接收池的槽位记账（见 backend/pool.zig 的
    /// `SlotList.realm`）——上行/下行的 realm 判定都不看这里，那些走连接上下文。
    realm: foundation.realm.RealmId,
    /// 每 Worker 一份的共享传输设施（见 backend/pool.zig）。
    ///
    /// 本实例**借用**它，不拥有：一个 Worker 上的所有 DirectTransport 共用同一个池，
    /// 因此 socket / picoquic 上下文 / 定时器 / GSO 缓冲 / 接收槽位存储各只有一份。
    /// 销毁顺序上池必须晚于所有 transport。
    pool: *BackendPool,

    /// 连接池：本服务各实例的后端连接（所有权在此，按 host:port 去重）
    conns: std.ArrayList(*BackendConn),
    /// 轮询游标，让请求在多个就绪副本间分散。
    next_conn: usize,

    /// 状态标记
    closed: bool,

    /// 等待 Worker 消费的连接故障域。
    ///
    /// 每个已创建副本至多占一项，容量在创建连接时预留，因此故障回调只做定容入队，
    /// 不分配内存。多个空闲副本同时关闭时必须逐项通知；把它们合成“整个 transport”
    /// 会误杀仍有活跃流量的健康副本。
    pending_failures: std.ArrayList(u32),
    last_failure_conn: u32,

    // ========================================================================
    // 生命周期
    // ========================================================================

    pub fn init(
        allocator: std.mem.Allocator,
        config: DirectConfig,
        event_loop: *xev.Loop,
        resolver_impl: Resolver,
        realm: foundation.realm.RealmId,
        shared_pool: *BackendPool,
    ) !Self {
        return .{
            .allocator = allocator,
            .config = config,
            .event_loop = event_loop,
            .resolver = resolver_impl,
            .realm = realm,
            .pool = shared_pool,
            .conns = .{ .items = &.{}, .capacity = 0 },
            .next_conn = 0,
            .closed = false,
            .pending_failures = .{ .items = &.{}, .capacity = 0 },
            .last_failure_conn = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.closed) return;
        for (self.pending_failures.items) |_| self.pool.acknowledgeFailure();
        self.pending_failures.deinit(self.allocator);
        for (self.conns.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }
        self.conns.deinit(self.allocator);
        self.closed = true;
    }

    // ========================================================================
    // 内部辅助方法
    // ========================================================================

    fn signalFailure(self: *Self, connection_key: u32) void {
        for (self.pending_failures.items) |pending| {
            if (pending == connection_key) return;
        }
        // getOrCreateConn 为每个连接预留一格；同一连接在消费前重复上报会被上面的
        // 去重吸收，因此这里不可能扩容，也就能安全地运行在 picoquic 回调栈内。
        self.pending_failures.appendAssumeCapacity(connection_key);
        self.pool.signalFailure();
    }

    /// 获取 endpoint 对应的池中连接，不存在则新建（按 host:port 去重）。
    fn getOrCreateConn(self: *Self, endpoint: Endpoint) TransportError!*BackendConn {
        for (self.conns.items) |existing| {
            if (existing.port == endpoint.port and std.mem.eql(u8, existing.host, endpoint.host)) return existing;
        }

        // 故障回调不能分配内存。在连接对外可见之前，先为它可能产生的一个待处理
        // 失败通知预留容量；失败则整条连接不创建，保持不变量简单可证。
        self.pending_failures.ensureUnusedCapacity(self.allocator, 1) catch return TransportError.OutOfMemory;
        const created = self.allocator.create(BackendConn) catch return TransportError.OutOfMemory;
        const conn_id = self.pool.allocConnId() catch {
            self.allocator.destroy(created);
            return TransportError.ConnectionFailed;
        };
        created.* = BackendConn.init(self, endpoint.host, endpoint.port, conn_id) catch {
            self.allocator.destroy(created);
            return TransportError.OutOfMemory;
        };
        self.conns.append(self.allocator, created) catch {
            self.allocator.destroy(created);
            return TransportError.OutOfMemory;
        };
        return created;
    }

    /// 合成跨连接且跨代际唯一的 stream 句柄。
    fn makeHandle(conn_id: u16, generation: u16, stream_id: u64) u64 {
        std.debug.assert(stream_id < (@as(u64, 1) << stream_id_bits));
        return (@as(u64, conn_id) << (generation_bits + stream_id_bits)) |
            (@as(u64, generation) << stream_id_bits) |
            stream_id;
    }

    /// 从句柄还原它属于哪条连接。
    fn handleConnId(handle: u64) u16 {
        return @intCast(handle >> (generation_bits + stream_id_bits));
    }

    /// 从句柄还原连接代际。
    fn handleGeneration(handle: u64) u16 {
        return @intCast((handle >> stream_id_bits) & std.math.maxInt(u16));
    }

    /// 从句柄还原后端连接上的 QUIC stream id。
    fn handleStreamId(handle: u64) u64 {
        return handle & ((@as(u64, 1) << stream_id_bits) - 1);
    }

    /// 按连接 id 找回池中的连接；已被移除时返回 null。
    fn connById(self: *Self, conn_id: u16) ?*BackendConn {
        for (self.conns.items) |conn| {
            if (conn.id == conn_id) return conn;
        }
        return null;
    }

    // ========================================================================
    // BackendTransport 接口实现
    // ========================================================================

    /// 建立到本服务后端的连接（异步，通过回调通知结果）
    ///
    /// 发起连接但不等待，连接结果通过 on_ready 回调通知。
    /// 如果连接已就绪，立即调用回调返回成功。
    /// route 参数仅为接口契约：注册表已按 RouteId 选中本实例，无需二次路由。
    pub fn resolveImpl(
        self: *Self,
        route: RouteId,
        on_ready: ?ResolveCallback,
        ctx: ?*anyopaque,
    ) void {
        _ = route;

        // 如果已关闭，立即回调错误
        if (self.closed) {
            if (on_ready) |cb| {
                cb(ctx, TransportError.Closed);
            }
            return;
        }

        const now = quic.c.currentTime();

        // 对配置里的全部副本建连。只连第一个会让 endpoints[1..] 成为死配置，
        // 单副本故障时也无处可切。
        var reachable: usize = 0;
        var waiting: ?*BackendConn = null;
        var last_error: TransportError = TransportError.RouteNotFound;
        for (self.config.endpoints) |endpoint| {
            const conn = self.getOrCreateConn(endpoint) catch |err| {
                last_error = err;
                continue;
            };
            reachable += 1;
            if (conn.isReady()) continue;
            conn.ensureConnecting(now);
            if (waiting == null) waiting = conn;
        }

        if (reachable == 0) {
            if (on_ready) |cb| cb(ctx, last_error);
            return;
        }

        // 已有就绪副本即视为可用。
        for (self.conns.items) |conn| {
            if (!conn.isReady()) continue;
            if (on_ready) |cb| cb(ctx, null);
            return;
        }

        // 排队等待就绪通知。只挂在一条连接上以保证回调恰好触发一次；
        // 若这条最终失败而另一条成功，调用方会收到一次失败通知，
        // 但后续 send 仍会走到就绪副本上。
        const target = waiting orelse self.conns.items[0];
        if (on_ready) |cb| {
            target.pending_callbacks.append(self.allocator, .{ .callback = cb, .ctx = ctx }) catch {
                cb(ctx, TransportError.OutOfMemory);
                return;
            };
        }
    }

    /// 在后端流上发送数据，返回跨连接唯一的 stream 句柄。
    ///
    /// handle 为 null 时新开一条流：从轮询游标开始遍历，让请求在多个就绪副本间
    /// 分散；单条发送失败时标记该副本并继续尝试下一条。全部不可用时顺手唤醒建连，
    /// 使连接在后续请求到来前有机会按退避节奏恢复。
    ///
    /// handle 非 null 时必须回到当初开流的那条连接——句柄的高 16 位就是连接 id。
    /// 换连接会让 stream id 落到另一条 QUIC 连接上，语义完全错位，因此这里
    /// 不做任何副本选择，也不做故障转移：连接已断则报错，由上层终止这条流式请求。
    pub fn sendStreamImpl(
        self: *Self,
        route: RouteId,
        handle: ?u64,
        data: []const u8,
        is_fin: bool,
    ) TransportError!u64 {
        _ = route;
        if (self.closed) return TransportError.Closed;
        if (self.conns.items.len == 0) return TransportError.RouteNotFound;

        if (handle) |value| {
            const conn = self.connById(handleConnId(value)) orelse return TransportError.Closed;
            if (!conn.isReady()) return TransportError.ConnectionFailed;
            return conn.sendOn(value, data, is_fin) catch |err| {
                self.signalFailure(conn.connectionKey());
                conn.markFailed(err);
                return err;
            };
        }

        const count = self.conns.items.len;
        var last_error: TransportError = TransportError.ConnectionFailed;
        var offset: usize = 0;
        while (offset < count) : (offset += 1) {
            const index = (self.next_conn + offset) % count;
            const conn = self.conns.items[index];
            if (!conn.isReady()) continue;
            const new_handle = conn.sendOn(null, data, is_fin) catch |err| {
                last_error = err;
                self.signalFailure(conn.connectionKey());
                conn.markFailed(err);
                continue;
            };
            self.next_conn = (index + 1) % count;
            return new_handle;
        }

        const now = quic.c.currentTime();
        for (self.conns.items) |conn| conn.ensureConnecting(now);
        return last_error;
    }

    /// 接收后端返回的 stream-aware 事件（轮询池中所有连接）。
    ///
    /// data 是接收池槽位的借用，调用方处理完必须调 releaseRecvImpl 归还。
    pub fn receiveImpl(self: *Self) TransportError!?TransportRecv {
        if (self.closed) return TransportError.Closed;

        for (self.conns.items) |conn| {
            const ready = self.pool.pop(&conn.queue) orelse continue;
            return .{
                // 入队时已经带上当时的 connection id + generation；连接在 Worker
                // 消费前重建也不能用新代际改写这个旧事件。
                .stream_id = ready.stream_id,
                .data = ready.data,
                .is_fin = ready.is_fin,
                .kind = ready.kind,
                // token 复用 handle 的编码：高 16 位连接 id + 低位共享池槽位下标。
                .token = ready.index,
                .peer_initiated = isPeerInitiated(ready.stream_id),
            };
        }

        if (self.pending_failures.pop()) |connection_key| {
            self.last_failure_conn = connection_key;
            self.pool.acknowledgeFailure();
            return TransportError.ReceiveFailed;
        }

        return null;
    }

    /// 最近一次 receive 错误的精确故障域。句柄高 32 位是连接 id + generation。
    pub fn failureSelectorImpl(self: *const Self) backend_mod.StreamSelector {
        const mask = @as(u64, std.math.maxInt(u32)) << stream_id_bits;
        return .{ .mask = mask, .value = @as(u64, self.last_failure_conn) << stream_id_bits };
    }

    /// 一个应用请求达到 Gateway deadline 后，只取消它自己的 QUIC 流。
    ///
    /// 多个交换会复用同一条后端连接；在这里关闭连接会把正常的兄弟流一并杀死。
    /// 句柄中的 connection id + generation 防止旧 deadline 误伤重连后复用编号的新流。
    pub fn invalidateStreamImpl(self: *Self, handle: u64) void {
        const conn = self.connById(handleConnId(handle)) orelse return;
        if (conn.generation != handleGeneration(handle)) return;
        if (!conn.isReady()) return;
        const raw = conn.cnx orelse return;
        var quic_conn = QUICConnection.fromRaw(raw);
        quic_conn.discardStream(handleStreamId(handle));
        // discard_stream 只把控制帧排入 picoquic；主动驱动共享客户端，避免取消信号
        // 最迟等到 QUIC timer 才发出。
        self.pool.flushClient();
    }

    /// 这条 QUIC 流是后端开的还是网关开的。
    ///
    /// 网关在这条连接上是 QUIC **客户端**，按 RFC 9000 客户端发起的流 id 满足
    /// `id % 4 == 0`（双向）或 `== 2`（单向）；服务端发起的是 `== 1` / `== 3`。
    /// 因此最低位就是"谁开的"：0 = 客户端（网关），1 = 服务端（后端）。
    fn isPeerInitiated(stream_id: u64) bool {
        return stream_id & 0x1 == 1;
    }

    /// 归还接收槽位。
    ///
    /// **不校验连接是否还活着**，这与早先的实现相反。理由：`receive` 已经把槽位从
    /// 连接的队列里摘走了，它此刻是调用方独占的；连接销毁时 `dropQueued` 只还队列里
    /// 剩下的那些，碰不到这一个。而槽位现在来自**共享**池——若因为连接已消失就跳过归还，
    /// 那是从整个 Worker 的接收容量里永久扣掉一格。
    pub fn releaseRecvImpl(self: *Self, recv: TransportRecv) void {
        self.pool.release(@intCast(recv.token));
    }

    /// 关闭
    pub fn closeImpl(self: *Self) void {
        self.deinit();
    }

    /// 转换为接口
    pub fn asTransport(self: *Self) BackendTransport {
        return BackendTransport.init(Self, self);
    }
};

// ============================================================================
// 测试
// ============================================================================

const StaticResolver = struct {
    address: foundation.net.Address,

    pub fn resolve(
        self: *StaticResolver,
        host: []const u8,
        port: u16,
        callback: foundation.resolver.ResolveCallback,
        ctx: ?*anyopaque,
    ) foundation.resolver.ResolveError!foundation.resolver.ResolveHandle {
        _ = host;
        const addr = switch (self.address) {
            .ip4 => |ip4| foundation.net.initIp4(ip4.bytes, port),
            .ip6 => |ip6| foundation.net.initIp6(ip6.bytes, port),
        };
        callback(ctx, .{ .address = addr });
        return .{ .id = 0 };
    }

    pub fn cancel(self: *StaticResolver, handle: foundation.resolver.ResolveHandle) void {
        _ = self;
        _ = handle;
    }

    pub fn deinit(self: *StaticResolver) void {
        _ = self;
    }

    fn asResolver(self: *StaticResolver) Resolver {
        return foundation.resolver.Resolver.init(StaticResolver, self);
    }
};

/// 测试用的共享池：容量给小值，用例只关心连接与队列的账目。
fn testPool(loop: *xev.Loop) !BackendPool {
    return BackendPool.init(std.testing.allocator, loop, .{ .recv_slots = 8, .max_slots_per_conn = 8 });
}

test "DirectTransport init and state check" {
    const allocator = std.testing.allocator;

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var shared = try testPool(&loop);
    defer shared.deinit();

    var static_resolver = StaticResolver{ .address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 8443) };
    var transport = try DirectTransport.init(allocator, .{
        .endpoints = &.{},
    }, &loop, static_resolver.asResolver(), foundation.realm.default_realm, &shared);
    defer transport.deinit();

    try std.testing.expectEqual(false, transport.closed);
    try std.testing.expectEqual(@as(usize, 0), transport.conns.items.len);
}

test "DirectTransport pools one connection per service replica" {
    const allocator = std.testing.allocator;

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var shared = try testPool(&loop);
    defer shared.deinit();

    const endpoints = [_]Endpoint{
        .{ .host = "replica-a.internal", .port = 9001 },
        .{ .host = "replica-b.internal", .port = 9002 },
    };
    var static_resolver = StaticResolver{ .address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 8443) };
    var transport = try DirectTransport.init(allocator, .{
        .endpoints = &endpoints,
    }, &loop, static_resolver.asResolver(), foundation.realm.default_realm, &shared);
    defer transport.deinit();

    const conn_a = try transport.getOrCreateConn(endpoints[0]);
    const conn_b = try transport.getOrCreateConn(endpoints[1]);
    const conn_a_again = try transport.getOrCreateConn(endpoints[0]);

    // 同一副本复用连接，不同副本各自建连
    try std.testing.expect(conn_a == conn_a_again);
    try std.testing.expect(conn_a != conn_b);
    try std.testing.expectEqual(@as(usize, 2), transport.conns.items.len);

    // stream 句柄跨连接唯一。连接 id 现在由**共享池**发号，因此跨 transport 也唯一
    // ——早先靠一个进程级 atomic u16 来保证，那是 (realm × 路由 × 副本 × Worker) 的硬上限。
    try std.testing.expect(conn_a.id != conn_b.id);
    try std.testing.expect(DirectTransport.makeHandle(conn_a.id, conn_a.generation, 0) != DirectTransport.makeHandle(conn_b.id, conn_b.generation, 0));
}

test "simultaneous replica failures keep independent failure selectors" {
    const allocator = std.testing.allocator;

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var shared = try testPool(&loop);
    defer shared.deinit();

    const endpoints = [_]Endpoint{
        .{ .host = "replica-a.internal", .port = 9001 },
        .{ .host = "replica-b.internal", .port = 9002 },
    };
    var static_resolver = StaticResolver{ .address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 8443) };
    var transport = try DirectTransport.init(allocator, .{
        .endpoints = &endpoints,
    }, &loop, static_resolver.asResolver(), foundation.realm.default_realm, &shared);
    defer transport.deinit();

    const conn_a = try transport.getOrCreateConn(endpoints[0]);
    const conn_b = try transport.getOrCreateConn(endpoints[1]);
    const handle_a = DirectTransport.makeHandle(conn_a.id, conn_a.generation, 0);
    const handle_b = DirectTransport.makeHandle(conn_b.id, conn_b.generation, 0);

    transport.signalFailure(conn_a.connectionKey());
    transport.signalFailure(conn_b.connectionKey());
    // 同一故障域重复上报只能产生一次通知。
    transport.signalFailure(conn_a.connectionKey());
    try std.testing.expectEqual(@as(usize, 2), shared.stats().pending_failures);

    try std.testing.expectError(TransportError.ReceiveFailed, transport.receiveImpl());
    const first = transport.failureSelectorImpl();
    try std.testing.expect(first.mask != 0);
    try std.testing.expect(first.matches(handle_a) != first.matches(handle_b));
    try std.testing.expectEqual(@as(usize, 1), shared.stats().pending_failures);

    try std.testing.expectError(TransportError.ReceiveFailed, transport.receiveImpl());
    const second = transport.failureSelectorImpl();
    try std.testing.expect(second.mask != 0);
    try std.testing.expect(second.matches(handle_a) != second.matches(handle_b));
    try std.testing.expect(first.value != second.value);
    try std.testing.expectEqual(@as(usize, 0), shared.stats().pending_failures);
    try std.testing.expectEqual(@as(?TransportRecv, null), try transport.receiveImpl());
}

test "a reconnected endpoint resets QUIC streams without reusing backend handles" {
    const allocator = std.testing.allocator;

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var shared = try testPool(&loop);
    defer shared.deinit();

    const endpoints = [_]Endpoint{.{ .host = "127.0.0.1", .port = 8443 }};
    var static_resolver = StaticResolver{ .address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 8443) };
    var transport = try DirectTransport.init(allocator, .{
        .endpoints = &endpoints,
    }, &loop, static_resolver.asResolver(), foundation.realm.default_realm, &shared);
    defer transport.deinit();

    const conn = try transport.getOrCreateConn(endpoints[0]);
    var unused_connection: QUICConnection = undefined;

    BackendConn.hookConnected(conn, &unused_connection);
    const first = DirectTransport.makeHandle(conn.id, conn.generation, conn.nextBidiStreamId());
    conn.next_bidi_stream_id = 4096;

    BackendConn.hookConnected(conn, &unused_connection);
    const second = DirectTransport.makeHandle(conn.id, conn.generation, conn.nextBidiStreamId());

    try std.testing.expectEqual(@as(u64, 0), DirectTransport.handleStreamId(first));
    try std.testing.expectEqual(@as(u64, 0), DirectTransport.handleStreamId(second));
    try std.testing.expect(DirectTransport.handleGeneration(first) != DirectTransport.handleGeneration(second));
    try std.testing.expect(first != second);
}

test "DirectTransport prepares every configured replica" {
    const allocator = std.testing.allocator;
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var shared = try testPool(&loop);
    defer shared.deinit();

    const endpoints = [_]Endpoint{
        .{ .host = "svc-a.internal", .port = 9002 },
        .{ .host = "svc-b.internal", .port = 9003 },
    };
    var static_resolver = StaticResolver{ .address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 8443) };
    var transport = try DirectTransport.init(allocator, .{
        .endpoints = &endpoints,
    }, &loop, static_resolver.asResolver(), foundation.realm.default_realm, &shared);
    defer transport.deinit();

    // 全部副本都要进入连接池：只连第一个会让 endpoints[1..] 成为死配置。
    transport.resolveImpl(RouteId.init(1, 0), null, null);
    try std.testing.expectEqual(@as(usize, 2), transport.conns.items.len);
    try std.testing.expectEqualStrings("svc-a.internal", transport.conns.items[0].host);
    try std.testing.expectEqualStrings("svc-b.internal", transport.conns.items[1].host);

    // 重复 resolve 按 host:port 去重，不会重复建连。
    transport.resolveImpl(RouteId.init(1, 0), null, null);
    try std.testing.expectEqual(@as(usize, 2), transport.conns.items.len);

    // 没有配置任何副本的服务无法建连，resolve 直接报错。
    const Probe = struct {
        err: ?TransportError = null,

        fn onReady(ctx: ?*anyopaque, err: ?TransportError) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.err = err;
        }
    };
    var probe: Probe = .{};
    var empty_transport = try DirectTransport.init(allocator, .{
        .endpoints = &.{},
    }, &loop, static_resolver.asResolver(), foundation.realm.default_realm, &shared);
    defer empty_transport.deinit();
    empty_transport.resolveImpl(RouteId.init(1, 0), Probe.onReady, &probe);
    try std.testing.expectEqual(TransportError.RouteNotFound, probe.err.?);
    try std.testing.expectEqual(@as(usize, 0), empty_transport.conns.items.len);
}

test "DirectTransport closed state logic" {
    std.debug.print("\n=== 正在运行测试: DirectTransport closed state ===\n", .{});
    const allocator = std.testing.allocator;
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var shared = try testPool(&loop);
    defer shared.deinit();

    var static_resolver = StaticResolver{ .address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 8443) };
    var transport = try DirectTransport.init(allocator, .{
        .endpoints = &.{},
    }, &loop, static_resolver.asResolver(), foundation.realm.default_realm, &shared);

    transport.deinit();

    // 测试关闭状态下的回调行为
    const TestCtx = struct {
        error_received: ?TransportError = null,

        fn onReady(ctx: ?*anyopaque, err: ?TransportError) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.error_received = err;
        }
    };

    var test_ctx = TestCtx{};
    transport.resolveImpl(RouteId.init(1, 0), TestCtx.onReady, &test_ctx);
    try std.testing.expect(test_ctx.error_received != null);
    try std.testing.expect(test_ctx.error_received.? == TransportError.Closed);

    try std.testing.expectError(TransportError.Closed, transport.sendStreamImpl(RouteId.init(1, 0), null, "test", true));
    try std.testing.expectError(TransportError.Closed, transport.receiveImpl());
}

test "DirectTransport integration test (Real Server)" {
    if (!build_options.enable_integration_tests) return error.SkipZigTest;

    std.debug.print("\n=== 集成测试: 连接本地 8443 服务器 (异步回调版) ===\n", .{});
    const allocator = std.testing.allocator;

    // 1. 初始化 Loop 和 Transport
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    const endpoints = [_]Endpoint{
        .{ .host = "127.0.0.1", .port = 8443 },
    };
    var static_resolver = StaticResolver{ .address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 8443) };
    // 池必须比 transport 活得久：连接销毁时要把接收槽位还回来。
    var shared = try testPool(&loop);
    defer shared.deinit();
    var transport = try DirectTransport.init(allocator, .{
        .endpoints = &endpoints,
        .alpn = "lyune/2",
        .verify_cert = false,
    }, &loop, static_resolver.asResolver(), foundation.realm.default_realm, &shared);
    defer transport.deinit();

    // 2. 定义测试上下文和回调
    const TestContext = struct {
        transport: *DirectTransport,
        allocator: std.mem.Allocator,
        connected: bool = false,
        connect_error: ?TransportError = null,
        sent_stream_id: ?u64 = null,

        fn onConnected(ctx: ?*anyopaque, err: ?TransportError) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));

            if (err) |e| {
                self.connect_error = e;
                std.debug.print("!! 连接失败: {}\n", .{e});
                return;
            }

            self.connected = true;
            std.debug.print("-> 连接成功!\n", .{});

            // 连接成功后发送完整的 Lyune Frame，而不是裸字符串。
            // 一次性交换：一个带 eof 的 OPEN 就是全部。
            const msg = "Hello from Zig Client!";
            var frame_buf: [1024]u8 = undefined;
            var encoder = protocol.codec.FrameEncoder.init(&frame_buf);
            const frame_data = encoder.encodeOpen(
                .service,
                RouteId.init(0x01, 0x00),
                .required,
                protocol.frame.Flags.last(),
                msg,
            ) catch |encode_err| {
                std.debug.print("!! 编码失败: {}\n", .{encode_err});
                return;
            };
            const stream_id = self.transport.sendStreamImpl(RouteId.init(0x01, 0x00), null, frame_data, true) catch |send_err| {
                std.debug.print("!! 发送失败: {}\n", .{send_err});
                return;
            };
            self.sent_stream_id = stream_id;
            std.debug.print("-> 消息已发送: stream={}, body={s}\n", .{ stream_id, msg });
        }
    };

    var test_ctx = TestContext{
        .transport = &transport,
        .allocator = allocator,
    };

    // 3. 发起异步连接
    transport.resolveImpl(RouteId.init(0x01, 0x00), TestContext.onConnected, &test_ctx);
    std.debug.print("-> 正在发起连接...\n", .{});

    // 4. 驱动事件循环直到连接成功或超时
    const timeout_ns = 6 * std.time.ns_per_s;
    var elapsed: u64 = 0;
    const step_ms: u64 = 10;

    while (!test_ctx.connected and test_ctx.connect_error == null) {
        try loop.run(.no_wait);
        try std.Io.sleep(
            std.Io.Threaded.global_single_threaded.io(),
            std.Io.Duration.fromMilliseconds(step_ms),
            .awake,
        );
        elapsed += step_ms * std.time.ns_per_ms;

        if (elapsed > timeout_ns) {
            std.debug.print("!! 测试超时 (6s) !!\n", .{});
            return error.TestTimeout;
        }
    }

    // 5. 检查连接结果
    if (test_ctx.connect_error) |err| {
        std.debug.print("!! 连接错误: {}\n", .{err});
        return error.ConnectionFailed;
    }

    // 6. 继续驱动循环，让数据发送出去并等待回复
    var received_any = false;
    var recv_attempts: usize = 0;
    // 后端响应可能被切成多次投递，先攒起来再就地扫描。
    var inbound: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
    defer inbound.deinit(allocator);

    while (recv_attempts < 100) : (recv_attempts += 1) {
        try loop.run(.no_wait);

        if (try transport.receiveImpl()) |event| {
            defer transport.releaseRecvImpl(event);
            if (event.data.len == 0) continue;

            if (test_ctx.sent_stream_id) |sent_stream_id| {
                try std.testing.expectEqual(sent_stream_id, event.stream_id);
            }

            try inbound.appendSlice(allocator, event.data);
            var scanner = protocol.codec.FrameScanner{ .data = inbound.items };
            if (try scanner.next()) |frame| {
                const body = frame.body;
                std.debug.print(
                    "<- 收到服务器回包: stream={}, fin={}, type={s}, dest={s}, group=0x{x}, body={s}\n",
                    .{ event.stream_id, event.is_fin, @tagName(frame.header.frame_type), @tagName(frame.header.dest_kind), frame.header.group, body },
                );
                try std.testing.expectEqual(protocol.frame.DestKind.service, frame.header.dest_kind);
                try std.testing.expectEqual(@as(u8, 0x01), frame.header.group);
                try std.testing.expect(std.mem.indexOf(u8, body, "Echo: Hello from Zig Client!") != null);
                received_any = true;
                break;
            }
        }

        try std.Io.sleep(
            std.Io.Threaded.global_single_threaded.io(),
            std.Io.Duration.fromMilliseconds(10),
            .awake,
        );
    }

    if (!received_any) {
        std.debug.print("!! 未收到有效回包\n", .{});
        return error.NoResponse;
    }

    std.debug.print("=== 集成测试结束 ===\n", .{});
}

// 接收路径的回归测试。
//
// 拆分、fin 落位、整段拒绝这三条不变量本身在 backend/pool.zig 里已有针对性用例；
// 这一条测的是**接缝**：连接把分片交给共享池、再从自己的队列里按序取回来，
// 并且 token 能把槽位准确还回共享池。接缝错了的表现同样是静默的字节流损坏。
test "a connection enqueues into the shared pool and drains in order" {
    const allocator = std.testing.allocator;

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var shared = try BackendPool.init(allocator, &loop, .{ .recv_slots = 4, .max_slots_per_conn = 4 });
    defer shared.deinit();

    var static_resolver = StaticResolver{ .address = foundation.net.initIp4(.{ 127, 0, 0, 1 }, 8443) };
    const endpoints = [_]Endpoint{.{ .host = "127.0.0.1", .port = 8443 }};
    var transport = try DirectTransport.init(allocator, .{
        .endpoints = &endpoints,
    }, &loop, static_resolver.asResolver(), foundation.realm.default_realm, &shared);
    defer transport.deinit();

    const conn = try transport.getOrCreateConn(endpoints[0]);

    var payload: [pool_mod.slot_bytes + 100]u8 = undefined;
    for (&payload, 0..) |*byte, i| byte.* = @truncate(i);

    try std.testing.expect(conn.enqueueRecv(7, &payload, true));
    // 一个分片跨两个槽位，都记在这条连接自己的队列上。
    try std.testing.expectEqual(@as(usize, 2), conn.queue.count);

    const first = shared.pop(&conn.queue).?;
    try std.testing.expectEqual(@as(usize, pool_mod.slot_bytes), first.data.len);
    try std.testing.expect(!first.is_fin);
    try std.testing.expectEqualSlices(u8, payload[0..pool_mod.slot_bytes], first.data);

    const second = shared.pop(&conn.queue).?;
    try std.testing.expectEqual(@as(usize, 100), second.data.len);
    try std.testing.expect(second.is_fin);
    try std.testing.expectEqualSlices(u8, payload[pool_mod.slot_bytes..], second.data);

    try std.testing.expect(shared.pop(&conn.queue) == null);

    // token 就是共享池槽位下标；流的连接/代际编码与归还内存无关。
    transport.releaseRecvImpl(.{ .stream_id = 7, .data = first.data, .is_fin = false, .token = first.index });
    transport.releaseRecvImpl(.{ .stream_id = 7, .data = second.data, .is_fin = true, .token = second.index });

    // 四个槽位全部回到共享池，容量没有单向流失。
    var probe: pool_mod.SlotList = .{};
    var i: usize = 0;
    while (i < 4) : (i += 1) try std.testing.expect(shared.enqueue(&probe, 0, "x", false));
    shared.dropQueued(&probe);
}
