//! app/config —— 运行期配置装配
//!
//! 把磁盘上的 GatewayConfig（原始配置）转换为各组件直接可用的 RuntimeConfig：
//! 完成字符串到 sentinel 字符串的复制、监听/广播地址解析、拥塞算法映射等一次性工作。
//! RuntimeConfig 拥有其中分配的内存，使用结束后必须调用 deinit 释放。

const std = @import("std");

const backend = @import("../backend/mod.zig");
const control = @import("../control/mod.zig");
const foundation = @import("../foundation/mod.zig");
const quic = @import("../quic/mod.zig");

/// 组件化的运行期配置：每个子字段直接喂给对应组件的 init。
pub const RuntimeConfig = struct {
    threads: u16,
    server_quic: quic.config.QUICConfig,
    /// 集群监听器的 QUIC 配置；null 表示不启用节点间应用层投递链路。
    ///
    /// 与 `server_quic` 分成两份而不是共用一份改端口：它必须开
    /// `require_client_auth`，而面向客户端的那份**绝不能**开——共用一个结构体就意味着
    /// 一个字段控制两个端口的语义，改错一次就是要求所有客户端带证书。
    peer_quic: ?quic.config.QUICConfig,
    /// 直连路由目录：注册表按此建立 ScopedRoute → Transport 实例的一一映射。
    ///
    /// 槽位按 `route_capacity` 一次分配好，启动期只填前 `route_startup` 个，剩下的空位
    /// 留给运行期追加（设计文档 §12.5）。追加靠原子长度发布，见 backend/catalog.zig。
    routes: backend.RouteCatalog,
    /// `routes.slots` 的实际存储。
    route_slots: []backend.RouteEntry,
    /// 其中由本结构持有 endpoints 内存的条目数（即启动期那批）。
    ///
    /// 运行期追加进来的条目借用别处的内存，deinit 不能碰它们。
    route_startup: usize,
    /// 直连传输的共享连接参数模板（endpoints 由 bootstrap 按路由的副本列表填充）。
    direct: backend.DirectConfig,
    /// SNI → RealmId 的解析表。
    ///
    /// 槽位按 `realm_capacity` 一次分配好，启动期只填前 `realm_startup` 个，剩下的空位
    /// 留给运行期追加（设计文档 §12.5）。Worker 只拿到 `*const` 指针——表跨线程共享，
    /// 追加靠原子长度发布，见 foundation/realm.zig。
    realms: foundation.realm.Table,
    /// `realms.slots` 的实际存储。
    realm_slots: []foundation.realm.Table.Entry,
    /// 其中由本结构持有 sni 字符串的条目数（即启动期那批）。
    ///
    /// 运行期追加进来的条目借用别处的内存，deinit 不能碰它们。
    realm_startup: usize,
    /// 是否强制接入认证（未认证连接只放行控制帧）。
    auth_required: bool,
    /// 认证服务的完整路由键；null 表示未配置。
    ///
    /// 不带 realm：每个 realm 在同一个路由键上注册自己的认证服务，查表时由连接的
    /// realm 补齐（见 worker/auth.zig）。
    auth_route: ?backend.RouteId,
    /// 连接级 session_online/session_offline 事件的后端路由；null 表示关闭。
    lifecycle_route: ?backend.RouteId,
    backend_poll_interval_ms: u64,
    /// 每 Worker 一份的后端传输设施容量（见 backend/pool.zig）。
    ///
    /// `max_receive_queue` 现在配的是**整个 Worker 共享**的槽位总数，而不是早先的
    /// "每条后端连接一份"。同一个数字下内存占用从 `连接数 × 2 MiB` 变成 `一份 2 MiB`。
    backend_pool: backend.pool.Config,
    cluster: control.coordinator.Config,

    pub fn deinit(self: *RuntimeConfig, allocator: std.mem.Allocator) void {
        if (self.server_quic.cert_file) |path| allocator.free(path);
        if (self.server_quic.key_file) |path| allocator.free(path);
        allocator.free(self.server_quic.base.alpn);
        if (self.peer_quic) |peer| {
            if (peer.cert_file) |path| allocator.free(path);
            if (peer.key_file) |path| allocator.free(path);
            if (peer.base.root_cert_file) |path| allocator.free(path);
        }
        for (self.route_slots[0..self.route_startup]) |route| freeEndpoints(allocator, route.endpoints);
        allocator.free(self.route_slots);
        for (self.realm_slots[0..self.realm_startup]) |entry| allocator.free(entry.sni);
        allocator.free(self.realm_slots);
        allocator.free(self.direct.alpn);
        if (self.direct.root_cert_file) |path| allocator.free(path);
        if (self.direct.cert_file) |path| allocator.free(path);
        if (self.direct.key_file) |path| allocator.free(path);
        allocator.free(self.cluster.secret);
        allocator.free(self.cluster.previous_secret);
        allocator.free(self.cluster.seeds);
    }
};

/// 从原始配置组装 RuntimeConfig。任何一步分配失败都会通过 errdefer 回滚。
pub fn prepare(allocator: std.mem.Allocator, config: foundation.config.GatewayConfig) !RuntimeConfig {
    const bind_address = std.Io.net.IpAddress.parseIp4(config.server.listen_host, config.server.listen_port) catch return error.InvalidListenAddress;
    const cert_file = try allocator.dupeSentinel(u8, config.server.certificate_file, 0);
    errdefer allocator.free(cert_file);
    const key_file = try allocator.dupeSentinel(u8, config.server.private_key_file, 0);
    errdefer allocator.free(key_file);
    const server_alpn = try allocator.dupeSentinel(u8, config.server.quic.alpn, 0);
    errdefer allocator.free(server_alpn);
    // 路由目录：槽位按 route_capacity 分配，只填前 routes.len 个——剩下的空位是运行期
    // 追加接入方用的（§12.5），装不下启动期条目在 validate 里就被拒了。
    const route_slots = try allocator.alloc(backend.RouteEntry, config.backend.direct.route_capacity);
    var routes_built: usize = 0;
    errdefer {
        for (route_slots[0..routes_built]) |route| freeEndpoints(allocator, route.endpoints);
        allocator.free(route_slots);
    }
    @memset(route_slots, .{});
    for (config.backend.direct.routes, route_slots[0..config.backend.direct.routes.len]) |raw, *route| {
        const endpoints = try allocator.alloc(backend.direct.Endpoint, raw.endpoints.len);
        var endpoints_built: usize = 0;
        errdefer {
            for (endpoints[0..endpoints_built]) |endpoint| allocator.free(endpoint.host);
            allocator.free(endpoints);
        }
        for (raw.endpoints, endpoints) |raw_endpoint, *endpoint| {
            endpoint.* = .{
                .host = try allocator.dupeSentinel(u8, raw_endpoint.host, 0),
                .port = raw_endpoint.port,
            };
            endpoints_built += 1;
        }
        route.* = .{
            .route = backend.ScopedRoute.init(raw.realm, raw.group, raw.route_key),
            .endpoints = endpoints,
        };
        routes_built += 1;
    }
    // realm 登记表：SNI 字符串要复制一份，原始配置树在 prepare 返回后就会被释放。
    //
    // 槽位按 realm_capacity 分配，只填前 config.realms.len 个——剩下的空位是运行期
    // 追加接入方用的（§12.5）。启动期就把容量定死，是为了让追加永不搬迁已有槽位，
    // 于是读者不需要任何锁。
    // 容量由配置定，装不下启动期条目在 validate 里就被拒了（见 validateRealms）。
    const realm_slots = try allocator.alloc(foundation.realm.Table.Entry, config.realm_capacity);
    var realms_built: usize = 0;
    errdefer {
        for (realm_slots[0..realms_built]) |entry| allocator.free(entry.sni);
        allocator.free(realm_slots);
    }
    @memset(realm_slots, .{});
    for (config.realms, realm_slots[0..config.realms.len]) |raw, *entry| {
        entry.* = .{
            .sni = try allocator.dupe(u8, raw.server_name),
            .realm = raw.id,
        };
        realms_built += 1;
    }
    const backend_alpn = try allocator.dupeSentinel(u8, config.backend.direct.alpn, 0);
    errdefer allocator.free(backend_alpn);
    const root_cert = if (config.backend.direct.root_certificate_file) |path| try allocator.dupeSentinel(u8, path, 0) else null;
    errdefer if (root_cert) |path| allocator.free(path);
    // 网关向后端出示的客户端证书（§10.1 的 mTLS）。validate 已保证两者同有或同无。
    const backend_cert = if (config.backend.direct.client_certificate_file) |path| try allocator.dupeSentinel(u8, path, 0) else null;
    errdefer if (backend_cert) |path| allocator.free(path);
    const backend_key = if (config.backend.direct.client_private_key_file) |path| try allocator.dupeSentinel(u8, path, 0) else null;
    errdefer if (backend_key) |path| allocator.free(path);
    const cluster_secret = try allocator.dupe(u8, config.cluster.secret);
    errdefer allocator.free(cluster_secret);
    const previous_cluster_secret = try allocator.dupe(u8, config.cluster.previous_secret);
    errdefer allocator.free(previous_cluster_secret);
    const cluster_seeds = try allocator.alloc(control.membership.runner.Seed, config.cluster.seeds.len);
    errdefer allocator.free(cluster_seeds);
    for (config.cluster.seeds, cluster_seeds) |raw, *seed| {
        seed.* = .{
            .node_id = raw.node_id,
            .address = std.Io.net.IpAddress.parseIp4(raw.host, raw.port) catch return error.InvalidSeedAddress,
        };
    }
    const advertise_address = std.Io.net.IpAddress.parseIp4(config.cluster.advertise_host, config.cluster.advertise_port) catch return error.InvalidAdvertiseAddress;
    const forward_address = std.Io.net.IpAddress.parseIp4(config.cluster.advertise_host, config.cluster.forward_port) catch return error.InvalidForwardAddress;

    // 集群监听器：证书三件套齐备才建。ALPN 复用客户端那份（同一套帧协议），
    // 但 `require_client_auth` 与 `verify_cert` 两个方向都必须开——这正是
    // "在这个端口握手成功 = 对端是网关节点"这条等价关系的全部依据（§8.5）。
    const peer_cert = if (config.cluster.clusterLinkEnabled()) try allocator.dupeSentinel(u8, config.cluster.peer_cert_file, 0) else null;
    errdefer if (peer_cert) |path| allocator.free(path);
    const peer_key = if (config.cluster.clusterLinkEnabled()) try allocator.dupeSentinel(u8, config.cluster.peer_key_file, 0) else null;
    errdefer if (peer_key) |path| allocator.free(path);
    const peer_ca = if (config.cluster.clusterLinkEnabled()) try allocator.dupeSentinel(u8, config.cluster.peer_ca_file, 0) else null;
    errdefer if (peer_ca) |path| allocator.free(path);

    return .{
        .threads = config.runtime.threads,
        .server_quic = .{
            .base = .{
                .max_connections = config.server.quic.max_connections,
                .idle_timeout_ms = config.server.quic.idle_timeout_ms,
                .max_datagram_frame_size = config.server.quic.max_datagram_frame_size,
                .alpn = server_alpn,
                .congestion_algorithm = mapCongestionControl(config.server.quic.congestion_control),
            },
            .cert_file = cert_file,
            .key_file = key_file,
            .bind_address = bind_address.ip4.bytes,
            .bind_port = config.server.listen_port,
        },
        .peer_quic = if (config.cluster.clusterLinkEnabled()) .{
            .base = .{
                .max_connections = config.server.quic.max_connections,
                .idle_timeout_ms = config.server.quic.idle_timeout_ms,
                // 集群链路刻意**不开**不可靠通路：跨节点那一跳走可靠 `.multicast` 帧，
                // 由收方节点在本地再落成 datagram（理由见 egress 的 fanOutUnreliable）。
                // 留着它只会多一条谁都不该走、也没人测过的路径。
                .max_datagram_frame_size = 0,
                // ALPN 借用客户端那份：节点间说的是同一套帧协议，不需要第二个标识。
                .alpn = server_alpn,
                .congestion_algorithm = mapCongestionControl(config.server.quic.congestion_control),
                .root_cert_file = peer_ca,
                .verify_cert = true,
            },
            .cert_file = peer_cert,
            .key_file = peer_key,
            // 集群链路只在通告地址那张网卡上服务，不跟着客户端端口绑 0.0.0.0：
            // 它不该对公网可见。
            .bind_address = advertise_address.ip4.bytes,
            .bind_port = config.cluster.peer_port,
            .require_client_auth = true,
        } else null,
        .auth_required = config.auth.required,
        .auth_route = if (config.auth.group) |group| backend.RouteId{ .group = group, .route_key = config.auth.route_key } else null,
        .lifecycle_route = if (config.auth.lifecycle) |route| backend.RouteId{ .group = route.group, .route_key = route.route_key } else null,
        .route_slots = route_slots,
        .route_startup = config.backend.direct.routes.len,
        .routes = .{
            .slots = route_slots,
            .len = .init(config.backend.direct.routes.len),
        },
        .realm_slots = realm_slots,
        .realm_startup = config.realms.len,
        .realms = .{
            .slots = realm_slots,
            .len = .init(config.realms.len),
            // 登记表为空 = 单域部署，所有连接归入 default_realm。
            // 一旦登记了任何域名就切成失败关闭：未登记的 SNI 拒连，不静默回落
            // 到别人的命名空间（设计文档 §12.3）。
            //
            // 它决定运行期能否追加：单域部署下追加会把这个语义翻过来，
            // 于是所有现有客户端的下一次连接被拒，因此被 `register` 明确拒绝。
            .fallback = if (config.realms.len == 0) foundation.realm.default_realm else null,
        },
        .direct = .{
            .endpoints = &.{},
            .verify_cert = config.backend.direct.verify_certificate,
            .root_cert_file = root_cert,
            .cert_file = backend_cert,
            .key_file = backend_key,
            .idle_timeout_ms = config.backend.direct.idle_timeout_ms,
            .alpn = backend_alpn,
            .congestion_algorithm = mapCongestionControl(config.backend.direct.congestion_control),
        },
        .backend_poll_interval_ms = config.worker.backend_poll_interval_ms,
        .backend_pool = .{ .recv_slots = config.backend.direct.max_receive_queue },
        .cluster = .{
            .cluster_enabled = config.cluster.enabled,
            .node_id = config.cluster.node_id,
            .advertise_address = advertise_address,
            .forward_address = forward_address,
            .worker_count = config.runtime.threads,
            .handoff_queue_capacity = config.cluster.handoff_queue_capacity,
            .message_queue_capacity = config.cluster.message_queue_capacity,
            .placement_strategy = config.cluster.placement,
            .deployment_mode = config.cluster.deployment_mode,
            .return_path_capacity = config.cluster.return_path_capacity,
            .return_path_timeout_ms = config.server.quic.idle_timeout_ms,
            .secret = cluster_secret,
            .previous_secret = previous_cluster_secret,
            .max_nodes = config.cluster.max_nodes,
            .seeds = cluster_seeds,
        },
    };
}

fn freeEndpoints(allocator: std.mem.Allocator, endpoints: []const backend.direct.Endpoint) void {
    for (endpoints) |endpoint| allocator.free(endpoint.host);
    allocator.free(endpoints);
}

fn mapCongestionControl(value: []const u8) quic.config.Config.CongestionAlgorithm {
    return switch (foundation.config.parseCongestionControl(value) catch unreachable) {
        .bbr => .bbr,
        .cubic => .cubic,
        .reno => .reno,
        .fast => .fast,
    };
}
