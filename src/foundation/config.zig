const std = @import("std");

const placement = @import("placement.zig");

/// JSON 配置通过结构解析后可能返回的业务校验错误。
pub const ConfigError = error{
    InvalidConfig,
    InvalidPort,
    InvalidThreadCount,
    InvalidPollInterval,
    InvalidQuicConfig,
    InvalidWssConfig,
    InvalidBackendConfig,
    InvalidClusterConfig,
    InvalidAuthConfig,
    InvalidRealmConfig,
};

/// `gateway.json` 的严格 schema；未知或缺失必填字段会在加载阶段失败。
pub const GatewayConfig = struct {
    runtime: Runtime,
    server: Server,
    backend: Backend,
    worker: Worker,
    cluster: Cluster,
    auth: Auth = .{},
    /// 隔离域登记表（设计文档 §12）；留空即"整个网关只有一个隔离域"。
    ///
    /// 非空时改为**失败关闭**：未登记的 SNI 一律拒连。理由是这条边界上一次静默
    /// 回落就等于把一个接入方的连接放进了另一个接入方的命名空间。
    realms: []const Realm = &.{},
    /// 隔离域登记表的槽位总数，决定运行期还能追加多少个接入方（设计文档 §12.5）。
    ///
    /// 表是启动期一次分配、运行期只追加的定容 slab，所以这个数字就是"这个进程一生
    /// 能服务多少个 realm"。它必须不小于 `realms` 的长度，否则启动期就装不下。
    ///
    /// 之所以是显式配置而不是按 `realms.len` 推算：推算出来的余量迟早会用光，
    /// 而那时的症状是"新接入方登记失败"，运维完全看不出上限从哪来。
    realm_capacity: usize = 256,

    /// 一个隔离域：它的接入域名与编号。
    ///
    /// id 显式配置而不是哈希域名：哈希碰撞在这条边界上就是静默的跨域泄露。
    pub const Realm = struct {
        /// 客户端在 TLS SNI 里给出的主机名，比较不区分大小写。
        server_name: []const u8,
        /// 该域的编号；0 是单域部署的默认值，多域部署应从 1 开始分配。
        id: u16,
    };

    /// 进程与 Worker 并发配置。
    pub const Runtime = struct {
        threads: u16,
    };

    /// 客户端侧 QUIC 服务监听与证书配置。
    pub const Server = struct {
        listen_host: []const u8,
        listen_port: u16,
        certificate_file: []const u8,
        private_key_file: []const u8,
        quic: Quic,
        /// 浏览器与 QUIC 不可用网络的 TLS/TCP 回退。默认关闭，不改变 Raw QUIC 基线。
        wss: Wss = .{},
    };

    pub const Wss = struct {
        enabled: bool = false,
        listen_host: []const u8 = "0.0.0.0",
        listen_port: u16 = 8444,
        /// 浏览器 Origin 精确白名单。不支持通配符，避免把凭据可用范围无意放大。
        allowed_origins: []const []const u8 = &.{},
        /// 原生 WSS 客户端可能不带 Origin；只能通过这一项显式允许。
        allow_missing_origin: bool = false,
        /// 每 Worker 独立上限；总上限还受共享 ConnectionManager 容量约束。
        max_connections_per_worker: usize = 64,
        /// 单会话待发送明文字节和 record 数上限。可靠消息溢出会只关闭该慢会话。
        max_queued_bytes: usize = 256 * 1024,
        max_queued_records: usize = 64,
        /// TLS BIO pair 每个方向的定容缓冲。
        tls_bio_capacity: usize = 64 * 1024,
        handshake_timeout_ms: u64 = 5_000,
    };

    /// 可从 JSON 表达的通用 QUIC 参数。
    pub const Quic = struct {
        max_connections: u32,
        idle_timeout_ms: u64,
        alpn: []const u8,
        congestion_control: []const u8,
        /// 本端愿意接收的单个 QUIC DATAGRAM 上限（字节）；0 表示关闭不可靠通路。
        ///
        /// **有默认值**，与本结构其他字段不同：不可靠通路是一项可选能力，不配它的
        /// 部署不该被迫在配置里写一行自己不关心的数字。默认 1200 落在 IPv6 最小 MTU
        /// 扣掉各层包头后的安全区里，因此满载 datagram 不会触发 IP 分片（§6.2）。
        max_datagram_frame_size: u16 = 1200,
    };

    /// 所有后端 Transport 实现的配置容器。
    pub const Backend = struct {
        direct: Direct,
    };

    /// 直连 QUIC Transport 的路由、副本和连接参数。
    pub const Direct = struct {
        /// 直连路由表：每条 (group, route_key) 组合路由到一个后端 endpoint。
        /// 这是 DirectTransport 的内部寻址配置，客户端与 Worker 均不感知。
        routes: []const Route,
        /// 路由目录的槽位总数，决定运行期还能追加多少条路由（设计文档 §12.5）。
        ///
        /// 它同时是**每个 Worker 的直连实例仓库容量**：实例地址必须稳定（注册表里存的是
        /// 指针），所以仓库不能扩容搬迁，用满时明确报错。理由与 `realm_capacity` 相同——
        /// 显式配置而不是按 `routes.len` 推算，否则余量用光时的症状是"新接入方的请求全都
        /// route not found"，运维看不出上限从哪来。
        route_capacity: usize = 256,
        verify_certificate: bool,
        root_certificate_file: ?[]const u8,
        /// 网关向后端出示的客户端证书与私钥（设计文档 §10.1 的 mTLS）。
        ///
        /// 两个都给才生效，只给一个是配置错误——那种半配状态会让运维以为双向认证已经开了，
        /// 而实际上握手仍然是单向的。多 realm 部署下这一项是上线阻塞项：不配它，任何能连上
        /// realm B 后端端口的东西都能冒充网关，包括 realm A。
        client_certificate_file: ?[]const u8 = null,
        client_private_key_file: ?[]const u8 = null,
        max_receive_queue: usize,
        idle_timeout_ms: u64,
        alpn: []const u8,
        congestion_control: []const u8,

        /// 一个 RouteId 对应的逻辑服务及其后端副本集合。
        pub const Route = struct {
            /// 这条路由属于哪个隔离域（设计文档 §12.2）。
            ///
            /// `(group, route_key)` 由客户端在帧里给出，多个接入方用同一组取值是常态，
            /// 因此注册表键必须带上 realm，否则后注册的会顶掉前一个。
            realm: u16 = 0,
            group: u8,
            route_key: u8 = 0,
            /// 该路由（逻辑服务）的后端实例列表，由对应的 DirectTransport 实例
            /// 用连接池统一管理。
            endpoints: []const Endpoint,

            /// 单个直连后端的主机与 QUIC 端口。
            pub const Endpoint = struct {
                host: []const u8,
                port: u16,
            };
        };
    };

    /// Worker 轮询后端接收队列的调度参数。
    pub const Worker = struct {
        backend_poll_interval_ms: u64,
    };

    /// 网关集群身份、gossip、转发隧道和静态引导配置。
    pub const Cluster = struct {
        /// false 时不创建 membership socket/线程，单机部署保持零额外开销。
        enabled: bool = false,
        node_id: u16,
        advertise_host: []const u8,
        advertise_port: u16,
        /// 节点间原始 QUIC 包转发隧道端口，必须与 gossip 端口不同。
        forward_port: u16 = 7947,
        /// 客户端侧入口网络模型，决定是否启用跨节点转发与 L4 回程。
        /// 默认取最保守的 direct：任何网络环境都成立，不依赖 anycast/ECMP 或 LB。
        deployment_mode: DeploymentMode = .direct,
        /// 每个 Worker 最多记录的 L4 回程地址数量。
        return_path_capacity: usize = 4096,
        handoff_queue_capacity: usize,
        /// 每个 Worker 的应用消息交接队列深度（跨 Worker 投递通路）。
        ///
        /// 与 `handoff_queue_capacity` 分开：包队列是深队列浅槽位（2KB 槽位，吸收
        /// 突发重传），应用消息队列是浅队列深槽位（64KB 槽位，低频、一轮事件循环
        /// 就排空）。槽位大小不暴露——它由协议的单帧上限决定，调小就是静默截断。
        message_queue_capacity: usize = 16,
        /// 跨 Worker / 跨节点投递的选路策略（见 protocol_design §8.5 第二层）。
        placement: placement.Strategy = .affinity,
        /// 集群监听端口：节点间应用层投递链路的服务端口（见 protocol_design §8.5）。
        ///
        /// 必须与 `advertise_port`（gossip）和 `forward_port`（原始包隧道）都不同。
        /// 它与面向客户端的端口分开是**结构性的安全边界**：这个端口要求客户端证书，
        /// 所以"在这个端口上握手成功"就等价于"对端是网关节点"，而面向客户端的端口
        /// 绝不能开客户端证书要求。
        peer_port: u16 = 7948,
        /// 本节点在集群链路上出示的证书（既作服务端也作客户端）。
        ///
        /// 三项必须由**私有集群 CA** 签发，且与面向客户端的那张证书分开——后者通常来自
        /// 公共 CA，而"任何公共 CA 签发的证书都算网关节点"显然不成立。
        /// 三项留空即不启用集群链路（单节点部署，或多节点但还没配证书）。
        peer_cert_file: []const u8 = "",
        peer_key_file: []const u8 = "",
        /// 集群 CA 证书，用来校验对端。
        peer_ca_file: []const u8 = "",
        /// gossip/forward 当前 HMAC 预共享密钥；为空表示单机开发模式。
        secret: []const u8 = "",
        /// 轮换期旧密钥；仅用于验证入站消息。
        previous_secret: []const u8 = "",
        /// 成员表容量上限，供 membership 状态机使用。
        max_nodes: u16 = 1024,
        /// 静态引导节点。node_id 与地址都显式配置，避免运行时猜测身份。
        seeds: []const Seed = &.{},

        /// 节点间应用层投递链路是否可用。
        ///
        /// 三项证书齐备才算。缺证书时跨节点投递不可用，扇出会把跨节点目标回报为
        /// 不可达而不是静默丢弃——运维因此能从回报里看出"这个集群还没配好"。
        pub fn clusterLinkEnabled(self: Cluster) bool {
            return self.enabled and
                self.peer_cert_file.len != 0 and
                self.peer_key_file.len != 0 and
                self.peer_ca_file.len != 0;
        }

        /// 客户端侧入口网络模型。决定集群是否需要跨节点纠错、以及响应能否直接回客户端。
        ///
        /// 新增取值时，下面两个能力查询的穷尽 switch 会编译失败，
        /// 强制在同一处明确新模式的语义，避免散落的 `mode == .xxx` 判断漏改。
        pub const DeploymentMode = enum {
            /// 客户端直连特定节点：DNS 多 A 记录、客户端侧负载均衡或单节点。
            ///
            /// 客户端记住的是节点自身地址，迁移后目的地址不变，报文永远到同一节点，
            /// 因此不会错投，不需要跨节点转发。
            direct,
            /// 多节点共享同一 IP（BGP anycast 或机房内 ECMP）。
            ///
            /// 路由收敛或客户端网络位置变化时会错投，需要跨节点转发纠正；
            /// 但所有节点都持有同一对外地址，owner 可以直接回客户端。
            anycast,
            /// 有状态 UDP 负载均衡器按五元组哈希分发。
            ///
            /// 客户端换源端口即可错投；且 owner 的真实地址不是客户端认可的对端，
            /// 响应必须经原入口节点回流，见 reactor/return_path.zig。
            l4_lb,

            /// 该模式下是否可能收到不属于本节点的报文，从而需要跨节点转发隧道。
            pub fn requiresCrossNodeForward(self: DeploymentMode) bool {
                return switch (self) {
                    .direct => false,
                    .anycast, .l4_lb => true,
                };
            }

            /// 该模式下 owner 的响应是否必须经原入口节点回流。
            pub fn requiresReturnPath(self: DeploymentMode) bool {
                return switch (self) {
                    .direct, .anycast => false,
                    .l4_lb => true,
                };
            }
        };

        /// 静态引导节点的唯一身份与 gossip 地址。
        pub const Seed = struct {
            node_id: u16,
            host: []const u8,
            port: u16,
        };
    };

    /// 接入认证策略。
    ///
    /// 网关本身不解析 token：auth_request 帧会被原样转发给 group + route_key
    /// 指向的后端认证服务，由其校验并返回 auth_success / auth_failure 帧，
    /// 网关只根据结果标记连接的认证状态。
    pub const Auth = struct {
        /// 是否强制认证：true 时未认证连接的数据帧一律拒绝，只放行控制帧。
        required: bool = false,
        /// 认证服务的服务分组；null 表示未配置认证服务。
        group: ?u8 = null,
        /// 认证服务的组内路由，与 group 组合构成完整路由键。
        route_key: u8 = 0,
        /// 认证成功以后用于接收连接级 online/offline 事件的后端路由。
        /// null 表示部署不需要生命周期事件；Gateway 不在本地聚合用户在线状态。
        lifecycle: ?LifecycleRoute = null,

        pub const LifecycleRoute = struct {
            group: u8,
            route_key: u8,
        };
    };

    /// 校验端口、容量、路由、认证与集群安全约束；不执行 I/O。
    pub fn validate(self: GatewayConfig) ConfigError!void {
        if (self.runtime.threads == 0 or self.runtime.threads > 256) return error.InvalidThreadCount;
        if (self.server.listen_port == 0) return error.InvalidPort;
        if (self.worker.backend_poll_interval_ms == 0) return error.InvalidPollInterval;
        if (self.server.listen_host.len == 0 or self.server.certificate_file.len == 0 or self.server.private_key_file.len == 0) return error.InvalidConfig;
        if (self.server.quic.max_connections == 0 or self.server.quic.idle_timeout_ms == 0 or self.server.quic.idle_timeout_ms > std.math.maxInt(u64) / std.time.us_per_ms or self.server.quic.alpn.len == 0 or self.server.quic.alpn.len > 255) return error.InvalidQuicConfig;
        // 不可靠通路的上限：0 = 关闭，否则必须落在"装得下 2 字节头再加点负载"到
        // "一个以太网帧装得下"之间。上界是真正的护栏：配大了之后每一个 datagram 都会
        // 被 picoquic 拒发，而那是一次静默的全量失效，运维只会看到"不可靠通路不通"。
        if (self.server.quic.max_datagram_frame_size != 0 and
            (self.server.quic.max_datagram_frame_size < 16 or self.server.quic.max_datagram_frame_size > 1452))
        {
            return error.InvalidQuicConfig;
        }
        if (self.server.wss.enabled) {
            // 65535 body + 8 Lyune header + 20 envelope + 最长 10-byte WS header。
            const largest_wire_record: usize = 65_573;
            if (self.server.wss.listen_host.len == 0 or self.server.wss.listen_port == 0 or
                self.server.wss.max_connections_per_worker == 0 or
                self.server.wss.max_queued_bytes < largest_wire_record or
                self.server.wss.max_queued_records < 2 or
                self.server.wss.tls_bio_capacity < 16 * 1024 or
                self.server.wss.handshake_timeout_ms == 0)
            {
                return error.InvalidWssConfig;
            }
            // 浏览器一定带 Origin。若既没有白名单又不显式允许缺失，监听器会拒绝所有
            // 客户端，这通常是误配置，直接在启动期指出。
            if (self.server.wss.allowed_origins.len == 0 and !self.server.wss.allow_missing_origin) {
                return error.InvalidWssConfig;
            }
            for (self.server.wss.allowed_origins, 0..) |origin, index| {
                if (origin.len == 0) return error.InvalidWssConfig;
                for (self.server.wss.allowed_origins[0..index]) |previous| {
                    if (std.mem.eql(u8, previous, origin)) return error.InvalidWssConfig;
                }
            }
        }
        if (self.backend.direct.routes.len == 0 or self.backend.direct.max_receive_queue == 0 or self.backend.direct.idle_timeout_ms == 0 or self.backend.direct.alpn.len == 0 or self.backend.direct.alpn.len > 255) return error.InvalidBackendConfig;
        // 目录容量装不下启动期路由：与 realm_capacity 同理，不能在 prepare 里悄悄放大。
        if (self.backend.direct.route_capacity < self.backend.direct.routes.len) return error.InvalidBackendConfig;
        // 客户端证书与私钥必须同时给出或同时省略。半配状态会让运维以为双向认证已经开了，
        // 而实际上 picoquic 拿不到完整的一对，握手仍然是单向的——静默的安全降级。
        if ((self.backend.direct.client_certificate_file == null) != (self.backend.direct.client_private_key_file == null)) {
            return error.InvalidBackendConfig;
        }
        if (self.backend.direct.client_certificate_file) |path| {
            if (path.len == 0) return error.InvalidBackendConfig;
        }
        if (self.backend.direct.client_private_key_file) |path| {
            if (path.len == 0) return error.InvalidBackendConfig;
        }
        try self.validateRealms();
        for (self.backend.direct.routes, 0..) |route, index| {
            if (route.endpoints.len == 0) return error.InvalidBackendConfig;
            for (route.endpoints) |endpoint| {
                if (endpoint.host.len == 0 or endpoint.port == 0) return error.InvalidBackendConfig;
            }
            // 路由必须落在一个真的能被连上的隔离域里，否则它永远不会被命中，
            // 而运维会以为服务已经接好了。
            if (!self.realmDeclared(route.realm)) return error.InvalidRealmConfig;
            // 同一 (realm, group, route_key) 注册两次时，注册表里后者会顶掉前者。
            // 这是静默的错误路由，必须在启动时拒绝。
            for (self.backend.direct.routes[0..index]) |previous| {
                if (previous.realm == route.realm and previous.group == route.group and previous.route_key == route.route_key) {
                    return error.InvalidRealmConfig;
                }
            }
        }
        if (self.cluster.node_id == 0 or self.cluster.advertise_host.len == 0 or self.cluster.advertise_port == 0 or self.cluster.forward_port == 0 or self.cluster.return_path_capacity == 0 or self.cluster.handoff_queue_capacity == 0 or self.cluster.max_nodes == 0) return error.InvalidClusterConfig;
        if (self.cluster.message_queue_capacity == 0) return error.InvalidClusterConfig;
        // 集群链路的三项证书要么全给、要么全不给：只给一半必然是配错了，
        // 而"少给一项就静默退化成不启用"会让运维以为跨节点投递在工作。
        const peer_parts = [_]usize{ self.cluster.peer_cert_file.len, self.cluster.peer_key_file.len, self.cluster.peer_ca_file.len };
        var peer_given: usize = 0;
        for (peer_parts) |len| {
            if (len != 0) peer_given += 1;
        }
        if (peer_given != 0 and peer_given != peer_parts.len) return error.InvalidClusterConfig;
        if (peer_given == peer_parts.len) {
            if (self.cluster.peer_port == 0) return error.InvalidClusterConfig;
            // 三个集群端口必须互不相同：撞了的话后起的那个 bind 失败，
            // 而症状是"集群某个功能不工作"，极难定位到端口配置。
            if (self.cluster.peer_port == self.cluster.advertise_port or
                self.cluster.peer_port == self.cluster.forward_port) return error.InvalidClusterConfig;
        }
        if (self.cluster.node_id >= self.cluster.max_nodes or self.cluster.return_path_capacity > std.math.maxInt(u32)) return error.InvalidClusterConfig;
        if (self.cluster.enabled and self.cluster.forward_port == self.cluster.advertise_port) return error.InvalidClusterConfig;
        if (self.cluster.enabled and self.cluster.secret.len < 16) return error.InvalidClusterConfig;
        if (!self.cluster.enabled and self.cluster.seeds.len != 0) return error.InvalidClusterConfig;
        // 集群关闭时不会创建 forward 隧道，需要跨节点纠错的入口模式无法生效。
        // 静默忽略会让运维以为回程已启用，必须在启动时拒绝这种组合。
        if (!self.cluster.enabled and self.cluster.deployment_mode.requiresCrossNodeForward()) {
            return error.InvalidClusterConfig;
        }
        if (self.cluster.secret.len != 0 and self.cluster.secret.len < 16) return error.InvalidClusterConfig;
        if (self.cluster.previous_secret.len != 0 and self.cluster.previous_secret.len < 16) return error.InvalidClusterConfig;
        _ = std.Io.net.IpAddress.parseIp4(self.cluster.advertise_host, self.cluster.advertise_port) catch return error.InvalidClusterConfig;
        for (self.cluster.seeds, 0..) |seed, index| {
            if (seed.node_id == 0 or seed.node_id == self.cluster.node_id or seed.node_id >= self.cluster.max_nodes or seed.port == 0) return error.InvalidClusterConfig;
            _ = std.Io.net.IpAddress.parseIp4(seed.host, seed.port) catch return error.InvalidClusterConfig;
            for (self.cluster.seeds[0..index]) |previous| {
                if (previous.node_id == seed.node_id) return error.InvalidClusterConfig;
            }
        }
        _ = parseCongestionControl(self.server.quic.congestion_control) catch return error.InvalidQuicConfig;
        _ = parseCongestionControl(self.backend.direct.congestion_control) catch return error.InvalidBackendConfig;
        if (self.auth.required and self.auth.group == null) return error.InvalidAuthConfig;
    }

    /// 隔离域登记表自身的约束。
    fn validateRealms(self: GatewayConfig) ConfigError!void {
        // 容量装不下启动期条目就是配置错，不能靠 prepare 里的 @max 悄悄放大——
        // 那会让运维以为自己配的上限生效了。
        if (self.realm_capacity < self.realms.len) return error.InvalidRealmConfig;
        for (self.realms, 0..) |realm, index| {
            if (realm.server_name.len == 0) return error.InvalidRealmConfig;
            // 同一个域名登记两次：resolve 只会命中第一条，第二条静默失效。
            // 主机名大小写无关，所以比较也必须无关，否则大小写不同的重复能混过去。
            for (self.realms[0..index]) |previous| {
                if (std.ascii.eqlIgnoreCase(previous.server_name, realm.server_name)) return error.InvalidRealmConfig;
            }
        }
    }

    /// 这个 realm 编号是否真的有域名指向它。
    ///
    /// 登记表为空时只承认 0：那是单域部署，所有连接都落进 default_realm。
    fn realmDeclared(self: GatewayConfig, id: u16) bool {
        if (self.realms.len == 0) return id == 0;
        for (self.realms) |realm| {
            if (realm.id == id) return true;
        }
        return false;
    }
};

/// 配置文件原始字节与解析树的共同所有者；两者由同一 allocator 分配。
pub const LoadedConfig = struct {
    bytes: []u8,
    parsed: std.json.Parsed(GatewayConfig),

    /// 释放解析树及原始文件缓冲；allocator 必须与 load 使用的实例相同。
    pub fn deinit(self: *LoadedConfig, allocator: std.mem.Allocator) void {
        self.parsed.deinit();
        allocator.free(self.bytes);
    }
};

/// 从当前工作目录读取至多 1 MiB 的 JSON，严格解析并完成业务校验。
pub fn load(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !LoadedConfig {
    // 从当前工作目录读取 path 指向的文件，限制文件大小为 1MB
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024));
    errdefer allocator.free(bytes);
    // 将 json 字符串解析为 GatewayConfig 结构体
    // 这里使用 var parsed 而不是 const parsed，主要是因为后面的 parsed.deinit 需要取得可变指针
    var parsed = try std.json.parseFromSlice(GatewayConfig, allocator, bytes, .{
        // json 中不允许出现 GatewayConfig 没有定义的字段
        .ignore_unknown_fields = false,
        // 字符串、数组等数据始终复制到解析器管理等内存中，不直接引用原始的 bytes。
        // 因此 parsed.value 中的字符串不会依赖原始文件缓冲区的生命周期
        .allocate = .alloc_always,
    });
    errdefer parsed.deinit();
    // 执行业务校验，检查线程数是否有效，端口是否为 0 等。
    try parsed.value.validate();
    return .{ .bytes = bytes, .parsed = parsed };
}

/// 把配置字符串映射为支持的拥塞控制标识；未知名称返回 InvalidCongestionControl。
pub fn parseCongestionControl(value: []const u8) !enum { bbr, cubic, reno, fast } {
    if (std.mem.eql(u8, value, "bbr")) return .bbr;
    if (std.mem.eql(u8, value, "cubic")) return .cubic;
    if (std.mem.eql(u8, value, "newreno")) return .reno;
    if (std.mem.eql(u8, value, "fast")) return .fast;
    return error.InvalidCongestionControl;
}

/// 一份最小可用的单域配置，供各校验用例改一处再断言。
fn testConfig() GatewayConfig {
    return .{
        .runtime = .{ .threads = 1 },
        .server = .{
            .listen_host = "0.0.0.0",
            .listen_port = 8443,
            .certificate_file = "cert.pem",
            .private_key_file = "key.pem",
            .quic = .{
                .max_connections = 10_000,
                .idle_timeout_ms = 30_000,
                .alpn = "lyune/2",
                .congestion_control = "bbr",
            },
        },
        .backend = .{ .direct = .{
            .routes = &.{.{ .group = 1, .endpoints = &.{.{ .host = "127.0.0.1", .port = 8443 }} }},
            .verify_certificate = false,
            .root_certificate_file = null,
            .max_receive_queue = 1024,
            .idle_timeout_ms = 30_000,
            .alpn = "lyune/2",
            .congestion_control = "bbr",
        } },
        .worker = .{ .backend_poll_interval_ms = 10 },
        .cluster = .{
            .node_id = 1,
            .advertise_host = "127.0.0.1",
            .advertise_port = 8443,
            .handoff_queue_capacity = 1024,
        },
    };
}

test "GatewayConfig rejects invalid values" {
    var config = testConfig();
    try config.validate();
    config.runtime.threads = 0;
    try std.testing.expectError(error.InvalidThreadCount, config.validate());

    config.runtime.threads = 1;
    config.server.quic.idle_timeout_ms = std.math.maxInt(u64);
    try std.testing.expectError(error.InvalidQuicConfig, config.validate());
    config.server.quic.idle_timeout_ms = 30_000;
    // 不可靠通路：0 是"关闭"，合法；配大了每一个 datagram 都会被拒发，
    // 那是一次静默的全量失效，所以上界必须在启动期拦住。
    config.server.quic.max_datagram_frame_size = 0;
    try config.validate();
    config.server.quic.max_datagram_frame_size = 8;
    try std.testing.expectError(error.InvalidQuicConfig, config.validate());
    config.server.quic.max_datagram_frame_size = 65000;
    try std.testing.expectError(error.InvalidQuicConfig, config.validate());
    config.server.quic.max_datagram_frame_size = 1200;
    try config.validate();
    config.auth = .{ .required = true, .group = null };
    try std.testing.expectError(error.InvalidAuthConfig, config.validate());
    config.auth = .{ .required = true, .group = 2 };
    try config.validate();

    config.cluster.node_id = config.cluster.max_nodes;
    try std.testing.expectError(error.InvalidClusterConfig, config.validate());
    config.cluster.node_id = 1;
    config.cluster.return_path_capacity = 0;
    try std.testing.expectError(error.InvalidClusterConfig, config.validate());
    config.cluster.return_path_capacity = 4096;
    // 集群关闭时不会创建 forward 隧道，声明需要跨节点纠错的入口模式属于矛盾配置。
    config.cluster.deployment_mode = .l4_lb;
    try std.testing.expectError(error.InvalidClusterConfig, config.validate());
    config.cluster.deployment_mode = .anycast;
    try std.testing.expectError(error.InvalidClusterConfig, config.validate());
    config.cluster.deployment_mode = .direct;
    try config.validate();

    // 开启集群后，需要跨节点转发的模式才成立。
    config.cluster.enabled = true;
    config.cluster.secret = "0123456789abcdef";
    config.cluster.deployment_mode = .l4_lb;
    try config.validate();

    const duplicate_seeds = [_]GatewayConfig.Cluster.Seed{
        .{ .node_id = 2, .host = "127.0.0.2", .port = 7946 },
        .{ .node_id = 2, .host = "127.0.0.3", .port = 7946 },
    };
    config.cluster.seeds = &duplicate_seeds;
    try std.testing.expectError(error.InvalidClusterConfig, config.validate());
}

test "realm registration and route scoping are validated at startup" {
    var config = testConfig();

    // 登记表为空 = 单域部署：路由只能属于 realm 0。
    try config.validate();
    config.backend.direct.routes = &.{
        .{ .realm = 1, .group = 1, .endpoints = &.{.{ .host = "127.0.0.1", .port = 8443 }} },
    };
    try std.testing.expectError(error.InvalidRealmConfig, config.validate());

    // 登记了 realm 1 之后同一份路由成立。
    config.realms = &.{.{ .server_name = "a.gw.example.com", .id = 1 }};
    try config.validate();

    // 指向未登记 realm 的路由永远不会被命中，属于配置错误而不是"暂时没接"。
    config.backend.direct.routes = &.{
        .{ .realm = 2, .group = 1, .endpoints = &.{.{ .host = "127.0.0.1", .port = 8443 }} },
    };
    try std.testing.expectError(error.InvalidRealmConfig, config.validate());

    // 同一 (realm, group, route_key) 注册两次：注册表里后者会顶掉前者，必须拒绝。
    config.backend.direct.routes = &.{
        .{ .realm = 1, .group = 1, .route_key = 0, .endpoints = &.{.{ .host = "127.0.0.1", .port = 8443 }} },
        .{ .realm = 1, .group = 1, .route_key = 0, .endpoints = &.{.{ .host = "127.0.0.2", .port = 8443 }} },
    };
    try std.testing.expectError(error.InvalidRealmConfig, config.validate());

    // 换 realm 就不再冲突——这正是隔离要的效果。
    config.realms = &.{
        .{ .server_name = "a.gw.example.com", .id = 1 },
        .{ .server_name = "b.gw.example.com", .id = 2 },
    };
    config.backend.direct.routes = &.{
        .{ .realm = 1, .group = 1, .route_key = 0, .endpoints = &.{.{ .host = "127.0.0.1", .port = 8443 }} },
        .{ .realm = 2, .group = 1, .route_key = 0, .endpoints = &.{.{ .host = "127.0.0.2", .port = 8443 }} },
    };
    try config.validate();

    // 域名重复（大小写无关）：resolve 只会命中第一条，第二条静默失效。
    config.realms = &.{
        .{ .server_name = "a.gw.example.com", .id = 1 },
        .{ .server_name = "A.GW.Example.com", .id = 2 },
    };
    try std.testing.expectError(error.InvalidRealmConfig, config.validate());

    config.realms = &.{.{ .server_name = "", .id = 1 }};
    try std.testing.expectError(error.InvalidRealmConfig, config.validate());

    // 容量装不下启动期条目：必须在启动时拒绝，而不是在 prepare 里悄悄放大。
    // 放大会让运维以为自己配的上限生效了，等到第 N 个接入方登记失败时无从解释。
    config.realms = &.{
        .{ .server_name = "a.gw.example.com", .id = 1 },
        .{ .server_name = "b.gw.example.com", .id = 2 },
    };
    config.realm_capacity = 1;
    try std.testing.expectError(error.InvalidRealmConfig, config.validate());
    // 留出余量才是正常形态：余量就是运行期还能追加多少个接入方（§12.5）。
    config.realm_capacity = 8;
    try config.validate();
}

test "backend mTLS must be configured as a complete pair" {
    // 半配是静默的安全降级：运维以为双向认证开了，而 picoquic 拿不到完整的一对，
    // 握手仍然是单向的，任何能连上后端端口的东西照旧能冒充网关（§10.1）。
    var config = testConfig();
    config.backend.direct.client_certificate_file = "gw.crt";
    try std.testing.expectError(error.InvalidBackendConfig, config.validate());

    config.backend.direct.client_private_key_file = "gw.key";
    try config.validate();

    // 空路径同样是配错——它会让 picoquic 拿到一个空文件名。
    config.backend.direct.client_certificate_file = "";
    try std.testing.expectError(error.InvalidBackendConfig, config.validate());
}

test "WSS is opt-in and rejects unsafe or ineffective limits" {
    var config = testConfig();
    // 默认关闭，旧配置不需要新增字段。
    try config.validate();

    config.server.wss.enabled = true;
    try std.testing.expectError(error.InvalidWssConfig, config.validate());
    config.server.wss.allowed_origins = &.{"https://chat.example.com"};
    try config.validate();

    config.server.wss.max_queued_bytes = 64 * 1024;
    try std.testing.expectError(error.InvalidWssConfig, config.validate());
    config.server.wss.max_queued_bytes = 256 * 1024;
    config.server.wss.tls_bio_capacity = 1024;
    try std.testing.expectError(error.InvalidWssConfig, config.validate());
}

test "deployment mode capabilities stay in sync with their semantics" {
    const Mode = GatewayConfig.Cluster.DeploymentMode;
    // direct：客户端目的地址固定，不会错投，两项能力都不需要。
    try std.testing.expect(!Mode.direct.requiresCrossNodeForward());
    try std.testing.expect(!Mode.direct.requiresReturnPath());
    // anycast：会错投，需要转发；但所有节点共享对外地址，owner 可直接回客户端。
    try std.testing.expect(Mode.anycast.requiresCrossNodeForward());
    try std.testing.expect(!Mode.anycast.requiresReturnPath());
    // l4_lb：会错投，且响应必须经原入口回流。
    try std.testing.expect(Mode.l4_lb.requiresCrossNodeForward());
    try std.testing.expect(Mode.l4_lb.requiresReturnPath());

    // 需要回程必然意味着需要转发：回程本身就是转发的响应方向。
    inline for (comptime std.enums.values(Mode)) |mode| {
        if (mode.requiresReturnPath()) try std.testing.expect(mode.requiresCrossNodeForward());
    }
}

test "GatewayConfig requires every field" {
    const incomplete =
        \\{
        \\  "runtime": {"threads": 1},
        \\  "server": {
        \\    "listen_host": "0.0.0.0",
        \\    "listen_port": 8443,
        \\    "certificate_file": "cert.pem",
        \\    "private_key_file": "key.pem"
        \\  }
        \\}
    ;
    try std.testing.expectError(
        error.MissingField,
        std.json.parseFromSlice(GatewayConfig, std.testing.allocator, incomplete, .{}),
    );
}
