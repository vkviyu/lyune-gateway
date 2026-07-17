const std = @import("std");

pub const ConfigError = error{
    InvalidConfig,
    InvalidPort,
    InvalidThreadCount,
    InvalidPollInterval,
    InvalidQuicConfig,
    InvalidBackendConfig,
    InvalidClusterConfig,
};

pub const GatewayConfig = struct {
    runtime: Runtime,
    server: Server,
    backend: Backend,
    worker: Worker,
    cluster: Cluster,

    pub const Runtime = struct {
        threads: u16,
    };

    pub const Server = struct {
        listen_host: []const u8,
        listen_port: u16,
        certificate_file: []const u8,
        private_key_file: []const u8,
        quic: Quic,
    };

    pub const Quic = struct {
        max_connections: u32,
        idle_timeout_ms: u64,
        alpn: []const u8,
        congestion_control: []const u8,
    };

    pub const Backend = struct {
        direct: Direct,
    };

    pub const Direct = struct {
        route_key: u8,
        host: []const u8,
        port: u16,
        verify_certificate: bool,
        root_certificate_file: ?[]const u8,
        max_receive_queue: usize,
        idle_timeout_ms: u64,
        alpn: []const u8,
        congestion_control: []const u8,
    };

    pub const Worker = struct {
        backend_poll_interval_ms: u64,
    };

    pub const Cluster = struct {
        node_id: []const u8,
        advertise_host: []const u8,
        advertise_port: u16,
        handoff_queue_capacity: usize,
    };

    pub fn validate(self: GatewayConfig) ConfigError!void {
        if (self.runtime.threads == 0 or self.runtime.threads > 256) return error.InvalidThreadCount;
        if (self.server.listen_port == 0 or self.backend.direct.port == 0) return error.InvalidPort;
        if (self.worker.backend_poll_interval_ms == 0) return error.InvalidPollInterval;
        if (self.server.listen_host.len == 0 or self.server.certificate_file.len == 0 or self.server.private_key_file.len == 0) return error.InvalidConfig;
        if (self.server.quic.max_connections == 0 or self.server.quic.idle_timeout_ms == 0 or self.server.quic.alpn.len == 0 or self.server.quic.alpn.len > 255) return error.InvalidQuicConfig;
        if (self.backend.direct.host.len == 0 or self.backend.direct.max_receive_queue == 0 or self.backend.direct.idle_timeout_ms == 0 or self.backend.direct.alpn.len == 0 or self.backend.direct.alpn.len > 255) return error.InvalidBackendConfig;
        if (self.cluster.node_id.len == 0 or self.cluster.advertise_host.len == 0 or self.cluster.advertise_port == 0 or self.cluster.handoff_queue_capacity == 0) return error.InvalidClusterConfig;
        _ = std.Io.net.IpAddress.parseIp4(self.cluster.advertise_host, self.cluster.advertise_port) catch return error.InvalidClusterConfig;
        _ = parseCongestionControl(self.server.quic.congestion_control) catch return error.InvalidQuicConfig;
        _ = parseCongestionControl(self.backend.direct.congestion_control) catch return error.InvalidBackendConfig;
    }
};

pub const LoadedConfig = struct {
    bytes: []u8,
    parsed: std.json.Parsed(GatewayConfig),

    pub fn deinit(self: *LoadedConfig, allocator: std.mem.Allocator) void {
        self.parsed.deinit();
        allocator.free(self.bytes);
    }
};

pub fn load(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !LoadedConfig {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024));
    errdefer allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(GatewayConfig, allocator, bytes, .{
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    });
    errdefer parsed.deinit();
    try parsed.value.validate();
    return .{ .bytes = bytes, .parsed = parsed };
}

pub fn parseCongestionControl(value: []const u8) !enum { bbr, cubic, reno, fast } {
    if (std.mem.eql(u8, value, "bbr")) return .bbr;
    if (std.mem.eql(u8, value, "cubic")) return .cubic;
    if (std.mem.eql(u8, value, "newreno")) return .reno;
    if (std.mem.eql(u8, value, "fast")) return .fast;
    return error.InvalidCongestionControl;
}

test "GatewayConfig rejects invalid values" {
    var config: GatewayConfig = .{
        .runtime = .{ .threads = 1 },
        .server = .{
            .listen_host = "0.0.0.0",
            .listen_port = 8443,
            .certificate_file = "cert.pem",
            .private_key_file = "key.pem",
            .quic = .{
                .max_connections = 10_000,
                .idle_timeout_ms = 30_000,
                .alpn = "lyune-gateway",
                .congestion_control = "bbr",
            },
        },
        .backend = .{ .direct = .{
            .route_key = 1,
            .host = "127.0.0.1",
            .port = 8443,
            .verify_certificate = false,
            .root_certificate_file = null,
            .max_receive_queue = 1024,
            .idle_timeout_ms = 30_000,
            .alpn = "lyune-gateway",
            .congestion_control = "bbr",
        } },
        .worker = .{ .backend_poll_interval_ms = 10 },
        .cluster = .{
            .node_id = "gateway-local-1",
            .advertise_host = "127.0.0.1",
            .advertise_port = 8443,
            .handoff_queue_capacity = 1024,
        },
    };
    try config.validate();
    config.runtime.threads = 0;
    try std.testing.expectError(error.InvalidThreadCount, config.validate());
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
