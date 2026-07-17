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
    direct_route_key: u8,
    direct: backend.DirectConfig,
    backend_poll_interval_ms: u64,
    cluster: control.coordinator.Config,

    pub fn deinit(self: *RuntimeConfig, allocator: std.mem.Allocator) void {
        if (self.server_quic.cert_file) |path| allocator.free(path);
        if (self.server_quic.key_file) |path| allocator.free(path);
        allocator.free(self.server_quic.base.alpn);
        allocator.free(self.direct.server_host);
        allocator.free(self.direct.alpn);
        if (self.direct.root_cert_file) |path| allocator.free(path);
        allocator.free(self.cluster.node_id);
    }
};

/// 从原始配置组装 RuntimeConfig。任何一步分配失败都会通过 errdefer 回滚。
pub fn prepare(allocator: std.mem.Allocator, config: foundation.config.GatewayConfig) !RuntimeConfig {
    const bind_address = std.Io.net.IpAddress.parseIp4(config.server.listen_host, config.server.listen_port) catch return error.InvalidListenAddress;
    const cert_file = try allocator.dupeZ(u8, config.server.certificate_file);
    errdefer allocator.free(cert_file);
    const key_file = try allocator.dupeZ(u8, config.server.private_key_file);
    errdefer allocator.free(key_file);
    const server_alpn = try allocator.dupeZ(u8, config.server.quic.alpn);
    errdefer allocator.free(server_alpn);
    const backend_host = try allocator.dupeZ(u8, config.backend.direct.host);
    errdefer allocator.free(backend_host);
    const backend_alpn = try allocator.dupeZ(u8, config.backend.direct.alpn);
    errdefer allocator.free(backend_alpn);
    const root_cert = if (config.backend.direct.root_certificate_file) |path| try allocator.dupeZ(u8, path) else null;
    errdefer if (root_cert) |path| allocator.free(path);
    const node_id = try allocator.dupe(u8, config.cluster.node_id);
    errdefer allocator.free(node_id);
    const advertise_address = std.Io.net.IpAddress.parseIp4(config.cluster.advertise_host, config.cluster.advertise_port) catch return error.InvalidAdvertiseAddress;

    return .{
        .threads = config.runtime.threads,
        .server_quic = .{
            .base = .{
                .max_connections = config.server.quic.max_connections,
                .idle_timeout_ms = config.server.quic.idle_timeout_ms,
                .alpn = server_alpn,
                .congestion_algorithm = mapCongestionControl(config.server.quic.congestion_control),
            },
            .cert_file = cert_file,
            .key_file = key_file,
            .bind_address = bind_address.ip4.bytes,
            .bind_port = config.server.listen_port,
        },
        .direct_route_key = config.backend.direct.route_key,
        .direct = .{
            .server_host = backend_host,
            .server_port = config.backend.direct.port,
            .verify_cert = config.backend.direct.verify_certificate,
            .root_cert_file = root_cert,
            .max_recv_queue = config.backend.direct.max_receive_queue,
            .idle_timeout_ms = config.backend.direct.idle_timeout_ms,
            .alpn = backend_alpn,
            .congestion_algorithm = mapCongestionControl(config.backend.direct.congestion_control),
        },
        .backend_poll_interval_ms = config.worker.backend_poll_interval_ms,
        .cluster = .{
            .node_id = node_id,
            .advertise_address = advertise_address,
            .worker_count = config.runtime.threads,
            .handoff_queue_capacity = config.cluster.handoff_queue_capacity,
        },
    };
}

fn mapCongestionControl(value: []const u8) quic.config.Config.CongestionAlgorithm {
    return switch (foundation.config.parseCongestionControl(value) catch unreachable) {
        .bbr => .bbr,
        .cubic => .cubic,
        .reno => .reno,
        .fast => .fast,
    };
}
