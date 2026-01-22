//! QUIC 配置
//!
//! 封装 picoquic 的配置选项，提供 Zig 友好的 API。

const std = @import("std");
const quic_c = @import("c.zig");

pub const Config = struct {
    /// 最大连接数
    max_connections: u32 = 256,

    /// 空闲超时（毫秒）
    idle_timeout_ms: u64 = 30_000,

    /// 证书文件路径
    cert_file: ?[:0]const u8 = null,

    /// 私钥文件路径
    key_file: ?[:0]const u8 = null,

    /// 根证书文件路径（用于验证对端证书）
    root_cert_file: ?[:0]const u8 = null,

    /// ALPN 协议标识
    alpn: [:0]const u8 = "lyune-im",

    /// 初始最大数据量
    initial_max_data: u64 = 10_000_000,

    /// 初始最大 stream 数据量（本地发起的双向流）
    initial_max_stream_data_bidi_local: u64 = 1_000_000,

    /// 初始最大 stream 数据量（远端发起的双向流）
    initial_max_stream_data_bidi_remote: u64 = 1_000_000,

    /// 初始最大双向流数量
    initial_max_streams_bidi: u64 = 128,

    /// 初始最大单向流数量
    initial_max_streams_uni: u64 = 128,

    /// 是否启用 0-RTT
    enable_0rtt: bool = true,

    /// 拥塞控制算法
    congestion_algorithm: CongestionAlgorithm = .bbr,

    pub const CongestionAlgorithm = enum {
        reno,
        cubic,
        bbr,
        fast,
    };

    /// 获取拥塞控制算法的 C 指针
    pub fn getCongestionAlgorithm(self: Config) *quic_c.c.picoquic_congestion_algorithm_t {
        return switch (self.congestion_algorithm) {
            .reno => quic_c.c.picoquic_newreno_algorithm,
            .cubic => quic_c.c.picoquic_cubic_algorithm,
            .bbr => quic_c.c.picoquic_bbr_algorithm,
            .fast => quic_c.c.picoquic_fastcc_algorithm,
        };
    }
};

/// 服务端配置（包含证书）
pub const QuicConfig = struct {
    base: Config = .{},

    /// 证书文件路径（必需）
    cert_file: ?[:0]const u8 = null,

    /// 私钥文件路径（必需）
    key_file: ?[:0]const u8 = null,

    /// 绑定端口
    /// 默认为 0 (由操作系统随机分配)，适用于客户端
    /// 服务端初始化时应显式指定为 4433 等
    bind_port: u16 = 0,

    /// 绑定地址
    /// 默认为 0.0.0.0 (IPv4 Any)，适用于客户端或默认服务端
    bind_address: [4]u8 = .{ 0, 0, 0, 0 },
};
