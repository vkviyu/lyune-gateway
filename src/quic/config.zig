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

    /// 是否验证对端证书（客户端模式）
    /// 如果为 false，将禁用证书验证（用于自签名证书的开发环境）
    verify_cert: bool = true,

    /// ALPN 协议标识。
    ///
    /// 协议版本就活在这里：帧头里没有 version 字段，版本不匹配在 QUIC 握手阶段
    /// 就失败，不会进到帧层（见 docs/protocol_design.md §3）。
    alpn: [:0]const u8 = "lyune/1",

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

    /// 本端愿意接收的单个 QUIC DATAGRAM 上限（字节）；0 表示不启用不可靠通路。
    ///
    /// 它作为传输参数通告给对端（RFC 9221 的 `max_datagram_frame_size`），对端据此
    /// 决定能不能发、能发多大。**DATAGRAM 不分片**：超过这个数的包发不出去，也不会
    /// 被切开——切开就需要分片 id、乱序重组、超时回收，等于在不可靠通路上把流重新
    /// 实现一遍（设计文档 §6）。
    ///
    /// 默认 0（关闭）是有意的：只有面向客户端的监听器需要它（`app/config.zig` 从 JSON
    /// 配置取值，那一层的默认是 1200，落在 IPv6 最小 MTU 扣掉各层包头后的安全区里）。
    /// 网关↔后端、网关↔对等节点这两条链路都只说可靠流，给它们默认打开等于凭空多出
    /// 两条谁都不该走、也没人测过的路径。
    max_datagram_frame_size: u16 = 0,

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
pub const QUICConfig = struct {
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

    /// 服务端是否**要求**对端出示客户端证书（mTLS）。
    ///
    /// 只给集群监听器用（设计文档 §8.5）：那个端口上握手成功即等价于"对端持有集群
    /// CA 签发的证书" = "对端是一个网关节点"，于是 `.peer` / `.multicast` 的权限判据
    /// 变成结构性的——**面向客户端的端口绝不能开它**，否则普通客户端也要带证书。
    ///
    /// 注意它与 `verify_cert` 是两个方向：`verify_cert` 是"我校验对端"（客户端角色），
    /// 这一项是"我要求对端出示"（服务端角色）。集群监听器两者都要开。
    require_client_auth: bool = false,
};
