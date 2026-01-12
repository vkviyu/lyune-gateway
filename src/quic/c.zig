//! picoquic C 绑定
//!
//! 这个文件导入 picoquic 的 C 头文件，并提供类型别名。

pub const c = @cImport({
    @cInclude("picoquic.h"); // 核心 API（连接、stream 等）
    @cInclude("picoquic_utils.h"); // 工具函数
    @cInclude("picoquic_packet_loop.h"); // 内置事件循环
    @cInclude("picosocks.h"); // socket 相关
    @cInclude("picoquic_config.h"); // 配置解析
    // 拥塞控制算法
    @cInclude("picoquic_newreno.h");
    @cInclude("picoquic_cubic.h");
    @cInclude("picoquic_bbr.h");
    @cInclude("picoquic_fastcc.h");
});

// =============================================================================
// 类型别名
// =============================================================================

/// QUIC 上下文（服务端或客户端实例）
///
/// picoquic 的顶层上下文指针。一个 Server 或 Client 对应一个 picoquic_quic_t
pub const QuicCtx = *c.picoquic_quic_t;

/// QUIC 连接
///
/// 单个 QUIC 连接的指针，一个上下文可以有多个连接
pub const QuicCnx = *c.picoquic_cnx_t;

/// Stream ID
///
/// QUIC Stream ID，64 位无符号整数。
pub const StreamId = u64;

/// 连接 ID
///
/// 包含 ID 字节和长度。这是值类型，不是指针。
pub const ConnectionId = c.picoquic_connection_id_t;

/// Socket 地址
///
/// 标准 BSD socket 地址结构
pub const SockAddr = c.struct_sockaddr;

/// 通用地址存储，可以存 IPv4 或 IPv6 地址
pub const SockAddrStorage = c.struct_sockaddr_storage;

// =============================================================================
// 回调事件类型
// =============================================================================

/// 回调事件类型
///
/// 把 C 的宏常量转换为 Zig 枚举。enum(c_int) 指定底层类型为 C 的 int。
pub const CallbackEvent = enum(c_int) {
    /// 收到 stream 数据，但还没结束（没有 FIN）。
    stream_data = c.picoquic_callback_stream_data,
    /// stream 结束，收到 FIN 标志，表示对端结束了这个 stream 的发送
    stream_fin = c.picoquic_callback_stream_fin,
    /// 准备发送数据。picoquic 请求应用层提供要发送的数据（用于流控）。
    prepare_to_send = c.picoquic_callback_prepare_to_send,
    /// 连接关闭。连接正常关闭。
    close = c.picoquic_callback_close,
    /// 对端发送了 STOP_SENDING 帧，请求停止发送数据。
    stop_sending = c.picoquic_callback_stop_sending,
    /// stream 重置，对端发送了 RESET_STREAM 帧，中止了这个 stream
    stream_reset = c.picoquic_callback_stream_reset,
    /// 无状态重置。收到无状态重置包，连接被强制终止。
    stateless_reset = c.picoquic_callback_stateless_reset,
    /// 应用层关闭。应用层主动关闭连接。
    application_close = c.picoquic_callback_application_close,
    /// TLS 握手即将完成，但还没完全就绪。
    almost_ready = c.picoquic_callback_almost_ready,
    /// 连接就绪。连接完全建立，可以开始收发应用数据。这是发送数据的最佳时机。
    ready = c.picoquic_callback_ready,
    /// 其他事件（用于未知事件），Zig 非穷尽枚举语法，允许接收未定义的值而不报错。
    /// 这样即使 picoquic 新增事件类型，代码也不会崩溃。
    _,
};

// =============================================================================
// 连接状态
// =============================================================================

/// 连接状态枚举
pub const ConnectionState = enum(c_int) {
    /// 已连接。连接完全建立，可以正常通信。
    connected = c.picoquic_state_ready,
    disconnected = c.picoquic_state_disconnected,
    /// 初始状态。客户端刚创建连接，还没发送初始包。
    client_init = c.picoquic_state_client_init,
    /// 等待服务器 Hello。客户端已发送 Initial 包，等待服务器响应。
    client_init_sent = c.picoquic_state_client_init_sent,
    client_init_resent = c.picoquic_state_client_init_resent,
    client_renegotiate = c.picoquic_state_client_renegotiate,
    client_retry_received = c.picoquic_state_client_retry_received,
    /// 握手中。TLS 握手进行中。
    client_handshake_start = c.picoquic_state_client_handshake_start,
    client_almost_ready = c.picoquic_state_client_almost_ready,
    client_ready = c.picoquic_state_client_ready,
    server_init = c.picoquic_state_server_init,
    server_handshake = c.picoquic_state_server_handshake,
    server_almost_ready = c.picoquic_state_server_almost_ready,
    server_ready = c.picoquic_state_server_ready,
    closing_received = c.picoquic_state_closing_received,
    /// 正在关闭。正在关闭连接，等待对端确认。
    closing = c.picoquic_state_closing,
    /// 等待关闭确认。等待残留包传输完成。
    draining = c.picoquic_state_draining,
    _,

    pub fn isConnected(self: ConnectionState) bool {
        return self == .client_ready or self == .server_ready;
    }

    pub fn isDisconnected(self: ConnectionState) bool {
        return self == .disconnected;
    }
};

// =============================================================================
// 常量
// =============================================================================

/// 重置密钥的大小（用于生成无状态重置包）
pub const RESET_SECRET_SIZE = c.PICOQUIC_RESET_SECRET_SIZE;

/// 最大包大小。1350 字节是考虑 Ipv6 + UDP 头部后的安全 MTU 值。
pub const MAX_PACKET_SIZE = 1350; // 典型 MTU 安全值

/// 空连接 ID（运行时获取）
pub fn nullConnectionId() ConnectionId {
    // 返回一个空的 Connection ID。这是函数而不是常量，
    // 因为 picoquic_null_connection_id 在编译期无法求值（它是 C 的全局变量）。
    return c.picoquic_null_connection_id;
}

// =============================================================================
// 辅助函数
// =============================================================================

/// 获取当前时间（微秒）
///
/// 获取 picoquic 使用的时间戳（微秒级），用于协议计时。
pub fn currentTime() u64 {
    return c.picoquic_current_time();
}

/// 获取服务器地址
pub fn getServerAddress(
    host: [*:0]const u8, // C 风格零终止字符串
    port: c_int, // C int 类型的端口
    addr: *SockAddrStorage, // 输出参数：地址结构
    is_name: *c_int, // 输出参数：是否是域名
) c_int {
    return c.picoquic_get_server_address(host, port, addr, is_name);
}
