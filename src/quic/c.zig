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

/// 连接 ID，
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
    ready = c.picoquic_state_ready,
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
    client_ready_start = c.picoquic_state_client_ready_start,
    server_init = c.picoquic_state_server_init,
    server_handshake = c.picoquic_state_server_handshake,
    server_false_start = c.picoquic_state_server_false_start,
    server_almost_ready = c.picoquic_state_server_almost_ready,
    handshake_failure = c.picoquic_state_handshake_failure,
    handshake_failure_resend = c.picoquic_state_handshake_failure_resend,
    disconnecting = c.picoquic_state_disconnecting,
    closing_received = c.picoquic_state_closing_received,
    /// 正在关闭。正在关闭连接，等待对端确认。
    closing = c.picoquic_state_closing,
    /// 等待关闭确认。等待残留包传输完成。
    draining = c.picoquic_state_draining,
    _,

    pub fn isConnected(self: ConnectionState) bool {
        return self == .ready;
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

// =============================================================================
// 高级 API（用于自定义 Connection ID 等）
// =============================================================================

/// Connection ID 生成回调函数类型
///
/// 当 picoquic 需要生成新的 Connection ID 时调用此回调。
/// 典型用途：在 CID 中编码线程 ID 或路由信息，以支持无锁负载均衡。
///
/// @param quic QUIC 上下文（可能为 null）
/// @param cnx_id_local 本地当前使用的 Connection ID
/// @param cnx_id_remote 对端的 Connection ID
/// @param cnx_id_cb_data 用户自定义数据（通过 picoquic_create 传入）
/// @param cnx_id_returned 输出参数，用于返回新生成的 Connection ID
pub const ConnectionIdCallbackFn = *const fn (
    quic: ?QuicCtx,
    cnx_id_local: ConnectionId,
    cnx_id_remote: ConnectionId,
    cnx_id_cb_data: ?*anyopaque,
    cnx_id_returned: [*c]ConnectionId,
) callconv(.c) void;

/// QUIC 包头解析错误类型
pub const ParseError = error{
    /// 包太短，无法解析
    PacketTooShort,
    /// DCID 长度超出 RFC 9000 规定的最大值（20 字节）
    DcidLengthExceedsMax,
    /// Version Negotiation 包（Version = 0），不包含有效的 DCID
    VersionNegotiation,
    /// 包格式无效
    InvalidFormat,
};

/// RFC 9000 规定的 Connection ID 最大长度
pub const MAX_CID_LENGTH: u8 = 20;

/// 本项目使用的固定 CID 长度（与 connectionIdCallback 中的生成逻辑一致）
/// 用于短包头解析，因为短包头不携带显式的 DCID 长度字段。
pub const DEFAULT_SHORT_HEADER_CID_LENGTH: u8 = 8;

/// 从 QUIC 包中解析 Destination Connection ID (DCID)。
///
/// 此函数用于在收到 UDP 包后，快速提取 DCID 以进行连接查找或负载均衡路由。
/// 它不解析完整的 QUIC 包，只提取必要的 DCID 字段。
///
/// QUIC 包头格式（RFC 9000）：
///
/// **长包头 (Long Header)** - 用于握手阶段：
/// ```
/// +-+-+-+-+-+-+-+-+
/// |1|1|T T|X X X X|  First Byte (Header Form=1, Fixed Bit=1, Type, Type-Specific)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Version (32)                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | DCID Len (8)  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |               Destination Connection ID (0..160)             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | SCID Len (8)  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 Source Connection ID (0..160)                |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// **短包头 (Short Header)** - 用于数据传输阶段：
/// ```
/// +-+-+-+-+-+-+-+-+
/// |0|1|S|R|R|K|P P|  First Byte (Header Form=0, Fixed Bit=1, ...)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |               Destination Connection ID (*)                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// 注意：短包头中 DCID 长度是隐式的，需要从连接上下文中获取。
/// 本项目使用固定的 8 字节 CID（见 DEFAULT_SHORT_HEADER_CID_LENGTH）。
///
/// @param packet 收到的原始 UDP 包数据
/// @param dcid 输出参数，用于存储解析出的 DCID
/// @return 成功返回 true，失败返回 false
pub fn parseDcid(packet: []const u8, dcid: *ConnectionId) bool {
    return parseDcidWithLength(packet, dcid, DEFAULT_SHORT_HEADER_CID_LENGTH);
}

/// 带有可配置短包头 CID 长度的 DCID 解析函数。
///
/// 此函数允许调用者指定短包头中期望的 CID 长度，适用于需要不同 CID 长度策略的场景。
///
/// @param packet 收到的原始 UDP 包数据
/// @param dcid 输出参数，用于存储解析出的 DCID
/// @param short_header_cid_len 短包头中期望的 CID 长度（本项目默认为 8）
/// @return 成功返回 true，失败返回 false
pub fn parseDcidWithLength(packet: []const u8, dcid: *ConnectionId, short_header_cid_len: u8) bool {
    const result = parseDcidDetailed(packet, dcid, short_header_cid_len);
    return if (result) |_| true else false;
}

/// 带有详细错误信息的 DCID 解析函数。
///
/// 适用于需要区分不同失败原因的场景（如日志记录、监控统计）。
///
/// @param packet 收到的原始 UDP 包数据
/// @param dcid 输出参数，用于存储解析出的 DCID
/// @param short_header_cid_len 短包头中期望的 CID 长度
/// @return 成功返回 void，失败返回具体的 ParseError
pub fn parseDcidDetailed(
    packet: []const u8,
    dcid: *ConnectionId,
    short_header_cid_len: u8,
) ParseError!void {
    // 最小包长检查：至少需要 1 字节的包头
    if (packet.len < 1) return ParseError.PacketTooShort;

    const first_byte = packet[0];
    const is_long_header = (first_byte & 0x80) != 0;

    if (is_long_header) {
        // ========== 长包头解析 ==========
        // 最小长度：1 (first byte) + 4 (version) + 1 (dcid len) = 6 字节
        if (packet.len < 6) return ParseError.PacketTooShort;

        // 检查 Version 字段（字节 1-4，大端序）
        // Version = 0x00000000 表示 Version Negotiation 包，其格式与常规长包头不同
        const version = @as(u32, packet[1]) << 24 |
            @as(u32, packet[2]) << 16 |
            @as(u32, packet[3]) << 8 |
            @as(u32, packet[4]);

        if (version == 0) {
            // Version Negotiation 包的格式：
            // [First Byte][Version=0][DCID Len][DCID][SCID Len][SCID][Supported Versions...]
            // 虽然它也有 DCID，但通常不用于路由，这里我们仍然尝试解析
            // 如果需要严格区分，可以返回错误
        }

        // 解析 DCID 长度（字节 5）
        const dcid_len = packet[5];

        // RFC 9000 Section 17.2: Connection ID 长度不能超过 20 字节
        if (dcid_len > MAX_CID_LENGTH) return ParseError.DcidLengthExceedsMax;

        // 检查包长度是否足够容纳 DCID
        const required_len: usize = 6 + dcid_len;
        if (packet.len < required_len) return ParseError.PacketTooShort;

        // 填充输出结构
        dcid.id_len = dcid_len;
        if (dcid_len > 0) {
            @memcpy(dcid.id[0..dcid_len], packet[6..required_len]);
        }
    } else {
        // ========== 短包头解析 ==========
        // 短包头没有显式的 DCID 长度字段，使用调用者指定的长度

        // 验证指定的长度是否合法
        if (short_header_cid_len > MAX_CID_LENGTH) return ParseError.DcidLengthExceedsMax;

        // 检查包长度：1 (first byte) + CID 长度
        const required_len: usize = 1 + short_header_cid_len;
        if (packet.len < required_len) return ParseError.PacketTooShort;

        // 填充输出结构
        dcid.id_len = short_header_cid_len;
        if (short_header_cid_len > 0) {
            @memcpy(dcid.id[0..short_header_cid_len], packet[1..required_len]);
        }
    }
}

/// 判断 QUIC 包是否为长包头格式
///
/// @param packet 原始 UDP 包数据
/// @return true 表示长包头，false 表示短包头或包太短
pub fn isLongHeader(packet: []const u8) bool {
    if (packet.len < 1) return false;
    return (packet[0] & 0x80) != 0;
}

/// 从长包头中提取 QUIC 版本号
///
/// @param packet 原始 UDP 包数据
/// @return 版本号（大端序转换后），如果包太短则返回 null
pub fn getVersion(packet: []const u8) ?u32 {
    if (packet.len < 5) return null;
    if (!isLongHeader(packet)) return null;

    return @as(u32, packet[1]) << 24 |
        @as(u32, packet[2]) << 16 |
        @as(u32, packet[3]) << 8 |
        @as(u32, packet[4]);
}
