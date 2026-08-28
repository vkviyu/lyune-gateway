//! QUIC 端点封装
//!
//! 负责管理 picoquic 上下文 (picoquic_quic_t) 的生命周期。它是 Server 和 Client 的底层基类。

const std = @import("std");

const foundation = @import("../foundation/mod.zig");
const io = @import("../io/mod.zig");
const cluster_cid = io.cid;
const net = foundation.net;
const Config = @import("config.zig");
const Connection = @import("connection.zig").Connection;
const quic_c = @import("c.zig");

/// picoquic 准备出的一个或多个同目标 UDP 数据报。
/// data 借用调用方的发送缓冲区；segment_size 是 GSO 分段长度，驱动层按它切分批量发送。
/// 不变量：segment_size 恒大于 0，由 preparePendingPacket 归一化保证，
/// 调用方可以直接用它推进偏移而无需额外判零。
pub const PacketInfo = struct {
    data: []const u8,
    dest: net.Address,
    segment_size: usize,
};

/// QUIC 端点
///
/// 封装 picoquic 上下文，通过外部 I/O 层收发数据。
pub const Endpoint = struct {
    const Self = @This();

    /// picoquic 上下文
    quic_ctx: quic_c.QuicCtx,

    /// 配置
    config: Config.QUICConfig,

    allocator: std.mem.Allocator,

    /// 回调上下文。由 init 内部创建时归 Endpoint 所有，外部传入时只借用。
    callback_ctx: *CallbackContext,
    owns_callback_ctx: bool,

    /// 节点和线程 ID（用于 CID v1 生成）。
    node_id: u16,
    thread_id: u8,
    cid_owner_ptr: *CidOwner,

    const CidOwner = struct { node_id: u16, worker_id: u8 };

    /// Endpoint 创建阶段可能返回的错误。
    pub const Error = error{
        CreateFailed,
        OutOfMemory,
        InvalidNodeId,
    };

    /// 使用默认 node_id=1 初始化 QUIC 端点，主要供单机客户端路径兼容使用。
    /// callback_ctx_opt 为 null 时内部创建并持有；非 null 时仅借用，调用方须保证其活到 deinit。
    pub fn init(
        allocator: std.mem.Allocator,
        config: Config.QUICConfig,
        thread_id: u8,
        callback_ctx_opt: ?*CallbackContext,
    ) Error!Self {
        return initWithNode(allocator, config, thread_id, callback_ctx_opt, 1);
    }

    /// 使用明确的 node_id 初始化服务端 Endpoint，以生成 CID v1。
    /// callback_ctx_opt 为外部所有的借用指针；传 null 时 Endpoint 负责分配和释放上下文。
    pub fn initWithNode(
        allocator: std.mem.Allocator,
        config: Config.QUICConfig,
        thread_id: u8,
        callback_ctx_opt: ?*CallbackContext,
        node_id: u16,
    ) Error!Self {
        if (node_id == 0) return Error.InvalidNodeId;

        // 使用传入的回调上下文，或者创建新的
        const callback_ctx = callback_ctx_opt orelse blk: {
            const ctx = allocator.create(CallbackContext) catch return Error.OutOfMemory;
            ctx.* = .{
                .allocator = allocator,
                .on_connection = null,
                .on_stream_data = null,
                .on_stream_control = null,
                .on_datagram = null,
                .on_connection_close = null,
                .user_data = null,
            };
            break :blk ctx;
        };
        const owns_callback_ctx = callback_ctx_opt == null;
        errdefer if (owns_callback_ctx) allocator.destroy(callback_ctx);

        // 创建 reset seed
        var reset_seed: [quic_c.RESET_SECRET_SIZE]u8 = undefined;
        std.Io.Threaded.global_single_threaded.io().random(&reset_seed);

        const now = quic_c.currentTime();

        // CID 归属信息指针由 picoquic 在回调中使用，生命周期覆盖整个 Endpoint。
        const cid_owner_ptr = allocator.create(CidOwner) catch return Error.OutOfMemory;
        errdefer allocator.destroy(cid_owner_ptr);
        cid_owner_ptr.* = .{ .node_id = node_id, .worker_id = thread_id };

        // picoquic 用 strlen 读取 default_alpn，因此必须传裸 C 字符串，
        // 不能传 TLS 线格式的长度前缀，否则 ALPN 协商必然失败。
        const quic_ctx = quic_c.c.picoquic_create(
            config.base.max_connections,
            if (config.cert_file) |s| s.ptr else null,
            if (config.key_file) |s| s.ptr else null,
            if (config.base.root_cert_file) |s| s.ptr else null,
            config.base.alpn.ptr,
            streamCallback,
            callback_ctx,
            connectionIdCallback,
            cid_owner_ptr,
            &reset_seed,
            now,
            null, // p_simulated_time
            null, // ticket_file_name
            null, // ticket_encryption_key
            0, // ticket_encryption_key_length
        ) orelse return Error.CreateFailed;
        errdefer quic_c.c.picoquic_free(quic_ctx);

        // 短包头不携带 CID 长度，picoquic 默认按 8 字节解析并查表。
        // 必须显式改成集群 CID 长度，否则本端签发的 CID 无法被自己查到。
        // 该调用必须在创建任何连接之前完成，否则 picoquic 返回
        // PICOQUIC_ERROR_CANNOT_CHANGE_ACTIVE_CONTEXT。
        if (quic_c.c.picoquic_set_default_connection_id_length(quic_ctx, cluster_cid.length) != 0) {
            return Error.CreateFailed;
        }

        // 设置拥塞控制算法
        quic_c.c.picoquic_set_default_congestion_algorithm(
            quic_ctx,
            config.base.getCongestionAlgorithm(),
        );

        // 配置 Transport Parameters
        //
        // 必须先取 picoquic 的默认值再覆盖需要的字段：picoquic_set_default_tp
        // 是整体 memcpy，不做字段合并。用全零结构体会把 ack_delay_exponent、
        // max_ack_delay、min_ack_delay、enable_loss_bit 等一并清零，
        // 而前两者直接参与对端的 RTT 与 PTO 计算。
        var tp: quic_c.c.picoquic_tp_t = if (quic_c.c.picoquic_get_default_tp(quic_ctx)) |defaults|
            defaults.*
        else
            std.mem.zeroes(quic_c.c.picoquic_tp_t);
        tp.initial_max_data = config.base.initial_max_data;
        tp.initial_max_stream_data_bidi_local = config.base.initial_max_stream_data_bidi_local;
        tp.initial_max_stream_data_bidi_remote = config.base.initial_max_stream_data_bidi_remote;
        tp.initial_max_stream_data_uni = config.base.initial_max_stream_data_bidi_local; // 复用 bidi_local 值
        tp.initial_max_stream_id_bidir = config.base.initial_max_streams_bidi * 4; // Stream ID 编码规则
        tp.initial_max_stream_id_unidir = config.base.initial_max_streams_uni * 4;
        tp.max_idle_timeout = config.base.idle_timeout_ms;
        tp.max_packet_size = quic_c.MAX_PACKET_SIZE;
        // 不可靠通路（RFC 9221）。0 表示不通告这个传输参数，对端因此发不了 datagram
        // ——这正是"没配就没有这条通路"的正确形态，而不是配了个小值让它半通。
        tp.max_datagram_frame_size = config.base.max_datagram_frame_size;
        // RFC 9000 要求 active_connection_id_limit 至少为 2
        tp.active_connection_id_limit = 8;
        _ = quic_c.c.picoquic_set_default_tp(quic_ctx, &tp);

        // 设置空闲超时
        quic_c.c.picoquic_set_default_idle_timeout(quic_ctx, config.base.idle_timeout_ms);

        // 如果禁用证书验证（用于自签名证书的开发环境）
        if (!config.base.verify_cert) {
            quic_c.c.picoquic_set_null_verifier(quic_ctx);
        }

        // 集群监听器要求对端出示客户端证书（mTLS）。
        //
        // 这一行就是"对等网关节点"这个身份的**全部**校验：这个端口上握手成功即
        // 等价于"对端持有集群 CA 签发的证书"。因此不需要任何应用层握手——
        // 没有 nonce、没有 HMAC、没有防重放窗口、没有时钟依赖（设计文档 §8.5）。
        //
        // 面向客户端的端口必须保持 false，否则普通客户端也要带证书。
        if (config.require_client_auth) {
            quic_c.c.picoquic_set_client_authentication(quic_ctx, 1);
        }

        return .{
            .quic_ctx = quic_ctx,
            .config = config,
            .allocator = allocator,
            .callback_ctx = callback_ctx,
            .owns_callback_ctx = owns_callback_ctx,
            .node_id = node_id,
            .thread_id = thread_id,
            .cid_owner_ptr = cid_owner_ptr,
        };
    }

    /// 释放 picoquic 上下文及 Endpoint 自有缓冲；外部传入的 CallbackContext 不会被释放。
    pub fn deinit(self: *Self) void {
        // picoquic_free 会先删除所有连接，而删除未断开的连接会同步回调应用层
        // （close 事件）。调用方通常已经释放了 io_loop 之类的资源，
        // 因此必须先摘除回调，避免回调打到已析构的对象上。
        self.callback_ctx.on_connection = null;
        self.callback_ctx.on_stream_data = null;
        self.callback_ctx.on_stream_control = null;
        self.callback_ctx.on_datagram = null;
        self.callback_ctx.on_connection_close = null;

        quic_c.c.picoquic_free(self.quic_ctx);
        if (self.owns_callback_ctx) self.allocator.destroy(self.callback_ctx);
        self.allocator.destroy(self.cid_owner_ptr);
        self.* = undefined;
    }

    /// 设置连接回调（QUIC 握手完成，连接建立时）
    pub fn onConnection(self: *Self, callback: *const fn (?*anyopaque, *Connection) void) void {
        self.callback_ctx.on_connection = callback;
    }

    /// 设置数据接收回调（收到客户端发送的数据时）
    pub fn onStreamData(self: *Self, callback: *const fn (?*anyopaque, *Connection, u64, []const u8, bool) void) void {
        self.callback_ctx.on_stream_data = callback;
    }

    /// 设置流控制事件回调。数据/FIN 仍走 onStreamData；这里只转交对端显式发来的
    /// RESET_STREAM 与 STOP_SENDING，让上层能及时释放交换状态而不是等连接超时。
    pub fn onStreamControl(self: *Self, callback: *const fn (?*anyopaque, *Connection, u64, quic_c.CallbackEvent) void) void {
        self.callback_ctx.on_stream_control = callback;
    }

    /// 设置 datagram 接收回调（不可靠通路，设计文档 §6）。
    pub fn onDatagram(self: *Self, callback: *const fn (?*anyopaque, *Connection, []const u8) void) void {
        self.callback_ctx.on_datagram = callback;
    }

    /// 设置连接关闭回调
    pub fn onConnectionClose(self: *Self, callback: *const fn (?*anyopaque, *Connection, quic_c.CallbackEvent) void) void {
        self.callback_ctx.on_connection_close = callback;
    }

    /// 设置用户数据（会传递给回调）
    pub fn setUserData(self: *Self, data: ?*anyopaque) void {
        self.callback_ctx.user_data = data;
    }

    /// 处理收到的 UDP 包（由上层 I/O 调用）
    ///
    /// 构造源地址和目标地址，把从网络收到的原始 UDP 数据喂给 QUIC 引擎处理
    pub fn handleIncomingPacket(
        self: *Self,
        data: []const u8,
        from_addr: net.Address,
        local_addr: net.Address,
        timestamp: u64,
    ) void {
        // 构造源/目标地址
        var addr_from = net.toSockAddrStorage(from_addr);
        var addr_to = net.toSockAddrStorage(local_addr);

        // 使用 I/O 层传递的时间戳（避免频繁系统调用）
        // libxev 传递的是微秒时间戳，与 picoquic 兼容
        const pico_time = timestamp;

        // 把从网络收到的原始 UDP 数据喂给 QUIC 引擎处理
        _ = quic_c.c.picoquic_incoming_packet(
            self.quic_ctx,
            @constCast(data.ptr),
            data.len,
            @ptrCast(&addr_from),
            @ptrCast(&addr_to),
            0,
            0,
            pico_time,
        );
    }

    /// 准备下一个要发送的包
    /// 返回 null 表示没有更多包需要发送
    pub fn preparePendingPacket(self: *Self, send_buf: []u8) ?PacketInfo {
        const now = quic_c.currentTime();

        var send_len: usize = 0;
        var addr_to: quic_c.c.struct_sockaddr_storage = undefined;
        var addr_from: quic_c.c.struct_sockaddr_storage = undefined;
        var if_index: c_int = 0;
        var log_cid: quic_c.c.picoquic_connection_id_t = undefined;
        var last_cnx: ?*quic_c.c.picoquic_cnx_t = null;
        var send_msg_size: usize = 0;

        const rc = quic_c.c.picoquic_prepare_next_packet_ex(
            self.quic_ctx,
            now,
            send_buf.ptr,
            send_buf.len,
            &send_len,
            &addr_to,
            &addr_from,
            &if_index,
            &log_cid,
            &last_cnx,
            &send_msg_size,
        );

        if (rc != 0 or send_len == 0) return null;

        // picoquic 的 stateless 包路径（Retry / Version Negotiation / Stateless Reset）
        // 不写回 send_msg_size，此时应视为单段发送。在源头归一化，
        // 避免调用方按 0 长度切分导致偏移永不推进的死循环。
        const segment_size = if (send_msg_size == 0) send_len else send_msg_size;

        const dest_addr = net.fromSockAddrStorage(@ptrCast(&addr_to)) catch return null;
        return .{ .data = send_buf[0..send_len], .dest = dest_addr, .segment_size = segment_size };
    }

    /// 获取下一个唤醒时间（微秒）
    pub fn getNextWakeTime(self: *Self) u64 {
        const now = quic_c.currentTime();
        return quic_c.c.picoquic_get_next_wake_time(self.quic_ctx, now);
    }

    /// 获取底层上下文（供高级用法）
    pub fn getContext(self: *Self) quic_c.QuicCtx {
        return self.quic_ctx;
    }

    // =========================================================================
    // 辅助函数
    // =========================================================================

};

/// Endpoint 的 picoquic 回调上下文。
/// 外部传入 Endpoint 时由调用方持有；内部创建时由 Endpoint.deinit 释放。
pub const CallbackContext = struct {
    allocator: std.mem.Allocator,
    on_connection: ?*const fn (?*anyopaque, *Connection) void,
    on_stream_data: ?*const fn (?*anyopaque, *Connection, u64, []const u8, bool) void,
    on_stream_control: ?*const fn (?*anyopaque, *Connection, u64, quic_c.CallbackEvent) void,
    on_datagram: ?*const fn (?*anyopaque, *Connection, []const u8) void,
    on_connection_close: ?*const fn (?*anyopaque, *Connection, quic_c.CallbackEvent) void,
    user_data: ?*anyopaque,
};

// =============================================================================
// C 回调函数
// =============================================================================

fn streamCallback(
    cnx: ?*quic_c.c.picoquic_cnx_t,
    stream_id: u64,
    bytes: [*c]u8,
    length: usize,
    fin_or_event: quic_c.c.picoquic_call_back_event_t,
    callback_ctx: ?*anyopaque,
    stream_ctx: ?*anyopaque,
) callconv(.c) c_int {
    _ = stream_ctx;

    const ctx: *CallbackContext = @ptrCast(@alignCast(callback_ctx orelse return 0));
    const conn_ptr = cnx orelse return 0;
    var connection = Connection.fromRaw(conn_ptr);
    const event: quic_c.CallbackEvent = @enumFromInt(fin_or_event);

    switch (event) {
        .stream_data, .stream_fin => {
            if (ctx.on_stream_data) |callback| {
                const data = if (length > 0) bytes[0..length] else &[_]u8{};
                callback(ctx.user_data, &connection, stream_id, data, event == .stream_fin);
            }
        },
        .stream_reset, .stop_sending => {
            if (ctx.on_stream_control) |callback| {
                callback(ctx.user_data, &connection, stream_id, event);
            }
        },

        // 不可靠通路（设计文档 §6）。`stream_id` 在这个事件下没有含义——datagram
        // 不属于任何流，这也正是它没有队头阻塞的原因。
        .datagram => {
            if (ctx.on_datagram) |callback| {
                const data = if (length > 0) bytes[0..length] else &[_]u8{};
                callback(ctx.user_data, &connection, data);
            }
        },
        // 发出去就不管了：为不可靠通路记这三个事件等于把 QUIC 已经明确放弃的可靠性
        // 又请回来一半，而上层的语义（游戏状态同步）本来就只关心最新那一包。
        .datagram_acked, .datagram_lost, .datagram_spurious => {},

        .ready => {
            // 只在连接完全就绪时触发回调（跳过 almost_ready）
            if (ctx.on_connection) |callback| {
                callback(ctx.user_data, &connection);
            }
        },
        .almost_ready => {
            // 握手几乎完成，但尚未完全就绪，暂不触发回调
        },
        .close, .application_close, .stateless_reset => {
            if (ctx.on_connection_close) |callback| {
                callback(ctx.user_data, &connection, event);
            }
        },
        else => {},
    }

    return 0;
}

/// Connection ID 生成回调函数
///
/// 当 picoquic 需要生成新的 Connection ID 时被调用。
/// 本实现签发固定 12 字节 CID v1，同时编码 node_id 与 worker_id，供跨节点和 reuseport 路由。
fn connectionIdCallback(
    quic: ?quic_c.QuicCtx,
    cnx_id_local: quic_c.ConnectionId,
    cnx_id_remote: quic_c.ConnectionId,
    cnx_id_cb_data: ?*anyopaque,
    cnx_id_returned: [*c]quic_c.ConnectionId,
) callconv(.c) void {
    _ = quic;
    _ = cnx_id_local;
    _ = cnx_id_remote;

    const owner = @as(*Endpoint.CidOwner, @ptrCast(@alignCast(cnx_id_cb_data)));

    var entropy: [6]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&entropy);
    const encoded = cluster_cid.encode(owner.node_id, owner.worker_id, entropy);

    var new_cid: quic_c.ConnectionId = std.mem.zeroes(quic_c.ConnectionId);
    new_cid.id_len = cluster_cid.length;
    @memcpy(new_cid.id[0..cluster_cid.length], &encoded);
    cnx_id_returned.* = new_cid;
}

// 编译时类型检查：确保 connectionIdCallback 符合 ConnectionIdCallbackFn 类型定义
comptime {
    _ = @as(quic_c.ConnectionIdCallbackFn, connectionIdCallback);
}
