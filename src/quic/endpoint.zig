//! QUIC 端点封装
//!
//! 负责管理 picoquic 上下文 (picoquic_quic_t) 的生命周期。它是 Server 和 Client 的底层基类。

const std = @import("std");

const foundation = @import("../foundation/mod.zig");
const cluster_cid = @import("../io/cid.zig");
const net = foundation.net;
const Config = @import("config.zig");
const Connection = @import("connection.zig").Connection;
const quic_c = @import("c.zig");

pub const PacketInfo = struct {
    data: []const u8,
    dest: net.Address,
    segment_size: usize, // 新增
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

    /// 回调上下文
    callback_ctx: *CallbackContext,

    /// 线程 ID（用于 CID 生成）
    thread_id: u8,
    thread_id_ptr: *u8,

    // 【新增】专门存转换格式后的 ALPN 数据，防止内存泄露
    alpn_buffer: []u8,

    pub const Error = error{
        CreateFailed,
        OutOfMemory,
    };

    /// 初始化 QUIC 端点
    /// callback_ctx_opt: 可选的回调上下文，如果为 null 则内部创建
    pub fn init(
        allocator: std.mem.Allocator,
        config: Config.QUICConfig,
        thread_id: u8,
        callback_ctx_opt: ?*CallbackContext,
    ) Error!Self {
        // 使用传入的回调上下文，或者创建新的
        const callback_ctx = callback_ctx_opt orelse blk: {
            const ctx = allocator.create(CallbackContext) catch return Error.OutOfMemory;
            ctx.* = .{
                .allocator = allocator,
                .on_connection = null,
                .on_stream_data = null,
                .on_connection_close = null,
                .user_data = null,
            };
            break :blk ctx;
        };

        // 创建 reset seed
        var reset_seed: [quic_c.RESET_SECRET_SIZE]u8 = undefined;
        std.Io.Threaded.global_single_threaded.io().random(&reset_seed);

        const now = quic_c.currentTime();

        // thread_id 指针
        const thread_id_ptr = allocator.create(u8) catch return Error.OutOfMemory;
        errdefer allocator.destroy(thread_id_ptr);
        thread_id_ptr.* = thread_id;

        const raw_alpn = config.base.alpn;
        const alpn_len = raw_alpn.len;
        if (alpn_len > 255) return Error.CreateFailed;

        const alpn_buffer = try allocator.alloc(u8, alpn_len + 2);
        errdefer allocator.free(alpn_buffer);

        alpn_buffer[0] = @intCast(alpn_len); // 第1个字节存长度
        @memcpy(alpn_buffer[1 .. 1 + alpn_len], raw_alpn); // 后面存内容
        alpn_buffer[1 + alpn_len] = 0; // 最后补个0安全点

        // 创建 picoquic 上下文
        const quic_ctx = quic_c.c.picoquic_create(
            config.base.max_connections,
            if (config.cert_file) |s| s.ptr else null,
            if (config.key_file) |s| s.ptr else null,
            if (config.base.root_cert_file) |s| s.ptr else null,
            alpn_buffer.ptr,
            streamCallback,
            callback_ctx,
            connectionIdCallback,
            thread_id_ptr,
            &reset_seed,
            now,
            null,
            null,
            null,
            0,
        ) orelse return Error.CreateFailed;

        // 设置拥塞控制算法
        quic_c.c.picoquic_set_default_congestion_algorithm(
            quic_ctx,
            config.base.getCongestionAlgorithm(),
        );

        // 配置 Transport Parameters
        var tp: quic_c.c.picoquic_tp_t = std.mem.zeroes(quic_c.c.picoquic_tp_t);
        tp.initial_max_data = config.base.initial_max_data;
        tp.initial_max_stream_data_bidi_local = config.base.initial_max_stream_data_bidi_local;
        tp.initial_max_stream_data_bidi_remote = config.base.initial_max_stream_data_bidi_remote;
        tp.initial_max_stream_data_uni = config.base.initial_max_stream_data_bidi_local; // 复用 bidi_local 值
        tp.initial_max_stream_id_bidir = config.base.initial_max_streams_bidi * 4; // Stream ID 编码规则
        tp.initial_max_stream_id_unidir = config.base.initial_max_streams_uni * 4;
        tp.max_idle_timeout = config.base.idle_timeout_ms;
        tp.max_packet_size = quic_c.MAX_PACKET_SIZE;
        // RFC 9000 要求 active_connection_id_limit 至少为 2
        tp.active_connection_id_limit = 8;
        _ = quic_c.c.picoquic_set_default_tp(quic_ctx, &tp);

        // 设置空闲超时
        quic_c.c.picoquic_set_default_idle_timeout(quic_ctx, config.base.idle_timeout_ms);

        // 如果禁用证书验证（用于自签名证书的开发环境）
        if (!config.base.verify_cert) {
            quic_c.c.picoquic_set_null_verifier(quic_ctx);
        }

        return .{
            .quic_ctx = quic_ctx,
            .config = config,
            .allocator = allocator,
            .callback_ctx = callback_ctx,
            .thread_id = thread_id,
            .thread_id_ptr = thread_id_ptr,
            .alpn_buffer = alpn_buffer, // 【别忘了存起来】
        };
    }

    pub fn deinit(self: *Self) void {
        quic_c.c.picoquic_free(self.quic_ctx);
        self.allocator.destroy(self.callback_ctx);
        self.allocator.destroy(self.thread_id_ptr);
        self.allocator.free(self.alpn_buffer);
    }

    /// 设置连接回调（QUIC 握手完成，连接建立时）
    pub fn onConnection(self: *Self, callback: *const fn (?*anyopaque, *Connection) void) void {
        self.callback_ctx.on_connection = callback;
    }

    /// 设置数据接收回调（收到客户端发送的数据时）
    pub fn onStreamData(self: *Self, callback: *const fn (?*anyopaque, *Connection, u64, []const u8, bool) void) void {
        self.callback_ctx.on_stream_data = callback;
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

        const dest_addr = net.fromSockAddrStorage(@ptrCast(&addr_to)) catch return null;
        return .{ .data = send_buf[0..send_len], .dest = dest_addr, .segment_size = send_msg_size };
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

/// 回调上下文
pub const CallbackContext = struct {
    allocator: std.mem.Allocator,
    on_connection: ?*const fn (?*anyopaque, *Connection) void,
    on_stream_data: ?*const fn (?*anyopaque, *Connection, u64, []const u8, bool) void,
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
/// 本实现将线程 ID 编码到 CID 的第一个字节，用于支持无锁负载均衡路由。
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

    const thread_id_ptr = @as(*u8, @ptrCast(@alignCast(cnx_id_cb_data)));
    const thread_id = thread_id_ptr.*;

    var entropy: [4]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&entropy);
    const encoded = cluster_cid.encode(thread_id, entropy);

    var new_cid: quic_c.ConnectionId = std.mem.zeroes(quic_c.ConnectionId);
    new_cid.id_len = cluster_cid.length;
    @memcpy(new_cid.id[0..cluster_cid.length], &encoded);
    cnx_id_returned.* = new_cid;
}

// 编译时类型检查：确保 connectionIdCallback 符合 ConnectionIdCallbackFn 类型定义
comptime {
    _ = @as(quic_c.ConnectionIdCallbackFn, connectionIdCallback);
}
