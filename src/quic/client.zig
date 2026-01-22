//! QUIC 客户端封装
//!
//! 封装 picoquic 客户端功能。
//!
//! 注意：客户端目前仅支持 picoquic 内置的事件循环。
//! 服务端支持 libxev 高性能事件循环，详见 server.zig。

const std = @import("std");
const quic_c = @import("c.zig");
const Config = @import("config.zig");
const Connection = @import("connection.zig").Connection;

pub const Client = struct {
    /// 底层 QUIC 上下文
    quic_ctx: quic_c.QuicCtx,

    /// 当前连接
    connection: ?Connection = null,

    /// 配置
    config: Config.QuicConfig,

    /// 内存分配器
    allocator: std.mem.Allocator,

    /// 回调上下文
    callback_ctx: *CallbackContext,

    /// 创建 QUIC 客户端
    pub fn init(allocator: std.mem.Allocator, config: Config.QuicConfig) Error!Client {
        // 创建回调上下文
        const callback_ctx = try allocator.create(CallbackContext);
        callback_ctx.* = .{
            .allocator = allocator,
            .on_connected = null,
            .on_stream_data = null,
            .on_disconnected = null,
            .user_data = null,
            .response_buf = null,
            .response_len = 0,
            .finished = false,
            .pending_data = null,
            .data_sent = false,
        };

        // 创建 reset seed
        var reset_seed: [quic_c.RESET_SECRET_SIZE]u8 = undefined;
        std.crypto.random.bytes(&reset_seed);

        const now = quic_c.currentTime();

        // 创建 QUIC 上下文
        const quic_ctx = quic_c.c.picoquic_create(
            1, // max connections (客户端只需要1个)
            null, // cert file (客户端不需要)
            null, // key file
            config.base.root_cert_file orelse null, // root cert
            config.base.alpn.ptr, // alpn
            clientStreamCallback, // callback
            callback_ctx, // callback context
            null, // cnx_id_callback
            null, // cnx_id_callback_ctx
            &reset_seed, // reset seed
            now, // current time
            null, // p_simulated_time
            null, // ticket_file_name
            null, // token_store
            0, // flags
        ) orelse return Error.CreateFailed;

        // 设置拥塞控制算法
        quic_c.c.picoquic_set_default_congestion_algorithm(
            quic_ctx,
            config.base.getCongestionAlgorithm(),
        );

        return .{
            .quic_ctx = quic_ctx,
            .config = config,
            .allocator = allocator,
            .callback_ctx = callback_ctx,
        };
    }

    /// 释放资源
    pub fn deinit(self: *Client) void {
        if (self.connection) |*conn| {
            conn.close();
        }
        quic_c.c.picoquic_free(self.quic_ctx);
        self.allocator.destroy(self.callback_ctx);
    }

    /// 连接到服务器
    pub fn connect(self: *Client, host: [:0]const u8, port: u16, sni: [:0]const u8) Error!*Connection {
        // 解析服务器地址
        var server_addr: quic_c.SockAddrStorage = undefined;
        var is_name: c_int = 0;

        const rc = quic_c.getServerAddress(
            host,
            @intCast(port),
            &server_addr,
            &is_name,
        );
        if (rc != 0) {
            return Error.ResolveFailed;
        }

        const now = quic_c.currentTime();

        // 创建连接
        const cnx = quic_c.c.picoquic_create_cnx(
            self.quic_ctx,
            quic_c.nullConnectionId(),
            quic_c.nullConnectionId(),
            @ptrCast(&server_addr),
            now,
            0, // preferred version
            sni.ptr,
            self.config.base.alpn.ptr,
            1, // client mode
        ) orelse return Error.ConnectFailed;

        // 设置回调
        quic_c.c.picoquic_set_callback(cnx, clientStreamCallback, self.callback_ctx);

        // 启动连接
        const start_rc = quic_c.c.picoquic_start_client_cnx(cnx);
        if (start_rc != 0) {
            return Error.ConnectFailed;
        }

        self.connection = Connection.fromRaw(cnx);
        return &self.connection.?;
    }

    /// 发送数据并等待响应
    pub fn sendAndReceive(
        self: *Client,
        data: []const u8,
        response_buf: []u8,
    ) Error![]u8 {
        _ = self.connection orelse return Error.NotConnected;

        // 设置待发送数据和响应缓冲区
        self.callback_ctx.pending_data = data;
        self.callback_ctx.data_sent = false;
        self.callback_ctx.response_buf = response_buf;
        self.callback_ctx.response_len = 0;
        self.callback_ctx.finished = false;

        // 运行事件循环，握手完成后会在回调中发送数据
        var params = quic_c.c.picoquic_packet_loop_param_t{
            .local_port = 0,
            .local_af = 0,
            .dest_if = 0,
            .socket_buffer_size = 0,
            .do_not_use_gso = 0,
            .extra_socket_required = 0,
            .prefer_extra_socket = 0,
            .simulate_eio = 0,
            .send_length_max = 0,
        };

        const loop_rc = quic_c.c.picoquic_packet_loop_v2(
            self.quic_ctx,
            &params,
            clientLoopCallback,
            self.callback_ctx,
        );

        if (loop_rc != 0 and loop_rc != quic_c.c.PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
            return Error.ReceiveFailed;
        }

        return response_buf[0..self.callback_ctx.response_len];
    }

    /// 设置连接成功回调
    pub fn onConnected(self: *Client, callback: *const fn (*Connection) void) void {
        self.callback_ctx.on_connected = callback;
    }

    /// 设置数据接收回调
    pub fn onStreamData(
        self: *Client,
        callback: *const fn (*Connection, u64, []const u8, bool) void,
    ) void {
        self.callback_ctx.on_stream_data = callback;
    }

    /// 设置断开连接回调
    pub fn onDisconnected(self: *Client, callback: *const fn (*Connection) void) void {
        self.callback_ctx.on_disconnected = callback;
    }

    pub const Error = error{
        CreateFailed,
        ResolveFailed,
        ConnectFailed,
        NotConnected,
        SendFailed,
        ReceiveFailed,
        OutOfMemory,
    };
};

/// 回调上下文
const CallbackContext = struct {
    allocator: std.mem.Allocator,
    on_connected: ?*const fn (*Connection) void,
    on_stream_data: ?*const fn (*Connection, u64, []const u8, bool) void,
    on_disconnected: ?*const fn (*Connection) void,
    user_data: ?*anyopaque,

    // 用于同步请求/响应
    response_buf: ?[]u8,
    response_len: usize,
    finished: bool,

    // 待发送的数据
    pending_data: ?[]const u8,
    data_sent: bool,
};

/// 客户端 Stream 回调
fn clientStreamCallback(
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
            // 复制数据到响应缓冲区
            if (ctx.response_buf) |buf| {
                if (length > 0 and ctx.response_len + length <= buf.len) {
                    @memcpy(buf[ctx.response_len..][0..length], bytes[0..length]);
                    ctx.response_len += length;
                }
            }

            // 调用用户回调
            if (ctx.on_stream_data) |callback| {
                const data = if (length > 0) bytes[0..length] else &[_]u8{};
                callback(&connection, stream_id, data, event == .stream_fin);
            }

            if (event == .stream_fin) {
                ctx.finished = true;
            }
        },
        .ready => {
            // 连接就绪，发送待发送的数据
            if (!ctx.data_sent) {
                if (ctx.pending_data) |data| {
                    // 使用客户端发起的双向流 (stream_id = 0)
                    const rc = quic_c.c.picoquic_add_to_stream(
                        conn_ptr,
                        0, // stream_id
                        data.ptr,
                        data.len,
                        1, // is_fin
                    );
                    if (rc == 0) {
                        ctx.data_sent = true;
                        // 标记 stream 为活跃
                        _ = quic_c.c.picoquic_mark_active_stream(conn_ptr, 0, 1, null);
                    }
                }
            }

            if (ctx.on_connected) |callback| {
                callback(&connection);
            }
        },
        .close, .application_close => {
            ctx.finished = true;
            if (ctx.on_disconnected) |callback| {
                callback(&connection);
            }
        },
        else => {},
    }

    return 0;
}

/// 客户端事件循环回调
fn clientLoopCallback(
    quic: ?*quic_c.c.picoquic_quic_t,
    cb_mode: quic_c.c.picoquic_packet_loop_cb_enum,
    callback_ctx: ?*anyopaque,
    callback_arg: ?*anyopaque,
) callconv(.c) c_int {
    _ = quic;
    _ = callback_arg;

    const ctx: *CallbackContext = @ptrCast(@alignCast(callback_ctx orelse return 0));

    return switch (cb_mode) {
        quic_c.c.picoquic_packet_loop_after_receive,
        quic_c.c.picoquic_packet_loop_after_send,
        => if (ctx.finished) quic_c.c.PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP else 0,
        else => 0,
    };
}
