//! QUIC 服务端封装
//!
//! 封装 picoquic 服务端功能，提供简洁的 Zig API。
//!
//! 支持两种事件循环模式：
//! - `run()`: 使用 picoquic 内置的事件循环（基于 select/poll）
//! - `runWithXev()`: 使用 libxev 高性能事件循环（io_uring/kqueue/IOCP）

const std = @import("std");
const quic_c = @import("c.zig");
const Config = @import("config.zig");
const Connection = @import("connection.zig").Connection;
const Stream = @import("stream.zig").Stream;
const event_loop = @import("event_loop.zig");

pub const Server = struct {
    /// 底层 QUIC 上下文。存储 picoquic 的上下文指针，这是整个服务端的核心。
    quic_ctx: quic_c.QuicCtx,

    /// 配置。保存服务端核心（端口、证书路径等）。
    config: Config.ServerConfig,

    /// 内存分配器
    allocator: std.mem.Allocator,

    /// 回调上下文。指向回调上下文的指针，用于在 C 回调中访问 Zig 数据。
    callback_ctx: *CallbackContext,

    /// 是否运行中。服务器运行状态标志，用于控制事件循环退出。
    running: bool = false,

    /// 创建 QUIC 服务端
    pub fn init(allocator: std.mem.Allocator, config: Config.ServerConfig) Error!Server {
        // 创建回调上下文
        // 在堆上分配 CallbackContext
        const callback_ctx = try allocator.create(CallbackContext);
        // 初始化回调上下文，所有回调都设为 null。callback_ctx.* 是解引用指针。
        callback_ctx.* = .{
            .allocator = allocator,
            .on_connection = null,
            .on_stream_data = null,
            .on_connection_close = null,
            .user_data = null,
        };

        // 创建 reset seed
        // 生成随机的重置密钥种子。undefined 表示不初始化（之后会被随机数覆盖）。
        // 这个种子用于生成无状态重置令牌。
        var reset_seed: [quic_c.RESET_SECRET_SIZE]u8 = undefined;
        std.crypto.random.bytes(&reset_seed);

        // 获取当前时间。获取 picoquic 时间戳，初始化时需要。
        const now = quic_c.currentTime();

        // 创建 QUIC 上下文
        const quic_ctx = quic_c.c.picoquic_create(
            // 最大连接数，来自配置
            config.base.max_connections, // max connections
            config.cert_file.ptr, // cert file
            config.key_file.ptr, // key file
            null, // cert root file
            config.base.alpn.ptr, // alpn
            streamCallback, // callback
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
    pub fn deinit(self: *Server) void {
        quic_c.c.picoquic_free(self.quic_ctx);
        self.allocator.destroy(self.callback_ctx);
    }

    /// 设置连接回调
    pub fn onConnection(self: *Server, callback: *const fn (*Connection) void) void {
        self.callback_ctx.on_connection = callback;
    }

    /// 设置数据接收回调
    pub fn onStreamData(
        self: *Server,
        callback: *const fn (*Connection, u64, []const u8, bool) void,
    ) void {
        self.callback_ctx.on_stream_data = callback;
    }

    /// 设置连接关闭回调
    pub fn onConnectionClose(self: *Server, callback: *const fn (*Connection) void) void {
        self.callback_ctx.on_connection_close = callback;
    }

    /// 设置用户数据
    pub fn setUserData(self: *Server, data: *anyopaque) void {
        self.callback_ctx.user_data = data;
    }

    /// 运行服务器（使用 picoquic 内置的事件循环）
    ///
    /// 基于 select/poll，适合简单场景或调试。
    pub fn run(self: *Server) Error!void {
        self.running = true;

        var params = quic_c.c.picoquic_packet_loop_param_t{
            .local_port = self.config.port,
            .local_af = 0, // AF_UNSPEC, 支持 IPv4 和 IPv6
            .dest_if = 0,
            .socket_buffer_size = 0,
            .do_not_use_gso = 0,
            .extra_socket_required = 0,
            .prefer_extra_socket = 0,
            .simulate_eio = 0,
            .send_length_max = 0,
        };

        const rc = quic_c.c.picoquic_packet_loop_v2(
            self.quic_ctx,
            &params,
            loopCallback,
            self.callback_ctx,
        );

        self.running = false;

        if (rc != 0 and rc != quic_c.c.PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
            return Error.PacketLoopFailed;
        }
    }

    /// 运行服务器（使用 libxev 高性能事件循环）
    ///
    /// 根据平台自动选择最优后端：
    /// - Linux: io_uring
    /// - macOS: kqueue
    /// - Windows: IOCP
    ///
    /// 推荐在生产环境使用此方法以获得最佳性能。
    pub fn runWithXev(self: *Server) Error!void {
        self.running = true;

        // 创建事件循环
        var ev_loop = event_loop.QuicEventLoop(CallbackContext).init(
            self.allocator,
            self.quic_ctx,
            self.config.port,
            self.callback_ctx,
        ) catch |err| {
            std.log.err("Failed to init event loop: {}", .{err});
            return Error.PacketLoopFailed;
        };
        defer ev_loop.deinit();

        std.log.info("Starting QUIC server with libxev on port {}...", .{self.config.port});

        // 运行事件循环
        ev_loop.run() catch |err| {
            std.log.err("Event loop error: {}", .{err});
            self.running = false;
            return Error.PacketLoopFailed;
        };

        self.running = false;
    }

    /// 停止服务器
    pub fn stop(self: *Server) void {
        self.running = false;
        // picoquic 会在下一次循环检测到 running = false 时退出
    }

    pub const Error = error{
        CreateFailed,
        BindFailed,
        PacketLoopFailed,
        OutOfMemory,
    };
};

/// 回调上下文
const CallbackContext = struct {
    allocator: std.mem.Allocator,
    on_connection: ?*const fn (*Connection) void,
    on_stream_data: ?*const fn (*Connection, u64, []const u8, bool) void,
    on_connection_close: ?*const fn (*Connection) void,
    user_data: ?*anyopaque,
};

/// Stream 回调函数（C ABI）
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

    // 把 void* 转换回 *CallbackContext
    // orelse return 0，如果是 null，直接返回
    // @ptrCast 类型转换，@alignCast 对齐转换（C 指针可能对齐不同）
    const ctx: *CallbackContext = @ptrCast(@alignCast(callback_ctx orelse return 0));
    // 检查连接指针是否为空
    const conn_ptr = cnx orelse return 0;

    // 创建临时 Connection 包装，把 C 指针包装成 Zig 的 Connection 结构。
    var connection = Connection.fromRaw(conn_ptr);

    // 把 C 整数转换成 Zig 枚举。
    const event: quic_c.CallbackEvent = @enumFromInt(fin_or_event);

    // 处理收到数据事件。
    switch (event) {
        .stream_data, .stream_fin => {
            // 处理收到数据的事件，如果设置了回调，调用它
            if (ctx.on_stream_data) |callback| {
                // bytes[0..length]：把 C 指针转换为 Zig 切片，&[_]u8{}：空切片（当 length 为 0 时）
                const data = if (length > 0) bytes[0..length] else &[_]u8{};
                const is_fin = event == .stream_fin;
                callback(&connection, stream_id, data, is_fin);
            }
        },
        // 连接就绪时调用连接回调
        .ready, .almost_ready => {
            if (ctx.on_connection) |callback| {
                callback(&connection);
            }
        },
        // 连接关闭时调用关闭回调
        .close, .application_close, .stateless_reset => {
            if (ctx.on_connection_close) |callback| {
                callback(&connection);
            }
        },
        .prepare_to_send => {
            // 准备发送，通常不需要处理
        },
        // 其他事件忽略，包括 _ 未知值。
        else => {},
    }

    return 0;
}

/// 事件循环回调（C ABI）
fn loopCallback(
    quic: ?*quic_c.c.picoquic_quic_t,
    cb_mode: quic_c.c.picoquic_packet_loop_cb_enum,
    callback_ctx: ?*anyopaque,
    callback_arg: ?*anyopaque,
) callconv(.c) c_int {
    _ = quic;
    _ = callback_ctx;
    _ = callback_arg;

    // 事件循环的回调，在不同阶段被调用
    return switch (cb_mode) {
        // 服务器准备就绪时打印日志。blk：标签块，允许在 switch 分支中执行多条语句并返回值。
        quic_c.c.picoquic_packet_loop_ready => blk: {
            std.log.info("QUIC server ready", .{});
            break :blk 0;
        },
        // 收包后的回调，返回 0 继续循环。
        quic_c.c.picoquic_packet_loop_after_receive => 0,
        quic_c.c.picoquic_packet_loop_after_send => 0,
        else => 0,
    };
}
