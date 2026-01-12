//! QUIC 事件循环封装
//!
//! 使用 libxev 高性能事件循环替代 picoquic 内置的 packet_loop。
//! 支持 Linux (io_uring), macOS (kqueue), Windows (IOCP)。

const std = @import("std");
const xev = @import("xev");
const quic_c = @import("c.zig");
const Connection = @import("connection.zig").Connection;

/// 最大数据包大小
const MAX_PACKET_SIZE = 1500;

/// 每次循环最大发送包数
const MAX_SEND_PER_LOOP = 10;

/// QUIC 事件循环
///
/// 封装 libxev 与 picoquic 的集成，提供高性能的事件驱动模型。
pub fn QuicEventLoop(comptime CallbackContext: type) type {
    return struct {
        const Self = @This();

        // =====================================================================
        // libxev 组件
        // =====================================================================

        /// libxev 事件循环
        loop: xev.Loop,

        /// UDP socket
        socket: std.posix.socket_t,

        /// 定时器
        timer: xev.Timer,

        // =====================================================================
        // picoquic 组件
        // =====================================================================

        /// QUIC 上下文
        quic_ctx: quic_c.QuicCtx,

        /// 回调上下文
        callback_ctx: *CallbackContext,

        // =====================================================================
        // 状态
        // =====================================================================

        /// 是否运行中
        running: bool,

        /// 本地地址
        local_addr: std.net.Address,

        /// 内存分配器
        allocator: std.mem.Allocator,

        // =====================================================================
        // Completions（必须保持稳定地址）
        // =====================================================================

        recv_completion: xev.Completion,
        timer_completion: xev.Completion,
        timer_cancel_completion: xev.Completion,

        // =====================================================================
        // 缓冲区
        // =====================================================================

        recv_buf: [MAX_PACKET_SIZE]u8,
        send_buf: [MAX_PACKET_SIZE]u8,

        // =====================================================================
        // 公共 API
        // =====================================================================

        /// 初始化事件循环
        pub fn init(
            allocator: std.mem.Allocator,
            quic_ctx: quic_c.QuicCtx,
            port: u16,
            callback_ctx: *CallbackContext,
        ) Error!Self {
            // 创建 libxev 事件循环
            const loop = xev.Loop.init(.{}) catch return Error.LoopInitFailed;

            // 创建 UDP socket
            const socket = std.posix.socket(
                std.posix.AF.INET,
                std.posix.SOCK.DGRAM | std.posix.SOCK.NONBLOCK,
                0,
            ) catch return Error.SocketCreateFailed;

            // 绑定地址
            const local_addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
            std.posix.bind(socket, &local_addr.any, local_addr.getOsSockLen()) catch {
                std.posix.close(socket);
                return Error.BindFailed;
            };

            // 创建定时器
            const timer = xev.Timer.init() catch {
                std.posix.close(socket);
                return Error.TimerInitFailed;
            };

            return .{
                .loop = loop,
                .socket = socket,
                .timer = timer,
                .quic_ctx = quic_ctx,
                .callback_ctx = callback_ctx,
                .running = false,
                .local_addr = local_addr,
                .allocator = allocator,
                .recv_completion = undefined,
                .timer_completion = undefined,
                .timer_cancel_completion = undefined,
                .recv_buf = undefined,
                .send_buf = undefined,
            };
        }

        /// 释放资源
        pub fn deinit(self: *Self) void {
            self.timer.deinit();
            std.posix.close(self.socket);
            self.loop.deinit();
        }

        /// 运行事件循环
        pub fn run(self: *Self) Error!void {
            self.running = true;

            // 启动 UDP 接收
            self.startRecv();

            // 启动定时器（初始延迟 1ms）
            self.scheduleTimer(1);

            std.log.info("QUIC event loop started with libxev (port {})", .{self.local_addr.getPort()});

            // 运行事件循环
            self.loop.run(.until_done) catch return Error.LoopRunFailed;

            self.running = false;
        }

        /// 停止事件循环
        pub fn stop(self: *Self) void {
            self.running = false;
        }

        // =====================================================================
        // 内部实现
        // =====================================================================

        /// 启动 UDP 接收
        fn startRecv(self: *Self) void {
            // 先配置 completion
            self.recv_completion = .{
                .op = .{
                    .recvfrom = .{
                        .fd = self.socket,
                        .buffer = .{ .slice = &self.recv_buf },
                    },
                },
                .userdata = self,
                .callback = recvCallback,
            };
            // 再添加到事件循环
            self.loop.add(&self.recv_completion);
        }

        /// 调度定时器
        fn scheduleTimer(self: *Self, delay_ms: u64) void {
            // timer.run 的 signature 是：
            // run(loop, c, timeout_ms, Userdata, userdata, callback)
            // userdata 是 ?*Userdata，其中 Userdata 是 Self
            // 所以 userdata 是 ?*Self
            // 传入 self 作为 userdata
            self.timer.run(
                &self.loop,
                &self.timer_completion,
                delay_ms,
                Self,
                self,
                timerCallback,
            );
        }

        /// UDP 接收回调
        fn recvCallback(
            ud: ?*anyopaque,
            loop: *xev.Loop,
            completion: *xev.Completion,
            result: xev.Result,
        ) xev.CallbackAction {
            _ = loop;
            _ = completion;

            const self_ptr = @as(*Self, @ptrCast(@alignCast(ud orelse return .disarm)));

            if (!self_ptr.running) {
                return .disarm;
            }

            // 处理接收结果 - recvfrom 直接返回读取的字节数
            const len = result.recvfrom catch |err| {
                std.log.err("UDP recv error: {}", .{err});
                return if (self_ptr.running) .rearm else .disarm;
            };

            if (len > 0) {
                // 注意：这里需要从 recv_buf 中获取源地址
                // 由于 libxev 底层 API 不直接提供源地址，我们使用本地地址
                // 实际应用中可能需要使用 libxev UDP 高层 API
                self_ptr.processIncomingPacket(len, self_ptr.local_addr);
            }

            // 发送待发送的包
            self_ptr.sendPendingPackets();

            // 更新定时器
            self_ptr.updateTimer();

            return if (self_ptr.running) .rearm else .disarm;
        }

        /// 定时器回调
        fn timerCallback(
            ud: ?*Self,
            loop: *xev.Loop,
            completion: *xev.Completion,
            result: xev.Timer.RunError!void,
        ) xev.CallbackAction {
            _ = loop;
            _ = completion;
            _ = result catch {};

            // ud 是 ?*Self
            const self_ptr = ud orelse return .disarm;

            if (!self_ptr.running) {
                return .disarm;
            }

            // 发送待发送的包
            self_ptr.sendPendingPackets();

            // 重新调度定时器
            self_ptr.updateTimer();

            return .disarm; // 定时器需要重新设置
        }

        /// 处理收到的数据包
        fn processIncomingPacket(self: *Self, len: usize, from_addr: std.net.Address) void {
            const now = quic_c.currentTime();

            // 构造源地址
            var addr_from: quic_c.c.struct_sockaddr_storage = std.mem.zeroes(quic_c.c.struct_sockaddr_storage);
            const src_bytes = std.mem.asBytes(&from_addr.any);
            const dst_bytes = std.mem.asBytes(&addr_from);
            @memcpy(dst_bytes[0..src_bytes.len], src_bytes);

            // 构造目标地址（本地地址）
            var addr_to: quic_c.c.struct_sockaddr_storage = std.mem.zeroes(quic_c.c.struct_sockaddr_storage);
            const local_bytes = std.mem.asBytes(&self.local_addr.any);
            const to_bytes = std.mem.asBytes(&addr_to);
            @memcpy(to_bytes[0..local_bytes.len], local_bytes);

            // 调用 picoquic 处理收到的包
            _ = quic_c.c.picoquic_incoming_packet(
                self.quic_ctx,
                &self.recv_buf,
                len,
                @ptrCast(&addr_from),
                @ptrCast(&addr_to),
                0, // if_index_to
                0, // received_ecn
                now,
            );
        }

        /// 发送待发送的数据包
        fn sendPendingPackets(self: *Self) void {
            const now = quic_c.currentTime();
            var packets_sent: usize = 0;

            while (packets_sent < MAX_SEND_PER_LOOP) {
                var send_len: usize = 0;
                var addr_to: quic_c.c.struct_sockaddr_storage = undefined;
                var addr_from: quic_c.c.struct_sockaddr_storage = undefined;
                var if_index: c_int = 0;
                var log_cid: quic_c.c.picoquic_connection_id_t = undefined;
                var last_cnx: ?*quic_c.c.picoquic_cnx_t = null;

                const rc = quic_c.c.picoquic_prepare_next_packet(
                    self.quic_ctx,
                    now,
                    &self.send_buf,
                    self.send_buf.len,
                    &send_len,
                    &addr_to,
                    &addr_from,
                    &if_index,
                    &log_cid,
                    &last_cnx,
                );

                if (rc != 0 or send_len == 0) {
                    break;
                }

                // 转换目标地址
                const dest_addr = sockaddrStorageToAddress(&addr_to) catch {
                    continue;
                };

                // 发送数据包
                _ = std.posix.sendto(
                    self.socket,
                    self.send_buf[0..send_len],
                    0,
                    &dest_addr.any,
                    dest_addr.getOsSockLen(),
                ) catch |err| {
                    std.log.err("UDP send error: {}", .{err});
                    break;
                };

                packets_sent += 1;
            }
        }

        /// 更新定时器
        fn updateTimer(self: *Self) void {
            if (!self.running) return;

            const now = quic_c.currentTime();
            const wake_time = quic_c.c.picoquic_get_next_wake_time(self.quic_ctx, now);

            // 计算延迟（微秒转毫秒）
            var delay_ms: u64 = 1; // 最小 1ms
            if (wake_time != std.math.maxInt(u64) and wake_time > now) {
                delay_ms = (wake_time - now) / 1000;
                if (delay_ms == 0) delay_ms = 1;
                if (delay_ms > 1000) delay_ms = 1000; // 最大 1 秒
            }

            // 重新调度定时器
            self.scheduleTimer(delay_ms);
        }

        /// 将 sockaddr_storage 转换为 std.net.Address
        fn sockaddrStorageToAddress(storage: *const quic_c.c.struct_sockaddr_storage) !std.net.Address {
            // ss_family 在 macOS 上是 u8，需要转成 u16 来比较
            const family = @as(u16, @intCast(storage.ss_family));
            if (family == std.posix.AF.INET) {
                const sockaddr_in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(storage));
                // 构造 IPv4 地址 (macOS 上 addr 是 u32 类型的网络字节序)
                // 使用 @constCast 来获取可变指针
                const addr = std.net.Address.initIp4(
                    @as(*[4]u8, @ptrCast(@constCast(&sockaddr_in.addr)))[0..4].*,
                    sockaddr_in.port,
                );
                return addr;
            } else if (family == std.posix.AF.INET6) {
                const sockaddr_in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(storage));
                // 构造 IPv6 地址
                const addr = std.net.Address.initIp6(
                    @constCast(&sockaddr_in6.addr).*,
                    sockaddr_in6.port,
                    0,
                    0,
                );
                return addr;
            }
            return error.UnsupportedAddressFamily;
        }

        pub const Error = error{
            LoopInitFailed,
            SocketCreateFailed,
            BindFailed,
            TimerInitFailed,
            LoopRunFailed,
        };
    };
}
