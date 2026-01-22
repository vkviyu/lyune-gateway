//! Transport I/O 抽象层
//!
//! 提供基于 libxev 的高性能事件循环和 UDP 收发能力。
//! 这是最底层的网络抽象，不知道任何协议细节。

const std = @import("std");
const builtin = @import("builtin");
const xev = @import("xev");
const err_handler = @import("../common/mod.zig").err;
const quic_c = @import("../quic/c.zig");

/// 最大数据包大小
pub const MAX_PACKET_SIZE = 1500;

/// 待发送的数据包结构
pub const Packet = struct {
    data: []const u8,
    dest: std.net.Address,
};

/// 收包回调类型
/// timestamp: picoquic 时间戳（微秒），由 picoquic_current_time() 获取
pub const RecvCallback = *const fn (
    ctx: *anyopaque,
    data: []const u8,
    from_addr: std.net.Address,
    timestamp: u64,
) void;

/// I/O 事件循环
///
/// 纯粹的 UDP I/O 抽象，不包含任何协议逻辑。
/// 上层（如 QUIC Endpoint）通过回调接收数据。
///
/// 需要外部传入 xev.Loop，支持多个组件共享同一事件循环。
pub const IoLoop = struct {
    const Self = @This();

    // libxev 组件
    loop: *xev.Loop,
    socket: std.posix.socket_t,
    timer: xev.Timer,
    async_notify: xev.Async,

    // 状态
    running: bool = false,
    local_addr: std.net.Address,
    allocator: std.mem.Allocator,

    // 回调
    recv_callback: ?RecvCallback = null,
    callback_ctx: ?*anyopaque = null,
    timer_callback: ?*const fn (ctx: *anyopaque) void = null,
    timer_interval_ms: u64 = 1,

    // 定时器状态
    timer_pending: bool = false,
    timer_needs_reschedule: bool = false,

    // Completions
    recv_completion: xev.Completion = undefined,
    timer_completion: xev.Completion = undefined,
    async_completion: xev.Completion = undefined,

    // 缓冲区
    recv_buf: [MAX_PACKET_SIZE]u8 = undefined,
    send_buf: [MAX_PACKET_SIZE]u8 = undefined,

    client_addr: std.posix.sockaddr = undefined,
    client_addr_size: std.posix.socklen_t = undefined,

    pub const Error = error{
        SocketCreateFailed,
        BindFailed,
        TimerInitFailed,
        LoopRunFailed,
    };

    /// 初始化 I/O 循环
    ///
    /// @param allocator 内存分配器
    /// @param port 监听端口（0 表示由系统分配）
    /// @param loop 外部事件循环指针
    pub fn init(allocator: std.mem.Allocator, addr: [4]u8, port: u16, loop: *xev.Loop) Error!Self {
        const socket = std.posix.socket(
            std.posix.AF.INET,
            std.posix.SOCK.DGRAM | std.posix.SOCK.NONBLOCK,
            0,
        ) catch return Error.SocketCreateFailed;

        // SO_REUSEPORT 支持多线程
        std.posix.setsockopt(
            socket,
            std.posix.SOL.SOCKET,
            std.posix.SO.REUSEPORT,
            &std.mem.toBytes(@as(c_int, 1)),
        ) catch |err| {
            std.log.warn("Failed to set SO_REUSEPORT: {}", .{err});
        };

        const local_addr = std.net.Address.initIp4(addr, port);

        std.posix.bind(socket, &local_addr.any, local_addr.getOsSockLen()) catch {
            std.posix.close(socket);
            return Error.BindFailed;
        };

        const timer = xev.Timer.init() catch {
            std.posix.close(socket);
            return Error.TimerInitFailed;
        };

        const async_notify = xev.Async.init() catch {
            timer.deinit();
            std.posix.close(socket);
            return Error.TimerInitFailed;
        };

        return .{
            .loop = loop,
            .socket = socket,
            .timer = timer,
            .async_notify = async_notify,
            .local_addr = local_addr,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.async_notify.deinit();
        self.timer.deinit();
        std.posix.close(self.socket);
        // loop 由外部管理，不在这里释放
    }

    /// 设置收包回调
    pub fn onRecv(self: *Self, ctx: *anyopaque, callback: RecvCallback) void {
        self.callback_ctx = ctx;
        self.recv_callback = callback;
    }

    /// 设置定时器回调
    pub fn onTimer(self: *Self, callback: *const fn (ctx: *anyopaque) void, interval_ms: u64) void {
        self.timer_callback = callback;
        self.timer_interval_ms = interval_ms;
    }

    /// 更新定时器间隔
    /// 如果新间隔比当前等待的更短，通过 Async 立即唤醒事件循环
    pub fn updateTimer(self: *Self, interval_ms: u64) void {
        const old_interval = self.timer_interval_ms;
        self.timer_interval_ms = interval_ms;

        // 如果时间变短了，使用 Async 立即唤醒事件循环
        // 这比取消定时器更安全，避免了复杂的异步取消逻辑
        if (interval_ms < old_interval) {
            self.timer_needs_reschedule = true;
            self.async_notify.notify() catch {};
        }
    }

    /// 发送 UDP 数据包
    pub fn send(self: *Self, data: []const u8, dest: std.net.Address) !void {
        _ = try std.posix.sendto(
            self.socket,
            data,
            0,
            &dest.any,
            dest.getOsSockLen(),
        );
    }

    /// 批量发送 UDP 数据包
    /// 在 Linux 上使用 sendmmsg 优化，在其他平台上回退到循环发送
    pub fn sendBatch(self: *Self, packets: []const Packet) !void {
        if (packets.len == 0) return;

        if (builtin.os.tag == .linux) {
            const linux = std.os.linux;
            // 限制单次系统调用的最大数量，防止栈爆炸
            const BATCH_LIMIT = 32;

            var msgs: [BATCH_LIMIT]linux.mmsghdr = undefined;
            var iovecs: [BATCH_LIMIT]linux.iovec = undefined;
            // 确保 sockaddr_storage 有足够的空间和对齐
            var sockaddrs: [BATCH_LIMIT]std.posix.sockaddr.storage = undefined;

            var i: usize = 0;
            while (i < packets.len) {
                const batch_len = @min(packets.len - i, BATCH_LIMIT);
                const batch = packets[i .. i + batch_len];

                // 1. 准备数据结构
                for (batch, 0..) |pkt, j| {
                    const addr_len = pkt.dest.getOsSockLen();

                    // 安全地复制地址
                    const dest_ptr = @as([*]u8, @ptrCast(&sockaddrs[j]));
                    const src_ptr = @as([*]const u8, @ptrCast(&pkt.dest.any));
                    @memcpy(dest_ptr[0..addr_len], src_ptr[0..addr_len]);

                    iovecs[j] = .{
                        .iov_base = @constCast(pkt.data.ptr),
                        .iov_len = pkt.data.len,
                    };

                    msgs[j] = .{
                        .msg_hdr = .{
                            .msg_name = @ptrCast(&sockaddrs[j]),
                            .msg_namelen = addr_len,
                            .msg_iov = &iovecs[j],
                            .msg_iovlen = 1,
                            .msg_control = null,
                            .msg_controllen = 0,
                            .msg_flags = 0,
                        },
                        .msg_len = 0,
                    };
                }

                // 2. 执行 sendmmsg
                const rc = linux.sendmmsg(
                    self.socket,
                    &msgs,
                    @intCast(batch_len),
                    0,
                );

                // 3. 检查返回值 (Zig 的 raw syscall 返回 usize)
                const errno = std.os.linux.getErrno(rc);

                if (errno != .SUCCESS) {
                    // 如果整个调用直接失败（比如 EBADF, EFAULT 等），尝试回退到逐个发送
                    // 这里的 rc 在出错时是一个很大的 usize，不能直接作为数量
                    // std.log.warn("sendmmsg sys-error: {}, fallback to loop", .{errno});
                    for (batch) |pkt| {
                        try self.send(pkt.data, pkt.dest);
                    }
                    i += batch_len;
                } else {
                    // 4. 处理发送结果
                    // rc 是成功发送的数据包数量
                    const sent_count = rc;

                    if (sent_count > 0) {
                        i += sent_count;
                    }

                    // 如果没发完（sent_count < batch_len），通常是因为 socket 缓冲区满了
                    // 或者遇到了部分错误。
                    // 策略：剩下的包回退到普通 send 尝试一下（普通 send 会处理 errno）
                    // 或者直接进入下一次循环尝试（取决于你的重试策略，这里选择简单回退）
                    if (sent_count < batch_len) {
                        const remaining = batch[sent_count..];
                        for (remaining) |pkt| {
                            try self.send(pkt.data, pkt.dest);
                        }
                        // 手动补齐索引
                        i += remaining.len;
                    }
                }
            }
        } else {
            // 非 Linux 平台回退路径
            for (packets) |pkt| {
                try self.send(pkt.data, pkt.dest);
            }
        }
    }

    /// 获取本地地址
    pub fn getLocalAddr(self: *Self) std.net.Address {
        return self.local_addr;
    }

    pub fn start(self: *Self) void {
        if (self.running) return;
        self.running = true;

        // 启动收包
        self.startRecv();
        // 启动 Async 通知
        self.startAsync();

        // 启动定时器
        self.timer_pending = true;
        self.scheduleTimer(self.timer_interval_ms);

        std.log.info("IoLoop started on port {}", .{self.local_addr.getPort()});
    }

    /// 运行事件循环
    pub fn run(self: *Self) Error!void {
        self.start();
        self.loop.run(.until_done) catch return Error.LoopRunFailed;
        self.running = false;
    }

    /// 停止事件循环
    pub fn stop(self: *Self) void {
        self.running = false;
    }

    // =========================================================================
    // 内部实现
    // =========================================================================

    fn startRecv(self: *Self) void {
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
        self.loop.add(&self.recv_completion);
    }

    fn scheduleTimer(self: *Self, delay_ms: u64) void {
        self.timer_pending = true;
        self.timer.run(self.loop, &self.timer_completion, delay_ms, Self, self, timerCallback);
    }

    fn startAsync(self: *Self) void {
        self.async_notify.wait(self.loop, &self.async_completion, Self, self, asyncCallback);
    }

    fn asyncCallback(
        ud: ?*Self,
        loop: *xev.Loop,
        c: *xev.Completion,
        r: xev.Async.WaitError!void,
    ) xev.CallbackAction {
        _ = loop;
        _ = c;
        _ = r catch {};

        const self = ud orelse return .disarm;
        if (!self.running) return .disarm;

        // Async 被触发说明需要立即处理（如定时器时间缩短了）
        if (self.timer_needs_reschedule) {
            self.timer_needs_reschedule = false;

            // 直接调用 timer_callback 处理紧急事件
            if (self.timer_callback) |cb| {
                if (self.callback_ctx) |ctx| {
                    cb(ctx);
                }
            }
        }

        return if (self.running) .rearm else .disarm;
    }

    fn recvCallback(
        ud: ?*anyopaque,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Result,
    ) xev.CallbackAction {
        _ = loop;

        const self = @as(*Self, @ptrCast(@alignCast(ud orelse return .disarm)));
        if (!self.running) return .disarm;

        const len = result.recvfrom catch |e| {
            err_handler.reportError(.transport, "UDP recv error", e);
            return if (self.running) .rearm else .disarm;
        };

        if (len > 0) {
            if (self.recv_callback) |cb| {
                if (self.callback_ctx) |ctx| {
                    // 使用 picoquic 时间函数，确保时间戳与 QUIC 协议栈一致
                    const timestamp = quic_c.currentTime();
                    var src_sockaddr = completion.op.recvfrom.addr;
                    const from_addr = std.net.Address.initPosix(@alignCast(&src_sockaddr));
                    cb(ctx, self.recv_buf[0..len], from_addr, timestamp);
                }
            }
        }

        return if (self.running) .rearm else .disarm;
    }

    fn timerCallback(
        ud: ?*Self,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        _ = result catch {};

        const self = ud orelse return .disarm;
        if (!self.running) return .disarm;

        // 定时器触发，调用上层回调驱动 QUIC 协议栈
        if (self.timer_callback) |cb| {
            if (self.callback_ctx) |ctx| {
                cb(ctx);
            }
        }

        // 重新调度定时器
        self.scheduleTimer(self.timer_interval_ms);
        return .disarm;
    }
};
