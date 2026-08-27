//! Transport I/O 抽象层
//!
//! 提供基于 libxev 的高性能事件循环和 UDP 收发能力。
//! 这是最底层的网络抽象，不知道任何协议细节。

const std = @import("std");
const builtin = @import("builtin");

const xev = @import("xev");

const foundation = @import("../foundation/mod.zig");
const err_handler = foundation.err;
const net = foundation.net;
const time = foundation.time;
const quic = @import("../quic/mod.zig");
const quic_c = quic.c;

/// 最大数据包大小
pub const MAX_PACKET_SIZE = 1500;

/// 上层传入的待发送数据包结构（不拥有数据所有权）
pub const Packet = struct {
    data: []const u8,
    dest: net.Address,
};

/// 内部队列使用的拥有数据所有权的包结构
const OwnedPacket = struct {
    data: []u8,
    dest: net.Address,

    fn deinit(self: *const OwnedPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

pub const RecvCallback = *const fn (
    ctx: *anyopaque,
    data: []const u8,
    from_addr: net.Address,
    timestamp: u64,
) void;

pub const IoLoop = struct {
    const Self = @This();

    loop: *xev.Loop,
    udp: xev.UDP,
    timer: xev.Timer,

    running: bool = false,
    local_addr: net.Address,
    allocator: std.mem.Allocator,

    recv_callback: ?RecvCallback = null,
    callback_ctx: ?*anyopaque = null,
    timer_callback: ?*const fn (ctx: *anyopaque) void = null,

    // 当前生效的定时间隔
    timer_interval_ms: u64 = 1,

    recv_state: xev.UDP.State = undefined,
    send_state: xev.UDP.State = undefined,

    // Completions
    recv_completion: xev.Completion = undefined,
    send_completion: xev.Completion = undefined,
    timer_completion: xev.Completion = undefined,
    cancel_completion: xev.Completion = undefined,

    recv_buf: [MAX_PACKET_SIZE]u8 = undefined,

    // 使用 Unmanaged 以便手动管理内存
    send_queue: std.ArrayList(OwnedPacket) = .{ .items = &.{}, .capacity = 0 },
    is_sending: bool = false,

    pub const Error = error{
        SocketCreateFailed,
        BindFailed,
        TimerInitFailed,
        LoopRunFailed,
        OutOfMemory,
    };

    pub fn init(allocator: std.mem.Allocator, addr: [4]u8, port: u16, loop: *xev.Loop, socket_fd: ?std.posix.socket_t) Error!Self {
        const local_addr = net.initIp4(addr, port);

        var udp = if (socket_fd) |fd|
            xev.UDP.initFd(fd)
        else
            xev.UDP.init(local_addr) catch return Error.SocketCreateFailed;
        if (socket_fd == null) {
            udp.bind(local_addr) catch {
                closeUdp(udp);
                return Error.BindFailed;
            };
        }

        const timer = xev.Timer.init() catch {
            closeUdp(udp);
            return Error.TimerInitFailed;
        };
        return .{
            .loop = loop,
            .udp = udp,
            .timer = timer,
            // Timer.reset 要求 timer/cancel completion 首次使用前不是 undefined。
            .timer_completion = .{},
            .cancel_completion = .{},
            // 必须回查内核实际绑定的地址：port 传 0 时由内核分配，
            // 接管外部 socket_fd 时配置参数也未必与 fd 实际绑定的地址一致。
            // 该地址会作为本地地址传给 picoquic 参与路径管理，不能是配置里的占位值。
            .local_addr = resolveBoundAddress(udp.fd, local_addr),
            .allocator = allocator,
        };
    }

    /// 用 getsockname 回查 socket 真实绑定地址；失败时退回调用方给出的期望地址。
    fn resolveBoundAddress(fd: std.posix.socket_t, fallback: net.Address) net.Address {
        var storage: std.posix.sockaddr.storage = std.mem.zeroes(std.posix.sockaddr.storage);
        var len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
        if (std.c.getsockname(fd, @ptrCast(&storage), &len) != 0) return fallback;
        return net.fromSockAddrStorage(&storage) catch fallback;
    }

    fn closeUdp(udp: xev.UDP) void {
        if (builtin.os.tag == .windows) {
            std.os.windows.CloseHandle(udp.fd);
        } else {
            _ = std.c.close(udp.fd);
        }
    }

    pub fn deinit(self: *Self) void {
        // 关闭 fd 与销毁 timer 会让在飞的 recv/send/timer completion 立刻完成
        // 并触发回调。这些回调会访问正在析构的 Driver，因此先摘除回调，
        // 让它们退化为 no-op。
        self.recv_callback = null;
        self.timer_callback = null;
        self.callback_ctx = null;

        for (self.send_queue.items) |pkt| {
            pkt.deinit(self.allocator);
        }
        self.send_queue.deinit(self.allocator);

        self.timer.deinit();
        closeUdp(self.udp);
    }

    pub fn getLocalAddr(self: *Self) net.Address {
        return self.local_addr;
    }

    pub fn onRecv(self: *Self, ctx: *anyopaque, callback: RecvCallback) void {
        self.callback_ctx = ctx;
        self.recv_callback = callback;
    }

    pub fn onTimer(self: *Self, callback: *const fn (ctx: *anyopaque) void, interval_ms: u64) void {
        self.timer_callback = callback;
        self.timer_interval_ms = interval_ms;
    }

    pub fn updateTimer(self: *Self, interval_ms: u64) void {
        // 总是更新记录值；timer callback 续期时使用它。
        self.timer_interval_ms = interval_ms;

        // QUIC 的下次唤醒会因应用写入从“空闲 10 秒后”骤然变成“现在”。只改记录值
        // 而保留旧 active timer，会让 ACK、后续发送和响应处理平白卡到旧 deadline。
        // libxev 的 reset 正是为此设计：它安全取消旧 timer 并用同一 completion 重排。
        if (self.timer_completion.state() == .active) {
            self.timer.reset(
                self.loop,
                &self.timer_completion,
                &self.cancel_completion,
                interval_ms,
                Self,
                self,
                timerCallback,
            );
            return;
        }

        self.scheduleTimer(interval_ms);
    }

    // 只有 Linux 下才需要这个回调函数
    // 使用条件编译包裹，防止在 macOS 上出现 "unused function" 编译错误
    const cancelCallback = if (builtin.os.tag == .linux) struct {
        fn cb(
            ud: ?*void,
            l: *xev.Loop,
            c: *xev.Completion,
            r: xev.CancelError!void,
        ) xev.CallbackAction {
            _ = ud;
            _ = l;
            _ = c;
            // 忽略取消结果
            _ = r catch {};
            return .disarm;
        }
    }.cb else undefined;

    pub fn send(self: *Self, data: []const u8, dest: net.Address) !void {
        const pkt = Packet{ .data = data, .dest = dest };
        try self.sendBatch(&.{pkt});
    }

    pub fn sendBatch(self: *Self, packets: []const Packet) !void {
        if (packets.len == 0) return;
        if (self.is_sending or self.send_queue.items.len > 0) {
            try self.enqueuePackets(packets);
            if (!self.is_sending) self.flushSendQueue();
            return;
        }
        var sent_count: usize = 0;
        if (builtin.os.tag == .linux) {
            sent_count = self.trySendBatchLinux(packets);
        } else {
            sent_count = self.trySendBatchFallback(packets);
        }
        if (sent_count < packets.len) {
            const remaining = packets[sent_count..];
            try self.enqueuePackets(remaining);
            self.flushSendQueue();
        }
    }

    fn enqueuePackets(self: *Self, packets: []const Packet) !void {
        try self.send_queue.ensureTotalCapacity(self.allocator, self.send_queue.items.len + packets.len);
        for (packets) |pkt| {
            const data_copy = try self.allocator.dupe(u8, pkt.data);
            self.send_queue.appendAssumeCapacity(.{ .data = data_copy, .dest = pkt.dest });
        }
    }

    fn trySendBatchLinux(self: *Self, packets: []const Packet) usize {
        const linux = std.os.linux;
        const BATCH_LIMIT = 32;
        var total_sent: usize = 0;
        while (total_sent < packets.len) {
            const batch_size = @min(packets.len - total_sent, BATCH_LIMIT);
            const batch = packets[total_sent .. total_sent + batch_size];
            var msgs: [BATCH_LIMIT]linux.mmsghdr = undefined;
            var iovecs: [BATCH_LIMIT]std.posix.iovec = undefined;
            var sockaddrs: [BATCH_LIMIT]std.posix.sockaddr.storage = undefined;
            for (batch, 0..) |pkt, i| {
                sockaddrs[i] = net.toSockAddrStorage(pkt.dest);
                const addr_len = net.sockAddrLen(pkt.dest);
                iovecs[i] = .{ .base = @constCast(pkt.data.ptr), .len = pkt.data.len };
                msgs[i] = .{ .hdr = .{ .name = @ptrCast(&sockaddrs[i]), .namelen = addr_len, .iov = @ptrCast(&iovecs[i]), .iovlen = 1, .control = null, .controllen = 0, .flags = 0 }, .len = 0 };
            }
            const rc = linux.sendmmsg(self.udp.fd, &msgs, @intCast(batch_size), 0);
            if (rc > std.math.maxInt(usize) - 4096) {
                const errno = std.posix.errno(rc);
                if (errno == .AGAIN) return total_sent;
                return total_sent;
            }
            const n = @as(usize, @intCast(rc));
            total_sent += n;
            if (n < batch_size) return total_sent;
        }
        return total_sent;
    }

    fn trySendBatchFallback(self: *Self, packets: []const Packet) usize {
        var total_sent: usize = 0;
        for (packets) |pkt| {
            var dest_storage = net.toSockAddrStorage(pkt.dest);
            const rc = std.c.sendto(
                self.udp.fd,
                pkt.data.ptr,
                pkt.data.len,
                0,
                @ptrCast(&dest_storage),
                net.sockAddrLen(pkt.dest),
            );
            if (rc < 0) {
                const errno = std.c._errno().*;
                if (errno == @intFromEnum(std.c.E.AGAIN)) return total_sent;
                return total_sent;
            }
            total_sent += 1;
        }
        return total_sent;
    }

    fn flushSendQueue(self: *Self) void {
        if (self.is_sending or self.send_queue.items.len == 0) return;
        self.is_sending = true;
        const pkt = self.send_queue.items[0];
        self.udp.write(self.loop, &self.send_completion, &self.send_state, pkt.dest, .{ .slice = pkt.data }, Self, self, sendQueueCallback);
    }

    fn sendQueueCallback(ud: ?*Self, loop: *xev.Loop, c: *xev.Completion, s: *xev.UDP.State, udp: xev.UDP, buf: xev.WriteBuffer, r: xev.WriteError!usize) xev.CallbackAction {
        _ = loop;
        _ = c;
        _ = s;
        _ = udp;
        _ = buf;
        const self = ud.?;
        if (self.send_queue.items.len > 0) {
            const pkt = self.send_queue.orderedRemove(0);
            pkt.deinit(self.allocator);
        }
        if (r) |_| {} else |err| {
            // 将 std.log.warn 替换为 err_handler.reportError
            // 这会将 err 作为 context.raw_error 传递，通常会被 ErrorHandler 打印出来
            err_handler.reportError(.transport, "Async UDP send failed", err);
        }
        self.is_sending = false;
        if (self.send_queue.items.len > 0) self.flushSendQueue();
        return .disarm;
    }

    pub fn start(self: *Self) void {
        if (self.running) return;
        self.running = true;

        self.startRecv();
        self.scheduleTimer(self.timer_interval_ms);

        // 将 std.log.info 替换为 err_handler.report
        // 构造消息字符串
        var msg_buf: [64]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "IoLoop started on port {}", .{self.local_addr.getPort()}) catch "IoLoop started";

        // 手动构造 Context 以支持 Severity.info
        err_handler.report(.{
            .source = .transport,
            .severity = .info,
            .message = msg,
            .timestamp = time.timestampMicros(),
        });
    }

    pub fn stop(self: *Self) void {
        if (!self.running) return;
        self.running = false;
    }

    fn startRecv(self: *Self) void {
        self.udp.read(
            self.loop,
            &self.recv_completion,
            &self.recv_state,
            .{ .slice = &self.recv_buf },
            Self,
            self,
            recvCallback,
        );
    }

    fn recvCallback(
        ud: ?*Self,
        loop: *xev.Loop,
        c: *xev.Completion,
        s: *xev.UDP.State,
        addr: net.Address,
        udp: xev.UDP,
        buf: xev.ReadBuffer,
        r: xev.ReadError!usize,
    ) xev.CallbackAction {
        _ = loop;
        _ = c;
        _ = s;
        _ = udp;
        _ = buf;
        const self = ud.?;
        if (!self.running) return .disarm;

        const len = r catch |e| {
            if (e != error.WouldBlock and e != error.OperationCanceled and e != error.EOF) {
                err_handler.reportError(.transport, "UDP recv error", e);
            }
            return if (self.running) .rearm else .disarm;
        };

        if (len > 0) {
            if (self.recv_callback) |cb| {
                if (self.callback_ctx) |ctx| {
                    const timestamp = quic_c.currentTime();
                    cb(ctx, self.recv_buf[0..len], addr, timestamp);
                }
            }
        }

        return if (self.running) .rearm else .disarm;
    }

    fn scheduleTimer(self: *Self, delay_ms: u64) void {
        self.timer.run(self.loop, &self.timer_completion, delay_ms, Self, self, timerCallback);
    }

    fn timerCallback(
        ud: ?*Self,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;

        const self = ud orelse return .disarm;
        if (!self.running) return .disarm;

        _ = result catch {};

        if (self.timer_callback) |cb| {
            if (self.callback_ctx) |ctx| {
                cb(ctx);
            }
        }

        // cb(ctx) 内部会通过 processQuicEvents → updateTimer → scheduleTimer 重新注册 timer
        // 只有当回调没有重新调度时（completion 仍为 .dead），才需要手动重新调度
        // 避免同一个 timer_completion 被双重推入 submissions 队列
        if (self.timer_completion.state() != .active) {
            self.scheduleTimer(self.timer_interval_ms);
        }

        return .disarm;
    }
};
