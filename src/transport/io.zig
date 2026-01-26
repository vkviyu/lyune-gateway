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

/// 上层传入的待发送数据包结构（不拥有数据所有权）
pub const Packet = struct {
    data: []const u8,
    dest: std.net.Address,
};

/// 内部队列使用的拥有数据所有权的包结构
const OwnedPacket = struct {
    data: []u8,
    dest: std.net.Address,

    fn deinit(self: *const OwnedPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

pub const RecvCallback = *const fn (
    ctx: *anyopaque,
    data: []const u8,
    from_addr: std.net.Address,
    timestamp: u64,
) void;

pub const IoLoop = struct {
    const Self = @This();

    loop: *xev.Loop,
    udp: xev.UDP,
    timer: xev.Timer,
    async_notify: xev.Async,

    running: bool = false,
    local_addr: std.net.Address,
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
    async_completion: xev.Completion = undefined,
    cancel_completion: xev.Completion = undefined,

    recv_buf: [MAX_PACKET_SIZE]u8 = undefined,

    // 使用 Unmanaged 以便手动管理内存
    send_queue: std.ArrayListUnmanaged(OwnedPacket) = .{},
    is_sending: bool = false,

    pub const Error = error{
        SocketCreateFailed,
        BindFailed,
        TimerInitFailed,
        LoopRunFailed,
        OutOfMemory,
    };

    pub fn init(allocator: std.mem.Allocator, addr: [4]u8, port: u16, loop: *xev.Loop) Error!Self {
        const local_addr = std.net.Address.initIp4(addr, port);

        const socket_fd = std.posix.socket(
            std.posix.AF.INET,
            std.posix.SOCK.DGRAM | std.posix.SOCK.NONBLOCK,
            0,
        ) catch return Error.SocketCreateFailed;

        std.posix.setsockopt(
            socket_fd,
            std.posix.SOL.SOCKET,
            std.posix.SO.REUSEPORT,
            &std.mem.toBytes(@as(c_int, 1)),
        ) catch |err| {
            err_handler.reportError(.transport, "setsockopt reuseport failed", err);
        };

        std.posix.bind(socket_fd, &local_addr.any, local_addr.getOsSockLen()) catch {
            std.posix.close(socket_fd);
            return Error.BindFailed;
        };

        const udp = xev.UDP.initFd(socket_fd);
        const timer = xev.Timer.init() catch {
            std.posix.close(socket_fd);
            return Error.TimerInitFailed;
        };
        const async_notify = xev.Async.init() catch {
            timer.deinit();
            std.posix.close(socket_fd);
            return Error.TimerInitFailed;
        };

        return .{
            .loop = loop,
            .udp = udp,
            .timer = timer,
            .async_notify = async_notify,
            .local_addr = local_addr,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.send_queue.items) |pkt| {
            pkt.deinit(self.allocator);
        }
        self.send_queue.deinit(self.allocator);

        self.async_notify.deinit();
        self.timer.deinit();
        if (builtin.os.tag == .windows) {
            std.os.windows.CloseHandle(self.udp.fd);
        } else {
            std.posix.close(self.udp.fd);
        }
    }

    pub fn getLocalAddr(self: *Self) std.net.Address {
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
        if (interval_ms < self.timer_interval_ms) {
            self.timer_interval_ms = interval_ms;

            self.loop.cancel(&self.cancel_completion, &self.timer_completion, void, null, cancelCallback);
        } else {
            self.timer_interval_ms = interval_ms;
        }
    }

    // <--- 修复：函数签名必须严格匹配
    // 1. ud: ?*void (因为 loop.cancel 传入了 void 类型)
    // 2. r: xev.CancelError!void (libxev 将底层 Result 转换为了具体的错误集)
    fn cancelCallback(
        ud: ?*void,
        l: *xev.Loop,
        c: *xev.Completion,
        r: xev.CancelError!void,
    ) xev.CallbackAction {
        _ = ud;
        _ = l;
        _ = c;
        // 忽略取消结果，如果是 NotFound 说明定时器刚好触发了，这也是符合预期的
        _ = r catch {};
        return .disarm;
    }

    pub fn send(self: *Self, data: []const u8, dest: std.net.Address) !void {
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
            var msgs: [BATCH_LIMIT]linux.mmsghdr_const = undefined;
            var iovecs: [BATCH_LIMIT]std.posix.iovec_const = undefined;
            var sockaddrs: [BATCH_LIMIT]std.posix.sockaddr.storage = undefined;
            for (batch, 0..) |pkt, i| {
                const addr_len = pkt.dest.getOsSockLen();
                const dest_ptr = @as([*]u8, @ptrCast(&sockaddrs[i]));
                const src_ptr = @as([*]const u8, @ptrCast(&pkt.dest.any));
                @memcpy(dest_ptr[0..addr_len], src_ptr[0..addr_len]);
                iovecs[i] = .{ .base = pkt.data.ptr, .len = pkt.data.len };
                msgs[i] = .{ .hdr = .{ .name = @ptrCast(&sockaddrs[i]), .namelen = addr_len, .iov = @as([*]const std.posix.iovec_const, @ptrCast(&iovecs[i])), .iovlen = 1, .control = null, .controllen = 0, .flags = 0 }, .len = 0 };
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
            const rc = std.posix.sendto(self.udp.fd, pkt.data, 0, &pkt.dest.any, pkt.dest.getOsSockLen()) catch |err| {
                if (err == error.WouldBlock) return total_sent;
                return total_sent;
            };
            _ = rc;
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
        if (r) |_| {} else |err| std.log.warn("Async UDP send failed: {}", .{err});
        self.is_sending = false;
        if (self.send_queue.items.len > 0) self.flushSendQueue();
        return .disarm;
    }

    pub fn start(self: *Self) void {
        if (self.running) return;
        self.running = true;

        self.startRecv();
        self.startAsync();
        self.scheduleTimer(self.timer_interval_ms);

        std.log.info("IoLoop started on port {}", .{self.local_addr.getPort()});
    }

    pub fn stop(self: *Self) void {
        if (!self.running) return;
        self.running = false;
        self.async_notify.notify() catch {};
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
        addr: std.net.Address,
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
            if (e != error.WouldBlock and e != error.OperationCanceled) {
                err_handler.reportError(.transport, "UDP recv error", e);
            }
            if (self.running) self.startRecv();
            return .disarm;
        };

        if (len > 0) {
            if (self.recv_callback) |cb| {
                if (self.callback_ctx) |ctx| {
                    const timestamp = quic_c.currentTime();
                    cb(ctx, self.recv_buf[0..len], addr, timestamp);
                }
            }
        }

        if (self.running) {
            self.startRecv();
        }
        return .disarm;
    }

    fn scheduleTimer(self: *Self, delay_ms: u64) void {
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

        const self = ud orelse return .disarm;
        if (!self.running) return .disarm;

        if (result) |_| {
            if (self.timer_callback) |cb| {
                if (self.callback_ctx) |ctx| {
                    cb(ctx);
                }
            }
            self.scheduleTimer(self.timer_interval_ms);
        } else |err| {
            if (err == error.OperationCanceled) {
                self.scheduleTimer(self.timer_interval_ms);
            } else {
                self.scheduleTimer(self.timer_interval_ms);
            }
        }

        return .disarm;
    }
};
