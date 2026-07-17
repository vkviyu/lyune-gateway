//! 本地跨 Worker 包交接（异常路径）
//!
//! 正常情况下，reuseport BPF 已经在内核态把每个包投递给了正确的 Worker，本模块不参与。
//! 但存在少数「误分流」场景需要用户态兜底，例如：
//!   - NAT rebinding 后客户端换了源地址，内核旧的 4 元组哈希短暂把包发到错误 socket；
//!   - 平台不支持 reuseport BPF（如 macOS），只能靠默认哈希分发。
//! 这时收到包的 Worker 会解析 CID 得到真正的 owner，把整段 UDP 数据交给本路由器，
//! 再由 owner Worker 取走并喂给自己的 picoquic 上下文。
//!
//! 注意：这里搬运的是「原始 UDP 数据包」，不是 QUIC 连接状态。连接状态（TLS 密钥、
//! 拥塞控制、流状态等）始终只属于一个 Worker，本模块不做真正的连接迁移。

const std = @import("std");
const net = @import("../foundation/mod.zig").net;

/// 单个交接包的最大字节数。QUIC 数据包不会超过典型 MTU，这里留足余量。
pub const max_packet_size: usize = 2048;

/// 交给 owner Worker 的一个 UDP 数据报。
///
/// 数据用定长内联数组存储，而不是堆分配的 slice：异常交接路径可能突发，
/// 内联存储可以完全避免每包 malloc/free，让队列项可按值拷贝进环形缓冲区。
pub const ForwardPacket = struct {
    data: [max_packet_size]u8 = undefined,
    len: u16,
    /// 原始来源地址，owner Worker 喂给 picoquic 时需要它作为对端地址。
    addr_from: net.Address,
    /// 收包时刻（微秒），保持与 picoquic 的时间语义一致。
    received_time: u64,

    /// 从一段外部 UDP 数据构造交接包（会复制内容）。超过上限则拒绝。
    pub fn init(packet: []const u8, addr_from: net.Address, received_time: u64) !ForwardPacket {
        if (packet.len > max_packet_size) return error.PacketTooLarge;
        var result: ForwardPacket = .{
            .len = @intCast(packet.len),
            .addr_from = addr_from,
            .received_time = received_time,
        };
        @memcpy(result.data[0..packet.len], packet);
        return result;
    }

    /// 返回有效负载切片（不含定长数组尾部的未使用部分）。
    pub fn bytes(self: *const ForwardPacket) []const u8 {
        return self.data[0..self.len];
    }
};

/// 唤醒目标 Worker 事件循环的回调封装。
///
/// 生产者线程往队列 push 之后，需要一种方式把正在 libxev 事件循环里休眠的 owner
/// Worker 唤醒。实际实现由 Worker 用 xev.Async 提供（见 gateway/worker.zig）。
pub const Notifier = struct {
    ptr: *anyopaque,
    notifyFn: *const fn (ptr: *anyopaque) void,

    pub fn notify(self: Notifier) void {
        self.notifyFn(self.ptr);
    }
};

/// 有界 MPSC 环形队列，用于低频包交接。
///
/// 多生产者（任意 Worker 都可能收到别人的包）、单消费者（owner Worker 独占取走）。
/// 用固定容量的环形缓冲区 + 互斥锁实现：交接是异常低频路径，简单可靠优先于极致无锁。
/// 容量满时直接返回 error.QueueFull 并由上层计数丢弃，绝不无界增长拖垮内存。
pub const PacketQueue = struct {
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    packets: []ForwardPacket,
    /// 环形缓冲区队头下标。
    head: usize = 0,
    /// 当前元素个数。
    len: usize = 0,
    /// 队列由空变非空时用来唤醒 owner Worker；owner 未就绪时可为 null。
    notifier: ?Notifier = null,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, capacity: usize) !PacketQueue {
        if (capacity == 0) return error.InvalidCapacity;
        return .{
            .io = io,
            .packets = try allocator.alloc(ForwardPacket, capacity),
        };
    }

    pub fn deinit(self: *PacketQueue, allocator: std.mem.Allocator) void {
        allocator.free(self.packets);
        self.* = undefined;
    }

    /// 设置/清除唤醒回调。若设置时队列里已有积压包，立即唤醒一次，避免漏处理。
    pub fn setNotifier(self: *PacketQueue, notifier: ?Notifier) void {
        self.mutex.lockUncancelable(self.io);
        const should_notify = notifier != null and self.len != 0;
        self.notifier = notifier;
        self.mutex.unlock(self.io);
        if (should_notify) notifier.?.notify();
    }

    /// 生产者：把一个包放入队尾。队列满返回 error.QueueFull。
    /// 只有在「由空变非空」时才触发唤醒，避免每个包都做一次昂贵的跨线程通知。
    pub fn push(self: *PacketQueue, packet: ForwardPacket) !void {
        self.mutex.lockUncancelable(self.io);
        if (self.len == self.packets.len) {
            self.mutex.unlock(self.io);
            return error.QueueFull;
        }

        const was_empty = self.len == 0;
        const tail = (self.head + self.len) % self.packets.len;
        self.packets[tail] = packet;
        self.len += 1;
        // 在持锁期间读取 notifier，但把真正的 notify 挪到解锁之后，缩短临界区。
        const notifier = if (was_empty) self.notifier else null;
        self.mutex.unlock(self.io);

        if (notifier) |value| value.notify();
    }

    /// 消费者：从队头取出一个包，空则返回 null。
    pub fn pop(self: *PacketQueue) ?ForwardPacket {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.len == 0) return null;

        const packet = self.packets[self.head];
        self.head = (self.head + 1) % self.packets.len;
        self.len -= 1;
        return packet;
    }

    /// 当前积压包数（主要用于测试/观测）。
    pub fn count(self: *PacketQueue) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.len;
    }
};

/// 本机异常路径路由器：为每个 Worker 维护一条交接队列。
///
/// 正常流量由 reuseport BPF 在内核分流，不经过这里；只有误分流的包才 forward 进来。
/// forwarded/dropped 两个原子计数用于观测异常路径的规模，便于定位 NAT/内核问题。
pub const LocalPacketRouter = struct {
    allocator: std.mem.Allocator,
    /// 下标即 worker_id，一一对应每个 Worker 的交接队列。
    queues: []PacketQueue,
    /// 成功交接的累计包数。
    forwarded: std.atomic.Value(u64) = .init(0),
    /// 因队列满或超长而丢弃的累计包数。
    dropped: std.atomic.Value(u64) = .init(0),

    pub fn init(io: std.Io, allocator: std.mem.Allocator, worker_count: usize, queue_capacity: usize) !LocalPacketRouter {
        if (worker_count == 0 or worker_count > 256) return error.InvalidWorkerCount;
        const queues = try allocator.alloc(PacketQueue, worker_count);
        errdefer allocator.free(queues);

        // 逐个初始化，任一失败都要回滚已建好的队列，避免泄漏。
        var initialized: usize = 0;
        errdefer for (queues[0..initialized]) |*queue| queue.deinit(allocator);
        for (queues) |*queue| {
            queue.* = try PacketQueue.init(io, allocator, queue_capacity);
            initialized += 1;
        }
        return .{ .allocator = allocator, .queues = queues };
    }

    pub fn deinit(self: *LocalPacketRouter) void {
        for (self.queues) |*queue| queue.deinit(self.allocator);
        self.allocator.free(self.queues);
        self.* = undefined;
    }

    pub fn workerCount(self: *const LocalPacketRouter) usize {
        return self.queues.len;
    }

    /// 为指定 Worker 注册/注销唤醒回调，通常在 Worker 启动/退出时调用。
    pub fn setNotifier(self: *LocalPacketRouter, worker_id: u8, notifier: ?Notifier) !void {
        if (worker_id >= self.queues.len) return error.InvalidWorkerId;
        self.queues[worker_id].setNotifier(notifier);
    }

    /// 把一个误分流的包交接给它真正的 owner Worker。
    /// 无论是拷贝失败还是队列满，都会累加 dropped 并把错误上抛给调用方记录。
    pub fn forward(self: *LocalPacketRouter, worker_id: u8, packet: []const u8, addr_from: net.Address, received_time: u64) !void {
        if (worker_id >= self.queues.len) return error.InvalidWorkerId;
        const owned = ForwardPacket.init(packet, addr_from, received_time) catch |err| {
            _ = self.dropped.fetchAdd(1, .monotonic);
            return err;
        };
        self.queues[worker_id].push(owned) catch |err| {
            _ = self.dropped.fetchAdd(1, .monotonic);
            return err;
        };
        _ = self.forwarded.fetchAdd(1, .monotonic);
    }

    /// owner Worker 被唤醒后，循环调用此方法取走属于自己的交接包。
    pub fn pop(self: *LocalPacketRouter, worker_id: u8) ?ForwardPacket {
        if (worker_id >= self.queues.len) return null;
        return self.queues[worker_id].pop();
    }

    /// 读取交接统计快照。
    pub fn stats(self: *const LocalPacketRouter) struct { forwarded: u64, dropped: u64 } {
        return .{
            .forwarded = self.forwarded.load(.monotonic),
            .dropped = self.dropped.load(.monotonic),
        };
    }
};

test "bounded packet queue preserves FIFO and rejects overflow" {
    var queue = try PacketQueue.init(std.testing.io, std.testing.allocator, 2);
    defer queue.deinit(std.testing.allocator);
    const address = net.initIp4(.{ 127, 0, 0, 1 }, 8443);

    try queue.push(try ForwardPacket.init("one", address, 1));
    try queue.push(try ForwardPacket.init("two", address, 2));
    try std.testing.expectError(error.QueueFull, queue.push(try ForwardPacket.init("three", address, 3)));
    try std.testing.expectEqualStrings("one", queue.pop().?.bytes());
    try std.testing.expectEqualStrings("two", queue.pop().?.bytes());
    try std.testing.expect(queue.pop() == null);
}

test "local packet router tracks forwarding and drops" {
    var router = try LocalPacketRouter.init(std.testing.io, std.testing.allocator, 2, 1);
    defer router.deinit();
    const address = net.initIp4(.{ 127, 0, 0, 1 }, 8443);

    try router.forward(1, "packet", address, 10);
    try std.testing.expectError(error.QueueFull, router.forward(1, "overflow", address, 11));
    try std.testing.expectEqualStrings("packet", router.pop(1).?.bytes());
    const current = router.stats();
    try std.testing.expectEqual(@as(u64, 1), current.forwarded);
    try std.testing.expectEqual(@as(u64, 1), current.dropped);
}
