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
const foundation = @import("../foundation/mod.zig");
const net = foundation.net;

/// 单个交接包的最大字节数。QUIC 数据包不会超过典型 MTU，这里留足余量。
pub const max_packet_size: usize = 2048;

/// 节点间隧道交接方向。
pub const TunnelKind = enum(u8) {
    /// 入口节点把客户端请求交给 CID owner。
    request = 1,
    /// CID owner 把响应交回原入口节点发往客户端/LB。
    response = 2,
};

/// 跨节点交接元数据；本地 Worker 误分流的包不携带该结构。
pub const TunnelMetadata = struct {
    kind: TunnelKind,
    source_node_id: u16,
    source_worker_id: u8,
};

/// 交给目标 Worker 的一个 UDP 数据报。
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
    /// 非 null 表示包来自节点间隧道，并保留源节点/Worker 与方向。
    tunnel: ?TunnelMetadata = null,

    /// 从一段外部 UDP 数据构造本地交接包（会复制内容）。超过上限则拒绝。
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

    /// 构造带节点间来源元数据的交接包，供目标 Worker 区分请求和回程响应。
    pub fn initTunnel(packet: []const u8, addr_from: net.Address, metadata: TunnelMetadata) !ForwardPacket {
        var result = try init(packet, addr_from, 0);
        result.tunnel = metadata;
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
/// Worker 唤醒。实际实现由 Worker 用 xev.Async 提供（见 worker/worker.zig）。
/// ptr/notifyFn 均为借用；注册期间实现对象必须保持有效。
pub const Notifier = struct {
    ptr: *anyopaque,
    notifyFn: *const fn (ptr: *anyopaque) void,

    /// 调用借用的唤醒回调，不转移 ptr 所有权。
    pub fn notify(self: Notifier) void {
        self.notifyFn(self.ptr);
    }
};

/// 有界 MPSC 环形队列，用于低频交接。
///
/// 多生产者（任意 Worker 都可能要交接给别人）、单消费者（目标 Worker 独占取走）。
/// 用固定容量的环形缓冲区 + 互斥锁实现：交接是低频路径，简单可靠优先于极致无锁。
/// 容量满时直接返回 error.QueueFull 并由上层计数丢弃，绝不无界增长拖垮内存。
///
/// 对 T 泛化是因为有两种交接物、尺寸差两个数量级：UDP 数据报（`ForwardPacket`，
/// 2KB 槽位、深队列）与应用消息（`AppMessage`，64KB 槽位、浅队列）。行为完全一样，
/// 只有维度不同，所以共用一份实现而不是抄两遍。
///
/// ## realm 公平只对带 realm 的那一种生效
///
/// 队列是定容共享池，所以同样要防吵闹邻居（设计文档 §12.4）。但**包队列没有这个维度**：
/// 它搬的是未解密的 UDP 数据报，而 realm 由 TLS SNI 决定，那时候还读不到。因此这里用
/// 一个 comptime 分支按 T 有没有 `realm` 字段决定，而不是给包硬塞一个假的 realm。
fn RingQueue(comptime T: type) type {
    return struct {
        const Self = @This();

        /// 本队列是否讲 realm 公平（见上文）。
        const tracks_realm = @hasField(T, "realm");

        io: std.Io,
        mutex: std.Io.Mutex = .init,
        items: []T,
        /// 环形缓冲区队头下标。
        head: usize = 0,
        /// 当前元素个数。
        len: usize = 0,
        /// 队列由空变非空时用来唤醒目标 Worker；目标未就绪时可为 null。
        notifier: ?Notifier = null,
        /// 按 realm 的积压公平上限；只有带 realm 的交接物才有。
        ///
        /// 它记的是**当前积压**而不是累计量：入队 +1、出队 -1，两处都在持锁期间完成
        /// ——`push` 在生产者线程、`pop` 在消费者线程，不放在锁里就是数据竞争。
        /// 正常情况下一轮事件循环就排空，计数始终接近 0，水位线以下无条件放行，
        /// 所以这套记账在热路径上是两次整数运算。
        quota: if (tracks_realm) foundation.quota.Quota else void,

        /// 预分配固定容量的槽位；capacity 必须大于零。
        pub fn init(io: std.Io, allocator: std.mem.Allocator, capacity: usize) !Self {
            if (capacity == 0) return error.InvalidCapacity;
            const items = try allocator.alloc(T, capacity);
            errdefer allocator.free(items);
            return .{
                .io = io,
                .items = items,
                .quota = if (tracks_realm) try foundation.quota.Quota.init(
                    allocator,
                    foundation.quota.max_tracked_realms,
                    capacity,
                    foundation.quota.default_watermark_percent,
                ) else {},
            };
        }

        /// 释放预分配槽位；调用方须先注销 notifier 并停止所有生产者/消费者。
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.items);
            if (tracks_realm) self.quota.deinit(allocator);
            self.* = undefined;
        }

        /// 设置/清除唤醒回调。若设置时队列里已有积压，立即唤醒一次，避免漏处理。
        pub fn setNotifier(self: *Self, notifier: ?Notifier) void {
            self.mutex.lockUncancelable(self.io);
            const should_notify = notifier != null and self.len != 0;
            self.notifier = notifier;
            self.mutex.unlock(self.io);
            if (should_notify) notifier.?.notify();
        }

        /// 生产者：把一项放入队尾。
        ///
        /// 队列满返回 error.QueueFull；本 realm 的积压超过争用时的公平份额返回
        /// error.RealmOverShare。两者分开，运维才能区分"整条队列堵了"和
        /// "这家接入方在刷"——前者要查消费侧，后者要查接入方。
        /// 只有在「由空变非空」时才触发唤醒，避免每一项都做一次昂贵的跨线程通知。
        pub fn push(self: *Self, item: T) !void {
            self.mutex.lockUncancelable(self.io);
            if (self.len == self.items.len) {
                self.mutex.unlock(self.io);
                return error.QueueFull;
            }
            if (tracks_realm and !self.quota.allows(item.realm)) {
                self.mutex.unlock(self.io);
                return error.RealmOverShare;
            }

            const was_empty = self.len == 0;
            const tail = (self.head + self.len) % self.items.len;
            self.items[tail] = item;
            self.len += 1;
            if (tracks_realm) self.quota.acquire(item.realm);
            // 在持锁期间读取 notifier，但把真正的 notify 挪到解锁之后，缩短临界区。
            const notifier = if (was_empty) self.notifier else null;
            self.mutex.unlock(self.io);

            if (notifier) |value| value.notify();
        }

        /// 消费者：从队头取出一项，空则返回 null。
        pub fn pop(self: *Self) ?T {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.len == 0) return null;

            const item = self.items[self.head];
            self.head = (self.head + 1) % self.items.len;
            self.len -= 1;
            // 出队即归还：积压计数与队列长度严格同步，是这条队列上唯一的归还路径。
            if (tracks_realm) self.quota.release(item.realm);
            return item;
        }

        /// 当前积压项数（主要用于测试/观测）。
        pub fn count(self: *Self) usize {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.len;
        }
    };
}

/// 误分流 UDP 数据报的交接队列。
pub const PacketQueue = RingQueue(ForwardPacket);

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

    /// 为每个 Worker 预分配一条相同容量的 MPSC 队列。
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

    /// 释放所有 Worker 队列；调用前须停止 Worker 并清除 notifier。
    pub fn deinit(self: *LocalPacketRouter) void {
        for (self.queues) |*queue| queue.deinit(self.allocator);
        self.allocator.free(self.queues);
        self.* = undefined;
    }

    /// 返回已配置的 Worker 队列数量。
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

    /// 把已认证的节点间隧道包及其来源元数据交给目标 Worker。
    pub fn forwardTunnel(self: *LocalPacketRouter, worker_id: u8, packet: []const u8, addr_from: net.Address, metadata: TunnelMetadata) !void {
        if (worker_id >= self.queues.len) return error.InvalidWorkerId;
        const owned = ForwardPacket.initTunnel(packet, addr_from, metadata) catch |err| {
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

// ============================================================================
// 应用消息交接
// ============================================================================

/// 单条应用消息的最大字节数：一整帧（协议层帧头 8 + body 上限 65535）。
///
/// **刻意不复用 `max_packet_size`（2048）。** 那个数字是给 UDP 数据报定的（QUIC 包
/// 典型不超过 1500）。把应用消息绑在它上面会让协议层的 64KB body 上限在跨 Worker
/// 投递时静默降级成 2KB——同一个 API 在单 Worker 与多 Worker 下行为不同，是最难
/// 排查的失败模式。
///
/// 代价是槽位大两个数量级，所以应用消息队列的**深度要小**（见 MessageRouter）：
/// 包队列是深队列浅槽位（吸收突发），应用消息队列是浅队列深槽位（低频、一轮事件
/// 循环就排空）。
pub const max_message_size: usize = 8 + 65535;

/// 交给同机另一个 Worker 执行的一条应用消息。
///
/// 与 `ForwardPacket` 的区别不只是尺寸：那个搬的是密文，目标 Worker 喂给 picoquic
/// 就完事；这个搬的是**已解密、已分帧的应用帧**，目标 Worker 要按 `dest_kind`
/// 重新走一遍投递逻辑。
pub const AppMessage = struct {
    data: [max_message_size]u8 = undefined,
    len: u32,
    /// 消息所属隔离域。
    ///
    /// 必须随消息一起传，**不能让目标 Worker 从帧里读**：realm 是网关按 SNI 定的
    /// （§12.3），而帧是后端给的。从帧里读就等于把隔离边界交给了消息内容。
    realm: u16,
    /// 流式推送的会话号；0 表示这是一条一次性投递（设计文档 §5.3）。
    ///
    /// 与 realm 同一个理由放在信封里而不是帧里：会话号是网关内部的记账，让目标
    /// Worker 从帧里读它就等于把内部状态暴露成协议字段，而后端可以伪造它——伪造
    /// 一个别人的会话号就能把自己的字节插进别人的流。
    ///
    /// 它由创建会话的 Worker 发号，高 8 位是那个 Worker 的编号，因此本节点内唯一，
    /// 信封不需要再带一个"来自哪个 Worker"。
    session: u64 = 0,

    /// 从一段完整帧构造消息（会复制内容）。超过上限则拒绝。
    pub fn init(frame_bytes: []const u8, realm: u16, session: u64) !AppMessage {
        if (frame_bytes.len > max_message_size) return error.MessageTooLarge;
        var result: AppMessage = .{ .len = @intCast(frame_bytes.len), .realm = realm, .session = session };
        @memcpy(result.data[0..frame_bytes.len], frame_bytes);
        return result;
    }

    /// 返回有效帧字节（不含定长数组尾部的未使用部分）。
    pub fn bytes(self: *const AppMessage) []const u8 {
        return self.data[0..self.len];
    }
};

/// 应用消息的交接队列。
pub const MessageQueue = RingQueue(AppMessage);

/// 本机应用消息路由器：为每个 Worker 维护一条应用消息队列。
///
/// 它补的是这样一个洞：`dest_id → [connection]` 索引是**每 Worker 一份**的，所以
/// 后端在 Worker 0 的连接上推给某个 `dest_id`，只能投到 Worker 0 持有的连接；同一台
/// 机器上落在 Worker 1 的那台设备收不到，而后端无从知道该用哪条连接（设计文档 §8.4）。
/// 收到消息的 Worker 把它扇给同机其他 Worker，各自在自己的索引里查一遍，问题就解了。
///
/// 这是 §8.5「第一层投递通路」在**单节点内**的那一半；跨节点那一半走 forward 隧道。
pub const MessageRouter = struct {
    allocator: std.mem.Allocator,
    /// 下标即 worker_id。
    queues: []MessageQueue,
    /// 成功交接的累计条数。
    delivered: std.atomic.Value(u64) = .init(0),
    /// 因队列满或超长而丢弃的累计条数。
    dropped: std.atomic.Value(u64) = .init(0),

    pub fn init(io: std.Io, allocator: std.mem.Allocator, worker_count: usize, queue_capacity: usize) !MessageRouter {
        if (worker_count == 0 or worker_count > 256) return error.InvalidWorkerCount;
        const queues = try allocator.alloc(MessageQueue, worker_count);
        errdefer allocator.free(queues);

        var initialized: usize = 0;
        errdefer for (queues[0..initialized]) |*queue| queue.deinit(allocator);
        for (queues) |*queue| {
            queue.* = try MessageQueue.init(io, allocator, queue_capacity);
            initialized += 1;
        }
        return .{ .allocator = allocator, .queues = queues };
    }

    pub fn deinit(self: *MessageRouter) void {
        for (self.queues) |*queue| queue.deinit(self.allocator);
        self.allocator.free(self.queues);
        self.* = undefined;
    }

    pub fn workerCount(self: *const MessageRouter) usize {
        return self.queues.len;
    }

    pub fn setNotifier(self: *MessageRouter, worker_id: u8, notifier: ?Notifier) !void {
        if (worker_id >= self.queues.len) return error.InvalidWorkerId;
        self.queues[worker_id].setNotifier(notifier);
    }

    /// 把一条应用消息交给指定 Worker。
    ///
    /// 三种拒绝都累加 dropped 并把错误上抛：应用消息丢失必须可观测，静默丢弃会表现成
    /// "某些设备偶发收不到推送"，而那是最难定位的一类故障。
    ///
    /// - `MessageTooLarge`：帧超过 `max_message_size`，是编码侧的问题；
    /// - `QueueFull`：整条队列堵了，要查目标 Worker 的消费侧；
    /// - `RealmOverShare`：这个 realm 的积压超了争用时的公平份额，要查接入方。
    pub fn deliver(self: *MessageRouter, worker_id: u8, frame_bytes: []const u8, realm: u16, session: u64) !void {
        if (worker_id >= self.queues.len) return error.InvalidWorkerId;
        const message = AppMessage.init(frame_bytes, realm, session) catch |err| {
            _ = self.dropped.fetchAdd(1, .monotonic);
            return err;
        };
        self.queues[worker_id].push(message) catch |err| {
            _ = self.dropped.fetchAdd(1, .monotonic);
            return err;
        };
        _ = self.delivered.fetchAdd(1, .monotonic);
    }

    pub fn pop(self: *MessageRouter, worker_id: u8) ?AppMessage {
        if (worker_id >= self.queues.len) return null;
        return self.queues[worker_id].pop();
    }

    pub fn stats(self: *const MessageRouter) struct { delivered: u64, dropped: u64 } {
        return .{
            .delivered = self.delivered.load(.monotonic),
            .dropped = self.dropped.load(.monotonic),
        };
    }
};

test "app messages carry their realm and session, and refuse oversized frames" {
    var router = try MessageRouter.init(std.testing.io, std.testing.allocator, 2, 2);
    defer router.deinit();

    try router.deliver(1, "frame-bytes", 7, 0x0300_0000_0000_0009);
    const popped = router.pop(1).?;
    try std.testing.expectEqualStrings("frame-bytes", popped.bytes());
    // realm 与会话号都随消息传递，目标 Worker 不从帧里读它们。
    try std.testing.expectEqual(@as(u16, 7), popped.realm);
    try std.testing.expectEqual(@as(u64, 0x0300_0000_0000_0009), popped.session);
    try std.testing.expect(router.pop(1) == null);
    // 别的 Worker 的队列不受影响。
    try std.testing.expect(router.pop(0) == null);

    const oversized = try std.testing.allocator.alloc(u8, max_message_size + 1);
    defer std.testing.allocator.free(oversized);
    try std.testing.expectError(error.MessageTooLarge, router.deliver(0, oversized, 1, 0));

    // 队列满与超长都要计入 dropped：应用消息丢失必须可观测。
    try router.deliver(0, "a", 1, 0);
    try router.deliver(0, "b", 1, 0);
    try std.testing.expectError(error.QueueFull, router.deliver(0, "c", 1, 0));
    try std.testing.expectEqual(@as(u64, 2), router.stats().dropped);
    try std.testing.expectEqual(@as(u64, 3), router.stats().delivered);
}

test "a realm over its share is refused while the queue still has room" {
    // 交接队列也是定容共享池：一个 realm 的推送风暴能把队列占满，让其他 realm 的
    // 推送一起丢（§12.4）。这里钉住"只拒超额的那个，而且队列还有空位时就开始拒"。
    var router = try MessageRouter.init(std.testing.io, std.testing.allocator, 1, 10);
    defer router.deinit();

    // 水位线（70%）以下无条件放行：realm 1 先积到 7 条，此刻只有它活跃，份额 = 全队列。
    var i: usize = 0;
    while (i < 7) : (i += 1) try router.deliver(0, "storm", 1, 0);

    // realm 2 进来，活跃变 2，份额腰斩到 5。
    try router.deliver(0, "quiet", 2, 0);
    // realm 1 已占 7 > 5 → 被拒，尽管队列还有 2 个空位。
    try std.testing.expectError(error.RealmOverShare, router.deliver(0, "storm", 1, 0));
    // realm 2 只占 1，照常放行。
    try router.deliver(0, "quiet", 2, 0);

    // 积压计数与队列长度同步：全部取走之后必须归零，否则这个 realm 的份额会被
    // 永久蚕食，症状是"这家接入方的推送过一阵就开始丢"。
    while (router.pop(0)) |_| {}
    try std.testing.expectEqual(@as(usize, 0), router.queues[0].quota.total);
    try std.testing.expectEqual(@as(usize, 0), router.queues[0].quota.active_realms);
}

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
