const std = @import("std");
const quic_c = @import("../quic/c.zig");

/// 转发的数据包
pub const ForwardPacket = struct {
    data: []u8, // 拥有的内存
    addr_from: std.net.Address,
    received_time: u64,

    pub fn deinit(self: *ForwardPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

/// 线程间的消息队列（简单互斥锁实现，适用于低频转发）
pub const PacketQueue = struct {
    mutex: std.Thread.Mutex = .{},
    queue: std.ArrayListUnmanaged(ForwardPacket) = .{},
    allocator: std.mem.Allocator,
    // 用于唤醒目标线程的 Async 句柄（这里简化，假设通过轮询或已有机制唤醒）
    // 在 xev 中，可以使用 async handle。

    pub fn init(allocator: std.mem.Allocator) PacketQueue {
        return .{
            .queue = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PacketQueue) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.queue.items) |*pkt| {
            pkt.deinit(self.allocator);
        }
        self.queue.deinit(self.allocator);
    }

    pub fn push(self: *PacketQueue, pkt: ForwardPacket) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.queue.append(self.allocator, pkt);
    }

    pub fn popAll(self: *PacketQueue, out: *std.ArrayListUnmanaged(ForwardPacket)) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.queue.items.len == 0) return;
        try out.appendSlice(self.allocator, self.queue.items);
        self.queue.clearRetainingCapacity();
    }
};

/// 连接迁移管理器：处理线程间（以及未来的节点间）的连接迁移
pub const MigrationManager = struct {
    queues: []PacketQueue,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, num_threads: usize) !*MigrationManager {
        const self = try allocator.create(MigrationManager);
        self.queues = try allocator.alloc(PacketQueue, num_threads);
        self.allocator = allocator;

        for (self.queues) |*q| {
            q.* = PacketQueue.init(allocator);
        }
        return self;
    }

    pub fn deinit(self: *MigrationManager) void {
        for (self.queues) |*q| {
            q.deinit();
        }
        self.allocator.free(self.queues);
        self.allocator.destroy(self);
    }

    /// 转发包给指定线程（本地 L1 迁移）
    pub fn forward(self: *MigrationManager, target_thread_id: usize, packet: []const u8, addr_from: std.net.Address, time: u64) !void {
        if (target_thread_id >= self.queues.len) return error.InvalidThreadId;

        // 复制数据包
        const data_copy = try self.allocator.dupe(u8, packet);
        const pkt = ForwardPacket{
            .data = data_copy,
            .addr_from = addr_from,
            .received_time = time,
        };

        try self.queues[target_thread_id].push(pkt);
    }
};
