//! 对象池 (Object Pool)
//!
//! 高性能内存复用机制，避免频繁的 alloc/free 调用。
//! 适用于生命周期短、频繁创建销毁的对象。
//!
//! ## 设计特点
//!
//! 1. **预分配**：初始化时可预分配一批对象
//! 2. **按需增长**：池空时自动创建新对象
//! 3. **零拷贝归还**：归还时仅修改链表指针
//! 4. **类型安全**：编译期泛型保证类型正确
//!
//! ## 使用示例
//!
//! ```zig
//! const BufferPool = ObjectPool([4096]u8);
//!
//! var pool = BufferPool.init(allocator);
//! defer pool.deinit();
//!
//! // 预分配 16 个缓冲区
//! try pool.prealloc(16);
//!
//! // 获取缓冲区
//! const buf = try pool.acquire();
//! defer pool.release(buf);
//!
//! // 使用缓冲区...
//! ```

const std = @import("std");

/// 泛型对象池
///
/// @param T: 池化对象的类型
pub fn ObjectPool(comptime T: type) type {
    return struct {
        const Self = @This();

        /// 池中的节点（包装对象 + 链表指针）
        const Node = struct {
            data: T,
            next: ?*Node,
        };

        allocator: std.mem.Allocator,
        /// 空闲链表头
        free_list: ?*Node,
        /// 已分配的所有节点（用于 deinit 时释放）
        all_nodes: std.ArrayList(*Node),
        /// 统计：当前池中空闲对象数
        free_count: usize,
        /// 统计：总分配对象数
        total_count: usize,

        /// 初始化对象池
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .free_list = null,
                .all_nodes = .{},
                .free_count = 0,
                .total_count = 0,
            };
        }

        /// 释放对象池及所有对象
        pub fn deinit(self: *Self) void {
            for (self.all_nodes.items) |node| {
                self.allocator.destroy(node);
            }
            self.all_nodes.deinit(self.allocator);
            self.free_list = null;
            self.free_count = 0;
            self.total_count = 0;
        }

        /// 预分配指定数量的对象
        pub fn prealloc(self: *Self, count: usize) !void {
            var i: usize = 0;
            while (i < count) : (i += 1) {
                const node = try self.allocator.create(Node);
                node.* = .{
                    .data = undefined,
                    .next = self.free_list,
                };
                self.free_list = node;
                try self.all_nodes.append(self.allocator, node);
                self.free_count += 1;
                self.total_count += 1;
            }
        }

        /// 获取一个对象
        ///
        /// 优先从空闲链表获取，如果池空则新分配。
        pub fn acquire(self: *Self) !*T {
            if (self.free_list) |node| {
                // 从空闲链表取出
                self.free_list = node.next;
                self.free_count -= 1;
                return &node.data;
            } else {
                // 池空，新分配
                const node = try self.allocator.create(Node);
                node.* = .{
                    .data = undefined,
                    .next = null,
                };
                try self.all_nodes.append(self.allocator, node);
                self.total_count += 1;
                return &node.data;
            }
        }

        /// 归还对象到池中
        pub fn release(self: *Self, ptr: *T) void {
            // 通过指针算术获取 Node（T 是 Node 的第一个字段）
            const node: *Node = @fieldParentPtr("data", ptr);
            node.next = self.free_list;
            self.free_list = node;
            self.free_count += 1;
        }

        /// 获取当前空闲对象数
        pub fn freeCount(self: *const Self) usize {
            return self.free_count;
        }

        /// 获取总分配对象数
        pub fn totalCount(self: *const Self) usize {
            return self.total_count;
        }
    };
}

/// 固定大小缓冲区
///
/// 用于替代 ArrayList 的动态缓冲区。
/// 适合已知最大大小的场景。
pub fn FixedBuffer(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        data: [capacity]u8,
        len: usize,

        pub fn init() Self {
            return .{
                .data = undefined,
                .len = 0,
            };
        }

        pub fn reset(self: *Self) void {
            self.len = 0;
        }

        pub fn append(self: *Self, bytes: []const u8) !void {
            if (self.len + bytes.len > capacity) {
                return error.BufferOverflow;
            }
            @memcpy(self.data[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
        }

        pub fn items(self: *const Self) []const u8 {
            return self.data[0..self.len];
        }

        pub fn remaining(self: *const Self) usize {
            return capacity - self.len;
        }

        pub fn isFull(self: *const Self) bool {
            return self.len >= capacity;
        }
    };
}

// ============================================================================
// 测试
// ============================================================================

test "ObjectPool basic" {
    const TestPool = ObjectPool(u64);

    var pool = TestPool.init(std.testing.allocator);
    defer pool.deinit();

    // 预分配
    try pool.prealloc(4);
    try std.testing.expectEqual(@as(usize, 4), pool.freeCount());

    // 获取
    const a = try pool.acquire();
    a.* = 42;
    try std.testing.expectEqual(@as(usize, 3), pool.freeCount());

    const b = try pool.acquire();
    b.* = 100;
    try std.testing.expectEqual(@as(usize, 2), pool.freeCount());

    // 归还
    pool.release(a);
    try std.testing.expectEqual(@as(usize, 3), pool.freeCount());

    // 再次获取（应该复用）
    const c = try pool.acquire();
    try std.testing.expectEqual(@as(usize, 2), pool.freeCount());
    _ = c;
}

test "ObjectPool auto grow" {
    const TestPool = ObjectPool(u32);

    var pool = TestPool.init(std.testing.allocator);
    defer pool.deinit();

    // 不预分配，直接获取
    const a = try pool.acquire();
    a.* = 1;
    try std.testing.expectEqual(@as(usize, 1), pool.totalCount());

    const b = try pool.acquire();
    b.* = 2;
    try std.testing.expectEqual(@as(usize, 2), pool.totalCount());

    pool.release(a);
    pool.release(b);
    try std.testing.expectEqual(@as(usize, 2), pool.freeCount());
}

test "FixedBuffer basic" {
    var buf = FixedBuffer(16).init();

    try buf.append("Hello");
    try std.testing.expectEqualStrings("Hello", buf.items());

    try buf.append(", World!");
    try std.testing.expectEqualStrings("Hello, World!", buf.items());

    // 超出容量
    try std.testing.expectError(error.BufferOverflow, buf.append("Extra"));

    // 重置
    buf.reset();
    try std.testing.expectEqual(@as(usize, 0), buf.len);
}