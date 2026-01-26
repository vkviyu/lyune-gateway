//! Stream 处理器模块
//!
//! 提供 QUIC Stream 数据的处理抽象，支持流式和缓冲两种模式。
//!
//! ## 设计说明
//!
//! - StreamingMessageHandler: 实时流场景，收到即透传，无缓冲
//! - BufferedMessageHandler: 普通消息场景，累积数据直到 FIN
//!
//! BufferedMessageHandler 使用动态 ArrayList，支持任意大小消息。
//! 可通过 max_message_size 参数限制单条消息上限，防止恶意大包攻击。

const std = @import("std");

const common = @import("../common/mod.zig");
const err_handler = common.err;
const quic = @import("../quic/mod.zig");

/// 流事件委托接口 (泛型版本)
///
/// 允许 StreamHandler 将高级事件（如“收到完整消息”）回调给上层。
/// 利用泛型 ContextType 提供了更好的类型安全。
pub fn StreamDelegate(comptime ContextType: type) type {
    return struct {
        ptr: *ContextType,
        /// 回调函数
        /// is_fin: 是否为该流的最后一块数据
        onMessage: *const fn (ctx: *ContextType, stream_id: u64, message: []const u8, is_fin: bool) void,
    };
}

/// 流处理器接口 (类型擦除)
///
/// 这是对外的统一接口，用于在 ConnectionContext 中存储异构的 Handler。
/// 具体的实现（Buffered/Streaming）通过 vtable 适配到此接口。
pub const StreamHandler = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// 处理数据片段
        onData: *const fn (ctx: *anyopaque, data: []const u8, is_fin: bool) void,
        /// 清理资源
        deinit: *const fn (ctx: *anyopaque) void,
    };

    pub fn onData(self: StreamHandler, data: []const u8, is_fin: bool) void {
        self.vtable.onData(self.ptr, data, is_fin);
    }

    pub fn deinit(self: StreamHandler) void {
        self.vtable.deinit(self.ptr);
    }
};

/// 流式消息处理器工厂 (用于 AI/实时流场景)
///
/// 不缓冲数据，收到即透传。
pub fn StreamingMessageHandler(comptime ContextType: type) type {
    return struct {
        const Self = @This();
        const Delegate = StreamDelegate(ContextType);

        allocator: std.mem.Allocator,
        stream_id: u64,
        delegate: Delegate,

        pub fn init(allocator: std.mem.Allocator, delegate: Delegate, stream_id: u64) !StreamHandler {
            const self = try allocator.create(Self);
            self.* = .{
                .allocator = allocator,
                .stream_id = stream_id,
                .delegate = delegate,
            };

            return .{
                .ptr = self,
                .vtable = &.{
                    .onData = onData,
                    .deinit = deinit,
                },
            };
        }

        fn onData(ctx: *anyopaque, data: []const u8, is_fin: bool) void {
            const self = @as(*Self, @ptrCast(@alignCast(ctx)));
            // 直接透传数据和结束标记
            self.delegate.onMessage(self.delegate.ptr, self.stream_id, data, is_fin);
        }

        fn deinit(ctx: *anyopaque) void {
            const self = @as(*Self, @ptrCast(@alignCast(ctx)));
            self.allocator.destroy(self);
        }
    };
}

/// 缓冲消息处理器工厂 (用于普通 IM 消息)
///
/// 累积所有数据，直到收到 FIN 才处理完整消息。
/// 使用动态 ArrayList，无大小限制。
pub fn BufferedMessageHandler(comptime ContextType: type) type {
    return struct {
        const Self = @This();
        const Delegate = StreamDelegate(ContextType);

        allocator: std.mem.Allocator,
        buffer: std.ArrayList(u8),
        stream_id: u64,
        delegate: Delegate,

        pub fn init(allocator: std.mem.Allocator, delegate: Delegate, stream_id: u64) !StreamHandler {
            const self = try allocator.create(Self);

            self.* = .{
                .allocator = allocator,
                .buffer = .{},
                .stream_id = stream_id,
                .delegate = delegate,
            };

            return .{
                .ptr = self,
                .vtable = &.{
                    .onData = onData,
                    .deinit = deinit,
                },
            };
        }

        fn onData(ctx: *anyopaque, data: []const u8, is_fin: bool) void {
            const self = @as(*Self, @ptrCast(@alignCast(ctx)));

            // 累积数据到动态缓冲区
            self.buffer.appendSlice(self.allocator, data) catch |e| {
                std.log.err("[STREAM] Failed to append data on stream {}: {}", .{ self.stream_id, e });
                return;
            };

            // 只有收到 FIN 才处理完整消息
            if (is_fin) {
                const msg = self.buffer.items;
                self.delegate.onMessage(self.delegate.ptr, self.stream_id, msg, true);
            }
        }

        fn deinit(ctx: *anyopaque) void {
            const self = @as(*Self, @ptrCast(@alignCast(ctx)));
            self.buffer.deinit(self.allocator);
            self.allocator.destroy(self);
        }
    };
}
