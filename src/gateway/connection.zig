const std = @import("std");

const protocol = @import("../protocol/mod.zig");
const quic = @import("../quic/mod.zig");
const QUICConnection = quic.connection.Connection;

// const StreamHandler = @import("stream_handler.zig").StreamHandler;
/// 业务连接上下文：附加在 QUIC Connection 上的业务数据
pub const ConnectionContext = struct {
    allocator: std.mem.Allocator,
    // 存储底层的 C 指针，它是唯一且稳定的。
    cnx_handle: quic.c.QuicCnx,
    user_id: u64 = 0, // 0 表示未认证
    connected_at: i64,

    // owning GatewayWorker pointer, kept opaque to avoid an import cycle.
    gateway_ctx: ?*anyopaque = null,

    // Stream 处理器映射表：stream_id -> Handler
    stream_handlers: std.AutoHashMap(u64, protocol.handler.StreamHandler),

    pub fn init(allocator: std.mem.Allocator, cnx: quic.c.QuicCnx) ConnectionContext {
        return .{
            .allocator = allocator,
            .cnx_handle = cnx,
            .connected_at = std.time.timestamp(),
            .stream_handlers = std.AutoHashMap(u64, protocol.handler.StreamHandler).init(allocator),
        };
    }

    pub fn deinit(self: *ConnectionContext) void {
        var it = self.stream_handlers.valueIterator();
        while (it.next()) |handler| {
            handler.deinit();
        }
        self.stream_handlers.deinit();
    }

    /// 获取 Stream 处理器
    pub fn getStreamHandler(self: *ConnectionContext, stream_id: u64) ?protocol.handler.StreamHandler {
        return self.stream_handlers.get(stream_id);
    }

    /// 注册 Stream 处理器
    pub fn registerStreamHandler(self: *ConnectionContext, stream_id: u64, handler: protocol.handler.StreamHandler) !void {
        try self.stream_handlers.put(stream_id, handler);
    }

    /// 移除 Stream 处理器
    pub fn removeStreamHandler(self: *ConnectionContext, stream_id: u64) void {
        if (self.stream_handlers.fetchRemove(stream_id)) |kv| {
            kv.value.deinit();
        }
    }
};

/// 业务层连接管理器
/// 负责维护所有活跃连接的生命周期
pub const ConnectionManager = struct {
    allocator: std.mem.Allocator,
    // C 指针 -> Context
    // 使用 picoquic_cnx_t* 作为键，它是全局唯一且稳定的
    contexts: std.AutoHashMap(quic.c.QuicCnx, *ConnectionContext),

    // 注意：在 Thread-per-Core 架构中，ConnectionManager 是线程局部的，
    // 只会被当前 EventLoop 所在的线程访问，因此不需要互斥锁。
    // 如果需要跨线程访问（如 Admin API），应通过消息传递机制。

    pub fn init(allocator: std.mem.Allocator) ConnectionManager {
        return .{
            .allocator = allocator,
            .contexts = std.AutoHashMap(quic.c.QuicCnx, *ConnectionContext).init(allocator),
        };
    }

    pub fn deinit(self: *ConnectionManager) void {
        var it = self.contexts.valueIterator();
        while (it.next()) |ctx| {
            ctx.*.deinit();
            self.allocator.destroy(ctx.*);
        }
        self.contexts.deinit();
    }

    /// 注册新连接
    pub fn add(self: *ConnectionManager, conn: *QUICConnection, gateway_ctx: ?*anyopaque) !*ConnectionContext {
        const ctx = try self.allocator.create(ConnectionContext);
        ctx.* = ConnectionContext.init(self.allocator, conn.inner);
        ctx.gateway_ctx = gateway_ctx;

        try self.contexts.put(conn.inner, ctx);
        return ctx;
    }

    /// 移除连接
    pub fn remove(self: *ConnectionManager, conn: *QUICConnection) void {
        if (self.contexts.fetchRemove(conn.inner)) |kv| {
            kv.value.deinit();
            self.allocator.destroy(kv.value);
        }
    }

    /// 获取连接上下文
    pub fn get(self: *ConnectionManager, conn: *QUICConnection) ?*ConnectionContext {
        return self.contexts.get(conn.inner);
    }
};
