//! QUIC 连接封装
//!
//! 封装单个 QUIC 连接的操作。

const std = @import("std");
const quic_c = @import("c.zig");

pub const Connection = struct {
    /// inner 存储 picoquic 的 C 连接指针（picoquic_cnx_t*）。这是对 C 结构体的包装
    inner: quic_c.QuicCnx,

    /// 可选的用户数据指针，用于关联自定义数据到连接上。?*anyopaque 是 Zig 的可空任意指针类型。
    user_ctx: ?*anyopaque = null,

    /// 工厂方法：把 C 指针包装成 Zig 的 Connection 结构
    pub fn fromRaw(cnx: quic_c.QuicCnx) Connection {
        return .{ .inner = cnx };
    }

    /// 获取连接状态
    /// 
    /// 调用 C 函数获取链接状态，然后用 @enumFromInt 把整数转换为我们定义的枚举类型
    pub fn getState(self: *const Connection) quic_c.ConnectionState {
        const state = quic_c.c.picoquic_get_cnx_state(self.inner);
        return @enumFromInt(state);
    }

    /// 连接是否已建立
    pub fn isConnected(self: *const Connection) bool {
        return self.getState().isConnected();
    }

    /// 连接是否已断开
    pub fn isDisconnected(self: *const Connection) bool {
        return self.getState().isDisconnected();
    }

    /// 获取本地连接 ID
    pub fn getLocalConnectionId(self: *const Connection) quic_c.ConnectionId {
        return quic_c.c.picoquic_get_local_cnxid(self.inner);
    }

    /// 获取远端连接 ID
    pub fn getRemoteConnectionId(self: *const Connection) quic_c.ConnectionId {
        return quic_c.c.picoquic_get_remote_cnxid(self.inner);
    }

    /// 获取连接 ID 的字节表示
    /// 
    /// 直接调用 picoquic C 函数获取连接 ID
    pub fn getConnectionIdBytes(self: *const Connection) []const u8 {
        const cid = self.getLocalConnectionId();
        return cid.id[0..cid.id_len];
    }

    /// 向 stream 写入数据
    pub fn streamWrite(
        self: *Connection,
        stream_id: u64,
        data: []const u8,
        is_fin: bool,
    ) Error!void {
        const rc = quic_c.c.picoquic_add_to_stream(
            self.inner,
            stream_id,
            data.ptr,
            data.len,
            if (is_fin) 1 else 0, // bool 转 C int
        );
        if (rc != 0) {
            return Error.StreamWriteFailed;
        }
    }

    /// 标记 stream 为活跃状态
    /// 
    /// picoquic 会在下次发送时处理该 stream
    pub fn markStreamActive(
        self: *Connection,
        stream_id: u64,
        is_active: bool,
        context: ?*anyopaque,
    ) Error!void {
        const rc = quic_c.c.picoquic_mark_active_stream(
            self.inner,
            stream_id,
            if (is_active) 1 else 0,
            context,
        );
        if (rc != 0) {
            return Error.MarkStreamFailed;
        }
    }

    /// 关闭 stream
    /// 
    /// 发送 RESET_STREAM 帧关闭 stream
    pub fn closeStream(self: *Connection, stream_id: u64) void {
        _ = quic_c.c.picoquic_reset_stream(self.inner, stream_id, 0);
    }

    /// 关闭连接
    pub fn close(self: *Connection) void {
        _ = quic_c.c.picoquic_close(self.inner, 0);
    }

    /// 设置连接的回调函数，用于接收事件通知
    pub fn setCallback(
        self: *Connection,
        callback: quic_c.c.picoquic_stream_data_cb_fn,
        context: ?*anyopaque,
    ) void {
        quic_c.c.picoquic_set_callback(self.inner, callback, context);
    }

    /// 获取连接所属的 QUIC 上下文（Server/Client 实例）
    pub fn getQuicContext(self: *const Connection) quic_c.QuicCtx {
        return quic_c.c.picoquic_get_quic_ctx(self.inner);
    }

    pub const Error = error{
        StreamWriteFailed,
        MarkStreamFailed,
        ConnectionClosed,
    };
};

/// 连接管理器
/// 用于管理多个连接，通过 Connection ID 查找
pub fn ConnectionManager(comptime Context: type) type {
    return struct {
        const Self = @This();
        // 存储分配器
        allocator: std.mem.Allocator,
        // AutoHashMap 是自动选择哈希函数的哈希表
        connections: std.AutoHashMap(u64, *ManagedConnection),

        /// 嵌套结构体，包含连接和用户上下文
        pub const ManagedConnection = struct {
            connection: Connection,
            context: Context,
        };

        /// 初始化连接管理器
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .connections = std.AutoHashMap(u64, *ManagedConnection).init(allocator),
            };
        }

        /// 销毁连接管理器：遍历释放所有连接，然后释放哈希表
        pub fn deinit(self: *Self) void {
            var iter = self.connections.valueIterator();
            while (iter.next()) |managed| {
                self.allocator.destroy(managed.*);
            }
            self.connections.deinit();
        }

        /// 添加连接
        /// 
        /// 分配新的 ManagedConnection，用 Connection ID 哈希值作为 key 存入哈希表
        pub fn add(self: *Self, conn: Connection, context: Context) !*ManagedConnection {
            const managed = try self.allocator.create(ManagedConnection);
            managed.* = .{
                .connection = conn,
                .context = context,
            };

            const cid_bytes = conn.getConnectionIdBytes();
            const key = hashConnectionId(cid_bytes);
            try self.connections.put(key, managed);

            return managed;
        }

        /// 通过连接 ID 字节查找连接
        pub fn get(self: *Self, cid_bytes: []const u8) ?*ManagedConnection {
            const key = hashConnectionId(cid_bytes);
            return self.connections.get(key);
        }

        /// 释放并移除连接
        pub fn remove(self: *Self, cid_bytes: []const u8) void {
            const key = hashConnectionId(cid_bytes);
            if (self.connections.fetchRemove(key)) |entry| {
                self.allocator.destroy(entry.value);
            }
        }

        /// 返回当前管理的连接数
        pub fn count(self: *const Self) usize {
            return self.connections.count();
        }

        /// 简单的哈希函数，把 Connection ID 字节转为 u64。*% 和 +% 是溢出包装运算符（溢出时回绕而不是报错）。
        fn hashConnectionId(cid: []const u8) u64 {
            var hash: u64 = 0;
            for (cid) |byte| {
                hash = hash *% 31 +% byte;
            }
            return hash;
        }
    };
}
