//! QUIC Stream 封装
//!
//! 封装 QUIC Stream 的读写操作。
//!
//! ## 设计说明：Stream 与 Connection 的关系
//!
//! 在 QUIC 协议中，Stream 是在 Connection 上传输数据的逻辑通道。
//! 本模块采用**反向引用（Back Reference）**的设计模式：
//!
//! - **Stream 持有对 Connection 的引用**，而不是 Connection 持有 Stream 列表。
//! - 这种设计准确地表达了"Stream **属于** Connection"的语义，
//!   而非"Connection **包含** Stream"。
//!
//! ### 为什么这样设计？
//!
//! 1. **协议语义**：Stream 不是 Connection 拥有的子对象，
//!    而是在 Connection 上发生的传输通道。Stream 的所有 I/O 操作
//!    都必须通过所属的 Connection 来执行。
//!
//! 2. **底层实现**：picoquic C 库中没有独立的 Stream 对象，
//!    Stream 只是一个数字 ID。所有操作都是 `picoquic_add_to_stream(connection, stream_id, ...)`
//!    的形式。本结构体将 `(Connection*, stream_id)` 打包成一个便捷的操作句柄。
//!
//! 3. **生命周期解耦**：Stream 的创建/销毁由使用者按需管理，
//!    不受 Connection 生命周期的直接约束（但 Connection 关闭后 Stream 自然失效）。
//!
//! 4. **类似设计**：这种模式在系统编程中很常见，
//!    例如 Go Runtime 的 GMP 调度模型中，G/M/P 三者也通过反向引用相互关联，
//!    而非简单的层次包含关系。
//!
//! ### 使用示例
//!
//! ```zig
//! // 创建 Stream（需要已建立的 Connection）
//! var stream = Stream.init(&connection, stream_id);
//!
//! // 写入数据（内部通过 connection 完成）
//! try stream.write("Hello, QUIC!");
//!
//! // 写入并结束
//! try stream.writeAndFinish("Goodbye!");
//! ```

const std = @import("std");
const quic_c = @import("c.zig");
const Connection = @import("connection.zig").Connection;

/// QUIC Stream 操作句柄
///
/// Stream 是 QUIC 协议中在单个 Connection 上多路复用的逻辑数据通道。
/// 本结构体是对 `(Connection, stream_id)` 组合的封装，提供了面向对象风格的 API。
///
/// **重要**：Stream 持有对 Connection 的指针引用，调用者必须确保：
/// - 在 Stream 使用期间，所引用的 Connection 保持有效
/// - Connection 关闭后，不再使用关联的 Stream
pub const Stream = struct {
    /// 所属连接的指针
    ///
    /// Stream 的所有 I/O 操作都委托给此 Connection 执行。
    /// 这是一种**反向引用**设计：Stream 知道自己属于哪个 Connection，
    /// 而非 Connection 维护 Stream 列表。
    connection: *Connection,

    /// QUIC Stream ID
    ///
    /// 64 位无符号整数，低 2 位编码了 Stream 类型：
    /// - bit 0: 0=客户端发起, 1=服务端发起
    /// - bit 1: 0=双向流, 1=单向流
    id: u64,

    /// 用户上下文（可选）
    ///
    /// 允许用户将自定义数据关联到此 Stream，便于在回调中访问。
    user_ctx: ?*anyopaque = null,

    /// 是否已结束
    ///
    /// 当发送 FIN 或调用 close() 后变为 true。
    finished: bool = false,

    /// 创建新的 Stream 操作句柄
    ///
    /// 注意：这只是创建一个 Zig 层面的句柄，不会向对端发送任何数据。
    /// 实际的 Stream 在首次写入数据时由 picoquic 隐式创建。
    pub fn init(connection: *Connection, stream_id: u64) Stream {
        return .{
            .connection = connection,
            .id = stream_id,
        };
    }

    /// 写入数据
    pub fn write(self: *Stream, data: []const u8) !void {
        try self.connection.streamWrite(self.id, data, false);
    }

    /// 写入数据并结束 stream
    pub fn writeAndFinish(self: *Stream, data: []const u8) !void {
        try self.connection.streamWrite(self.id, data, true);
        self.finished = true;
    }

    /// 结束 stream（不发送额外数据）
    pub fn finish(self: *Stream) !void {
        try self.connection.streamWrite(self.id, &[_]u8{}, true);
        self.finished = true;
    }

    /// 关闭 stream（发送 RESET_STREAM）
    pub fn close(self: *Stream) void {
        self.connection.closeStream(self.id);
        self.finished = true;
    }

    /// 标记为活跃
    pub fn markActive(self: *Stream, context: ?*anyopaque) !void {
        try self.connection.markStreamActive(self.id, true, context);
    }

    /// 标记为非活跃
    pub fn markInactive(self: *Stream) !void {
        try self.connection.markStreamActive(self.id, false, null);
    }

    /// 是否是客户端发起的流
    pub fn isClientInitiated(self: *const Stream) bool {
        return (self.id & 1) == 0;
    }

    /// 是否是双向流
    pub fn isBidirectional(self: *const Stream) bool {
        return (self.id & 2) == 0;
    }
};

/// Stream 类型
pub const StreamType = enum {
    /// 客户端发起的双向流
    client_bidi,
    /// 服务端发起的双向流
    server_bidi,
    /// 客户端发起的单向流
    client_uni,
    /// 服务端发起的单向流
    server_uni,

    pub fn fromStreamId(stream_id: u64) StreamType {
        const type_bits: u2 = @truncate(stream_id);
        return switch (type_bits) {
            0b00 => .client_bidi,
            0b01 => .server_bidi,
            0b10 => .client_uni,
            0b11 => .server_uni,
        };
    }
};

/// Stream 事件
pub const StreamEvent = union(enum) {
    /// 收到数据
    data: struct {
        stream_id: u64,
        data: []const u8,
        is_fin: bool,
    },
    /// Stream 重置
    reset: struct {
        stream_id: u64,
        error_code: u64,
    },
    /// 收到 STOP_SENDING
    stop_sending: struct {
        stream_id: u64,
        error_code: u64,
    },
};
