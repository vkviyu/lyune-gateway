//! QUIC Stream 封装
//!
//! 封装 QUIC Stream 的读写操作。

const std = @import("std");
const quic_c = @import("c.zig");
const Connection = @import("connection.zig").Connection;

pub const Stream = struct {
    /// 所属连接
    connection: *Connection,

    /// Stream ID
    id: u64,

    /// 用户上下文
    user_ctx: ?*anyopaque = null,

    /// 是否已结束
    finished: bool = false,

    /// 创建新的 Stream
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
