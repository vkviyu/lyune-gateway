//! 单条 WSS 会话的有界明文发送队列。
//!
//! 队列保存已经封好 WebSocket frame 的字节，TLS driver 只需 `peek/consume`。字节环与
//! record 描述符都在连接建立时一次分配，运行期不扩容：可靠 record 放不下时返回
//! `QueueFull`，上层关闭**这一条**慢会话；ephemeral 放不下则在入队前明确丢弃。

const std = @import("std");
const envelope = @import("envelope.zig");
const websocket = @import("websocket.zig");

pub const Delivery = enum {
    reliable,
    ephemeral,
};

pub const EnqueueOutcome = enum {
    queued,
    dropped,
};

pub const Error = error{
    QueueFull,
    RecordTooLarge,
    InvalidRecord,
};

const Entry = struct {
    start: usize = 0,
    len: usize = 0,
    sent: usize = 0,
};

pub const Queue = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    entries: []Entry,
    byte_write: usize = 0,
    bytes_used: usize = 0,
    entry_head: usize = 0,
    entry_count: usize = 0,

    pub fn init(allocator: std.mem.Allocator, byte_capacity: usize, record_capacity: usize) !Queue {
        if (byte_capacity == 0 or record_capacity == 0) return error.InvalidCapacity;
        const bytes = try allocator.alloc(u8, byte_capacity);
        errdefer allocator.free(bytes);
        const entries = try allocator.alloc(Entry, record_capacity);
        @memset(entries, .{});
        return .{ .allocator = allocator, .bytes = bytes, .entries = entries };
    }

    pub fn deinit(self: *Queue) void {
        self.allocator.free(self.entries);
        self.allocator.free(self.bytes);
        self.* = undefined;
    }

    pub fn enqueueRecord(self: *Queue, record: envelope.Record, delivery: Delivery) Error!EnqueueOutcome {
        var ws_header: [10]u8 = undefined;
        const message_len = envelope.header_size + record.payload.len;
        const ws_head = websocket.encodeServerHeader(&ws_header, .binary, true, message_len) catch return error.InvalidRecord;
        var record_header: [envelope.header_size]u8 = undefined;
        envelope.encodeHeader(&record_header, record) catch return error.InvalidRecord;
        const total = ws_head.len + record_header.len + record.payload.len;
        if (total > self.bytes.len) return if (delivery == .ephemeral) .dropped else error.RecordTooLarge;
        if (!self.hasCapacity(total, 1)) return if (delivery == .ephemeral) .dropped else error.QueueFull;
        self.enqueuePieces(&.{ ws_head, &record_header, record.payload }, total);
        return .queued;
    }

    /// 入队尚未进入 WebSocket framing 的明文字节。
    ///
    /// 目前只用于 TLS 建立后的 HTTP 101 响应。它仍占用一个 record 描述符，因此和
    /// 后续 WebSocket 消息共享完全相同的背压与顺序保证；调用者不能借此绕过队列上限。
    pub fn enqueueRaw(self: *Queue, payload: []const u8) Error!void {
        if (payload.len > self.bytes.len) return error.RecordTooLarge;
        if (!self.hasCapacity(payload.len, 1)) return error.QueueFull;
        self.enqueuePieces(&.{payload}, payload.len);
    }

    /// RESET + STOP 是一个不可拆的本地状态收敛动作。只够放一条时不能留下半套语义。
    pub fn enqueueDiscard(self: *Queue, stream_id: u64, app_error_code: u32) Error!void {
        const reset = envelope.Record{ .record_type = .reset, .stream_id = stream_id, .app_error_code = app_error_code };
        const stop = envelope.Record{ .record_type = .stop, .stream_id = stream_id, .app_error_code = app_error_code };
        const first_len = encodedRecordSize(reset) catch return error.InvalidRecord;
        const second_len = encodedRecordSize(stop) catch return error.InvalidRecord;
        if (!self.hasCapacity(first_len + second_len, 2)) return error.QueueFull;
        self.enqueueRecordUnchecked(reset);
        self.enqueueRecordUnchecked(stop);
    }

    /// WebSocket ping/pong/close 控制帧不套 Lyune envelope。
    pub fn enqueueControl(self: *Queue, opcode: websocket.Opcode, payload: []const u8) Error!void {
        var header: [10]u8 = undefined;
        const head = websocket.encodeServerHeader(&header, opcode, true, payload.len) catch return error.InvalidRecord;
        const total = head.len + payload.len;
        if (total > self.bytes.len) return error.RecordTooLarge;
        if (!self.hasCapacity(total, 1)) return error.QueueFull;
        self.enqueuePieces(&.{ head, payload }, total);
    }

    /// 当前最老 record 尚未发送的第一段连续内存；环尾处会自然拆成两次 TLS write。
    pub fn peek(self: *const Queue) ?[]const u8 {
        if (self.entry_count == 0) return null;
        const entry = self.entries[self.entry_head];
        const position = (entry.start + entry.sent) % self.bytes.len;
        const remaining = entry.len - entry.sent;
        return self.bytes[position .. position + @min(remaining, self.bytes.len - position)];
    }

    /// 确认 TLS 已消费 `count` 个明文字节。
    pub fn consume(self: *Queue, count: usize) void {
        const available = self.peek() orelse return;
        std.debug.assert(count <= available.len);
        var entry = &self.entries[self.entry_head];
        entry.sent += count;
        self.bytes_used -= count;
        if (entry.sent == entry.len) {
            entry.* = .{};
            self.entry_head = (self.entry_head + 1) % self.entries.len;
            self.entry_count -= 1;
        }
    }

    pub fn queuedBytes(self: *const Queue) usize {
        return self.bytes_used;
    }

    pub fn queuedRecords(self: *const Queue) usize {
        return self.entry_count;
    }

    fn hasCapacity(self: *const Queue, byte_count: usize, record_count: usize) bool {
        return byte_count <= self.bytes.len - self.bytes_used and
            record_count <= self.entries.len - self.entry_count;
    }

    fn enqueueRecordUnchecked(self: *Queue, record: envelope.Record) void {
        var ws_header: [10]u8 = undefined;
        const message_len = envelope.header_size + record.payload.len;
        const ws_head = websocket.encodeServerHeader(&ws_header, .binary, true, message_len) catch unreachable;
        var record_header: [envelope.header_size]u8 = undefined;
        envelope.encodeHeader(&record_header, record) catch unreachable;
        self.enqueuePieces(&.{ ws_head, &record_header, record.payload }, ws_head.len + message_len);
    }

    fn enqueuePieces(self: *Queue, pieces: []const []const u8, total: usize) void {
        std.debug.assert(self.hasCapacity(total, 1));
        const entry_index = (self.entry_head + self.entry_count) % self.entries.len;
        self.entries[entry_index] = .{ .start = self.byte_write, .len = total };
        self.entry_count += 1;
        self.bytes_used += total;
        for (pieces) |piece| self.writeBytes(piece);
    }

    fn writeBytes(self: *Queue, input: []const u8) void {
        var rest = input;
        while (rest.len != 0) {
            const count = @min(rest.len, self.bytes.len - self.byte_write);
            @memcpy(self.bytes[self.byte_write..][0..count], rest[0..count]);
            self.byte_write = (self.byte_write + count) % self.bytes.len;
            rest = rest[count..];
        }
    }
};

fn encodedRecordSize(record: envelope.Record) !usize {
    var header: [10]u8 = undefined;
    envelope.validate(record) catch return error.InvalidRecord;
    const message_len = envelope.header_size + record.payload.len;
    const ws_header = websocket.encodeServerHeader(&header, .binary, true, message_len) catch return error.InvalidRecord;
    return ws_header.len + message_len;
}

test "queue owns record bytes and exposes complete WebSocket message" {
    var queue = try Queue.init(std.testing.allocator, 256, 4);
    defer queue.deinit();
    var payload = [_]u8{ 1, 2, 3 };
    try std.testing.expectEqual(EnqueueOutcome.queued, try queue.enqueueRecord(.{
        .record_type = .stream,
        .fin = true,
        .stream_id = 4,
        .payload = &payload,
    }, .reliable));
    payload[0] = 99;

    var wire: [256]u8 = undefined;
    var len: usize = 0;
    while (queue.peek()) |part| {
        @memcpy(wire[len..][0..part.len], part);
        len += part.len;
        queue.consume(part.len);
    }
    // 2-byte WS header, then the 20-byte envelope; payload was copied before mutation.
    try std.testing.expectEqual(@as(u8, 0x82), wire[0]);
    const decoded = try envelope.decode(wire[2..len]);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, decoded.payload);
}

test "ephemeral drops before enqueue while reliable overflow is explicit" {
    var queue = try Queue.init(std.testing.allocator, 48, 1);
    defer queue.deinit();
    try std.testing.expectEqual(EnqueueOutcome.queued, try queue.enqueueRecord(.{
        .record_type = .stream,
        .stream_id = 4,
        .payload = "first",
    }, .reliable));
    try std.testing.expectEqual(EnqueueOutcome.dropped, try queue.enqueueRecord(.{
        .record_type = .ephemeral,
        .payload = "typing",
    }, .ephemeral));
    try std.testing.expectError(error.QueueFull, queue.enqueueRecord(.{
        .record_type = .stream,
        .stream_id = 8,
        .payload = "second",
    }, .reliable));
    try std.testing.expectEqual(@as(usize, 1), queue.queuedRecords());
}

test "discard enqueue is atomic" {
    var queue = try Queue.init(std.testing.allocator, 128, 1);
    defer queue.deinit();
    try std.testing.expectError(error.QueueFull, queue.enqueueDiscard(4, 7));
    try std.testing.expectEqual(@as(usize, 0), queue.queuedRecords());
    try std.testing.expectEqual(@as(usize, 0), queue.queuedBytes());
}

test "byte ring wraps without exposing overwritten data" {
    var queue = try Queue.init(std.testing.allocator, 64, 3);
    defer queue.deinit();
    _ = try queue.enqueueRecord(.{ .record_type = .stream, .stream_id = 4, .payload = "abcdefgh" }, .reliable);
    while (queue.peek()) |part| queue.consume(part.len);
    _ = try queue.enqueueRecord(.{ .record_type = .stream, .stream_id = 8, .payload = "wrap-around-data" }, .reliable);

    var wire: [64]u8 = undefined;
    var len: usize = 0;
    while (queue.peek()) |part| {
        @memcpy(wire[len..][0..part.len], part);
        len += part.len;
        queue.consume(part.len);
    }
    const decoded = try envelope.decode(wire[2..len]);
    try std.testing.expectEqualStrings("wrap-around-data", decoded.payload);
}

test "raw bytes share queue ordering and capacity" {
    var queue = try Queue.init(std.testing.allocator, 64, 2);
    defer queue.deinit();
    try queue.enqueueRaw("HTTP/1.1 101\r\n\r\n");
    _ = try queue.enqueueRecord(.{ .record_type = .ephemeral, .payload = "ready" }, .reliable);

    try std.testing.expectEqualStrings("HTTP/1.1 101\r\n\r\n", queue.peek().?);
    queue.consume(queue.peek().?.len);
    try std.testing.expectEqual(@as(u8, 0x82), queue.peek().?[0]);
}
