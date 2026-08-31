//! WSS listener 使用的 RFC 6455 子集。
//!
//! 这里只实现服务端需要的纯字节状态机：严格 Upgrade、client masking、控制帧与
//! binary message 分片。TLS socket 和 libxev 生命周期在 listener 层处理。把解析器
//! 独立出来后，畸形输入无需真实网络即可穷尽测试。

const std = @import("std");

pub const path = "/lyune/v2";
pub const subprotocol = "lyune.v2";
pub const max_http_head_size: usize = 8 * 1024;
const websocket_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub const UpgradeRequest = struct {
    key: []const u8,
    origin: ?[]const u8,
    host: []const u8,
    consumed: usize,
};

pub const OriginPolicy = struct {
    allowed: []const []const u8,
    /// 原生非浏览器客户端可能没有 Origin。该降级必须由配置显式打开。
    allow_missing: bool = false,

    pub fn allows(self: OriginPolicy, origin: ?[]const u8) bool {
        const value = origin orelse return self.allow_missing;
        for (self.allowed) |candidate| {
            if (std.mem.eql(u8, candidate, value)) return true;
        }
        return false;
    }
};

pub const UpgradeError = error{
    NeedMore,
    HeaderTooLarge,
    MalformedRequest,
    WrongMethodOrVersion,
    WrongPath,
    MissingHost,
    DuplicateHost,
    MissingUpgrade,
    MissingConnectionUpgrade,
    MissingWebSocketKey,
    DuplicateWebSocketKey,
    InvalidWebSocketKey,
    WrongWebSocketVersion,
    DuplicateWebSocketVersion,
    MissingSubprotocol,
    DuplicateOrigin,
};

/// 解析一份完整或部分 HTTP/1.1 Upgrade head。返回切片借用 `input`。
pub fn parseUpgrade(input: []const u8) UpgradeError!UpgradeRequest {
    if (input.len > max_http_head_size and std.mem.indexOf(u8, input, "\r\n\r\n") == null) {
        return error.HeaderTooLarge;
    }
    const end = std.mem.indexOf(u8, input, "\r\n\r\n") orelse return error.NeedMore;
    const consumed = end + 4;
    if (consumed > max_http_head_size) return error.HeaderTooLarge;
    const head = input[0..end];

    const first_end = std.mem.indexOf(u8, head, "\r\n") orelse return error.MalformedRequest;
    const request_line = head[0..first_end];
    var request_parts = std.mem.splitScalar(u8, request_line, ' ');
    const method = request_parts.next() orelse return error.MalformedRequest;
    const target = request_parts.next() orelse return error.MalformedRequest;
    const http_version = request_parts.next() orelse return error.MalformedRequest;
    if (request_parts.next() != null) return error.MalformedRequest;
    if (!std.mem.eql(u8, method, "GET") or !std.mem.eql(u8, http_version, "HTTP/1.1")) {
        return error.WrongMethodOrVersion;
    }
    if (!std.mem.eql(u8, target, path)) return error.WrongPath;

    var host: ?[]const u8 = null;
    var key: ?[]const u8 = null;
    var origin: ?[]const u8 = null;
    var upgrade = false;
    var connection_upgrade = false;
    var version_13 = false;
    var version_seen = false;
    var protocol_match = false;

    var lines = std.mem.splitSequence(u8, head[first_end + 2 ..], "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == ' ' or line[0] == '\t') return error.MalformedRequest;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedRequest;
        const name = line[0..colon];
        const value = trimOws(line[colon + 1 ..]);
        if (!validHeaderName(name) or !validHeaderValue(value)) return error.MalformedRequest;

        if (std.ascii.eqlIgnoreCase(name, "host")) {
            if (host != null) return error.DuplicateHost;
            host = value;
        } else if (std.ascii.eqlIgnoreCase(name, "upgrade")) {
            upgrade = upgrade or containsToken(value, "websocket");
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            connection_upgrade = connection_upgrade or containsToken(value, "upgrade");
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-key")) {
            if (key != null) return error.DuplicateWebSocketKey;
            key = value;
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-version")) {
            if (version_seen) return error.DuplicateWebSocketVersion;
            version_seen = true;
            version_13 = std.mem.eql(u8, value, "13");
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-protocol")) {
            protocol_match = protocol_match or containsToken(value, subprotocol);
        } else if (std.ascii.eqlIgnoreCase(name, "origin")) {
            if (origin != null) return error.DuplicateOrigin;
            origin = value;
        }
    }

    const actual_host = host orelse return error.MissingHost;
    if (actual_host.len == 0) return error.MissingHost;
    if (!upgrade) return error.MissingUpgrade;
    if (!connection_upgrade) return error.MissingConnectionUpgrade;
    const actual_key = key orelse return error.MissingWebSocketKey;
    if (!validKey(actual_key)) return error.InvalidWebSocketKey;
    if (!version_13) return error.WrongWebSocketVersion;
    if (!protocol_match) return error.MissingSubprotocol;
    return .{ .key = actual_key, .origin = origin, .host = actual_host, .consumed = consumed };
}

/// 生成 101 响应，并固定回显 `lyune.v2` 子协议。输出上限当前为 173 字节。
pub fn buildUpgradeResponse(out: []u8, key: []const u8) ![]const u8 {
    if (!validKey(key)) return error.InvalidWebSocketKey;
    var sha1 = std.crypto.hash.Sha1.init(.{});
    sha1.update(key);
    sha1.update(websocket_guid);
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    sha1.final(&digest);
    var accept: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&accept, &digest);
    return std.fmt.bufPrint(
        out,
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n" ++
            "Sec-WebSocket-Protocol: " ++ subprotocol ++ "\r\n\r\n",
        .{accept},
    );
}

fn validKey(key: []const u8) bool {
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(key) catch return false;
    if (decoded_len != 16) return false;
    var decoded: [16]u8 = undefined;
    std.base64.standard.Decoder.decode(&decoded, key) catch return false;
    return true;
}

fn trimOws(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t");
}

fn containsToken(value: []const u8, expected: []const u8) bool {
    var tokens = std.mem.splitScalar(u8, value, ',');
    while (tokens.next()) |raw| {
        if (std.ascii.eqlIgnoreCase(trimOws(raw), expected)) return true;
    }
    return false;
}

fn validHeaderName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", byte) != null)) {
            return false;
        }
    }
    return true;
}

fn validHeaderValue(value: []const u8) bool {
    for (value) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n' or (byte < 0x20 and byte != '\t')) return false;
    }
    return true;
}

pub const Opcode = enum(u4) {
    continuation = 0x0,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
};

pub const Frame = struct {
    opcode: Opcode,
    fin: bool,
    payload: []u8,
};

pub const ParsedFrame = struct {
    frame: Frame,
    consumed: usize,
};

pub const FrameError = error{
    NeedMore,
    ReservedBitsSet,
    UnsupportedOpcode,
    ClientFrameNotMasked,
    NonCanonicalLength,
    PayloadTooLarge,
    FragmentedControlFrame,
    InvalidControlPayload,
};

/// 从 TCP 累积缓冲的开头解出一个客户端 frame，并就地解除 masking。
pub fn parseClientFrame(input: []u8, max_payload: usize) FrameError!ParsedFrame {
    if (input.len < 2) return error.NeedMore;
    const first = input[0];
    const second = input[1];
    const fin = first & 0x80 != 0;
    if (first & 0x70 != 0) return error.ReservedBitsSet;
    const opcode: Opcode = switch (first & 0x0F) {
        0x0 => .continuation,
        0x2 => .binary,
        0x8 => .close,
        0x9 => .ping,
        0xA => .pong,
        else => return error.UnsupportedOpcode,
    };
    if (second & 0x80 == 0) return error.ClientFrameNotMasked;

    var offset: usize = 2;
    var payload_len: u64 = second & 0x7F;
    if (payload_len == 126) {
        if (input.len < offset + 2) return error.NeedMore;
        payload_len = std.mem.readInt(u16, input[offset..][0..2], .big);
        offset += 2;
        if (payload_len < 126) return error.NonCanonicalLength;
    } else if (payload_len == 127) {
        if (input.len < offset + 8) return error.NeedMore;
        payload_len = std.mem.readInt(u64, input[offset..][0..8], .big);
        offset += 8;
        if (payload_len <= std.math.maxInt(u16) or payload_len >> 63 != 0) return error.NonCanonicalLength;
    }
    if (payload_len > max_payload or payload_len > std.math.maxInt(usize)) return error.PayloadTooLarge;
    if (@intFromEnum(opcode) >= 0x8) {
        if (!fin) return error.FragmentedControlFrame;
        if (payload_len > 125 or (opcode == .close and payload_len == 1)) return error.InvalidControlPayload;
    }
    if (input.len < offset + 4) return error.NeedMore;
    const mask = input[offset..][0..4].*;
    offset += 4;
    const len: usize = @intCast(payload_len);
    if (input.len < offset + len) return error.NeedMore;
    const payload = input[offset .. offset + len];
    for (payload, 0..) |*byte, index| byte.* ^= mask[index & 3];
    return .{ .frame = .{ .opcode = opcode, .fin = fin, .payload = payload }, .consumed = offset + len };
}

/// 服务端 frame 不使用 masking。返回写入 `out` 的头部切片，payload 由调用者随后发送。
pub fn encodeServerHeader(out: *[10]u8, opcode: Opcode, fin: bool, payload_len: usize) ![]const u8 {
    if (@intFromEnum(opcode) >= 0x8 and (!fin or payload_len > 125)) return error.InvalidControlPayload;
    out[0] = (if (fin) @as(u8, 0x80) else 0) | @intFromEnum(opcode);
    if (payload_len <= 125) {
        out[1] = @intCast(payload_len);
        return out[0..2];
    }
    if (payload_len <= std.math.maxInt(u16)) {
        out[1] = 126;
        std.mem.writeInt(u16, out[2..4], @intCast(payload_len), .big);
        return out[0..4];
    }
    out[1] = 127;
    std.mem.writeInt(u64, out[2..10], payload_len, .big);
    return out[0..10];
}

pub const Message = union(enum) {
    binary: []const u8,
    close: []const u8,
    ping: []const u8,
    pong: []const u8,
    incomplete,
};

pub const MessageError = error{
    UnexpectedContinuation,
    InterleavedDataMessage,
    MessageTooLarge,
};

/// 在控制帧可插入任意分片之间的前提下，重组一条 binary message。
pub const MessageAssembler = struct {
    scratch: []u8,
    len: usize = 0,
    fragmented: bool = false,

    pub fn init(scratch: []u8) MessageAssembler {
        return .{ .scratch = scratch };
    }

    pub fn accept(self: *MessageAssembler, frame: Frame) MessageError!Message {
        switch (frame.opcode) {
            .binary => {
                if (self.fragmented) return error.InterleavedDataMessage;
                if (frame.fin) return .{ .binary = frame.payload };
                self.fragmented = true;
                self.len = 0;
                try self.append(frame.payload);
                return .incomplete;
            },
            .continuation => {
                if (!self.fragmented) return error.UnexpectedContinuation;
                try self.append(frame.payload);
                if (!frame.fin) return .incomplete;
                self.fragmented = false;
                const message = self.scratch[0..self.len];
                self.len = 0;
                return .{ .binary = message };
            },
            .close => return .{ .close = frame.payload },
            .ping => return .{ .ping = frame.payload },
            .pong => return .{ .pong = frame.payload },
        }
    }

    fn append(self: *MessageAssembler, bytes: []const u8) MessageError!void {
        if (bytes.len > self.scratch.len - self.len) return error.MessageTooLarge;
        @memcpy(self.scratch[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }
};

test "Upgrade parser validates key protocol and Origin policy" {
    const request =
        "GET /lyune/v2 HTTP/1.1\r\n" ++
        "Host: gateway.example.com\r\n" ++
        "Upgrade: WebSocket\r\n" ++
        "Connection: keep-alive, Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Protocol: other, lyune.v2\r\n" ++
        "Origin: https://chat.example.com\r\n\r\n" ++
        "next";
    const parsed = try parseUpgrade(request);
    try std.testing.expectEqualStrings("gateway.example.com", parsed.host);
    try std.testing.expectEqualStrings("https://chat.example.com", parsed.origin.?);
    try std.testing.expectEqual(request.len - 4, parsed.consumed);
    const policy = OriginPolicy{ .allowed = &.{"https://chat.example.com"} };
    try std.testing.expect(policy.allows(parsed.origin));
    try std.testing.expect(!policy.allows("https://evil.example"));
    try std.testing.expect(!policy.allows(null));
}

test "Upgrade response matches the RFC 6455 example" {
    var response: [256]u8 = undefined;
    const bytes = try buildUpgradeResponse(&response, "dGhlIHNhbXBsZSBub25jZQ==");
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Sec-WebSocket-Protocol: lyune.v2\r\n") != null);
}

test "Upgrade rejects protocol downgrade and malformed keys" {
    const missing_protocol =
        "GET /lyune/v2 HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n" ++
        "Connection: Upgrade\r\nSec-WebSocket-Key: bad\r\nSec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expectError(error.InvalidWebSocketKey, parseUpgrade(missing_protocol));

    const wrong_path =
        "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Protocol: lyune.v2\r\n\r\n";
    try std.testing.expectError(error.WrongPath, parseUpgrade(wrong_path));

    const duplicate_host =
        "GET /lyune/v2 HTTP/1.1\r\nHost: localhost\r\nHost: attacker.example\r\n" ++
        "Upgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Protocol: lyune.v2\r\n\r\n";
    try std.testing.expectError(error.DuplicateHost, parseUpgrade(duplicate_host));

    const wrong_version =
        "GET /lyune/v2 HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 12, 13\r\n" ++
        "Sec-WebSocket-Protocol: lyune.v2\r\n\r\n";
    try std.testing.expectError(error.WrongWebSocketVersion, parseUpgrade(wrong_version));

    const duplicate_version =
        "GET /lyune/v2 HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: lyune.v2\r\n\r\n";
    try std.testing.expectError(error.DuplicateWebSocketVersion, parseUpgrade(duplicate_version));

    const split_upgrade =
        "GET /lyune/v2 HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nUpgrade: h2c\r\n" ++
        "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: lyune.v2\r\n\r\n";
    _ = try parseUpgrade(split_upgrade);
}

test "client frame parser unmasks binary payload and rejects unmasked input" {
    var frame_bytes = [_]u8{ 0x82, 0x84, 0x37, 0xfa, 0x21, 0x3d, 0x63, 0x9f, 0x52, 0x49 };
    const parsed = try parseClientFrame(&frame_bytes, 64);
    try std.testing.expectEqual(Opcode.binary, parsed.frame.opcode);
    try std.testing.expectEqualStrings("Test", parsed.frame.payload);
    try std.testing.expectEqual(frame_bytes.len, parsed.consumed);

    var unmasked = [_]u8{ 0x82, 0x00 };
    try std.testing.expectError(error.ClientFrameNotMasked, parseClientFrame(&unmasked, 64));
}

test "message assembler permits control frames between binary fragments" {
    var scratch: [32]u8 = undefined;
    var assembler = MessageAssembler.init(&scratch);
    try std.testing.expectEqual(Message.incomplete, try assembler.accept(.{ .opcode = .binary, .fin = false, .payload = @constCast("hel") }));
    const ping = try assembler.accept(.{ .opcode = .ping, .fin = true, .payload = @constCast("?") });
    try std.testing.expectEqualStrings("?", ping.ping);
    const complete = try assembler.accept(.{ .opcode = .continuation, .fin = true, .payload = @constCast("lo") });
    try std.testing.expectEqualStrings("hello", complete.binary);
}

test "server frame headers are unmasked and use canonical lengths" {
    var header: [10]u8 = undefined;
    const small = try encodeServerHeader(&header, .binary, true, 12);
    try std.testing.expectEqualSlices(u8, &.{ 0x82, 12 }, small);
    const medium = try encodeServerHeader(&header, .binary, true, 126);
    try std.testing.expectEqualSlices(u8, &.{ 0x82, 126, 0, 126 }, medium);
}
