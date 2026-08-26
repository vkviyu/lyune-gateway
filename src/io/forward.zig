//! 节点间 QUIC 原始包转发隧道。
//!
//! 隧道只搬运原始 UDP 数据报和客户端地址，不复制任何 QUIC 连接状态。
//! request 把误投递包送到 CID owner，response 把 owner 回包送回有状态 L4 LB 的原入口。
//! 报文使用 HMAC-SHA256 认证，并携带方向、源/目标节点与 Worker、随机会话和单调序号。
//! 接收线程先做目标校验和滑动窗口防重放，再通过 LocalPacketRouter 投递目标 Worker。

const std = @import("std");
const handoff = @import("handoff.zig");
const foundation = @import("../foundation/mod.zig");
const net = foundation.net;

/// 线路魔数 "LF"（Lyune Forward）。
pub const magic: u16 = 0x4c46;
/// 首次发布的双向转发线路格式版本。
pub const version: u8 = 1;
/// HMAC-SHA256 认证标签长度。
pub const tag_size: usize = std.crypto.auth.hmac.sha2.HmacSha256.mac_length;
/// 预共享密钥的最低配置长度。
pub const min_secret_size: usize = 16;
/// 单个已封装 UDP 数据报的缓冲上限。
pub const max_datagram_size: usize = 2200;
const fixed_header_size: usize = 32;
const replay_cache_capacity: usize = 128;
const replay_window_bits: u64 = 64;

/// 通过认证的隧道报文视图；payload 直接借用输入缓冲区。
pub const Decoded = struct {
    kind: handoff.TunnelKind,
    source_node_id: u16,
    source_worker_id: u8,
    target_node_id: u16,
    target_worker_id: u8,
    session_id: u64,
    sequence: u64,
    client_address: net.Address,
    payload: []const u8,
};

const ReplayWindow = struct {
    source_node_id: u16,
    session_id: u64,
    highest_sequence: u64,
    seen: u64,
};

/// 转发报文编码、严格解码与认证可能返回的错误。
pub const CodecError = error{
    BufferTooSmall,
    PacketTooLarge,
    SecretTooShort,
    MessageTooShort,
    BadMagic,
    BadVersion,
    InvalidIdentity,
    BadKind,
    BadAddressFamily,
    InvalidTag,
    TrailingBytes,
};

/// 编码并认证一个转发数据报。节点、会话和序号均纳入 HMAC，不能被中途改写。
pub fn encode(
    kind: handoff.TunnelKind,
    source_node_id: u16,
    source_worker_id: u8,
    target_node_id: u16,
    target_worker_id: u8,
    session_id: u64,
    sequence: u64,
    client_address: net.Address,
    payload: []const u8,
    secret: []const u8,
    out: []u8,
) CodecError![]u8 {
    if (secret.len < min_secret_size) return error.SecretTooShort;
    if (source_node_id == 0 or target_node_id == 0 or session_id == 0 or sequence == 0) return error.InvalidIdentity;
    if (payload.len > handoff.max_packet_size) return error.PacketTooLarge;
    const address_len: usize = switch (client_address) {
        .ip4 => 4,
        .ip6 => 16,
    };
    const total = fixed_header_size + address_len + payload.len + tag_size;
    if (out.len < total) return error.BufferTooSmall;

    std.mem.writeInt(u16, out[0..2], magic, .big);
    out[2] = version;
    out[3] = target_worker_id;
    out[4] = switch (client_address) {
        .ip4 => 4,
        .ip6 => 6,
    };
    const port = switch (client_address) {
        .ip4 => |value| value.port,
        .ip6 => |value| value.port,
    };
    std.mem.writeInt(u16, out[5..7], port, .big);
    std.mem.writeInt(u16, out[7..9], @intCast(payload.len), .big);
    std.mem.writeInt(u16, out[9..11], source_node_id, .big);
    std.mem.writeInt(u16, out[11..13], target_node_id, .big);
    std.mem.writeInt(u64, out[13..21], session_id, .big);
    std.mem.writeInt(u64, out[21..29], sequence, .big);
    out[29] = @intFromEnum(kind);
    out[30] = source_worker_id;
    out[31] = 0;

    var offset: usize = fixed_header_size;
    switch (client_address) {
        .ip4 => |value| @memcpy(out[offset..][0..4], &value.bytes),
        .ip6 => |value| @memcpy(out[offset..][0..16], &value.bytes),
    }
    offset += address_len;
    @memcpy(out[offset..][0..payload.len], payload);
    offset += payload.len;

    var tag: [tag_size]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&tag, out[0..offset], secret);
    @memcpy(out[offset..][0..tag_size], &tag);
    return out[0 .. offset + tag_size];
}

/// 严格校验并解码转发数据报。此函数验证 HMAC，但防重放由 Tunnel 接收线程执行。
pub fn decode(bytes: []const u8, secret: []const u8) CodecError!Decoded {
    if (secret.len < min_secret_size) return error.SecretTooShort;
    if (bytes.len < fixed_header_size + 4 + tag_size) return error.MessageTooShort;
    if (std.mem.readInt(u16, bytes[0..2], .big) != magic) return error.BadMagic;
    if (bytes[2] != version) return error.BadVersion;
    if (bytes[31] != 0) return error.BadVersion;
    const kind: handoff.TunnelKind = switch (bytes[29]) {
        @intFromEnum(handoff.TunnelKind.request) => .request,
        @intFromEnum(handoff.TunnelKind.response) => .response,
        else => return error.BadKind,
    };

    const source_node_id = std.mem.readInt(u16, bytes[9..11], .big);
    const target_node_id = std.mem.readInt(u16, bytes[11..13], .big);
    const session_id = std.mem.readInt(u64, bytes[13..21], .big);
    const sequence = std.mem.readInt(u64, bytes[21..29], .big);
    if (source_node_id == 0 or target_node_id == 0 or session_id == 0 or sequence == 0) return error.InvalidIdentity;

    const address_len: usize = switch (bytes[4]) {
        4 => 4,
        6 => 16,
        else => return error.BadAddressFamily,
    };
    const payload_len = std.mem.readInt(u16, bytes[7..9], .big);
    const payload_offset = fixed_header_size + address_len;
    const authenticated_len = payload_offset + payload_len;
    if (authenticated_len + tag_size != bytes.len) return error.TrailingBytes;

    var expected: [tag_size]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&expected, bytes[0..authenticated_len], secret);
    var received: [tag_size]u8 = undefined;
    @memcpy(&received, bytes[authenticated_len..]);
    if (!std.crypto.timing_safe.eql([tag_size]u8, expected, received)) return error.InvalidTag;

    const port = std.mem.readInt(u16, bytes[5..7], .big);
    const address = switch (bytes[4]) {
        4 => net.initIp4(bytes[fixed_header_size..][0..4].*, port),
        6 => net.initIp6(bytes[fixed_header_size..][0..16].*, port),
        else => unreachable,
    };
    return .{
        .kind = kind,
        .source_node_id = source_node_id,
        .source_worker_id = bytes[30],
        .target_node_id = target_node_id,
        .target_worker_id = bytes[3],
        .session_id = session_id,
        .sequence = sequence,
        .client_address = address,
        .payload = bytes[payload_offset..authenticated_len],
    };
}

/// 使用 current/previous 双密钥验证转发报文。
pub fn decodeWithFallback(bytes: []const u8, current: []const u8, previous: []const u8) CodecError!Decoded {
    return decode(bytes, current) catch |err| switch (err) {
        error.InvalidTag => if (previous.len == 0) error.InvalidTag else decode(bytes, previous),
        else => err,
    };
}

/// ServerDriver 使用的跨节点发送接口，隐藏 Coordinator 和 UDP socket 的具体实现。
/// Sender 只借用 ptr 指向的实现，不管理其生命周期；实现必须覆盖所有 send 调用。
pub const Sender = struct {
    ptr: *anyopaque,
    return_path_enabled: bool,
    return_path_capacity: usize,
    return_path_timeout_us: u64,
    sendFn: *const fn (*anyopaque, handoff.TunnelKind, u16, u8, u8, []const u8, net.Address) anyerror!void,

    /// 把客户端请求发送给 CID owner，并记录发起转发的入口 Worker。
    pub fn sendRequest(self: Sender, node_id: u16, target_worker_id: u8, source_worker_id: u8, payload: []const u8, client_address: net.Address) !void {
        return self.sendFn(self.ptr, .request, node_id, target_worker_id, source_worker_id, payload, client_address);
    }

    /// 把 owner 响应发送回原入口 Worker，由其使用服务 socket 发往客户端/LB。
    pub fn sendResponse(self: Sender, node_id: u16, target_worker_id: u8, source_worker_id: u8, payload: []const u8, client_address: net.Address) !void {
        return self.sendFn(self.ptr, .response, node_id, target_worker_id, source_worker_id, payload, client_address);
    }
};

/// 隧道运行时计数器。
///
/// forward 是低频兜底路径：只有 anycast/ECMP 重哈希或客户端迁移导致误投递时
/// 才会有流量。低频路径的故障最难发现，因此每一类丢弃都必须单独计数——
/// 否则"配错密钥"、"配错 node_id"、"队列满"和"根本没有流量"在现象上完全一样。
pub const Stats = struct {
    /// 魔数/版本/HMAC/长度校验失败而丢弃的入站报文数。
    decode_failures: u64 = 0,
    /// target_node_id 不是本节点而丢弃的报文数（典型症状是 node_id 配错）。
    misrouted: u64 = 0,
    /// 重放窗口拒绝的报文数。
    replayed: u64 = 0,
    /// 成功交接给本机 Worker 的报文数。
    delivered: u64 = 0,
    /// 本机交接失败（队列满或 worker_id 越界）的报文数。
    handoff_failures: u64 = 0,
    /// recvfrom 返回非 EAGAIN 错误的次数。
    receive_errors: u64 = 0,
    /// 接收线程是否已退出。非 0 表示本节点此后收不到任何跨节点转发包。
    receiver_exited: u64 = 0,
};

/// 独立 UDP socket 的转发隧道运行器。send 可被多个 Worker 并发调用。
pub const Tunnel = struct {
    io: std.Io,
    fd: std.posix.socket_t,
    node_id: u16,
    session_id: u64,
    secret: []const u8,
    previous_secret: []const u8,
    packet_router: *handoff.LocalPacketRouter,
    next_sequence: std.atomic.Value(u64) = .init(1),
    /// 接收状态只由隧道线程访问，因此不需要锁。
    replay_cache: [replay_cache_capacity]?ReplayWindow = @splat(null),
    replay_next: usize = 0,
    stopping: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,
    /// 计数器由隧道线程写、任意线程读，因此用原子字段。
    counters: Counters = .{},

    const Counters = struct {
        decode_failures: std.atomic.Value(u64) = .init(0),
        misrouted: std.atomic.Value(u64) = .init(0),
        replayed: std.atomic.Value(u64) = .init(0),
        delivered: std.atomic.Value(u64) = .init(0),
        handoff_failures: std.atomic.Value(u64) = .init(0),
        receive_errors: std.atomic.Value(u64) = .init(0),
        receiver_exited: std.atomic.Value(u64) = .init(0),
    };

    /// 创建仅使用当前密钥的节点隧道；node_id 会写入并校验每个报文。
    pub fn init(io: std.Io, bind_address: net.Address, node_id: u16, secret: []const u8, packet_router: *handoff.LocalPacketRouter) !Tunnel {
        return initWithPrevious(io, bind_address, node_id, secret, &.{}, packet_router);
    }

    /// 初始化支持 current/previous 双密钥验收的隧道。
    pub fn initWithPrevious(io: std.Io, bind_address: net.Address, node_id: u16, secret: []const u8, previous_secret: []const u8, packet_router: *handoff.LocalPacketRouter) !Tunnel {
        if (node_id == 0) return error.InvalidNodeId;
        if (secret.len < min_secret_size) return error.SecretTooShort;
        if (previous_secret.len != 0 and previous_secret.len < min_secret_size) return error.SecretTooShort;
        const family: c_uint = switch (bind_address) {
            .ip4 => std.posix.AF.INET,
            .ip6 => std.posix.AF.INET6,
        };
        const fd = std.c.socket(family, std.posix.SOCK.DGRAM, 0);
        if (fd == -1) return error.SocketCreateFailed;
        errdefer _ = std.c.close(fd);
        const flags = std.c.fcntl(fd, std.posix.F.GETFL);
        if (flags == -1) return error.SocketConfigFailed;
        const nonblock: c_int = @intCast(@as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));
        if (std.c.fcntl(fd, std.posix.F.SETFL, flags | nonblock) == -1) return error.SocketConfigFailed;
        if (std.c.fcntl(fd, std.posix.F.SETFD, @as(c_int, std.posix.FD_CLOEXEC)) == -1) return error.SocketConfigFailed;
        var storage = net.toSockAddrStorage(bind_address);
        if (std.c.bind(fd, @ptrCast(&storage), net.sockAddrLen(bind_address)) != 0) return error.BindFailed;
        var session_id: u64 = 0;
        io.random(std.mem.asBytes(&session_id));
        if (session_id == 0) session_id = 1;
        return .{
            .io = io,
            .fd = fd,
            .node_id = node_id,
            .session_id = session_id,
            .secret = secret,
            .previous_secret = previous_secret,
            .packet_router = packet_router,
        };
    }

    /// 返回实际绑定地址；端口配置为 0 时用于取得内核分配端口。
    pub fn localAddress(self: *const Tunnel) !net.Address {
        var storage: std.posix.sockaddr.storage = undefined;
        var len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
        if (std.c.getsockname(self.fd, @ptrCast(&storage), &len) != 0) return error.GetSockNameFailed;
        return net.fromSockAddrStorage(&storage);
    }

    /// 停止接收线程并关闭 UDP socket；packet_router 与密钥切片由调用方持有。
    pub fn deinit(self: *Tunnel) void {
        self.stop();
        _ = std.c.close(self.fd);
        self.* = undefined;
    }

    /// 启动唯一接收线程；重复启动返回 AlreadyStarted。
    pub fn start(self: *Tunnel) !void {
        if (self.thread != null) return error.AlreadyStarted;
        self.stopping.store(false, .release);
        self.thread = try std.Thread.spawn(.{}, runThread, .{self});
    }

    /// 请求接收线程退出并等待完成；可重复调用。
    pub fn stop(self: *Tunnel) void {
        self.stopping.store(true, .release);
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
    }

    /// 认证封装并发送到目标节点的 forward 端口；序号由原子计数器分配，支持多 Worker 并发。
    pub fn sendTo(self: *Tunnel, to: net.Address, kind: handoff.TunnelKind, target_node_id: u16, target_worker_id: u8, source_worker_id: u8, payload: []const u8, client_address: net.Address) !void {
        const sequence = self.next_sequence.fetchAdd(1, .monotonic);
        if (sequence == 0) return error.SequenceExhausted;
        var buffer: [max_datagram_size]u8 = undefined;
        const encoded = try encode(
            kind,
            self.node_id,
            source_worker_id,
            target_node_id,
            target_worker_id,
            self.session_id,
            sequence,
            client_address,
            payload,
            self.secret,
            &buffer,
        );
        const storage = net.toSockAddrStorage(to);
        const rc = std.c.sendto(self.fd, encoded.ptr, encoded.len, 0, @ptrCast(&storage), net.sockAddrLen(to));
        if (rc < 0 or rc != encoded.len) return error.SendFailed;
    }

    /// 返回当前计数器快照。
    pub fn stats(self: *const Tunnel) Stats {
        return .{
            .decode_failures = self.counters.decode_failures.load(.monotonic),
            .misrouted = self.counters.misrouted.load(.monotonic),
            .replayed = self.counters.replayed.load(.monotonic),
            .delivered = self.counters.delivered.load(.monotonic),
            .handoff_failures = self.counters.handoff_failures.load(.monotonic),
            .receive_errors = self.counters.receive_errors.load(.monotonic),
            .receiver_exited = self.counters.receiver_exited.load(.monotonic),
        };
    }

    /// 接受窗口内未见过的序号。窗口允许 UDP 乱序，但拒绝重复包和落后 64 个以上的旧包。
    /// 目标节点不匹配与重放分别计数：前者是配置错误，后者可能是攻击或链路重复。
    fn acceptReplay(self: *Tunnel, packet: Decoded) bool {
        if (packet.target_node_id != self.node_id) {
            _ = self.counters.misrouted.fetchAdd(1, .monotonic);
            return false;
        }
        for (&self.replay_cache) |*slot| {
            if (slot.*) |*window| {
                if (window.source_node_id != packet.source_node_id or window.session_id != packet.session_id) continue;
                if (packet.sequence > window.highest_sequence) {
                    const advance = packet.sequence - window.highest_sequence;
                    window.seen = if (advance >= replay_window_bits)
                        1
                    else
                        (window.seen << @intCast(advance)) | 1;
                    window.highest_sequence = packet.sequence;
                    return true;
                }

                const age = window.highest_sequence - packet.sequence;
                if (age >= replay_window_bits) {
                    _ = self.counters.replayed.fetchAdd(1, .monotonic);
                    return false;
                }
                const mask = @as(u64, 1) << @intCast(age);
                if (window.seen & mask != 0) {
                    _ = self.counters.replayed.fetchAdd(1, .monotonic);
                    return false;
                }
                window.seen |= mask;
                return true;
            }
        }

        self.replay_cache[self.replay_next] = .{
            .source_node_id = packet.source_node_id,
            .session_id = packet.session_id,
            .highest_sequence = packet.sequence,
            .seen = 1,
        };
        self.replay_next = (self.replay_next + 1) % replay_cache_capacity;
        return true;
    }

    fn runThread(self: *Tunnel) void {
        // 线程退出即意味着本节点此后收不到任何跨节点转发包，必须可观测。
        defer _ = self.counters.receiver_exited.fetchAdd(1, .monotonic);

        var buffer: [max_datagram_size]u8 = undefined;
        while (!self.stopping.load(.acquire)) {
            var storage: std.posix.sockaddr.storage = undefined;
            var address_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
            const rc = std.c.recvfrom(self.fd, &buffer, buffer.len, 0, @ptrCast(&storage), &address_len);
            if (rc >= 0) {
                const packet = decodeWithFallback(buffer[0..@intCast(rc)], self.secret, self.previous_secret) catch {
                    _ = self.counters.decode_failures.fetchAdd(1, .monotonic);
                    continue;
                };
                if (!self.acceptReplay(packet)) continue;
                self.packet_router.forwardTunnel(packet.target_worker_id, packet.payload, packet.client_address, .{
                    .kind = packet.kind,
                    .source_node_id = packet.source_node_id,
                    .source_worker_id = packet.source_worker_id,
                }) catch {
                    _ = self.counters.handoff_failures.fetchAdd(1, .monotonic);
                    continue;
                };
                _ = self.counters.delivered.fetchAdd(1, .monotonic);
                continue;
            }

            // 只有 EAGAIN/EWOULDBLOCK 是"暂时无数据"的正常情况；其余错误
            // （EBADF/ENOTSOCK 等）会让这里变成静默忙等，必须计数。
            switch (std.posix.errno(rc)) {
                .AGAIN, .INTR => {},
                else => _ = self.counters.receive_errors.fetchAdd(1, .monotonic),
            }
            std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(1), .awake) catch break;
        }
    }
};

test "forward codec authenticates IPv4 identity and rejects tampering" {
    const secret = "0123456789abcdef";
    const client = net.initIp4(.{ 192, 0, 2, 1 }, 44321);
    var buffer: [max_datagram_size]u8 = undefined;
    const encoded = try encode(.request, 1, 3, 2, 7, 11, 19, client, "quic-packet", secret, &buffer);
    const decoded = try decode(encoded, secret);
    _ = try decodeWithFallback(encoded, "fedcba9876543210", secret);
    try std.testing.expectEqual(handoff.TunnelKind.request, decoded.kind);
    try std.testing.expectEqual(@as(u16, 1), decoded.source_node_id);
    try std.testing.expectEqual(@as(u8, 3), decoded.source_worker_id);
    try std.testing.expectEqual(@as(u16, 2), decoded.target_node_id);
    try std.testing.expectEqual(@as(u64, 11), decoded.session_id);
    try std.testing.expectEqual(@as(u64, 19), decoded.sequence);
    try std.testing.expectEqual(@as(u8, 7), decoded.target_worker_id);
    try std.testing.expectEqualStrings("quic-packet", decoded.payload);
    try std.testing.expect(std.meta.eql(client, decoded.client_address));
    buffer[fixed_header_size] ^= 1;
    try std.testing.expectError(error.InvalidTag, decode(buffer[0..encoded.len], secret));
}

test "forward codec roundtrips IPv6" {
    const secret = "0123456789abcdef";
    const client = net.initIp6(.{0xfd} ++ .{0} ** 14 ++ .{1}, 44321);
    var buffer: [max_datagram_size]u8 = undefined;
    const decoded = try decode(try encode(.response, 1, 4, 2, 2, 11, 1, client, "v6", secret, &buffer), secret);
    try std.testing.expectEqual(handoff.TunnelKind.response, decoded.kind);
    try std.testing.expectEqual(@as(u8, 4), decoded.source_worker_id);
    try std.testing.expectEqual(@as(u8, 2), decoded.target_worker_id);
    try std.testing.expect(std.meta.eql(client, decoded.client_address));
}

test "tunnel replay window accepts reordering and rejects duplicates old packets and wrong targets" {
    const secret = "0123456789abcdef";
    const client = net.initIp4(.{ 192, 0, 2, 1 }, 44321);
    var router = try handoff.LocalPacketRouter.init(std.testing.io, std.testing.allocator, 1, 1);
    defer router.deinit();
    var tunnel = try Tunnel.init(std.testing.io, net.initIp4(.{ 127, 0, 0, 1 }, 0), 2, secret, &router);
    defer tunnel.deinit();
    var buffer: [max_datagram_size]u8 = undefined;

    const sequence_10 = try decode(try encode(.request, 1, 3, 2, 0, 11, 10, client, "a", secret, &buffer), secret);
    try std.testing.expect(tunnel.acceptReplay(sequence_10));
    try std.testing.expect(!tunnel.acceptReplay(sequence_10));

    const sequence_8 = try decode(try encode(.request, 1, 3, 2, 0, 11, 8, client, "b", secret, &buffer), secret);
    try std.testing.expect(tunnel.acceptReplay(sequence_8));
    try std.testing.expect(!tunnel.acceptReplay(sequence_8));

    const sequence_74 = try decode(try encode(.request, 1, 3, 2, 0, 11, 74, client, "c", secret, &buffer), secret);
    try std.testing.expect(tunnel.acceptReplay(sequence_74));
    try std.testing.expect(!tunnel.acceptReplay(sequence_10));

    const wrong_target = try decode(try encode(.request, 1, 3, 3, 0, 11, 75, client, "d", secret, &buffer), secret);
    try std.testing.expect(!tunnel.acceptReplay(wrong_target));

    const restarted_sender = try decode(try encode(.request, 1, 3, 2, 0, 12, 1, client, "e", secret, &buffer), secret);
    try std.testing.expect(tunnel.acceptReplay(restarted_sender));
}

test "UDP tunnel injects authenticated packet into owner Worker queue" {
    const secret = "0123456789abcdef";
    var receiver_router = try handoff.LocalPacketRouter.init(std.testing.io, std.testing.allocator, 2, 4);
    defer receiver_router.deinit();
    var sender_router = try handoff.LocalPacketRouter.init(std.testing.io, std.testing.allocator, 1, 1);
    defer sender_router.deinit();

    var receiver = try Tunnel.init(std.testing.io, net.initIp4(.{ 127, 0, 0, 1 }, 0), 2, secret, &receiver_router);
    defer receiver.deinit();
    try receiver.start();
    var sender = try Tunnel.init(std.testing.io, net.initIp4(.{ 127, 0, 0, 1 }, 0), 1, secret, &sender_router);
    defer sender.deinit();

    const client = net.initIp4(.{ 198, 51, 100, 7 }, 45678);
    try sender.sendTo(try receiver.localAddress(), .request, 2, 1, 0, "raw-quic", client);
    var received: ?handoff.ForwardPacket = null;
    for (0..2000) |_| {
        received = receiver_router.pop(1);
        if (received != null) break;
        try std.Io.sleep(std.testing.io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqualStrings("raw-quic", received.?.bytes());
    try std.testing.expect(std.meta.eql(client, received.?.addr_from));
    try std.testing.expectEqual(handoff.TunnelKind.request, received.?.tunnel.?.kind);
    try std.testing.expectEqual(@as(u16, 1), received.?.tunnel.?.source_node_id);
    try std.testing.expectEqual(@as(u8, 0), received.?.tunnel.?.source_worker_id);

    try sender.sendTo(try receiver.localAddress(), .response, 2, 0, 1, "raw-response", client);
    received = null;
    for (0..2000) |_| {
        received = receiver_router.pop(0);
        if (received != null) break;
        try std.Io.sleep(std.testing.io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqualStrings("raw-response", received.?.bytes());
    try std.testing.expectEqual(handoff.TunnelKind.response, received.?.tunnel.?.kind);
    try std.testing.expectEqual(@as(u8, 1), received.?.tunnel.?.source_worker_id);
}
