//! gossip 网络发送层
//!
//! Transport 是 SWIM 运行器的出站抽象（vtable + 类型擦除，风格同 foundation.resolver）：
//!   - 生产实现：UdpTransport，独立 UDP socket（对应配置的 advertise_address）；
//!   - 测试实现：sim.zig 的虚拟网络（不经过本接口，直接搬运 outbox，语义等价）。
//!
//! 注意分层：swim.zig 纯状态机不持有 Transport——它只往 outbox 写帧；
//! 由 runner.zig 的独立协议线程负责：
//!   收包 → swim.handleMessage → swim.tick → 把 outbox 经 Transport 发出。

const std = @import("std");
const foundation = @import("../../foundation/mod.zig");
const net = foundation.net;

/// 尽力而为 gossip 发送接口对系统错误的稳定归并。
pub const SendError = error{
    /// 发送缓冲区暂时写不进去。gossip 帧允许直接丢弃（协议自会重试）。
    WouldBlock,
    /// 其余系统级发送失败的归并。gossip 是尽力而为语义，调用方计数后继续即可。
    SendFailed,
};

/// 出站发送接口（类型擦除）。实现方不得阻塞：gossip 线程同时负责协议时钟。
pub const Transport = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    /// Transport 实现的非阻塞发送函数表；ptr 与实现对象均由调用方持有。
    pub const VTable = struct {
        send: *const fn (ptr: *anyopaque, to: net.Address, payload: []const u8) SendError!void,
    };

    /// 从任意带 send(to, payload) 方法的实现类型构造接口实例。
    pub fn init(comptime T: type, impl: *T) Transport {
        const gen = struct {
            fn send(ptr: *anyopaque, to: net.Address, payload: []const u8) SendError!void {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.send(to, payload);
            }
        };
        return .{ .ptr = impl, .vtable = &.{ .send = gen.send } };
    }

    /// 通过借用的实现发送一帧，不复制 payload，也不接管其生命周期。
    pub fn send(self: Transport, to: net.Address, payload: []const u8) SendError!void {
        return self.vtable.send(self.ptr, to, payload);
    }
};

/// 基于非阻塞 UDP socket 的生产实现。
/// 收发共用一个 socket：本地端口即对外通告端口，对端回包自然回到这里。
pub const UdpTransport = struct {
    fd: std.posix.socket_t,

    /// 创建、配置并绑定非阻塞 CLOEXEC UDP socket；支持端口 0。
    pub fn init(bind_address: net.Address) !UdpTransport {
        const family: c_uint = switch (bind_address) {
            .ip4 => std.posix.AF.INET,
            .ip6 => std.posix.AF.INET6,
        };
        const fd = std.c.socket(family, std.posix.SOCK.DGRAM, 0);
        if (fd == -1) return error.SocketCreateFailed;
        errdefer _ = std.c.close(fd);

        // SOCK_NONBLOCK/SOCK_CLOEXEC 原子标志并非所有平台都支持（macOS 就没有），
        // 统一用 fcntl 事后设置，行为跨平台一致。
        const flags = std.c.fcntl(fd, std.posix.F.GETFL);
        if (flags == -1) return error.SocketConfigFailed;
        const nonblock: c_int = @intCast(@as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));
        if (std.c.fcntl(fd, std.posix.F.SETFL, flags | nonblock) == -1) return error.SocketConfigFailed;
        if (std.c.fcntl(fd, std.posix.F.SETFD, @as(c_int, std.posix.FD_CLOEXEC)) == -1) return error.SocketConfigFailed;

        var storage = net.toSockAddrStorage(bind_address);
        if (std.c.bind(fd, @ptrCast(&storage), net.sockAddrLen(bind_address)) != 0) {
            return error.BindFailed;
        }
        return .{ .fd = fd };
    }

    /// 关闭 UDP socket；调用后实例不可再使用。
    pub fn deinit(self: *UdpTransport) void {
        _ = std.c.close(self.fd);
        self.* = undefined;
    }

    /// 实际绑定的本地地址（端口配 0 时由内核分配，测试与诊断需要读回）。
    pub fn localAddress(self: *const UdpTransport) !net.Address {
        var storage: std.posix.sockaddr.storage = undefined;
        var len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
        if (std.c.getsockname(self.fd, @ptrCast(&storage), &len) != 0) {
            return error.GetSockNameFailed;
        }
        return net.fromSockAddrStorage(&storage);
    }

    /// 非阻塞发送一帧。任何失败都归并为 SendError（gossip 尽力而为，调用方计数即可）。
    pub fn send(self: *UdpTransport, to: net.Address, payload: []const u8) SendError!void {
        const storage = net.toSockAddrStorage(to);
        const rc = std.c.sendto(self.fd, payload.ptr, payload.len, 0, @ptrCast(&storage), net.sockAddrLen(to));
        if (rc == -1) {
            return switch (std.posix.errno(rc)) {
                .AGAIN => error.WouldBlock,
                else => error.SendFailed,
            };
        }
    }

    /// 非阻塞收一帧；无数据返回 null。buf 建议不小于 codec.max_message_size。
    pub fn recv(self: *UdpTransport, buf: []u8) !?struct { len: usize, from: net.Address } {
        var storage: std.posix.sockaddr.storage = undefined;
        var addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
        const rc = std.c.recvfrom(self.fd, buf.ptr, buf.len, 0, @ptrCast(&storage), &addr_len);
        if (rc == -1) {
            return switch (std.posix.errno(rc)) {
                .AGAIN => null,
                else => error.RecvFailed,
            };
        }
        return .{ .len = @intCast(rc), .from = try net.fromSockAddrStorage(&storage) };
    }

    /// 类型擦除的接口实例。
    pub fn transport(self: *UdpTransport) Transport {
        return Transport.init(UdpTransport, self);
    }
};

test "udp transport loopback roundtrip" {
    var a = try UdpTransport.init(net.initIp4(.{ 127, 0, 0, 1 }, 0));
    defer a.deinit();
    var b = try UdpTransport.init(net.initIp4(.{ 127, 0, 0, 1 }, 0));
    defer b.deinit();

    const b_addr = try b.localAddress();
    try a.transport().send(b_addr, "swim-frame");

    // 非阻塞收包：本机环回通常立刻可读，保守起见带上限重试。
    var buf: [64]u8 = undefined;
    var received: ?[]const u8 = null;
    for (0..100) |_| {
        if (try b.recv(&buf)) |result| {
            received = buf[0..result.len];
            break;
        }
        try std.Io.sleep(
            std.Io.Threaded.global_single_threaded.io(),
            std.Io.Duration.fromMilliseconds(1),
            .awake,
        );
    }
    try std.testing.expectEqualStrings("swim-frame", received.?);
}
