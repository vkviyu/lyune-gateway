const std = @import("std");

/// 组件间统一使用的 IPv4/IPv6 地址值类型。
pub const Address = std.Io.net.IpAddress;

/// 原生 sockaddr 转换遇到不支持地址族时返回的错误。
pub const SockAddrError = error{UnsupportedAddressFamily};

/// 从网络序字节和主机序端口构造 IPv4 地址。
pub fn initIp4(bytes: [4]u8, port: u16) Address {
    return .{ .ip4 = .{ .bytes = bytes, .port = port } };
}

/// 从网络序字节和主机序端口构造 IPv6 地址。
pub fn initIp6(bytes: [16]u8, port: u16) Address {
    return .{ .ip6 = .{ .bytes = bytes, .port = port } };
}

/// 保留 IP，只替换端口。membership 与 forward 隧道共享节点 IP、使用独立端口。
pub fn withPort(address: Address, port: u16) Address {
    return switch (address) {
        .ip4 => |value| initIp4(value.bytes, port),
        .ip6 => |value| initIp6(value.bytes, port),
    };
}

/// 返回 Address 中的主机序端口。
pub fn addressPort(address: Address) u16 {
    return switch (address) {
        .ip4 => |value| value.port,
        .ip6 => |value| value.port,
    };
}

/// 写成客户端可直接拨号的 "host:port" 文本。
///
/// IPv6 用方括号包住主机部分（RFC 3986），并且**不做零压缩**——它只需要可拨号，
/// 不需要是规范形式，而零压缩的实现和它的边界情形不值得为此引入。
pub fn writeDialString(address: Address, buf: []u8) ![]const u8 {
    return switch (address) {
        .ip4 => |value| std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{
            value.bytes[0],
            value.bytes[1],
            value.bytes[2],
            value.bytes[3],
            value.port,
        }),
        .ip6 => |value| blk: {
            var groups: [8]u16 = undefined;
            for (&groups, 0..) |*group, i| {
                group.* = (@as(u16, value.bytes[i * 2]) << 8) | value.bytes[i * 2 + 1];
            }
            break :blk std.fmt.bufPrint(buf, "[{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}]:{d}", .{
                groups[0],  groups[1], groups[2], groups[3],
                groups[4],  groups[5], groups[6], groups[7],
                value.port,
            });
        },
    };
}

/// 转换为可传给 POSIX socket API 的 sockaddr_storage，并把端口写为网络序。
pub fn toSockAddrStorage(address: Address) std.posix.sockaddr.storage {
    var storage: std.posix.sockaddr.storage = std.mem.zeroes(std.posix.sockaddr.storage);
    switch (address) {
        .ip4 => |ip4| {
            const sockaddr: *std.posix.sockaddr.in = @ptrCast(@alignCast(&storage));
            sockaddr.family = std.posix.AF.INET;
            sockaddr.port = std.mem.nativeToBig(u16, ip4.port);
            sockaddr.addr = @bitCast(ip4.bytes);
        },
        .ip6 => |ip6| {
            const sockaddr: *std.posix.sockaddr.in6 = @ptrCast(@alignCast(&storage));
            sockaddr.family = std.posix.AF.INET6;
            sockaddr.port = std.mem.nativeToBig(u16, ip6.port);
            sockaddr.addr = ip6.bytes;
            sockaddr.flowinfo = 0;
            sockaddr.scope_id = 0;
        },
    }
    return storage;
}

/// 返回 Address 对应原生 sockaddr 结构的精确长度。
pub fn sockAddrLen(address: Address) std.posix.socklen_t {
    return switch (address) {
        .ip4 => @sizeOf(std.posix.sockaddr.in),
        .ip6 => @sizeOf(std.posix.sockaddr.in6),
    };
}

/// 从原生 sockaddr_storage 还原 Address；只接受 AF_INET/AF_INET6。
pub fn fromSockAddrStorage(storage: *const std.posix.sockaddr.storage) SockAddrError!Address {
    const family = @as(u16, @intCast(storage.family));
    if (family == std.posix.AF.INET) {
        const sockaddr: *const std.posix.sockaddr.in = @ptrCast(@alignCast(storage));
        return initIp4(@as(*const [4]u8, @ptrCast(&sockaddr.addr)).*, std.mem.bigToNative(u16, sockaddr.port));
    }
    if (family == std.posix.AF.INET6) {
        const sockaddr: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(storage));
        return initIp6(sockaddr.addr, std.mem.bigToNative(u16, sockaddr.port));
    }
    return error.UnsupportedAddressFamily;
}
