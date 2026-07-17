const std = @import("std");

pub const Address = std.Io.net.IpAddress;

pub const SockAddrError = error{UnsupportedAddressFamily};

pub fn initIp4(bytes: [4]u8, port: u16) Address {
    return .{ .ip4 = .{ .bytes = bytes, .port = port } };
}

pub fn initIp6(bytes: [16]u8, port: u16) Address {
    return .{ .ip6 = .{ .bytes = bytes, .port = port } };
}

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

pub fn sockAddrLen(address: Address) std.posix.socklen_t {
    return switch (address) {
        .ip4 => @sizeOf(std.posix.sockaddr.in),
        .ip6 => @sizeOf(std.posix.sockaddr.in6),
    };
}

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
