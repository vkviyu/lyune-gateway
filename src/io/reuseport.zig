//! reuseport 分类器的 Zig 侧封装
//!
//! 真正的分流逻辑在 reuseport.c 里（Linux classic BPF）。本文件只做两件事：
//! 1. 声明并封装 C 侧的两个入口函数；
//! 2. 在 Zig 中对同一套分流逻辑做等价测试，避免 BPF 字节码写错却无人察觉。
//!
//! 数据面工作方式：主线程创建一组 SO_REUSEPORT socket 后，把 BPF 分类器 attach 到
//! socket 组，内核收到 UDP 包时按 QUIC DCID 里的 worker_id 选择目标 socket，
//! 从而把同一条连接的包稳定投递给固定 Worker。

const std = @import("std");

/// 当分类器返回这个值时，内核会回退到默认的 reuseport 哈希分发。
/// 用于握手期还没有服务端 CID、或 CID 不是本网关签发的场景。
pub const fallback: u32 = std.math.maxInt(u32);

// C 侧实现（reuseport.c）。非 Linux 平台是空实现，attach 直接返回 0。
extern fn lyune_attach_reuseport_classifier(fd: c_int, socket_count: u32) c_int;
extern fn lyune_classify_quic_packet(packet: [*]const u8, length: usize, socket_count: u32) u32;

/// 把 reuseport 分类器 attach 到 socket 组中的任意一个 fd（内核会应用到整组）。
/// socket_count 必须等于实际 Worker/ socket 数量，BPF 用它做边界检查。
pub fn attach(fd: std.posix.socket_t, socket_count: u32) !void {
    if (lyune_attach_reuseport_classifier(fd, socket_count) != 0) {
        return error.AttachReusePortClassifierFailed;
    }
}

/// 纯 Zig 侧调用 C 分类函数，仅供下面的单元测试验证分流逻辑是否正确。
/// 生产路径由内核执行 BPF，不会走这里。
fn classify(packet: []const u8, socket_count: u32) u32 {
    if (packet.len == 0) return fallback;
    return lyune_classify_quic_packet(packet.ptr, packet.len, socket_count);
}

test "reuseport classifier routes short-header server CID" {
    // 短包头：DCID 从偏移 1 开始，worker_id 在偏移 6。
    const packet = [_]u8{ 0x40, 'L', 'Y', 1, 0, 9, 3, 10, 11, 12, 13, 14, 15 };
    try std.testing.expectEqual(@as(u32, 3), classify(&packet, 4));
    // worker_id(3) 超过 socket_count(3) 的合法范围 [0,3)，应回退。
    try std.testing.expectEqual(fallback, classify(&packet, 3));
}

test "reuseport classifier routes long-header server CID" {
    // 长包头：偏移 5 是 DCID 长度(12)，DCID 从偏移 6 开始，worker_id 在偏移 11。
    const packet = [_]u8{ 0xc0, 0, 0, 0, 1, 12, 'L', 'Y', 1, 0, 9, 2, 10, 11, 12, 13, 14, 15 };
    try std.testing.expectEqual(@as(u32, 2), classify(&packet, 4));
}

test "reuseport classifier falls back for initial and malformed packets" {
    const initial = [_]u8{ 0xc0, 0, 0, 0, 2, 12, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }; // 非本网关魔数
    const bad_length = [_]u8{ 0xc0, 0, 0, 0, 1, 8, 'L', 'Y', 1, 0, 1, 2, 3, 4, 5, 6, 7, 8 }; // DCID 长度不是 12
    const truncated = [_]u8{ 0x40, 'L', 'Y', 1 }; // 短于最小 CID 长度

    try std.testing.expectEqual(fallback, classify(&initial, 4));
    try std.testing.expectEqual(fallback, classify(&bad_length, 4));
    try std.testing.expectEqual(fallback, classify(&truncated, 4));
}
