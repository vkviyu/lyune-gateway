//! 服务端 Connection ID 编解码
//!
//! 网关签发的每个 QUIC 连接 ID 都把「哪个 Worker 拥有这条连接」直接编码进 CID。
//! 这样内核态的 reuseport BPF（见 reuseport.c）和用户态收包路径都能在 O(1) 时间内
//! 判断一个数据包应该由哪个 Worker 处理，实现零锁的连接亲和路由。
//!
//! 固定 8 字节布局：
//! ```
//! ┌─────────┬─────────┬─────────┬─────────┬───────────────────┐
//! │ 'L'     │ 'Y'     │ version │ worker  │ entropy (4 bytes) │
//! │ byte 0  │ byte 1  │ byte 2  │ byte 3  │ byte 4..7         │
//! └─────────┴─────────┴─────────┴─────────┴───────────────────┘
//! ```
//! 前 3 个字节是魔数 + 版本，用来把本网关签发的 CID 与外部/旧版 CID 区分开；
//! 第 4 字节是 worker_id；最后 4 字节是随机熵，保证同一 Worker 的多条连接 CID 不冲突。

const std = @import("std");

/// CID 固定总长度（字节）。短包头没有显式长度字段，收发两端必须约定同一个值。
pub const length: u8 = 8;
/// 魔数 "LY"（Lyune），用于识别本网关签发的 CID。
pub const magic: u16 = 0x4c59; // "LY"
/// CID 布局版本号。将来若调整字段布局，递增此值即可与旧 CID 区分。
pub const version: u8 = 1;
/// worker_id 在 CID 中的字节偏移。
pub const worker_offset: usize = 3;

/// 把 worker_id 和随机熵编码成一个固定 8 字节的服务端 CID。
/// entropy 由调用方提供（通常是 CSPRNG），用于避免同一 Worker 的连接 CID 碰撞。
pub fn encode(worker_id: u8, entropy: [4]u8) [length]u8 {
    return .{
        @intCast(magic >> 8), // byte 0: 'L'
        @intCast(magic & 0xff), // byte 1: 'Y'
        version, // byte 2: 版本
        worker_id, // byte 3: 归属 Worker
        entropy[0],
        entropy[1],
        entropy[2],
        entropy[3],
    };
}

/// 从一个 CID 中解析出归属的 worker_id。
/// 只有长度、魔数、版本全部匹配才认为是本网关签发的 CID；否则返回 null，
/// 调用方应回退到内核默认哈希分发（例如握手期尚未签发服务端 CID 的 Initial 包）。
pub fn workerId(connection_id: []const u8) ?u8 {
    if (connection_id.len != length) return null;
    if (connection_id[0] != @as(u8, @intCast(magic >> 8))) return null;
    if (connection_id[1] != @as(u8, @intCast(magic & 0xff))) return null;
    if (connection_id[2] != version) return null;
    return connection_id[worker_offset];
}

test "worker CID roundtrip" {
    const encoded = encode(37, .{ 1, 2, 3, 4 });
    try std.testing.expectEqual(@as(?u8, 37), workerId(&encoded));
}

test "rejects foreign CID" {
    var encoded = encode(1, .{ 1, 2, 3, 4 });
    encoded[0] ^= 1;
    try std.testing.expectEqual(@as(?u8, null), workerId(&encoded));
}

test "rejects CID with wrong length or version" {
    var encoded = encode(1, .{ 1, 2, 3, 4 });
    try std.testing.expectEqual(@as(?u8, null), workerId(encoded[0 .. length - 1]));

    encoded[2] += 1;
    try std.testing.expectEqual(@as(?u8, null), workerId(&encoded));
}
