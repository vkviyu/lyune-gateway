//! 服务端 Connection ID 编解码。
//!
//! v1 固定 12 字节布局：
//! ```
//! magic(2) | version(1) | node_id(2) | worker_id(1) | entropy(6)
//! ```
//! node_id 决定集群归属，worker_id 决定本机 Worker 归属。

const std = @import("std");

/// 集群内统一的服务端 CID 固定长度。
pub const length: u8 = 12;
/// CID 魔数 "LY"。
pub const magic: u16 = 0x4c59;
/// 首次发布的 CID 布局版本。
pub const version: u8 = 1;
/// node_id 在 CID 中的起始偏移。
pub const node_offset: usize = 3;
/// worker_id 在 CID 中的偏移。
pub const worker_offset: usize = 5;
/// 放置提示的长度：CID 的定位段（magic | version | node_id | worker_id），不含熵。
pub const placement_hint_size: usize = 6;

/// 合法 CID v1 的路由字段；熵只用于唯一性，不向路由层暴露。
pub const Fields = struct {
    node_id: u16,
    worker_id: u8,
};

/// 编码 v1 CID。
pub fn encode(node_id: u16, worker_id: u8, entropy: [6]u8) [length]u8 {
    return .{
        @intCast(magic >> 8),   @intCast(magic & 0xff),   version,
        @intCast(node_id >> 8), @intCast(node_id & 0xff), worker_id,
        entropy[0],             entropy[1],               entropy[2],
        entropy[3],             entropy[4],               entropy[5],
    };
}

/// 生成交给客户端的放置提示：CID 的定位段，**不含熵**。
///
/// 客户端把它原样填进下次连接首个 Initial 包的 DCID 前缀，剩下 6 字节自己随机填，
/// 内核态 reuseport BPF 就会把首包投给正确的 Worker（设计文档 §8.5 策略 B）。
///
/// **绝不能给出完整 CID**：尾部 6 字节是熵，交出去就等于给了客户端主动撞上一条
/// 在用连接 CID 的机会。撞上也拿不到密钥（包会被丢弃），但没必要给这个机会。
pub fn placementHint(node_id: u16, worker_id: u8) [placement_hint_size]u8 {
    const full = encode(node_id, worker_id, @splat(0));
    return full[0..placement_hint_size].*;
}

/// 解析 v1 CID 的节点和 Worker 归属。
pub fn parse(connection_id: []const u8) ?Fields {
    if (connection_id.len != length) return null;
    if (connection_id[0] != @as(u8, @intCast(magic >> 8)) or
        connection_id[1] != @as(u8, @intCast(magic & 0xff)) or
        connection_id[2] != version) return null;
    const node_id = (@as(u16, connection_id[node_offset]) << 8) | connection_id[node_offset + 1];
    if (node_id == 0) return null;
    return .{
        .node_id = node_id,
        .worker_id = connection_id[worker_offset],
    };
}

/// 从合法的 v1 CID 中读取节点归属；格式不匹配时返回 null。
pub fn nodeId(connection_id: []const u8) ?u16 {
    return if (parse(connection_id)) |fields| fields.node_id else null;
}

/// 从合法的 v1 CID 中读取 Worker 归属；格式不匹配时返回 null。
pub fn workerId(connection_id: []const u8) ?u8 {
    return if (parse(connection_id)) |fields| fields.worker_id else null;
}

test "v1 CID roundtrip" {
    const encoded = encode(513, 37, .{ 1, 2, 3, 4, 5, 6 });
    const fields = parse(&encoded).?;
    try std.testing.expectEqual(@as(u16, 513), fields.node_id);
    try std.testing.expectEqual(@as(u8, 37), fields.worker_id);
}

test "the placement hint carries location but never entropy" {
    const hint = placementHint(513, 37);
    const full = encode(513, 37, .{ 9, 9, 9, 9, 9, 9 });
    // 前 6 字节与真实 CID 的定位段一致，客户端填进 DCID 后 BPF 才能认出来。
    try std.testing.expectEqualSlices(u8, full[0..placement_hint_size], &hint);
    // 而熵一个字节都不在里面。
    try std.testing.expectEqual(placement_hint_size, hint.len);
}

test "rejects foreign-version or malformed CID" {
    var encoded = encode(1, 1, .{ 1, 2, 3, 4, 5, 6 });
    encoded[0] ^= 1;
    try std.testing.expect(parse(&encoded) == null);
    try std.testing.expect(parse(encoded[0 .. length - 1]) == null);
    encoded[0] = 'L';
    encoded[1] = 'Y';
    encoded[2] = 2;
    try std.testing.expect(parse(&encoded) == null);
    const reserved_node = encode(0, 1, .{ 1, 2, 3, 4, 5, 6 });
    try std.testing.expect(parse(&reserved_node) == null);
}
