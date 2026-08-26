//! src/reactor/return_path.zig
//!
//! 普通有状态 L4 负载均衡下的 QUIC 回程追踪。
//!
//! 背景：五元组哈希型 UDP LB 不理解 QUIC Connection ID，客户端迁移或 LB
//! 重哈希后，属于节点 A 的报文可能被投给节点 B。B 解出 CID 归属后经隧道
//! 转给 A，而 A 的响应必须回到 B——因为客户端只认 B 这条 UDP 流。
//!
//! 因此一条连接在两侧各需要一份状态，两者语义相反，绝不能混用：
//!
//!   owner 侧（真正持有 QUIC 连接的节点）
//!     记录「该客户端的响应应当经由哪个入口节点/Worker 回去」
//!     -> rememberRoute / lookupRoute / forgetRoute
//!
//!   ingress 侧（收到误投递报文、把它转走的节点）
//!     记录「允许哪个 owner 节点/Worker 为该客户端回包」
//!     -> grantResponse / isGranted
//!
//! ingress 侧那份是安全边界：没有它，任何能向 forward 隧道发包的对端都能
//! 让本节点朝任意客户端地址发送任意字节，隧道会退化成 UDP 反射器。
//!
//! 两份状态都是 Worker 本地的，只由所属 Worker 线程访问，因此不需要锁；
//! 都是有界的，容量满时淘汰最久未使用的条目，并按空闲超时回收。

const std = @import("std");

const foundation = @import("../foundation/mod.zig");
const net = foundation.net;
const io = @import("../io/mod.zig");
const migration = io.handoff;

/// 一次批量过期扫描单轮最多收集的键数；用固定数组换取零分配。
const purge_batch = 64;

/// 地址键：family(1) + 地址(16) + 端口(2)。IPv4 只用前 4 字节地址位。
const AddressKey = [19]u8;

/// 对端节点/Worker 二元组及其最近活跃时刻。
///
/// 在 owner 侧表示「响应要回到的入口」，在 ingress 侧表示「被授权回包的 owner」。
pub const Peer = struct {
    node_id: u16,
    worker_id: u8,
    last_seen: u64,
};

/// Worker 本地、有界的地址到对端映射。
///
/// 这是 Tracker 的实现细节，两个方向各持有一份实例。
const PeerTable = struct {
    entries: std.AutoHashMap(AddressKey, Peer),
    capacity: usize,
    timeout_us: u64,

    fn init(allocator: std.mem.Allocator, capacity: usize, timeout_us: u64) !PeerTable {
        if (capacity > std.math.maxInt(u32)) return error.CapacityOverflow;
        var result: PeerTable = .{
            .entries = std.AutoHashMap(AddressKey, Peer).init(allocator),
            .capacity = capacity,
            .timeout_us = timeout_us,
        };
        errdefer result.entries.deinit();
        // 预分配到容量上限，避免热路径触发扩容。
        try result.entries.ensureTotalCapacity(@intCast(capacity));
        return result;
    }

    fn deinit(self: *PeerTable) void {
        self.entries.deinit();
        self.* = undefined;
    }

    /// 记录或刷新一条映射。已存在时原地更新，不占用新容量。
    fn remember(self: *PeerTable, address: net.Address, node_id: u16, worker_id: u8, now: u64) !void {
        const key = addressKey(address);
        if (self.entries.getPtr(key)) |entry| {
            entry.* = .{ .node_id = node_id, .worker_id = worker_id, .last_seen = now };
            return;
        }
        self.removeExpired(now);
        if (self.entries.count() >= self.capacity) self.removeOldest();
        try self.entries.put(key, .{ .node_id = node_id, .worker_id = worker_id, .last_seen = now });
    }

    /// 查询映射；命中但已超时的条目会被顺手删除并返回 null。
    fn lookup(self: *PeerTable, address: net.Address, now: u64) ?Peer {
        const key = addressKey(address);
        const entry = self.entries.getPtr(key) orelse return null;
        if (isExpired(entry.last_seen, now, self.timeout_us)) {
            _ = self.entries.remove(key);
            return null;
        }
        return entry.*;
    }

    fn remove(self: *PeerTable, address: net.Address) void {
        _ = self.entries.remove(addressKey(address));
    }

    /// 批量回收超时条目。分批收集键再删除，避免在迭代中修改哈希表。
    fn removeExpired(self: *PeerTable, now: u64) void {
        var keys: [purge_batch]AddressKey = undefined;
        while (true) {
            var count: usize = 0;
            var iterator = self.entries.iterator();
            while (iterator.next()) |item| {
                if (!isExpired(item.value_ptr.last_seen, now, self.timeout_us)) continue;
                keys[count] = item.key_ptr.*;
                count += 1;
                if (count == keys.len) break;
            }
            for (keys[0..count]) |key| _ = self.entries.remove(key);
            if (count < keys.len) break;
        }
    }

    /// 容量满时淘汰最久未活跃的条目。
    fn removeOldest(self: *PeerTable) void {
        var oldest_key: ?AddressKey = null;
        var oldest_seen: u64 = std.math.maxInt(u64);
        var iterator = self.entries.iterator();
        while (iterator.next()) |item| {
            if (item.value_ptr.last_seen >= oldest_seen) continue;
            oldest_seen = item.value_ptr.last_seen;
            oldest_key = item.key_ptr.*;
        }
        if (oldest_key) |key| _ = self.entries.remove(key);
    }
};

/// 把 IP 地址与端口压成定长键，供哈希表使用。
///
/// family 字节参与键值，因此 IPv4 与 IPv6 不会因零填充而互相碰撞。
fn addressKey(address: net.Address) AddressKey {
    var key: AddressKey = @splat(0);
    switch (address) {
        .ip4 => |value| {
            key[0] = 4;
            @memcpy(key[1..5], &value.bytes);
            std.mem.writeInt(u16, key[17..19], value.port, .big);
        },
        .ip6 => |value| {
            key[0] = 6;
            @memcpy(key[1..17], &value.bytes);
            std.mem.writeInt(u16, key[17..19], value.port, .big);
        },
    }
    return key;
}

/// 判断条目是否超过空闲超时。now 早于 last_seen（时钟回拨）时不判过期。
fn isExpired(last_seen: u64, now: u64, timeout_us: u64) bool {
    return now > last_seen and now - last_seen > timeout_us;
}

/// 隧道元数据里的来源是否与已授权对端一致。
///
/// node 与 worker 必须同时匹配：只校验 node 会让同主机的其他 Worker
/// 借用这条授权向客户端发包。
pub fn matchesPeer(peer: Peer, metadata: migration.TunnelMetadata) bool {
    return peer.node_id == metadata.source_node_id and peer.worker_id == metadata.source_worker_id;
}

/// 单个 Worker 的 L4 回程状态。
///
/// 同时持有 owner 侧与 ingress 侧两份映射；调用方按语义化方法访问，
/// 不需要知道内部有几张表。
pub const Tracker = struct {
    /// owner 侧：客户端地址 -> 响应要回到的入口节点/Worker。
    routes: PeerTable,
    /// ingress 侧：客户端地址 -> 被允许为其回包的 owner 节点/Worker。
    grants: PeerTable,

    pub const Error = error{CapacityOverflow} || std.mem.Allocator.Error;

    /// capacity 为单侧表的条目上限，timeout_us 为条目空闲超时。
    pub fn init(allocator: std.mem.Allocator, capacity: usize, timeout_us: u64) Error!Tracker {
        var routes = try PeerTable.init(allocator, capacity, timeout_us);
        errdefer routes.deinit();
        const grants = try PeerTable.init(allocator, capacity, timeout_us);
        return .{ .routes = routes, .grants = grants };
    }

    pub fn deinit(self: *Tracker) void {
        self.routes.deinit();
        self.grants.deinit();
        self.* = undefined;
    }

    /// 【owner 侧】记录该客户端的响应应经由哪个入口节点/Worker 回去。
    /// 在收到经隧道转来的 request 时调用。
    pub fn rememberRoute(self: *Tracker, client: net.Address, node_id: u16, worker_id: u8, now: u64) !void {
        try self.routes.remember(client, node_id, worker_id, now);
    }

    /// 【owner 侧】查询回程入口；无记录或已超时返回 null（此时直接回客户端）。
    pub fn lookupRoute(self: *Tracker, client: net.Address, now: u64) ?Peer {
        return self.routes.lookup(client, now);
    }

    /// 【owner 侧】清除回程记录。
    ///
    /// 客户端报文直达本节点说明它已能直连，此前经隧道建立的回程路径失效；
    /// 继续沿用会把响应绕回一个不再需要的入口节点。
    pub fn forgetRoute(self: *Tracker, client: net.Address) void {
        self.routes.remove(client);
    }

    /// 【ingress 侧】授权某 owner 为该客户端回包。
    /// 在把误投递报文转给 owner 之前调用，必须先授权再转发。
    pub fn grantResponse(self: *Tracker, client: net.Address, node_id: u16, worker_id: u8, now: u64) !void {
        try self.grants.remember(client, node_id, worker_id, now);
    }

    /// 【ingress 侧】校验一条回程响应是否来自已授权的 owner。
    ///
    /// 这是防 UDP 反射的唯一门禁：未授权的响应必须丢弃，不能发往客户端。
    pub fn isGranted(self: *Tracker, client: net.Address, metadata: migration.TunnelMetadata, now: u64) bool {
        const expected = self.grants.lookup(client, now) orelse return false;
        return matchesPeer(expected, metadata);
    }
};

test "peer table is bounded refreshes entries and expires idle peers" {
    var table = try PeerTable.init(std.testing.allocator, 2, 10);
    defer table.deinit();
    const first = net.initIp4(.{ 192, 0, 2, 1 }, 1001);
    const second = net.initIp4(.{ 192, 0, 2, 2 }, 1002);
    const third = net.initIp4(.{ 192, 0, 2, 3 }, 1003);

    try table.remember(first, 1, 2, 1);
    try table.remember(second, 2, 3, 2);
    // 刷新 first 使 second 成为最久未活跃者，插入 third 时应淘汰 second。
    try table.remember(first, 1, 2, 3);
    try table.remember(third, 3, 4, 4);
    try std.testing.expect(table.lookup(second, 4) == null);
    try std.testing.expectEqual(@as(u16, 1), table.lookup(first, 4).?.node_id);
    // 超过 timeout 后两者都不再命中。
    try std.testing.expect(table.lookup(first, 15) == null);
    try std.testing.expect(table.lookup(third, 15) == null);
}

test "peer table updates the peer for a migrated address" {
    var table = try PeerTable.init(std.testing.allocator, 1, 100);
    defer table.deinit();
    const client = net.initIp4(.{ 198, 51, 100, 1 }, 44321);
    try table.remember(client, 1, 2, 1);
    try table.remember(client, 3, 4, 2);
    const current = table.lookup(client, 2).?;
    try std.testing.expectEqual(@as(u16, 3), current.node_id);
    try std.testing.expectEqual(@as(u8, 4), current.worker_id);
}

test "ipv4 and ipv6 addresses do not collide in the key space" {
    const v4 = net.initIp4(.{ 0, 0, 0, 0 }, 443);
    const v6 = net.initIp6(@splat(0), 443);
    try std.testing.expect(!std.mem.eql(u8, &addressKey(v4), &addressKey(v6)));
}

test "response must match the granted owner node and Worker" {
    const peer: Peer = .{ .node_id = 7, .worker_id = 3, .last_seen = 1 };
    try std.testing.expect(matchesPeer(peer, .{ .kind = .response, .source_node_id = 7, .source_worker_id = 3 }));
    try std.testing.expect(!matchesPeer(peer, .{ .kind = .response, .source_node_id = 8, .source_worker_id = 3 }));
    try std.testing.expect(!matchesPeer(peer, .{ .kind = .response, .source_node_id = 7, .source_worker_id = 4 }));
}

test "tracker keeps owner routes and ingress grants separate" {
    var tracker = try Tracker.init(std.testing.allocator, 4, 100);
    defer tracker.deinit();
    const client = net.initIp4(.{ 203, 0, 113, 9 }, 55000);

    // owner 侧记录回程入口，不应让 ingress 侧误认为已授权。
    try tracker.rememberRoute(client, 5, 1, 1);
    try std.testing.expectEqual(@as(u16, 5), tracker.lookupRoute(client, 2).?.node_id);
    try std.testing.expect(!tracker.isGranted(client, .{ .kind = .response, .source_node_id = 5, .source_worker_id = 1 }, 2));

    // ingress 侧授权后才放行，且必须 node 与 worker 同时匹配。
    try tracker.grantResponse(client, 9, 2, 3);
    try std.testing.expect(tracker.isGranted(client, .{ .kind = .response, .source_node_id = 9, .source_worker_id = 2 }, 4));
    try std.testing.expect(!tracker.isGranted(client, .{ .kind = .response, .source_node_id = 9, .source_worker_id = 3 }, 4));

    // 客户端直连后回程记录失效，但 ingress 授权不受影响。
    tracker.forgetRoute(client);
    try std.testing.expect(tracker.lookupRoute(client, 5) == null);
    try std.testing.expect(tracker.isGranted(client, .{ .kind = .response, .source_node_id = 9, .source_worker_id = 2 }, 5));
}
