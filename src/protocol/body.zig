//! 网关会读写的 Body 前缀
//!
//! 帧头（`frame.zig`）之外，有几处 Body 里的字节是网关必须处理的。它们都是**定长
//! 前缀 + 不透明尾部**的形状。
//!
//! 读的方向（`AuthGrant`、`TargetList`）只读前缀、绝不剥离：剥离会改变 `body_len`，
//! 迫使网关重新编码帧头并拷贝一次，把零拷贝转发变成有拷贝转发。
//!
//! 写的方向只有一处（`AuthContext`）：网关把自己的定长前缀插到 `auth_request` 的
//! body 前面再转发。这一处必须重编帧头，因为长度变了；代价可接受——认证是每条连接
//! 一次的低频路径，不在收包热路径上。
//!
//! ## 为什么单独一个文件
//!
//! `frame.zig` 描述的是"从哪到哪是一帧"，两个方向对称、与业务无关。本文件描述的
//! 是"网关在 Body 里认识哪几个字段"，每一个都对应一条具体的网关职责（准入、扇出、
//! 精确 kick）。混在一起会让帧头定义看起来像业务协议。

const std = @import("std");

const datagram = @import("datagram.zig");
const frame = @import("frame.zig");

const FrameError = frame.FrameError;

// ============================================================================
// 认证上下文（auth_request 的前缀）
// ============================================================================

/// 网关插在 `auth_request` body 前面的定长前缀（设计文档 §10.4）。
///
/// ```
/// 偏移  长度  字段
/// 0     2     realm (u16, 大端)
/// 2     16    conn_token (u128, 大端)
/// 18    ..    客户端原样的认证 body（token 等），网关一个字节都不看
/// ```
///
/// 它与 `AuthGrant` 构成一对对称的前缀：请求方向网关告诉后端"这是谁、在哪"，
/// 响应方向后端告诉网关"准入到什么程度"。两边都只碰自己的定长前缀。
///
/// 后端拿这两个字段各干一件事：
///
/// - `realm`：知道这次认证属于哪个接入方，从而校验自己该用哪套 token 体系。它由
///   网关从 SNI 解析（§12.3），比客户端自称的任何字段都可信。
/// - `conn_token`：**存进 presence，用于之后精确 kick 这一条连接。** 没有它，后端
///   只能按 `dest_id` 踢掉某个账号的全部设备，而"换设备登录只踢旧设备"这个最常见的
///   场景就表达不了（§5.6 说明了 `dest_id` 是一对多的）。
///
/// `conn_token` 对后端不透明：原样存、原样回传，不解析也不构造。
pub const AuthContext = struct {
    /// 前缀长度。
    pub const SIZE: usize = 18;

    /// 这条连接所属的隔离域。
    realm: u16 = 0,
    /// 这条连接在集群里的唯一标识（见 worker/connection.zig 的 ConnToken）。
    conn_token: u128 = 0,

    pub fn encode(self: AuthContext, buf: []u8) FrameError!void {
        if (buf.len < SIZE) return error.BufferTooSmall;
        std.mem.writeInt(u16, buf[0..2], self.realm, .big);
        std.mem.writeInt(u128, buf[2..18], self.conn_token, .big);
    }

    /// 解析前缀。短于 18 字节一律拒绝，不做默认值兜底——后端若把一个截断的前缀
    /// 当成 `realm = 0`，就会用错误的 token 体系去校验。
    pub fn decode(body: []const u8) FrameError!AuthContext {
        if (body.len < SIZE) return error.BufferTooSmall;
        return .{
            .realm = std.mem.readInt(u16, body[0..2], .big),
            .conn_token = std.mem.readInt(u128, body[2..18], .big),
        };
    }
};

// ============================================================================
// 准入结果（auth_success 的前缀）
// ============================================================================

/// `auth_success` body 的网关自有前缀（设计文档 §10.3）。
///
/// ```
/// 偏移  长度  字段
/// 0     8     dest_id (u64, 大端)
/// 8     4     ttl_seconds (u32, 大端)
/// 12    ..    opaque，网关不解析，原样透传给客户端
/// ```
///
/// 这不违反"网关不解析 token"：网关读的是自己协议的字段，token 的形态、签名方式、
/// 吊销机制依然完全不可见。前缀之后的字节网关一个都不看。
pub const AuthGrant = struct {
    /// 前缀长度。
    pub const SIZE: usize = 12;

    /// 这条连接可被寻址的标识；0 表示"不可被寻址"（例如纯拉取型客户端）。
    ///
    /// 只能由认证服务下发。**绝不能取自客户端声明的字段**——否则任何人都能把自己
    /// 注册成别人的 dest_id，然后收走别人的消息。
    dest_id: u64 = 0,
    /// 准入有效期（秒）；0 表示不过期。
    ///
    /// 有它才有"最迟 T 秒后失效"的正确性保证。`kick_off` 只是这个地基上的延迟优化：
    /// 没有 TTL 兜底的 kick 是无效的，客户端立刻重连就又进来了。
    ttl_seconds: u32 = 0,

    /// 解析前缀。
    ///
    /// body 短于 12 字节一律拒绝。宁可判认证失败，也不能把一个截断的响应当成
    /// "认证通过且不可寻址且永不过期"——那会让一次网络截断变成一次静默的降级。
    pub fn decode(body: []const u8) FrameError!AuthGrant {
        if (body.len < SIZE) return error.BufferTooSmall;
        return .{
            .dest_id = std.mem.readInt(u64, body[0..8], .big),
            .ttl_seconds = std.mem.readInt(u32, body[8..12], .big),
        };
    }

    /// 写入前缀。网关自己不产生 auth_success，这个方向给测试与后端 SDK 用。
    pub fn encode(self: AuthGrant, buf: []u8) FrameError!void {
        if (buf.len < SIZE) return error.BufferTooSmall;
        std.mem.writeInt(u64, buf[0..8], self.dest_id, .big);
        std.mem.writeInt(u32, buf[8..12], self.ttl_seconds, .big);
    }
};

// ============================================================================
// 连接生命周期（session_online / session_offline 的 body）
// ============================================================================

/// 一条连接级生命周期事件。Gateway 只报告连接事实，不聚合用户的多设备状态。
///
/// ```
/// 偏移  长度  字段
/// 0     2     realm (u16, 大端)
/// 2     16    conn_token (u128, 大端)
/// 18    8     dest_id (u64, 大端)
/// 26    8     connected_at (i64 Unix 秒，大端位模式)
/// 34    8     occurred_at (i64 Unix 秒，大端位模式)
/// 42    8     sequence (同一 conn_token 上严格递增)
/// 50    1     reason
/// ```
///
/// Reactor 以 `conn_token` 为会话主键，再按 `dest_id` 聚合多设备。Gateway 不知道
/// 设备类型、主设备、last_seen 或“用户整体是否在线”，也不应该替业务层做这些判断。
pub const SessionLifecycle = struct {
    pub const SIZE: usize = 51;

    pub const Reason = enum(u8) {
        authenticated = 0x00,
        transport_closed = 0x01,
        application_closed = 0x02,
        stateless_reset = 0x03,
        client_disconnect = 0x04,
        kicked = 0x05,
        admission_expired = 0x06,
        identity_replaced = 0x07,
        lease_refresh = 0x08,

        pub fn decode(byte: u8) FrameError!Reason {
            return switch (byte) {
                0x00 => .authenticated,
                0x01 => .transport_closed,
                0x02 => .application_closed,
                0x03 => .stateless_reset,
                0x04 => .client_disconnect,
                0x05 => .kicked,
                0x06 => .admission_expired,
                0x07 => .identity_replaced,
                0x08 => .lease_refresh,
                else => error.ReservedBitsSet,
            };
        }
    };

    realm: u16,
    conn_token: u128,
    dest_id: u64,
    connected_at: i64,
    occurred_at: i64,
    /// 同一连接内严格递增的事件序号。生命周期事件各走独立 QUIC 流，跨流不保证
    /// 到达顺序；Reactor 必须靠它拒绝迟到的旧事件，否则 offline 可能覆盖一次
    /// 更新的 online（身份替换时尤其容易发生）。
    sequence: u64,
    reason: Reason,

    pub fn encode(self: SessionLifecycle, buf: []u8) FrameError!void {
        if (buf.len < SIZE) return error.BufferTooSmall;
        std.mem.writeInt(u16, buf[0..2], self.realm, .big);
        std.mem.writeInt(u128, buf[2..18], self.conn_token, .big);
        std.mem.writeInt(u64, buf[18..26], self.dest_id, .big);
        std.mem.writeInt(u64, buf[26..34], @bitCast(self.connected_at), .big);
        std.mem.writeInt(u64, buf[34..42], @bitCast(self.occurred_at), .big);
        std.mem.writeInt(u64, buf[42..50], self.sequence, .big);
        buf[50] = @intFromEnum(self.reason);
    }

    pub fn decode(buf: []const u8) FrameError!SessionLifecycle {
        if (buf.len < SIZE) return error.BufferTooSmall;
        return .{
            .realm = std.mem.readInt(u16, buf[0..2], .big),
            .conn_token = std.mem.readInt(u128, buf[2..18], .big),
            .dest_id = std.mem.readInt(u64, buf[18..26], .big),
            .connected_at = @bitCast(std.mem.readInt(u64, buf[26..34], .big)),
            .occurred_at = @bitCast(std.mem.readInt(u64, buf[34..42], .big)),
            .sequence = std.mem.readInt(u64, buf[42..50], .big),
            .reason = try Reason.decode(buf[50]),
        };
    }
};

// ============================================================================
// 目标列表（.peer 的 OPEN 前缀 / 投递回报）
// ============================================================================

/// 一个 `dest_id` 占的字节数。
pub const dest_id_size: usize = 8;

/// 目标列表能容纳的最大条目数。
///
/// 受单帧 Body 上限约束：`(65535 - 2) / 8`。更大的群由后端分多帧发。
pub const max_targets: usize = (frame.MAX_BODY_SIZE - 2) / dest_id_size;

/// `count (u16) + dest_id[count] (每个 8 字节，大端)`。
///
/// 两处用到同一个形状：
///
/// - `.peer` 交换的 **OPEN 帧** body 前缀，声明这一次交换投给谁；
/// - 投递回报，网关在后端那条流上回写投不出去的 `dest_id`。
///
/// 只出现在 OPEN 上，后续 DATA 不重复——目标是流级属性（同 `dest_kind`）。DATA 的
/// body 是纯负载，接收方不需要在它上面跳前缀。
///
/// 解出的 `entries` 是对输入的借用，不拥有内存。
pub const TargetList = struct {
    count: u16,
    /// dest_id 区，长度恒为 `count * 8`。
    entries: []const u8,

    /// 一个含 count 个目标的列表占多少字节。
    pub fn byteSize(count: usize) usize {
        return 2 + count * dest_id_size;
    }

    /// 解析前缀；不校验尾部还剩多少（那是负载，长度由帧头决定）。
    ///
    /// `count = 0` 是合法的：后端可以发一个空目标列表（虽然没有意义），网关按
    /// "零个目标"处理，不当成错误。真正的错误只有"声明了 N 个但字节不够"。
    pub fn decode(body: []const u8) FrameError!TargetList {
        if (body.len < 2) return error.BufferTooSmall;
        const count = std.mem.readInt(u16, body[0..2], .big);
        const end = byteSize(count);
        if (body.len < end) return error.BufferTooSmall;
        return .{ .count = count, .entries = body[2..end] };
    }

    /// 取第 i 个目标。
    pub fn get(self: TargetList, i: usize) u64 {
        const offset = i * dest_id_size;
        return std.mem.readInt(u64, self.entries[offset..][0..dest_id_size], .big);
    }

    /// 本列表（含 count 字段）占的字节数，即负载的起始偏移。
    pub fn prefixLen(self: TargetList) usize {
        return byteSize(self.count);
    }

    /// 写入一个目标列表，返回写入的字节数。
    ///
    /// 网关用它编码投递回报；后端 SDK 用它编码 `.peer` 的 OPEN 前缀。
    pub fn encode(buf: []u8, targets: []const u64) FrameError!usize {
        if (targets.len > max_targets) return error.BodyTooLarge;
        const total = byteSize(targets.len);
        if (buf.len < total) return error.BufferTooSmall;

        std.mem.writeInt(u16, buf[0..2], @intCast(targets.len), .big);
        for (targets, 0..) |target, i| {
            const offset = 2 + i * dest_id_size;
            std.mem.writeInt(u64, buf[offset..][0..dest_id_size], target, .big);
        }
        return total;
    }
};

/// `conn_token` 是带进程 incarnation 的 128 位不透明值，不能再复用 64 位 dest_id
/// 列表。把两种列表分成独立类型，编译器会阻止 kick/group 路径误用 TargetList。
pub const conn_token_size: usize = 16;
pub const max_conn_tokens: usize = (frame.MAX_BODY_SIZE - 2) / conn_token_size;

pub const TokenList = struct {
    count: u16,
    entries: []const u8,

    pub fn byteSize(count: usize) usize {
        return 2 + count * conn_token_size;
    }

    pub fn decode(input: []const u8) FrameError!TokenList {
        if (input.len < 2) return error.BufferTooSmall;
        const count = std.mem.readInt(u16, input[0..2], .big);
        const end = byteSize(count);
        if (input.len < end) return error.BufferTooSmall;
        return .{ .count = count, .entries = input[2..end] };
    }

    pub fn get(self: TokenList, i: usize) u128 {
        const offset = i * conn_token_size;
        return std.mem.readInt(u128, self.entries[offset..][0..conn_token_size], .big);
    }

    pub fn encode(buf: []u8, tokens: []const u128) FrameError!usize {
        if (tokens.len > max_conn_tokens) return error.BodyTooLarge;
        const total = byteSize(tokens.len);
        if (buf.len < total) return error.BufferTooSmall;
        std.mem.writeInt(u16, buf[0..2], @intCast(tokens.len), .big);
        for (tokens, 0..) |token, i| {
            const offset = 2 + i * conn_token_size;
            std.mem.writeInt(u128, buf[offset..][0..conn_token_size], token, .big);
        }
        return total;
    }
};

// ============================================================================
// 组播成员变更（join_group / leave_group 的 body）
// ============================================================================

/// `join_group` / `leave_group` 的 body（设计文档 §7.2 后端 → 网关控制交换）。
///
/// ```
/// 偏移  长度  字段
/// 0     8     group_id (u64, 大端)
/// 8     ..    TokenList，条目是 128 位 conn_token
/// ```
///
/// **组标识在前、成员列表在后**，因为一次变更天然是"把这批连接加进同一个组"：
/// 后端把一局游戏的玩家一起放进房间、把一个文档的协作者一起放进会话。反过来
/// （每个条目带自己的 group_id）会让常见情形重复 8 字节 × N。
///
/// 成员用 `conn_token` 而不是 `dest_id`：`dest_id` 是一对多的（一个账号多台设备，
/// §5.6），而"这台设备打开了这个文档"不该把该账号的其他设备也拉进组。后端在认证时
/// 就拿到了 `conn_token`（§10.4 的 `AuthContext`），本来就要为 `kick_off` 存着它。
pub const GroupBinding = struct {
    /// 组标识前缀长度。
    pub const SIZE: usize = 8;

    group_id: u64 = 0,
    /// 成员的 conn_token 列表。
    members: TokenList,

    pub fn decode(body: []const u8) FrameError!GroupBinding {
        if (body.len < SIZE) return error.BufferTooSmall;
        return .{
            .group_id = std.mem.readInt(u64, body[0..8], .big),
            .members = try TokenList.decode(body[SIZE..]),
        };
    }

    /// 写入一次组成员变更，返回写入的字节数。网关自己不产生它，这个方向给测试与后端 SDK 用。
    pub fn encode(buf: []u8, group_id: u64, members: []const u128) FrameError!usize {
        if (buf.len < SIZE) return error.BufferTooSmall;
        std.mem.writeInt(u64, buf[0..8], group_id, .big);
        return SIZE + try TokenList.encode(buf[SIZE..], members);
    }
};

// ============================================================================
// 通道绑定（bind_channel / unbind_channel 的 body）
// ============================================================================

/// `bind_channel` 控制帧的 body（设计文档 §6.1）。
///
/// ```
/// 偏移  长度  字段
/// 0     1     channel
/// 1     8     group_id
/// ```
///
/// `unbind_channel` 只用第一个字节，因此两者共用一个解码器（`decodeChannel`）。
///
/// **只能绑到组播组，不能绑到 `dest_id`。** 设计文档原先在 §6.1 里两种都列了，但
/// `.peer` 那半边过不了 §5.4 的权限矩阵：网关对"这个客户端能不能不可靠地寻址那个
/// 账号"没有任何本地判据，临时发明一个就正好是 §5.4 要防的越权。而组成员关系是
/// **后端通过 `join_group` 建立的**，所以"已经是该组成员"是一次真实的、有权威来源的
/// 本地判断。需要 1:1 不可靠通路时，让后端把两条连接放进一个两人组——组成员边本来
/// 就是池化的，这不额外花钱，授权也留在了它该在的地方。
pub const ChannelBinding = struct {
    /// 绑定请求的固定长度。
    pub const SIZE: usize = 9;

    channel: u8,
    group_id: u64,

    pub fn decode(body: []const u8) FrameError!ChannelBinding {
        if (body.len < SIZE) return error.BufferTooSmall;
        const channel = body[0];
        if (channel >= datagram.max_channels) return error.InvalidChannel;
        return .{
            .channel = channel,
            .group_id = std.mem.readInt(u64, body[1..9], .big),
        };
    }

    /// 写入一次绑定请求，返回写入的字节数。网关自己不产生它，这个方向给测试与客户端 SDK 用。
    pub fn encode(buf: []u8, channel: u8, group_id: u64) FrameError!usize {
        if (buf.len < SIZE) return error.BufferTooSmall;
        if (channel >= datagram.max_channels) return error.InvalidChannel;
        buf[0] = channel;
        std.mem.writeInt(u64, buf[1..9], group_id, .big);
        return SIZE;
    }
};

/// 解出一个只带通道号的 body（`unbind_channel`）。
pub fn decodeChannel(body: []const u8) FrameError!u8 {
    if (body.len < 1) return error.BufferTooSmall;
    if (body[0] >= datagram.max_channels) return error.InvalidChannel;
    return body[0];
}

// ============================================================================
// 重定向（redirect 的 body）
// ============================================================================

/// `redirect` 控制帧的 body（设计文档 §8.5 策略 B）。
///
/// ```
/// 偏移  长度         字段
/// 0     1            hint_len
/// 1     1            address_len
/// 2     hint_len     placement hint（不透明）
/// ..    address_len  home 节点地址，UTF-8 的 "host:port"
/// ```
///
/// 两个字段各解决亲和的一级：
///
/// - **address** 解决节点级。客户端把它缓存下来，下次重连直接拨这个地址。
///   记忆放在客户端而不是服务端签发的凭据里，所以不需要 `NEW_TOKEN`
///   （picoquic 也不支持应用层读它）。home 因扩缩容漂移时缓存过期，客户端连到错
///   节点、再吃一次重定向、更新缓存，**自愈**。
/// - **placement hint** 解决 Worker 级。客户端把它原样填进下次连接**首个 Initial 包
///   的 DCID 前缀**，内核态 reuseport BPF 就会把首包投给正确的 Worker。这条成立是
///   因为 QUIC 规定客户端首个 Initial 的 DCID 由客户端自选（8–20 字节，服务端必须
///   接受）。重定向本身治不了 Worker 级——客户端只能选连哪个节点地址。
///
/// 三条必须守住的约束：
///
/// - **hint 对客户端不透明。** 它不该知道哈希函数与 `worker_count`，否则扩缩容改了
///   Worker 数就要改客户端。
/// - **hint 绝不包含完整 CID。** 只含定位段，entropy 由客户端自己随机填。把完整 CID
///   交给客户端复用，就给了它主动撞上一条在用连接 CID 的机会。
/// - **hint 不需要 MAC。** 它只回答"去哪"，不回答"你是谁能干什么"：伪造它最坏是
///   客户端把自己钉到某个 Worker 上制造热点，而身份始终只来自 `auth_success`。
pub const RedirectHint = struct {
    /// 定长头长度（hint_len + address_len）。
    pub const HEADER_SIZE: usize = 2;

    /// 不透明的放置提示，原样填进下次连接的 initial DCID 前缀。
    hint: []const u8,
    /// home 节点地址，UTF-8 的 "host:port"。
    address: []const u8,

    pub fn decode(body: []const u8) FrameError!RedirectHint {
        if (body.len < HEADER_SIZE) return error.BufferTooSmall;
        const hint_len: usize = body[0];
        const address_len: usize = body[1];
        const total = HEADER_SIZE + hint_len + address_len;
        if (body.len < total) return error.BufferTooSmall;
        return .{
            .hint = body[HEADER_SIZE..][0..hint_len],
            .address = body[HEADER_SIZE + hint_len ..][0..address_len],
        };
    }

    pub fn encode(buf: []u8, hint: []const u8, address: []const u8) FrameError!usize {
        if (hint.len > 255 or address.len > 255) return error.BodyTooLarge;
        const total = HEADER_SIZE + hint.len + address.len;
        if (buf.len < total) return error.BufferTooSmall;
        buf[0] = @intCast(hint.len);
        buf[1] = @intCast(address.len);
        @memcpy(buf[HEADER_SIZE..][0..hint.len], hint);
        @memcpy(buf[HEADER_SIZE + hint.len ..][0..address.len], address);
        return total;
    }
};

// ============================================================================
// 测试
// ============================================================================

test "AuthGrant roundtrip" {
    const grant = AuthGrant{ .dest_id = 0x0123456789ABCDEF, .ttl_seconds = 3600 };

    var buf: [AuthGrant.SIZE]u8 = undefined;
    try grant.encode(&buf);

    const decoded = try AuthGrant.decode(&buf);
    try std.testing.expectEqual(grant.dest_id, decoded.dest_id);
    try std.testing.expectEqual(grant.ttl_seconds, decoded.ttl_seconds);
}

test "AuthGrant ignores whatever follows the prefix" {
    // 前缀之后是认证服务给客户端的不透明数据，网关不看也不要求它存在。
    var buf: [64]u8 = undefined;
    const grant = AuthGrant{ .dest_id = 7, .ttl_seconds = 60 };
    try grant.encode(&buf);
    @memcpy(buf[AuthGrant.SIZE..][0..5], "hello");

    const decoded = try AuthGrant.decode(buf[0 .. AuthGrant.SIZE + 5]);
    try std.testing.expectEqual(@as(u64, 7), decoded.dest_id);
    try std.testing.expectEqual(@as(u32, 60), decoded.ttl_seconds);
}

test "SessionLifecycle roundtrip" {
    const event: SessionLifecycle = .{
        .realm = 7,
        .conn_token = 0x1111_2222_3333_4444,
        .dest_id = 42,
        .connected_at = 1_700_000_000,
        .occurred_at = 1_700_000_123,
        .sequence = 9,
        .reason = .application_closed,
    };
    var buf: [SessionLifecycle.SIZE]u8 = undefined;
    try event.encode(&buf);
    try std.testing.expectEqualDeep(event, try SessionLifecycle.decode(&buf));
    try std.testing.expectError(error.BufferTooSmall, SessionLifecycle.decode(buf[0 .. SessionLifecycle.SIZE - 1]));
}

test "a truncated AuthGrant is rejected, not defaulted" {
    // 关键回归：截断必须报错。若默认成 dest_id=0 / ttl=0，一次网络截断就会静默
    // 变成"认证通过、不可寻址、永不过期"。
    var buf: [AuthGrant.SIZE]u8 = undefined;
    try (AuthGrant{ .dest_id = 1, .ttl_seconds = 1 }).encode(&buf);

    try std.testing.expectError(error.BufferTooSmall, AuthGrant.decode(buf[0 .. AuthGrant.SIZE - 1]));
    try std.testing.expectError(error.BufferTooSmall, AuthGrant.decode(&.{}));
}

test "TargetList roundtrip and payload offset" {
    const targets = [_]u64{ 1, 0xFFFF_FFFF_FFFF_FFFF, 42 };

    var buf: [128]u8 = undefined;
    const written = try TargetList.encode(&buf, &targets);
    try std.testing.expectEqual(TargetList.byteSize(targets.len), written);

    // 后面接一段负载，模拟真实的 .peer OPEN body。
    @memcpy(buf[written..][0..4], "body");

    const list = try TargetList.decode(buf[0 .. written + 4]);
    try std.testing.expectEqual(@as(u16, 3), list.count);
    for (targets, 0..) |expected, i| {
        try std.testing.expectEqual(expected, list.get(i));
    }
    // 负载从前缀之后开始；网关读前缀但不剥离，接收方按同样规则跳过。
    try std.testing.expectEqual(written, list.prefixLen());
    try std.testing.expectEqualStrings("body", buf[list.prefixLen()..][0..4]);
}

test "TargetList rejects a count that the bytes cannot back" {
    // 声明 3 个目标却只给了 1 个的字节数：必须报错，否则 get() 会越界读。
    var buf: [16]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], 3, .big);
    try std.testing.expectError(error.BufferTooSmall, TargetList.decode(buf[0..10]));

    try std.testing.expectError(error.BufferTooSmall, TargetList.decode(buf[0..1]));
}

test "an empty TargetList is legal" {
    var buf: [8]u8 = undefined;
    const written = try TargetList.encode(&buf, &.{});
    try std.testing.expectEqual(@as(usize, 2), written);

    const list = try TargetList.decode(buf[0..written]);
    try std.testing.expectEqual(@as(u16, 0), list.count);
    try std.testing.expectEqual(@as(usize, 2), list.prefixLen());
}

test "TargetList refuses more targets than one frame can carry" {
    var buf: [16]u8 = undefined;
    const too_many = try std.testing.allocator.alloc(u64, max_targets + 1);
    defer std.testing.allocator.free(too_many);
    @memset(too_many, 0);

    try std.testing.expectError(error.BodyTooLarge, TargetList.encode(&buf, too_many));
}

test "AuthContext roundtrip and opaque tail" {
    var buf: [AuthContext.SIZE + 5]u8 = undefined;
    const context: AuthContext = .{ .realm = 0x0709, .conn_token = 0xDEAD_BEEF_CAFE_BABE };
    try context.encode(buf[0..AuthContext.SIZE]);
    @memcpy(buf[AuthContext.SIZE..][0..5], "token");

    const decoded = try AuthContext.decode(&buf);
    try std.testing.expectEqual(context.realm, decoded.realm);
    try std.testing.expectEqual(context.conn_token, decoded.conn_token);
    // 前缀之后的字节是后端的，网关既不解析也不改动。
    try std.testing.expectEqualStrings("token", buf[AuthContext.SIZE..]);
}

test "a truncated AuthContext is rejected, not defaulted" {
    // 关键回归：后端若把截断的前缀当成 realm = 0，就会用错误的 token 体系去校验。
    var buf: [AuthContext.SIZE]u8 = undefined;
    const context: AuthContext = .{ .realm = 7, .conn_token = 1 };
    try context.encode(&buf);

    try std.testing.expectError(error.BufferTooSmall, AuthContext.decode(buf[0 .. AuthContext.SIZE - 1]));
    try std.testing.expectError(error.BufferTooSmall, AuthContext.decode(&.{}));
    // 恰好等于前缀长度、没有尾部是合法的。
    try std.testing.expectEqual(@as(u16, 7), (try AuthContext.decode(&buf)).realm);
}

test "GroupBinding carries one group and a batch of conn_tokens" {
    var buf: [64]u8 = undefined;
    const members = [_]u128{ 0x1111, 0x2222, 0x3333 };
    const written = try GroupBinding.encode(&buf, 0xABCD_EF01_2345_6789, &members);

    const decoded = try GroupBinding.decode(buf[0..written]);
    try std.testing.expectEqual(@as(u64, 0xABCD_EF01_2345_6789), decoded.group_id);
    try std.testing.expectEqual(@as(u16, 3), decoded.members.count);
    for (members, 0..) |expected, i| {
        try std.testing.expectEqual(expected, decoded.members.get(i));
    }
}

test "a GroupBinding without a member list is rejected" {
    // 只有 group_id 没有 TargetList 时必须报错：默认成"零个成员"会让一次截断
    // 静默变成一次空操作，后端会以为加组成功了。
    var buf: [GroupBinding.SIZE]u8 = undefined;
    std.mem.writeInt(u64, buf[0..8], 7, .big);
    try std.testing.expectError(error.BufferTooSmall, GroupBinding.decode(&buf));
    try std.testing.expectError(error.BufferTooSmall, GroupBinding.decode(buf[0..3]));
}

test "RedirectHint roundtrip" {
    var buf: [64]u8 = undefined;
    const hint = [_]u8{ 0x4c, 0x59, 0x01, 0x00, 0x07, 0x03 };
    const written = try RedirectHint.encode(&buf, &hint, "10.0.0.7:8443");

    const decoded = try RedirectHint.decode(buf[0..written]);
    try std.testing.expectEqualSlices(u8, &hint, decoded.hint);
    try std.testing.expectEqualStrings("10.0.0.7:8443", decoded.address);
}

test "RedirectHint allows an empty hint but still needs its header" {
    // 空 hint 是合法的：只做节点级亲和（客户端缓存地址）而不做 Worker 级时就是这个形态。
    var buf: [32]u8 = undefined;
    const written = try RedirectHint.encode(&buf, &.{}, "gw-2:8443");
    const decoded = try RedirectHint.decode(buf[0..written]);
    try std.testing.expectEqual(@as(usize, 0), decoded.hint.len);
    try std.testing.expectEqualStrings("gw-2:8443", decoded.address);

    try std.testing.expectError(error.BufferTooSmall, RedirectHint.decode(buf[0..1]));
    // 声明的长度必须有字节兜住，否则 decode 会切出越界切片。
    try std.testing.expectError(error.BufferTooSmall, RedirectHint.decode(buf[0 .. written - 1]));
}
