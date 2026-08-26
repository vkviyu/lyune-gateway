const std = @import("std");

const foundation = @import("../foundation/mod.zig");
const RealmId = foundation.realm.RealmId;
const protocol = @import("../protocol/mod.zig");
const backend_mod = @import("../backend/mod.zig");
const ScopedRoute = backend_mod.ScopedRoute;
const inflight = @import("inflight.zig");
const quic = @import("../quic/mod.zig");
const QUICConnection = quic.connection.Connection;

/// 一条已开出的后端流。
pub const BackendStream = struct {
    /// 这条流在在途表里的键：transport 实例身份 + 该实例内部的句柄。
    ///
    /// 存整个键而不只存句柄，是为了让"作废这次交换"在任何分支上都能执行——包括
    /// transport 中途消失（配置重载、后端摘除）那一支，那时已经拿不到 transport
    /// 实例了，但条目还必须删掉。
    ///
    /// 同一次交换的所有 DATA 帧都写到 `key.stream` 上，后端因此看到一条完整有序的
    /// 字节流。
    key: inflight.StreamKey,
    /// 开流时使用的注册表键（realm + 路由键）。客户端中途断开时要靠它找回
    /// transport 去 fin 后端流，否则后端会一直等一个永远不来的结束标记。
    ///
    /// 存下来而不是每次从连接上下文再读一次 realm：那样"用哪个 realm 查表"就变成了
    /// 每个调用点各自的判断，而查错 realm 的后果是把字节写进另一个接入方的后端。
    scope: ScopedRoute,
};

/// 一条客户端流上的交换状态。
///
/// 协议规定"一条 QUIC 流 = 一次交换"（OPEN + N×DATA，末帧带 eof）。条目的存在
/// 表示"这条流上有一次已被接纳的交换"，由此得到两条判据（设计文档 §7.5）：
///
/// - 交换还在进行却又来 OPEN → 一条流上塞了两次交换，协议违规
/// - 交换已 `completed` 却又来帧 → eof 之后继续发，协议违规
///
/// 反过来，被拒绝的交换**不登记**：网关回了错误帧就当这次交换没发生。这样后续
/// 分片会因为"查不到交换"被丢弃，而不是升级成协议违规——一次配额拒绝不该
/// 顺带杀掉整条连接。
///
/// 条目在 QUIC FIN 或流被终止时清理，因此"客户端发了 eof 却迟迟不发 FIN"会
/// 让条目滞留。这只会占用它自己那份 `max_exchanges_per_connection` 额度，
/// 伤不到别的连接。
pub const Exchange = struct {
    /// 后端流；仅当目的地是 `.service` 且交换仍在进行时有值。
    ///
    /// 一次性交换（OPEN 直接带 eof）不留句柄：后端流已经随首帧 fin 了，
    /// 再存着只会给"这条流还能追加"这个错觉。
    backend: ?BackendStream = null,
    /// 这条流承载的流式推送会话号；0 表示不是（设计文档 §5.3）。
    ///
    /// 只可能出现在**对等网关节点**的连接上：那一侧的入站流是别的节点开的会话流，
    /// 会话身份就是这条流。客户端连接上永远是 0——客户端无权寻址 `.peer`。
    push_session: u64 = 0,
    /// 已收到带 eof 的帧，这次交换结束了，但流还没被 QUIC FIN 收走。
    completed: bool = false,
};

/// 一条连接在整个集群里的唯一标识。
///
/// 后端拿它来精确指定"踢掉哪一条连接"（设计文档 §7.2 的后端 → 网关控制交换）。
/// `dest_id` 做不到这件事：它是一对多的（一个账号多台设备，§5.6），而换设备登录
/// 恰恰只想踢掉旧的那一台。
///
/// 它同时**自带位置**：`node_id` + `worker_id` 就是这条连接所在的 (节点, Worker)。
/// 这是 §8.4「两跳都不知道」的破解口——那节说的是客户端**首包**时还不知道自己的
/// `dest_id`，所以位置无法由身份决定；而 kick 的前提是连接已经认证过了，这时网关
/// 完全知道"我在哪"，只要在认证成功那一刻说出来就行。CID 不能事后重贴，token 可以。
///
/// 对后端**不透明**：它只负责原样存下、原样回传。位段布局是网关的内部约定，
/// 后端不解析、也不构造。
pub const ConnToken = packed struct(u64) {
    /// 槽位复用计数器，防 ABA：槽位被新连接复用后，旧 token 必须失配。
    ///
    /// u16 意味着同一槽位被复用 65536 次之后会绕回。要撞上得让一个后端持有某个
    /// token 跨越同一槽位的 65536 次连接更替，实践上不可达；而绕回的后果是一次
    /// 误踢，不是权限逃逸——realm 仍然会被单独校验。
    generation: u16 = 0,
    /// 会话槽位下标。
    slot: u24 = 0,
    /// 这条连接所在的 Worker。
    worker_id: u8 = 0,
    /// 这条连接所在的节点。
    node_id: u16 = 0,

    /// 线格式是大端 u64（与 body.TargetList 的条目一致）。
    pub fn encode(self: ConnToken) u64 {
        return @bitCast(self);
    }

    pub fn decode(raw: u64) ConnToken {
        return @bitCast(raw);
    }
};

/// 业务连接上下文：附加在 QUIC Connection 上的业务数据
pub const ConnectionContext = struct {
    allocator: std.mem.Allocator,
    // 存储底层的 C 指针，它是唯一且稳定的。
    cnx_handle: quic.c.QuicCnx,
    /// 这条连接所属的隔离域（设计文档 §12）。
    ///
    /// 握手完成时由 SNI 解析一次，此后**不可变**：它是路由键与 `dest_id` 的
    /// 命名空间前缀，中途改变等于把一条连接搬进别人的命名空间。客户端在帧里
    /// 没有任何字段能影响它。
    realm: RealmId,
    /// 是否已通过接入认证（由后端认证服务返回 auth_success 后置位）
    authenticated: bool = false,
    /// 这是一条**对等网关节点**的连接，不是客户端连接。
    ///
    /// 唯一来源是「它从集群监听器进来的」——那个端口要求由私有集群 CA 签发的客户端
    /// 证书，握手成功即等价于"对端是一个网关节点"（设计文档 §8.5）。
    ///
    /// 判据刻意是**结构性的**（从哪个监听器进来）而不是应用层握手：一条客户端连接
    /// 没有任何方式能让这个字段变成 true，因为它落在另一个 socket 上。这比"一个必须
    /// 被正确设置的标记"强一档——后者只要有一条代码路径忘了检查就是权限逃逸。
    ///
    /// 它放开的能力：可以发 `.peer` / `.multicast`，且 realm 取自帧头的
    /// `realmHint()` 而不是 SNI。对等节点本来就持有所有 realm 的连接，因此
    /// "它能指定任意 realm"不是新增的信任，而是它已有信任的一部分。
    peer_node: bool = false,
    /// 这条连接可被寻址的标识；0 表示不可被寻址（设计文档 §5.6）。
    ///
    /// 由认证服务在 `auth_success` 前缀里下发，网关从不采信客户端声明的值。
    /// 一个 `dest_id` 可以对应多条连接（同一账号的多台设备），因此它不是连接的
    /// 唯一键——连接的唯一键始终是 `cnx_handle`。只在本连接的 realm 内唯一。
    dest_id: u64 = 0,
    /// 准入失效时刻（微秒，与 `quic.c.currentTime()` 同一时钟）；0 表示不过期。
    ///
    /// 有它才有"最迟 T 秒后失效"的保证：否则 token 过期、账号吊销都无法反映到
    /// 已经建立的连接上。
    auth_expires_at: u64 = 0,
    /// 下一个由网关主动发起的双向流 id（设计文档 §7.4）。
    ///
    /// QUIC 规定服务端发起的双向流 id 从 1 开始、每次 +4，客户端发起的是 0/4/8…，
    /// 两个空间不重叠。因此推送流永远不会撞上客户端自己开的流，不需要任何协调。
    next_push_stream_id: u64 = 1,
    /// datagram 通道表：下标即通道号，取值是绑定的组标识；0 表示未绑定（设计文档 §6.1）。
    ///
    /// 用定长数组内联在上下文里而不是哈希表：容量是 8，一次线性扫描比一次哈希更快，
    /// 而连接槽位本来就是启动期一次分配的，内联进去意味着运行期零分配。
    ///
    /// 0 当"未绑定"是安全的：`group_id == 0` 在组索引里本来就查不到任何东西
    /// （见 `groupConnections`），与 `dest_id == 0` 表示"不可寻址"是同一套约定。
    channels: [protocol.datagram.max_channels]u64 = @splat(0),
    connected_at: i64,

    // owning GatewayWorker pointer, kept opaque to avoid an import cycle.
    gateway_ctx: ?*anyopaque = null,

    /// 跨回调的上行残帧，按客户端 stream_id 存放。
    ///
    /// 只有一次回调没带来整帧时才会有条目；帧边界对齐的常态下这张表是空的，
    /// 也不会发生任何堆分配。
    frame_spills: std.AutoHashMap(u64, protocol.framing.Spill),

    /// 进行中的交换：客户端 stream_id -> 交换状态。
    exchanges: std.AutoHashMap(u64, Exchange),

    /// 本次分帧循环结束后需要关闭这条连接。
    ///
    /// 不能在循环里就地关闭：正在分派的帧指向 spill 缓冲，连接一旦被销毁
    /// 后续迭代就会读到已释放内存。因此这里只置位，由分帧调用方收尾时处理。
    close_requested: bool = false,

    pub fn init(allocator: std.mem.Allocator, cnx: quic.c.QuicCnx, realm: RealmId) ConnectionContext {
        return .{
            .allocator = allocator,
            .cnx_handle = cnx,
            .realm = realm,
            .connected_at = foundation.time.timestampSeconds(),
            .frame_spills = std.AutoHashMap(u64, protocol.framing.Spill).init(allocator),
            .exchanges = std.AutoHashMap(u64, Exchange).init(allocator),
        };
    }

    pub fn deinit(self: *ConnectionContext) void {
        var it = self.frame_spills.valueIterator();
        while (it.next()) |spill| spill.deinit(self.allocator);
        self.frame_spills.deinit();
        self.exchanges.deinit();
    }

    /// 取这条流的残帧缓冲；没有残帧时返回 null。
    pub fn frameSpill(self: *ConnectionContext, stream_id: u64) ?*protocol.framing.Spill {
        return self.frame_spills.getPtr(stream_id);
    }

    /// 存入这条流的残帧缓冲，接管其内存所有权。
    ///
    /// 只在真的产生残帧时调用：帧边界对齐的常态下这张表一次也不会被写，
    /// 热路径上因此没有任何哈希表插入与删除的开销。
    pub fn storeFrameSpill(self: *ConnectionContext, stream_id: u64, spill: protocol.framing.Spill) !void {
        try self.frame_spills.put(stream_id, spill);
    }

    /// 释放并移除这条流的残帧缓冲。
    pub fn dropFrameSpill(self: *ConnectionContext, stream_id: u64) void {
        if (self.frame_spills.fetchRemove(stream_id)) |removed| {
            var spill = removed.value;
            spill.deinit(self.allocator);
        }
    }

    /// 取这条客户端流的交换状态；这条流还没收过 OPEN 时返回 null。
    ///
    /// 返回指针是为了让调用方就地推进状态（收到 eof 改 `.completed`、
    /// 业务失败改 `.failed`），省掉一次哈希查找。
    pub fn exchange(self: *ConnectionContext, stream_id: u64) ?*Exchange {
        return self.exchanges.getPtr(stream_id);
    }

    /// 登记一次新交换。
    pub fn openExchange(self: *ConnectionContext, stream_id: u64, entry: Exchange) !void {
        try self.exchanges.put(stream_id, entry);
    }

    /// 移除交换状态（QUIC FIN，或这条流被终止）。
    pub fn closeExchange(self: *ConnectionContext, stream_id: u64) void {
        _ = self.exchanges.remove(stream_id);
    }

    /// 当前这条连接上的交换数量，用于按连接限流。
    pub fn exchangeCount(self: *const ConnectionContext) usize {
        return self.exchanges.count();
    }

    /// 这条连接此刻是否仍然被准入。
    ///
    /// 两个条件都要满足：认证通过过，且没有过期。分开存是因为它们的来源不同——
    /// 前者是认证服务的结论，后者是它给出的有效期。
    pub fn isAdmitted(self: *const ConnectionContext, now: u64) bool {
        if (!self.authenticated) return false;
        if (self.auth_expires_at == 0) return true;
        return now < self.auth_expires_at;
    }

    /// 取一个新的推送流 id（网关主动发起的方向）。
    pub fn nextPushStream(self: *ConnectionContext) u64 {
        const stream_id = self.next_push_stream_id;
        self.next_push_stream_id += 4;
        return stream_id;
    }

    // ------------------------------------------------------------------------
    // datagram 通道表（设计文档 §6.1）
    // ------------------------------------------------------------------------

    /// 这个通道绑定的组；未绑定返回 null。
    pub fn channelGroup(self: *const ConnectionContext, channel: u8) ?u64 {
        if (channel >= self.channels.len) return null;
        const group_id = self.channels[channel];
        return if (group_id == 0) null else group_id;
    }

    /// 这条连接为这个组绑定的通道；没绑返回 null。
    ///
    /// 下行要用它：一个 datagram 投给组成员时，用的是**每个成员自己**的通道号
    /// ——通道号是连接本地的资源，不同成员完全可以给同一个组绑不同的号。
    pub fn channelFor(self: *const ConnectionContext, group_id: u64) ?u8 {
        if (group_id == 0) return null;
        for (self.channels, 0..) |bound, channel| {
            if (bound == group_id) return @intCast(channel);
        }
        return null;
    }

    /// 绑定一个通道；重复绑定同一个号即覆盖。
    ///
    /// 覆盖而不是拒绝：通道号是客户端自己的资源，它重用一个号只说明它换了房间，
    /// 而拒绝会逼客户端去猜哪个号还空着。
    pub fn bindChannel(self: *ConnectionContext, channel: u8, group_id: u64) void {
        if (channel >= self.channels.len) return;
        self.channels[channel] = group_id;
    }

    pub fn unbindChannel(self: *ConnectionContext, channel: u8) void {
        if (channel >= self.channels.len) return;
        self.channels[channel] = 0;
    }

    /// 清空所有绑定。
    ///
    /// **准入被吊销时必须调用。** §6.1 的取舍是"授权只在绑定时查一次，热路径上不做
    /// 任何权限判断"，那么权限消失的那一刻就得把通道一起收走——否则一条被踢掉、
    /// 还没断开的连接仍能继续往组里灌状态包。
    pub fn clearChannels(self: *ConnectionContext) void {
        @memset(&self.channels, 0);
    }
};

/// cnx 指针 -> 槽位下标的定容索引表。
///
/// 用开放寻址 + 线性探测，容量在启动时定死：负载因子不超过 0.5，因此探测长度
/// 不会退化，而且运行期永不 rehash——AutoHashMap 那种"插到某个水位突然搬一次家"
/// 的尖刺在收包路径上是不可接受的。
const IndexTable = struct {
    entries: []Entry,
    mask: usize,

    const Entry = struct {
        key: ?quic.c.QuicCnx = null,
        slot: u32 = 0,
    };

    fn init(allocator: std.mem.Allocator, capacity: usize) !IndexTable {
        var size: usize = 8;
        while (size < capacity * 2) size *= 2;
        const entries = try allocator.alloc(Entry, size);
        @memset(entries, .{});
        return .{ .entries = entries, .mask = size - 1 };
    }

    fn deinit(self: *IndexTable, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
    }

    /// 指针低位全是对齐带来的常量 0，先右移再做 Fibonacci 散列，否则同一簇里全是冲突。
    fn hashKey(self: *const IndexTable, key: quic.c.QuicCnx) usize {
        const addr = @intFromPtr(key) >> 4;
        const mixed = @as(u64, @intCast(addr)) *% 0x9E3779B97F4A7C15;
        return @as(usize, @intCast(mixed >> 32)) & self.mask;
    }

    /// 环形距离：从 from 走到 to 需要几步。
    fn distance(self: *const IndexTable, from: usize, to: usize) usize {
        return (to -% from) & self.mask;
    }

    /// 调用方保证 live < capacity，因此一定能找到空槽，循环不会打转。
    fn put(self: *IndexTable, key: quic.c.QuicCnx, slot: u32) void {
        var i = self.hashKey(key);
        while (self.entries[i].key) |existing| {
            if (existing == key) {
                self.entries[i].slot = slot;
                return;
            }
            i = (i + 1) & self.mask;
        }
        self.entries[i] = .{ .key = key, .slot = slot };
    }

    fn get(self: *const IndexTable, key: quic.c.QuicCnx) ?u32 {
        var i = self.hashKey(key);
        while (self.entries[i].key) |existing| {
            if (existing == key) return self.entries[i].slot;
            i = (i + 1) & self.mask;
        }
        return null;
    }

    /// 用回移法删除，不留墓碑。
    ///
    /// 线性探测下直接置空会切断同一簇的探测链，让后面的键再也查不到；
    /// 而墓碑会随连接反复建立/关闭不断累积，最终把表填满。
    fn remove(self: *IndexTable, key: quic.c.QuicCnx) ?u32 {
        var i = self.hashKey(key);
        var found = false;
        while (self.entries[i].key) |existing| {
            if (existing == key) {
                found = true;
                break;
            }
            i = (i + 1) & self.mask;
        }
        if (!found) return null;

        const removed = self.entries[i].slot;
        var hole = i;
        var j = (i + 1) & self.mask;
        while (self.entries[j].key) |candidate| {
            const ideal = self.hashKey(candidate);
            // candidate 的理想位置若在 hole 之前（或正是 hole），把它前移填洞是安全的。
            if (self.distance(ideal, hole) <= self.distance(ideal, j)) {
                self.entries[hole] = self.entries[j];
                self.entries[j] = .{};
                hole = j;
            }
            j = (j + 1) & self.mask;
        }
        self.entries[hole] = .{};
        return removed;
    }
};

/// `(realm, u64 标识)` -> 链表头的定容索引表。
///
/// 两处用同一份实现，因为形状完全一样、只有"标识是什么"不同：
///
/// - `dest_index`：`dest_id` -> 槽位链表头。一个 `dest_id` 可以对应多条连接
///   （同一账号的多台设备，见设计文档 §5.6）。
/// - `groups.table`：组播组标识 -> 成员边链表头。
///
/// 值是链表头而不是单个元素，链本身通过被索引者自己的 `next_*` 字段串起来，
/// 因此整张索引不需要任何额外分配——链表节点就是槽位/边自己，而它们都是启动期
/// 一次分配的。
///
/// 键里必须带 realm：标识由各接入方的认证服务/业务自己生成，两家都从 1 开始发号
/// 是常态。只用标识做键，A 的后端推一条消息就会同时投给 B 的同号用户
/// （设计文档 §12.2）。
///
/// `key = 0` 用作空槽标记：0 不是合法标识（`dest_id = 0` 表示"不可寻址"），
/// 因此不会进表。
const HeadTable = struct {
    entries: []Entry,
    mask: usize,

    const Entry = struct {
        key: u64 = 0,
        realm: RealmId = 0,
        head: u32 = 0,
    };

    fn init(allocator: std.mem.Allocator, capacity: usize) !HeadTable {
        var size: usize = 8;
        while (size < capacity * 2) size *= 2;
        const entries = try allocator.alloc(Entry, size);
        @memset(entries, .{});
        return .{ .entries = entries, .mask = size - 1 };
    }

    fn deinit(self: *HeadTable, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
    }

    /// 标识由业务侧生成，不能假设它已经均匀分布（很可能是自增主键），因此照样做
    /// 一次 Fibonacci 散列。realm 也要参与，否则多个 realm 下的同号标识会全部挤在
    /// 同一条探测链上。
    fn hashKey(self: *const HeadTable, realm: RealmId, key: u64) usize {
        const salted = key ^ (@as(u64, realm) *% 0xD6E8_FEB8_6659_FD93);
        const mixed = salted *% 0x9E3779B97F4A7C15;
        return @as(usize, @intCast(mixed >> 32)) & self.mask;
    }

    fn distance(self: *const HeadTable, from: usize, to: usize) usize {
        return (to -% from) & self.mask;
    }

    /// 返回可写条目指针，调用方就地改 head（挂链/摘链）。
    fn find(self: *HeadTable, realm: RealmId, key: u64) ?*Entry {
        var i = self.hashKey(realm, key);
        while (self.entries[i].key != 0) {
            const entry = &self.entries[i];
            if (entry.key == key and entry.realm == realm) return entry;
            i = (i + 1) & self.mask;
        }
        return null;
    }

    /// 调用方保证该键尚不存在。表容量是元素数的两倍以上，而不同键的数量
    /// 不会超过元素数，因此一定能找到空位，循环不会打转。
    fn insert(self: *HeadTable, realm: RealmId, key: u64, head: u32) void {
        var i = self.hashKey(realm, key);
        while (self.entries[i].key != 0) i = (i + 1) & self.mask;
        self.entries[i] = .{ .key = key, .realm = realm, .head = head };
    }

    /// 用回移法删除，不留墓碑。理由同 `IndexTable.remove`。
    fn remove(self: *HeadTable, realm: RealmId, key: u64) void {
        var i = self.hashKey(realm, key);
        var found = false;
        while (self.entries[i].key != 0) {
            if (self.entries[i].key == key and self.entries[i].realm == realm) {
                found = true;
                break;
            }
            i = (i + 1) & self.mask;
        }
        if (!found) return;

        var hole = i;
        var j = (i + 1) & self.mask;
        while (self.entries[j].key != 0) {
            const ideal = self.hashKey(self.entries[j].realm, self.entries[j].key);
            if (self.distance(ideal, hole) <= self.distance(ideal, j)) {
                self.entries[hole] = self.entries[j];
                self.entries[j] = .{};
                hole = j;
            }
            j = (j + 1) & self.mask;
        }
        self.entries[hole] = .{};
    }
};

/// 一条连接最多可同时加入多少个组播组。
///
/// 它决定成员边池的大小：`max_connections × max_groups_per_connection`。取 8 是因为
/// 真实场景里一条连接同时在的组是个位数（几个协作文档 + 一个游戏房间 + 一个直播间），
/// 而每多一格就是每 Worker 多一份 `max_connections × 边大小` 的常驻内存。
///
/// 不做成配置项：它是内存预算的一部分，调大了是静默的 RSS 增长，调小了是静默的
/// "加组失败"。真需要更多时应当先想清楚为什么。
pub const max_groups_per_connection: u8 = 8;

/// 组播组成员索引：`(realm, group_id)` <-> 连接 的多对多关系。
///
/// 为什么不能像 `dest_id` 那样在 ConnectionContext 上放一个字段：一条连接可以同时
/// 属于多个组（三个协作文档 + 一个游戏房间），而 `dest_id` 是一条连接一个。多对多
/// 关系需要一份**边**，所以这里有一个定容边池。
///
/// 每条边挂在两条链上：
///
/// - `next_in_group` —— 同一个组里的下一条边，用于扇出时遍历组成员
/// - `next_of_slot`  —— 同一条连接的下一条边，用于连接关闭时一次摘干净
///
/// 少了后者，连接关闭时就得扫全池才能找出它的所有边，那是 O(池大小)；而连接关闭
/// 是常态事件，不能是 O(池大小)。
const GroupIndex = struct {
    edges: []Edge,
    table: HeadTable,
    free_head: ?u32,

    const Edge = struct {
        realm: RealmId = 0,
        group_id: u64 = 0,
        /// 这条边指向的连接槽位。
        slot: u32 = 0,
        next_in_group: ?u32 = null,
        next_of_slot: ?u32 = null,
        next_free: ?u32 = null,
        in_use: bool = false,
    };

    pub const Error = error{
        /// 边池已满（这条连接加入的组太多，或整机组成员总数超限）。
        TooManyGroupMemberships,
    };

    fn init(allocator: std.mem.Allocator, max_connections: usize) !GroupIndex {
        const capacity = max_connections * max_groups_per_connection;
        const edges = try allocator.alloc(Edge, capacity);
        errdefer allocator.free(edges);
        for (edges, 0..) |*edge, i| {
            edge.* = .{ .next_free = if (i + 1 < capacity) @intCast(i + 1) else null };
        }

        var table = try HeadTable.init(allocator, capacity);
        errdefer table.deinit(allocator);

        return .{ .edges = edges, .table = table, .free_head = if (capacity == 0) null else 0 };
    }

    fn deinit(self: *GroupIndex, allocator: std.mem.Allocator) void {
        allocator.free(self.edges);
        self.table.deinit(allocator);
    }
};

/// 业务层连接管理器
///
/// 会话状态用启动期一次分配的定容槽位池承载，运行期不再向 allocator 申请：
/// 建立连接是从空闲链表摘一个槽，关闭是还回去。上限取 QUIC 层的
/// max_connections——两边用同一个数字，避免出现"picoquic 接了但业务层放不下"。
///
/// 这样做的收益不只是省一次分配：进程 RSS 在启动后就不再随连接数变化，
/// 也不会出现哈希表扩容的尖刺。
pub const ConnectionManager = struct {
    allocator: std.mem.Allocator,
    /// 本节点编号；只用于签发/校验 ConnToken。
    node_id: u16,
    /// 本 Worker 编号；只用于签发/校验 ConnToken。
    worker_id: u8,
    slots: []Slot,
    index: IndexTable,
    /// (realm, dest_id) -> 槽位链表头。空表示当前没有任何连接被绑定过标识。
    dest_index: HeadTable,
    /// 组播组成员索引（多对多，见 GroupIndex）。
    groups: GroupIndex,
    /// 会话槽位池的按 realm 公平上限（见 foundation/quota.zig）。
    ///
    /// 水位线以下不管，以上只拒超额的那个 realm。少了它，一个吵闹的接入方能把
    /// `max_connections` 吃干，其他所有接入方一起连不上。
    conn_quota: foundation.quota.Quota,
    /// 组播成员边池的按 realm 公平上限。
    ///
    /// 这个池的放大效应更隐蔽：A 的用户每人进 8 个组就能占满，之后 B 的 join 全失败
    /// （设计文档 §12.4）。
    group_quota: foundation.quota.Quota,
    /// 空闲链表头；null 表示池已耗尽。
    free_head: ?u32,
    live: usize,

    const Slot = struct {
        ctx: ConnectionContext,
        /// 空闲链表的下一个槽位；仅在 in_use 为 false 时有意义。
        next_free: ?u32,
        /// 同一个 dest_id 链上的下一个槽位；仅在 in_use 且 ctx.dest_id != 0 时有意义。
        ///
        /// 与 next_free 分开存而不复用同一个字段：两者的有效期互斥，但复用会让
        /// "槽位在哪条链上"变成需要额外推理的事，而这里省下的 8 字节没有意义。
        next_by_dest: ?u32,
        /// 本连接的组播成员边链表头；null 表示它不在任何组里。
        group_head: ?u32,
        /// 本槽位被占用过多少次；每次 add 自增，构成 ConnToken 的防 ABA 位段。
        ///
        /// 没有它，一个过期 token 会在槽位被复用后精确命中无关的新连接——表现是
        /// "踢错了人"，而且只在高连接更替率下偶发。
        generation: u16,
        in_use: bool,
    };

    pub const Error = error{
        /// 池已满。上限由配置决定，超限必须明确拒绝而不是继续增长。
        TooManyConnections,
        /// 池还没满，但这个 realm 已经超过它在争用时的公平份额。
        ///
        /// 与 `TooManyConnections` 分成两个错误码，是为了让运维一眼看出
        /// "整机满了"和"你这家接入方超额了"——两者的处置完全不同：前者要扩容，
        /// 后者要么调权重要么让该接入方自己收敛。合成一个就只能靠猜。
        RealmQuotaExceeded,
    } || GroupIndex.Error;

    // 注意：在 Thread-per-Core 架构中，ConnectionManager 是线程局部的，
    // 只会被当前 EventLoop 所在的线程访问，因此不需要互斥锁。
    // 如果需要跨线程访问（如 Admin API），应通过消息传递机制。

    /// `node_id` / `worker_id` 只用于签发与校验 ConnToken：token 自带位置，
    /// 而位置只有本管理器知道，交给调用方拼就会拼错。
    pub fn init(allocator: std.mem.Allocator, max_connections: usize, node_id: u16, worker_id: u8) !ConnectionManager {
        const effective = @max(max_connections, 1);
        const slots = try allocator.alloc(Slot, effective);
        errdefer allocator.free(slots);

        // 逆序串联空闲链表，让最先分配的槽位下标最小，日志与调试更直观。
        for (slots, 0..) |*slot, i| {
            slot.* = .{
                .ctx = undefined,
                .next_free = if (i + 1 < effective) @intCast(i + 1) else null,
                .next_by_dest = null,
                .group_head = null,
                .generation = 0,
                .in_use = false,
            };
        }

        var index = try IndexTable.init(allocator, effective);
        errdefer index.deinit(allocator);

        var dest_index = try HeadTable.init(allocator, effective);
        errdefer dest_index.deinit(allocator);

        var groups = try GroupIndex.init(allocator, effective);
        errdefer groups.deinit(allocator);

        // 水位线取全局默认：池用量到七成才开始讲公平。理由见 foundation/quota.zig ——
        // 空闲机器上的突发不该被拒。
        var conn_quota = try foundation.quota.Quota.init(allocator, foundation.quota.max_tracked_realms, effective, foundation.quota.default_watermark_percent);
        errdefer conn_quota.deinit(allocator);

        var group_quota = try foundation.quota.Quota.init(allocator, foundation.quota.max_tracked_realms, groups.edges.len, foundation.quota.default_watermark_percent);
        errdefer group_quota.deinit(allocator);

        return .{
            .allocator = allocator,
            .node_id = node_id,
            .worker_id = worker_id,
            .slots = slots,
            .index = index,
            .dest_index = dest_index,
            .groups = groups,
            .conn_quota = conn_quota,
            .group_quota = group_quota,
            .free_head = 0,
            .live = 0,
        };
    }

    pub fn deinit(self: *ConnectionManager) void {
        for (self.slots) |*slot| {
            if (slot.in_use) slot.ctx.deinit();
        }
        self.allocator.free(self.slots);
        self.index.deinit(self.allocator);
        self.dest_index.deinit(self.allocator);
        self.groups.deinit(self.allocator);
        self.conn_quota.deinit(self.allocator);
        self.group_quota.deinit(self.allocator);
    }

    /// 注册新连接。池满时返回 TooManyConnections，调用方应当关掉这条连接。
    ///
    /// `realm` 在这一刻定死：它由握手时的 SNI 解析而来，之后连接上的任何字节
    /// 都不能改变它。
    pub fn add(self: *ConnectionManager, conn: *QUICConnection, realm: RealmId, gateway_ctx: ?*anyopaque) !*ConnectionContext {
        const slot_index = self.free_head orelse return Error.TooManyConnections;
        // 池还有位置，但这个 realm 可能已经超过它在争用时的公平份额。
        // 两个判据分开报错，运维才能区分"整机满了"和"你超额了"。
        if (!self.conn_quota.allows(realm)) return Error.RealmQuotaExceeded;
        const slot = &self.slots[slot_index];

        self.free_head = slot.next_free;
        slot.next_free = null;
        slot.next_by_dest = null;
        slot.group_head = null;
        // 在占用时自增而不是在归还时：这样"当前占用者"的代次一定与上一任不同，
        // 上一任的 token 立刻失配，不依赖归还路径是否被走到。
        slot.generation +%= 1;
        slot.in_use = true;
        slot.ctx = ConnectionContext.init(self.allocator, conn.inner, realm);
        slot.ctx.gateway_ctx = gateway_ctx;

        self.index.put(conn.inner, slot_index);
        self.conn_quota.acquire(realm);
        self.live += 1;
        return &slot.ctx;
    }

    /// 注册一条对等网关节点的连接。
    ///
    /// 与 `add` 分成两个入口而不是加一个 `peer_node: bool` 参数：布尔参数在调用点
    /// 是 `add(conn, realm, ctx, true)` 这种读不出含义的形状，而"把客户端连接误标成
    /// 对等节点"是一次完整的权限逃逸。分成两个名字之后，误用需要写错函数名。
    ///
    /// `realm` 取默认值且**没有意义**：对等节点的每一帧自带 realm（`realmHint()`），
    /// 连接级 realm 从不参与它的寻址。
    pub fn addPeerNode(self: *ConnectionManager, conn: *QUICConnection, gateway_ctx: ?*anyopaque) !*ConnectionContext {
        const ctx = try self.add(conn, foundation.realm.default_realm, gateway_ctx);
        ctx.peer_node = true;
        return ctx;
    }

    /// 移除连接，槽位还回空闲链表。
    pub fn remove(self: *ConnectionManager, conn: *QUICConnection) void {
        const slot_index = self.index.remove(conn.inner) orelse return;
        const slot = &self.slots[slot_index];
        // 必须先摘掉 dest 链与组播成员边，再销毁 ctx：摘链要读 ctx.dest_id / ctx.realm，
        // 而且残留的链节点会让下行扇出路径遍历到一个已经归还的槽位。
        self.unbindDest(slot_index);
        self.leaveAllGroups(slot_index);
        // 计数在归还槽位的同一个函数里递减，绝不放在调用点：漏掉一条归还路径的后果
        // 是这个 realm 的配额被永久蚕食，症状是"这家接入方过几天就连不上了"。
        self.conn_quota.release(slot.ctx.realm);
        slot.ctx.deinit();
        slot.in_use = false;
        slot.next_free = self.free_head;
        self.free_head = slot_index;
        self.live -= 1;
    }

    // ========================================================================
    // ConnToken
    // ========================================================================

    /// 为这条连接签发 ConnToken；连接不在本管理器里时返回 null。
    ///
    /// 只在认证成功时签发一次并告知后端（见 worker/auth.zig）。
    pub fn tokenFor(self: *ConnectionManager, cnx: quic.c.QuicCnx) ?ConnToken {
        const slot_index = self.index.get(cnx) orelse return null;
        return .{
            .node_id = self.node_id,
            .worker_id = self.worker_id,
            .slot = @intCast(slot_index),
            .generation = self.slots[slot_index].generation,
        };
    }

    /// 按 ConnToken 找回连接上下文；任一位段不符就返回 null。
    ///
    /// 四道校验缺一不可，每一道对应一种真实的失配：
    /// - node/worker 不是本 Worker：这条 token 指向别处，调用方该转投而不是本地找
    /// - slot 越界：伪造或跨配置（改小了 max_connections）的 token
    /// - 槽位空闲：连接已经关了
    /// - generation 不符：槽位已被新连接复用，旧 token 不能命中新占用者
    ///
    /// 注意它**不校验 realm**：realm 属于授权判断，由调用方按"发起方所属 realm"
    /// 单独比对（见 worker/egress.zig 的 kick 执行）。放在这里会让"定位"与"授权"
    /// 混成一个函数，而两者失败时的处置不同。
    pub fn byToken(self: *ConnectionManager, token: ConnToken) ?*ConnectionContext {
        if (token.node_id != self.node_id or token.worker_id != self.worker_id) return null;
        if (token.slot >= self.slots.len) return null;
        const slot = &self.slots[token.slot];
        if (!slot.in_use) return null;
        if (slot.generation != token.generation) return null;
        return &slot.ctx;
    }

    // ========================================================================
    // dest_id 索引
    // ========================================================================

    /// 把 `dest_id` 绑定到这条连接，之后 `.peer` 投递才能找到它。
    ///
    /// 只应由认证成功路径调用，且 `dest_id` 必须来自认证服务下发的
    /// `auth_success` 前缀——采信客户端声明的值等于允许任何人冒领别人的消息。
    ///
    /// realm 不是参数：它取自这条连接自己的上下文。让调用方传 realm 就等于给了
    /// 它一个"把标识绑进别的 realm"的机会，而那正是要防的事。
    ///
    /// `dest_id = 0` 表示不可寻址：解绑原有标识后直接返回。重复认证时会先解绑
    /// 旧标识，因此重新认证换 id 是安全的。
    pub fn bindDest(self: *ConnectionManager, cnx: quic.c.QuicCnx, dest_id: u64) void {
        const slot_index = self.index.get(cnx) orelse return;
        const slot = &self.slots[slot_index];
        if (slot.ctx.dest_id == dest_id) return;

        const realm = slot.ctx.realm;
        self.unbindDest(slot_index);
        slot.ctx.dest_id = dest_id;
        if (dest_id == 0) return;

        if (self.dest_index.find(realm, dest_id)) |entry| {
            // 已有同 id 的连接（同一账号的另一台设备）：挂到链头，O(1)。
            slot.next_by_dest = entry.head;
            entry.head = slot_index;
        } else {
            slot.next_by_dest = null;
            self.dest_index.insert(realm, dest_id, slot_index);
        }
    }

    /// 把槽位从它所在的 dest 链上摘掉，并清空 ctx.dest_id。
    ///
    /// 单链表 + 遍历找前驱：链长等于"同一标识下的在线连接数"，也就是一个账号的
    /// 在线设备数（个位数量级），因此不值得为 O(1) 删除多存一份 prev 指针。
    fn unbindDest(self: *ConnectionManager, slot_index: u32) void {
        const slot = &self.slots[slot_index];
        const dest_id = slot.ctx.dest_id;
        if (dest_id == 0) return;
        const realm = slot.ctx.realm;

        slot.ctx.dest_id = 0;
        const entry = self.dest_index.find(realm, dest_id) orelse return;

        if (entry.head == slot_index) {
            if (slot.next_by_dest) |next| {
                entry.head = next;
            } else {
                // 链空了，条目也要删掉，否则 find 会返回一个指向已归还槽位的头。
                self.dest_index.remove(realm, dest_id);
            }
        } else {
            var cursor = entry.head;
            while (self.slots[cursor].next_by_dest) |next| {
                if (next == slot_index) {
                    self.slots[cursor].next_by_dest = slot.next_by_dest;
                    break;
                }
                cursor = next;
            }
        }
        slot.next_by_dest = null;
    }

    /// 遍历某个 realm 里绑定在某个 `dest_id` 上的所有活连接。
    ///
    /// **迭代期间不得增删连接**：链表节点就是槽位本身，摘链或归还槽位会让游标
    /// 指向已失效的位置。扇出路径只做 `streamWrite`（picoquic 的关闭是异步的，
    /// 槽位要等关闭回调才归还），因此满足这个约定。
    pub fn destConnections(self: *ConnectionManager, realm: RealmId, dest_id: u64) DestIterator {
        if (dest_id == 0) return .{ .manager = self, .cursor = null };
        const entry = self.dest_index.find(realm, dest_id) orelse return .{ .manager = self, .cursor = null };
        return .{ .manager = self, .cursor = entry.head };
    }

    /// dest 链上的活连接数量。0 即"不可达"，是投递回报的判据（设计文档 §5.5）。
    pub fn destCount(self: *ConnectionManager, realm: RealmId, dest_id: u64) usize {
        var it = self.destConnections(realm, dest_id);
        var n: usize = 0;
        while (it.next()) |_| n += 1;
        return n;
    }

    /// 从 `start` 下标起找下一个在用槽位。
    ///
    /// 给漂移巡检用（`worker.rehomeDrifted`）：它要按 tick 限额分批扫全表，因此必须能
    /// 从上次停下的地方接着走，而不是每次从 0 开始——从 0 开始的话限额会让后半张表
    /// 永远轮不到，那些连接就一直留在错位置上。
    ///
    /// 返回下标而不是把游标藏在管理器里：巡检自己决定何时归零（扫完一圈），
    /// 而管理器不该知道"一圈"这个概念。
    pub fn nextLive(self: *ConnectionManager, start: usize) ?LiveSlot {
        var index = start;
        while (index < self.slots.len) : (index += 1) {
            if (self.slots[index].in_use) return .{ .index = index, .ctx = &self.slots[index].ctx };
        }
        return null;
    }

    pub const LiveSlot = struct {
        index: usize,
        ctx: *ConnectionContext,
    };

    pub const DestIterator = struct {
        manager: *ConnectionManager,
        cursor: ?u32,

        pub fn next(self: *DestIterator) ?*ConnectionContext {
            const index = self.cursor orelse return null;
            const slot = &self.manager.slots[index];
            self.cursor = slot.next_by_dest;
            return &slot.ctx;
        }
    };

    // ========================================================================
    // 组播组成员
    // ========================================================================

    /// 把一条连接加入某个组播组。
    ///
    /// **只应由后端 → 网关的控制交换调用**（设计文档 §7.2）。成员关系的权威在后端：
    /// 谁能进哪个文档、哪局游戏，是业务判断，网关没有任何判据。网关只持有"组 -> 连接"
    /// 这份投递索引，不持有"谁有权进组"这份业务状态。
    ///
    /// realm 不是参数，取自连接自己的上下文——理由同 `bindDest`：让调用方传 realm
    /// 就等于给了它一个"把连接加进别的 realm 的组"的机会。
    ///
    /// 重复加入是幂等的（不会挂两条边），因此后端重发 join 是安全的。
    pub fn joinGroup(self: *ConnectionManager, cnx: quic.c.QuicCnx, group_id: u64) Error!void {
        if (group_id == 0) return;
        const slot_index = self.index.get(cnx) orelse return;
        const slot = &self.slots[slot_index];
        const realm = slot.ctx.realm;

        // 幂等：先看这条连接是否已经在这个组里。链长是"这条连接加入的组数"，
        // 上限 max_groups_per_connection，所以线性扫描是常数级的。
        if (self.isGroupMember(cnx, group_id)) return;

        const edge_index = self.groups.free_head orelse return Error.TooManyGroupMemberships;
        // 边池还有位置，但这个 realm 可能已经超过份额。这个池的放大效应更隐蔽：
        // A 的用户每人进 8 个组就能占满，之后 B 的 join 全失败（§12.4）。
        if (!self.group_quota.allows(realm)) return Error.RealmQuotaExceeded;
        const edge = &self.groups.edges[edge_index];
        self.groups.free_head = edge.next_free;
        self.group_quota.acquire(realm);

        edge.* = .{
            .realm = realm,
            .group_id = group_id,
            .slot = slot_index,
            .next_of_slot = slot.group_head,
            .in_use = true,
        };
        slot.group_head = edge_index;

        if (self.groups.table.find(realm, group_id)) |entry| {
            edge.next_in_group = entry.head;
            entry.head = edge_index;
        } else {
            edge.next_in_group = null;
            self.groups.table.insert(realm, group_id, edge_index);
        }
    }

    /// 这条连接是否已经在某个组播组里。
    ///
    /// 链长是"这条连接加入的组数"，上限 `max_groups_per_connection`，所以线性扫描是
    /// 常数级的——刻意走每连接那条链而不是每组那条链：后者的长度是组成员数，一个
    /// 5000 人的房间会让一次判定退化成 5000 步。
    ///
    /// realm 取自连接自己的上下文，理由同 `joinGroup`。
    pub fn isGroupMember(self: *ConnectionManager, cnx: quic.c.QuicCnx, group_id: u64) bool {
        if (group_id == 0) return false;
        const slot_index = self.index.get(cnx) orelse return false;
        const slot = &self.slots[slot_index];
        const realm = slot.ctx.realm;

        var cursor = slot.group_head;
        while (cursor) |edge_index| {
            const edge = &self.groups.edges[edge_index];
            if (edge.group_id == group_id and edge.realm == realm) return true;
            cursor = edge.next_of_slot;
        }
        return false;
    }

    /// 把一条连接从某个组播组里摘掉；不在组里则什么也不做。
    pub fn leaveGroup(self: *ConnectionManager, cnx: quic.c.QuicCnx, group_id: u64) void {
        const slot_index = self.index.get(cnx) orelse return;
        const realm = self.slots[slot_index].ctx.realm;

        var cursor = self.slots[slot_index].group_head;
        while (cursor) |edge_index| {
            const edge = &self.groups.edges[edge_index];
            if (edge.group_id == group_id and edge.realm == realm) {
                self.releaseGroupEdge(slot_index, edge_index);
                return;
            }
            cursor = edge.next_of_slot;
        }
    }

    /// 连接关闭时一次摘干净它的所有组成员边。
    ///
    /// 靠 `next_of_slot` 链走，因此是 O(这条连接加入的组数) 而不是 O(边池大小)。
    /// 连接关闭是常态事件，扫全池是不可接受的。
    fn leaveAllGroups(self: *ConnectionManager, slot_index: u32) void {
        while (self.slots[slot_index].group_head) |edge_index| {
            self.releaseGroupEdge(slot_index, edge_index);
        }
    }

    /// 摘掉一条成员边并归还给边池。
    ///
    /// 两条链都要摘：组内链（否则扇出会遍历到已归还的边）与连接链（否则连接关闭时
    /// 摘不干净）。组内链空了必须删掉哈希条目，否则 find 会返回一个指向已归还边的头
    /// ——那会让下一次扇出写给一条不存在的连接。
    fn releaseGroupEdge(self: *ConnectionManager, slot_index: u32, edge_index: u32) void {
        const edge = &self.groups.edges[edge_index];
        const realm = edge.realm;
        const group_id = edge.group_id;

        if (self.groups.table.find(realm, group_id)) |entry| {
            if (entry.head == edge_index) {
                if (edge.next_in_group) |next| {
                    entry.head = next;
                } else {
                    self.groups.table.remove(realm, group_id);
                }
            } else {
                var cursor = entry.head;
                while (self.groups.edges[cursor].next_in_group) |next| {
                    if (next == edge_index) {
                        self.groups.edges[cursor].next_in_group = edge.next_in_group;
                        break;
                    }
                    cursor = next;
                }
            }
        }

        const slot = &self.slots[slot_index];
        if (slot.group_head == edge_index) {
            slot.group_head = edge.next_of_slot;
        } else if (slot.group_head) |head| {
            var cursor = head;
            while (self.groups.edges[cursor].next_of_slot) |next| {
                if (next == edge_index) {
                    self.groups.edges[cursor].next_of_slot = edge.next_of_slot;
                    break;
                }
                cursor = next;
            }
        }

        edge.* = .{ .next_free = self.groups.free_head };
        self.groups.free_head = edge_index;
        // 与 acquire 贴在同一对函数里，理由同 conn_quota。
        self.group_quota.release(realm);
    }

    /// 遍历某个 realm 里某个组播组的所有成员连接。
    ///
    /// 迭代期间的约定同 `destConnections`：不得增删连接或成员边。
    pub fn groupConnections(self: *ConnectionManager, realm: RealmId, group_id: u64) GroupIterator {
        if (group_id == 0) return .{ .manager = self, .cursor = null };
        const entry = self.groups.table.find(realm, group_id) orelse return .{ .manager = self, .cursor = null };
        return .{ .manager = self, .cursor = entry.head };
    }

    /// 某个组当前的成员连接数。
    pub fn groupCount(self: *ConnectionManager, realm: RealmId, group_id: u64) usize {
        var it = self.groupConnections(realm, group_id);
        var n: usize = 0;
        while (it.next()) |_| n += 1;
        return n;
    }

    pub const GroupIterator = struct {
        manager: *ConnectionManager,
        cursor: ?u32,

        pub fn next(self: *GroupIterator) ?*ConnectionContext {
            const edge_index = self.cursor orelse return null;
            const edge = &self.manager.groups.edges[edge_index];
            self.cursor = edge.next_in_group;
            return &self.manager.slots[edge.slot].ctx;
        }
    };

    /// 当前活跃连接数；drain 期间用它判断存量是否已收敛。
    pub fn count(self: *const ConnectionManager) usize {
        return self.live;
    }

    /// 池容量，即配置允许的最大并发连接数。
    pub fn capacity(self: *const ConnectionManager) usize {
        return self.slots.len;
    }

    /// 获取连接上下文
    pub fn get(self: *ConnectionManager, conn: *QUICConnection) ?*ConnectionContext {
        return self.getByHandle(conn.inner);
    }

    /// 通过底层连接句柄获取上下文（用于异步回程时校验连接仍然存活）
    pub fn getByHandle(self: *ConnectionManager, cnx: quic.c.QuicCnx) ?*ConnectionContext {
        const slot_index = self.index.get(cnx) orelse return null;
        return &self.slots[slot_index].ctx;
    }
};

/// 单 realm 部署的取值；只有跨 realm 隔离的用例才显式换成别的。
const test_realm: RealmId = foundation.realm.default_realm;
const test_node: u16 = 1;
const test_worker: u8 = 0;

fn testManager(capacity: usize) !ConnectionManager {
    return ConnectionManager.init(std.testing.allocator, capacity, test_node, test_worker);
}

test "connection pool reuses slots and refuses overflow" {
    var manager = try testManager(2);
    defer manager.deinit();

    var first = QUICConnection{ .inner = @ptrFromInt(0x1000) };
    var second = QUICConnection{ .inner = @ptrFromInt(0x2000) };
    var third = QUICConnection{ .inner = @ptrFromInt(0x3000) };

    const ctx_first = try manager.add(&first, test_realm, null);
    _ = try manager.add(&second, test_realm, null);
    try std.testing.expectEqual(@as(usize, 2), manager.count());

    // 超过配置上限必须明确拒绝，而不是继续增长。
    try std.testing.expectError(ConnectionManager.Error.TooManyConnections, manager.add(&third, test_realm, null));

    // 关闭一条后槽位应当被回收复用。
    manager.remove(&first);
    try std.testing.expectEqual(@as(usize, 1), manager.count());
    const ctx_third = try manager.add(&third, test_realm, null);
    try std.testing.expectEqual(ctx_first, ctx_third);

    try std.testing.expect(manager.get(&first) == null);
    try std.testing.expect(manager.get(&second) != null);
    try std.testing.expectEqual(third.inner, manager.get(&third).?.cnx_handle);
}

test "index table keeps probe chains intact after churn" {
    // 回移删除的回归测试：同一簇里删掉中间的键之后，后面的键仍要能查到。
    // 用墓碑或直接置空都会在这里暴露成 null。
    const capacity = 64;
    var manager = try testManager(capacity);
    defer manager.deinit();

    var conns: [capacity]QUICConnection = undefined;
    for (&conns, 0..) |*conn, i| {
        // 指针间隔 16 字节，散列后大量落在相邻桶里，正好压测探测链。
        conn.* = .{ .inner = @ptrFromInt(0x10000 + i * 16) };
        _ = try manager.add(conn, test_realm, null);
    }
    try std.testing.expectEqual(@as(usize, capacity), manager.count());

    // 删掉一半（隔一个删一个），剩下的必须全部仍可查到。
    var i: usize = 0;
    while (i < capacity) : (i += 2) manager.remove(&conns[i]);

    i = 0;
    while (i < capacity) : (i += 1) {
        const found = manager.get(&conns[i]);
        if (i % 2 == 0) {
            try std.testing.expect(found == null);
        } else {
            try std.testing.expect(found != null);
            try std.testing.expectEqual(conns[i].inner, found.?.cnx_handle);
        }
    }

    // 槽位全部回收后可以重新填满。
    i = 0;
    while (i < capacity) : (i += 2) _ = try manager.add(&conns[i], test_realm, null);
    try std.testing.expectEqual(@as(usize, capacity), manager.count());
}

/// dest 链上是否包含某条连接。链是无序的（挂到链头），因此测试不能依赖顺序。
fn destChainHas(manager: *ConnectionManager, realm: RealmId, dest_id: u64, cnx: quic.c.QuicCnx) bool {
    var it = manager.destConnections(realm, dest_id);
    while (it.next()) |ctx| {
        if (ctx.cnx_handle == cnx) return true;
    }
    return false;
}

test "one dest_id addresses every connection bound to it" {
    // §5.6 的核心：一个标识对多条连接（同一账号的多台设备）。
    var manager = try testManager(8);
    defer manager.deinit();

    var phone = QUICConnection{ .inner = @ptrFromInt(0x1000) };
    var desktop = QUICConnection{ .inner = @ptrFromInt(0x2000) };
    var other = QUICConnection{ .inner = @ptrFromInt(0x3000) };

    _ = try manager.add(&phone, test_realm, null);
    _ = try manager.add(&desktop, test_realm, null);
    _ = try manager.add(&other, test_realm, null);

    manager.bindDest(phone.inner, 42);
    manager.bindDest(desktop.inner, 42);
    manager.bindDest(other.inner, 99);

    try std.testing.expectEqual(@as(usize, 2), manager.destCount(test_realm, 42));
    try std.testing.expect(destChainHas(&manager, test_realm, 42, phone.inner));
    try std.testing.expect(destChainHas(&manager, test_realm, 42, desktop.inner));
    try std.testing.expect(!destChainHas(&manager, test_realm, 42, other.inner));

    try std.testing.expectEqual(@as(usize, 1), manager.destCount(test_realm, 99));
    // 没有人绑定过的标识就是"不可达"，这是投递回报的判据。
    try std.testing.expectEqual(@as(usize, 0), manager.destCount(test_realm, 7));
}

test "dest_id 0 means not addressable and never enters the index" {
    var manager = try testManager(4);
    defer manager.deinit();

    var conn = QUICConnection{ .inner = @ptrFromInt(0x1000) };
    const ctx = try manager.add(&conn, test_realm, null);

    manager.bindDest(conn.inner, 0);
    try std.testing.expectEqual(@as(u64, 0), ctx.dest_id);
    try std.testing.expectEqual(@as(usize, 0), manager.destCount(test_realm, 0));
}

test "removing a connection unlinks it and keeps the rest of the chain reachable" {
    // 关键回归：摘链只能摘掉自己。摘错前驱会让链尾整段丢失，表现为"某些设备
    // 收不到推送"，而且只在多端在线时出现。
    var manager = try testManager(8);
    defer manager.deinit();

    var a = QUICConnection{ .inner = @ptrFromInt(0x1000) };
    var b = QUICConnection{ .inner = @ptrFromInt(0x2000) };
    var c = QUICConnection{ .inner = @ptrFromInt(0x3000) };

    _ = try manager.add(&a, test_realm, null);
    _ = try manager.add(&b, test_realm, null);
    _ = try manager.add(&c, test_realm, null);
    manager.bindDest(a.inner, 5);
    manager.bindDest(b.inner, 5);
    manager.bindDest(c.inner, 5);
    try std.testing.expectEqual(@as(usize, 3), manager.destCount(test_realm, 5));

    // 摘掉链中间那个（挂链是前插，所以 b 在 c 与 a 之间）。
    manager.remove(&b);
    try std.testing.expectEqual(@as(usize, 2), manager.destCount(test_realm, 5));
    try std.testing.expect(destChainHas(&manager, test_realm, 5, a.inner));
    try std.testing.expect(destChainHas(&manager, test_realm, 5, c.inner));
    try std.testing.expect(!destChainHas(&manager, test_realm, 5, b.inner));

    // 摘掉链头。
    manager.remove(&c);
    try std.testing.expectEqual(@as(usize, 1), manager.destCount(test_realm, 5));
    try std.testing.expect(destChainHas(&manager, test_realm, 5, a.inner));
}

test "the index entry disappears when its last connection goes away" {
    // 关键回归：链空了必须把哈希条目也删掉。留下来的话 head 指向一个已经归还
    // 给空闲链表的槽位，下一次扇出会把数据写给一条早就不存在的连接。
    var manager = try testManager(4);
    defer manager.deinit();

    var conn = QUICConnection{ .inner = @ptrFromInt(0x1000) };
    _ = try manager.add(&conn, test_realm, null);
    manager.bindDest(conn.inner, 77);
    try std.testing.expectEqual(@as(usize, 1), manager.destCount(test_realm, 77));

    manager.remove(&conn);
    try std.testing.expectEqual(@as(usize, 0), manager.destCount(test_realm, 77));

    // 槽位复用之后也不能"复活"旧绑定。
    var reused = QUICConnection{ .inner = @ptrFromInt(0x4000) };
    const ctx = try manager.add(&reused, test_realm, null);
    try std.testing.expectEqual(@as(u64, 0), ctx.dest_id);
    try std.testing.expectEqual(@as(usize, 0), manager.destCount(test_realm, 77));
}

test "rebinding moves a connection off its old dest_id" {
    // 重新认证换 id 的路径：旧链上不能留残影，否则老标识仍能寻址到它。
    var manager = try testManager(4);
    defer manager.deinit();

    var conn = QUICConnection{ .inner = @ptrFromInt(0x1000) };
    const ctx = try manager.add(&conn, test_realm, null);

    manager.bindDest(conn.inner, 1);
    manager.bindDest(conn.inner, 2);

    try std.testing.expectEqual(@as(u64, 2), ctx.dest_id);
    try std.testing.expectEqual(@as(usize, 0), manager.destCount(test_realm, 1));
    try std.testing.expectEqual(@as(usize, 1), manager.destCount(test_realm, 2));
}

test "dest chains survive a churn that stresses the probe sequence" {
    // 把大量连接绑到少数几个 dest_id 上，再从每条链上删掉一半：探测链的回移删除与
    // 槽位链表的摘链必须同时正确，否则剩下的连接会查不到。
    const capacity = 64;
    var manager = try testManager(capacity);
    defer manager.deinit();

    var conns: [capacity]QUICConnection = undefined;
    for (&conns, 0..) |*conn, i| {
        conn.* = .{ .inner = @ptrFromInt(0x10000 + i * 16) };
        _ = try manager.add(conn, test_realm, null);
        // 4 个标识，每个标识下 16 条连接。
        manager.bindDest(conn.inner, @as(u64, i % 4) + 1);
    }
    for (1..5) |d| {
        try std.testing.expectEqual(@as(usize, 16), manager.destCount(test_realm, @intCast(d)));
    }

    // 按 4 个一组隔组删除。这样每条 dest 链都只丢一半，而不是整条消失——
    // "只摘掉自己"这条不变量才真正被压到。
    const doomed = struct {
        fn f(i: usize) bool {
            return (i / 4) % 2 == 0;
        }
    }.f;

    for (&conns, 0..) |*conn, i| {
        if (doomed(i)) manager.remove(conn);
    }

    for (1..5) |d| {
        try std.testing.expectEqual(@as(usize, 8), manager.destCount(test_realm, @intCast(d)));
    }
    for (conns, 0..) |conn, i| {
        const dest: u64 = @as(u64, i % 4) + 1;
        try std.testing.expectEqual(!doomed(i), destChainHas(&manager, test_realm, dest, conn.inner));
    }
}

test "the same dest_id in two realms addresses two different connections" {
    // §12.2 的核心回归：dest_id 由各接入方的认证服务自己发号，两家都从 1 开始是常态。
    // 索引键漏掉 realm 时，A 的后端推一条消息会同时投给 B 的同号用户。
    var manager = try testManager(8);
    defer manager.deinit();

    const realm_a: RealmId = 7;
    const realm_b: RealmId = 9;

    var in_a = QUICConnection{ .inner = @ptrFromInt(0x1000) };
    var in_b = QUICConnection{ .inner = @ptrFromInt(0x2000) };

    _ = try manager.add(&in_a, realm_a, null);
    _ = try manager.add(&in_b, realm_b, null);

    // 两条连接绑同一个 dest_id，但属于不同 realm。
    manager.bindDest(in_a.inner, 1);
    manager.bindDest(in_b.inner, 1);

    try std.testing.expectEqual(@as(usize, 1), manager.destCount(realm_a, 1));
    try std.testing.expectEqual(@as(usize, 1), manager.destCount(realm_b, 1));
    try std.testing.expect(destChainHas(&manager, realm_a, 1, in_a.inner));
    try std.testing.expect(!destChainHas(&manager, realm_a, 1, in_b.inner));
    try std.testing.expect(destChainHas(&manager, realm_b, 1, in_b.inner));
    try std.testing.expect(!destChainHas(&manager, realm_b, 1, in_a.inner));

    // 第三个 realm 里这个号码根本不存在，不会回落到任何人。
    try std.testing.expectEqual(@as(usize, 0), manager.destCount(8, 1));

    // 摘掉一个 realm 的连接不影响另一个（回移删除必须按整键比较）。
    manager.remove(&in_a);
    try std.testing.expectEqual(@as(usize, 0), manager.destCount(realm_a, 1));
    try std.testing.expectEqual(@as(usize, 1), manager.destCount(realm_b, 1));
}

test "a ConnToken locates exactly one connection and expires with its slot" {
    // kick_off 的定位基础：token 必须只命中它签发时的那条连接。
    var manager = try testManager(2);
    defer manager.deinit();

    var first = QUICConnection{ .inner = @ptrFromInt(0x1000) };
    _ = try manager.add(&first, test_realm, null);

    const token = manager.tokenFor(first.inner).?;
    try std.testing.expectEqual(test_node, token.node_id);
    try std.testing.expectEqual(test_worker, token.worker_id);
    try std.testing.expectEqual(first.inner, manager.byToken(token).?.cnx_handle);

    // 线格式往返：后端只原样存回一个大端 u64。
    try std.testing.expectEqual(token, ConnToken.decode(token.encode()));

    // 连接关掉后 token 立刻失效。
    manager.remove(&first);
    try std.testing.expect(manager.byToken(token) == null);

    // 关键回归：槽位被复用后旧 token 不能命中新占用者，否则就是"踢错人"。
    var reused = QUICConnection{ .inner = @ptrFromInt(0x2000) };
    _ = try manager.add(&reused, test_realm, null);
    const fresh = manager.tokenFor(reused.inner).?;
    try std.testing.expectEqual(token.slot, fresh.slot);
    try std.testing.expect(fresh.generation != token.generation);
    try std.testing.expect(manager.byToken(token) == null);
    try std.testing.expectEqual(reused.inner, manager.byToken(fresh).?.cnx_handle);

    // 指向别的节点/Worker，或越界的槽位，一律不在本地解析。
    var elsewhere = fresh;
    elsewhere.node_id = test_node + 1;
    try std.testing.expect(manager.byToken(elsewhere) == null);
    elsewhere = fresh;
    elsewhere.worker_id = test_worker + 1;
    try std.testing.expect(manager.byToken(elsewhere) == null);
    elsewhere = fresh;
    elsewhere.slot = 99;
    try std.testing.expect(manager.byToken(elsewhere) == null);
}

test "admission needs both a successful auth and a live TTL" {
    var ctx = ConnectionContext.init(std.testing.allocator, @ptrFromInt(0x1000), test_realm);
    defer ctx.deinit();

    // 没认证过：任何时刻都不放行。
    try std.testing.expect(!ctx.isAdmitted(0));

    ctx.authenticated = true;
    // TTL 为 0 表示不过期。
    try std.testing.expect(ctx.isAdmitted(std.math.maxInt(u64)));

    ctx.auth_expires_at = 1_000;
    try std.testing.expect(ctx.isAdmitted(999));
    // 边界即失效：expires_at 那一刻已经不算有效。
    try std.testing.expect(!ctx.isAdmitted(1_000));
    try std.testing.expect(!ctx.isAdmitted(1_001));
}

test "a noisy realm is refused before it starves the others" {
    // §12.4 的吵闹邻居：池是每 Worker 全局的，没有按 realm 的公平上限时，
    // 一个接入方能把 max_connections 吃干，其他所有接入方一起连不上。
    var manager = try testManager(10);
    defer manager.deinit();

    var handles: [10]QUICConnection = undefined;
    for (&handles, 0..) |*handle, i| handle.* = .{ .inner = @ptrFromInt(0x1000 + i * 0x100) };

    // realm 1 独占到水位线（10 × 70% = 7）之前不受限——空闲机器上的突发不该被拒。
    var taken: usize = 0;
    while (taken < 7) : (taken += 1) _ = try manager.add(&handles[taken], 1, null);

    // realm 2 进来一条，活跃 realm 变 2，份额降到 5。realm 1 已占 7 > 5。
    _ = try manager.add(&handles[7], 2, null);

    // 于是 realm 1 被拒——而且是 RealmQuotaExceeded，不是 TooManyConnections：
    // 池里明明还有两个空位，运维必须能区分"整机满了"和"你超额了"。
    try std.testing.expectError(
        ConnectionManager.Error.RealmQuotaExceeded,
        manager.add(&handles[8], 1, null),
    );
    // 而 realm 2 只占 1 格，远低于份额，照常放行。
    _ = try manager.add(&handles[8], 2, null);
}

test "quota counters return to zero after a churn cycle" {
    // 这条钉住的是最难查的那类故障：漏掉一条归还路径 → 某个 realm 的配额被永久蚕食 →
    // "这家接入方过几天就连不上了"。所以计数必须与槽位/边的取还严格配对。
    var manager = try testManager(4);
    defer manager.deinit();

    var round: usize = 0;
    while (round < 3) : (round += 1) {
        var conns: [4]QUICConnection = undefined;
        for (&conns, 0..) |*conn, i| {
            conn.* = .{ .inner = @ptrFromInt(0x1000 + i * 0x100) };
            _ = try manager.add(conn, @intCast(i + 1), null);
            // 顺手也占几条组播成员边，一起验证它们的归还。
            try manager.joinGroup(conn.inner, 100 + i);
            try manager.joinGroup(conn.inner, 200 + i);
        }
        // remove 会连带 leaveAllGroups，两个配额都该被还干净。
        for (&conns) |*conn| manager.remove(conn);
    }

    try std.testing.expectEqual(@as(usize, 0), manager.conn_quota.total);
    try std.testing.expectEqual(@as(usize, 0), manager.conn_quota.active_realms);
    try std.testing.expectEqual(@as(usize, 0), manager.group_quota.total);
    try std.testing.expectEqual(@as(usize, 0), manager.group_quota.active_realms);
    try std.testing.expectEqual(@as(usize, 0), manager.live);
}

test "a connection can belong to several groups and a group to several connections" {
    var manager = try testManager(4);
    defer manager.deinit();

    var phone = QUICConnection{ .inner = @ptrFromInt(0x1000) };
    var desktop = QUICConnection{ .inner = @ptrFromInt(0x2000) };
    _ = try manager.add(&phone, test_realm, null);
    _ = try manager.add(&desktop, test_realm, null);

    // 一条连接进两个组（一个协作文档 + 一个游戏房间），一个组有两条连接。
    try manager.joinGroup(phone.inner, 100);
    try manager.joinGroup(phone.inner, 200);
    try manager.joinGroup(desktop.inner, 100);

    try std.testing.expectEqual(@as(usize, 2), manager.groupCount(test_realm, 100));
    try std.testing.expectEqual(@as(usize, 1), manager.groupCount(test_realm, 200));

    // 重复加入必须幂等：后端重发 join 不该让同一条连接在组里出现两次
    // （否则一次扇出会给它投两遍）。
    try manager.joinGroup(phone.inner, 100);
    try std.testing.expectEqual(@as(usize, 2), manager.groupCount(test_realm, 100));

    // 退一个组不影响另一个组，也不影响同组的其他连接。
    manager.leaveGroup(phone.inner, 100);
    try std.testing.expectEqual(@as(usize, 1), manager.groupCount(test_realm, 100));
    try std.testing.expectEqual(@as(usize, 1), manager.groupCount(test_realm, 200));
    var remaining = manager.groupConnections(test_realm, 100);
    try std.testing.expectEqual(desktop.inner, remaining.next().?.cnx_handle);
}

test "closing a connection leaves every group it was in" {
    // 关键回归：残留的成员边会让扇出遍历到一个已经归还的槽位，
    // 也就是把消息写给一条不存在的连接。
    var manager = try testManager(2);
    defer manager.deinit();

    var conn = QUICConnection{ .inner = @ptrFromInt(0x1000) };
    _ = try manager.add(&conn, test_realm, null);
    try manager.joinGroup(conn.inner, 1);
    try manager.joinGroup(conn.inner, 2);
    try manager.joinGroup(conn.inner, 3);

    manager.remove(&conn);
    try std.testing.expectEqual(@as(usize, 0), manager.groupCount(test_realm, 1));
    try std.testing.expectEqual(@as(usize, 0), manager.groupCount(test_realm, 2));
    try std.testing.expectEqual(@as(usize, 0), manager.groupCount(test_realm, 3));

    // 边池必须真的还回来了，否则连接反复建立/关闭会把它耗干。
    var again = QUICConnection{ .inner = @ptrFromInt(0x3000) };
    _ = try manager.add(&again, test_realm, null);
    var i: u64 = 0;
    while (i < max_groups_per_connection) : (i += 1) try manager.joinGroup(again.inner, i + 1);
}

test "groups are isolated per realm" {
    // 组标识由各接入方自己发号，两家都从 1 开始是常态。只用 group_id 做键，
    // A 的一次组播就会同时投给 B 的同号组——跨 realm 消息泄露。
    var manager = try testManager(2);
    defer manager.deinit();

    var in_a = QUICConnection{ .inner = @ptrFromInt(0x1000) };
    var in_b = QUICConnection{ .inner = @ptrFromInt(0x2000) };
    _ = try manager.add(&in_a, 7, null);
    _ = try manager.add(&in_b, 9, null);

    try manager.joinGroup(in_a.inner, 1);
    try manager.joinGroup(in_b.inner, 1);

    try std.testing.expectEqual(@as(usize, 1), manager.groupCount(7, 1));
    try std.testing.expectEqual(@as(usize, 1), manager.groupCount(9, 1));
    var in_realm_7 = manager.groupConnections(7, 1);
    var in_realm_9 = manager.groupConnections(9, 1);
    try std.testing.expectEqual(in_a.inner, in_realm_7.next().?.cnx_handle);
    try std.testing.expectEqual(in_b.inner, in_realm_9.next().?.cnx_handle);
}

test "the membership edge pool has a hard ceiling per connection" {
    var manager = try testManager(1);
    defer manager.deinit();

    var conn = QUICConnection{ .inner = @ptrFromInt(0x1000) };
    _ = try manager.add(&conn, test_realm, null);

    var i: u64 = 0;
    while (i < max_groups_per_connection) : (i += 1) try manager.joinGroup(conn.inner, i + 1);
    // 超限必须明确拒绝而不是静默无操作：静默会表现成"某些人收不到这个组的广播"。
    try std.testing.expectError(
        ConnectionManager.Error.TooManyGroupMemberships,
        manager.joinGroup(conn.inner, max_groups_per_connection + 1),
    );
}

test "group membership is queryable per connection, and scoped by realm" {
    // `bind_channel` 的授权就靠这一问（设计文档 §6.1）：客户端能往哪个组发状态包，
    // 判据是后端**已经**把它放进了那个组。
    var manager = try testManager(2);
    defer manager.deinit();

    var mine = QUICConnection{ .inner = @ptrFromInt(0x1000) };
    var theirs = QUICConnection{ .inner = @ptrFromInt(0x2000) };
    _ = try manager.add(&mine, test_realm, null);
    _ = try manager.add(&theirs, test_realm + 1, null);

    try manager.joinGroup(mine.inner, 100);

    try std.testing.expect(manager.isGroupMember(mine.inner, 100));
    try std.testing.expect(!manager.isGroupMember(mine.inner, 200));
    // 同号的组在别的 realm 里是另一个组——否则绑定就是一条跨 realm 的通路。
    try std.testing.expect(!manager.isGroupMember(theirs.inner, 100));
    // 0 号组不存在；不认识的连接也一律 false。
    try std.testing.expect(!manager.isGroupMember(mine.inner, 0));
    try std.testing.expect(!manager.isGroupMember(@ptrFromInt(0x9000), 100));

    manager.leaveGroup(mine.inner, 100);
    try std.testing.expect(!manager.isGroupMember(mine.inner, 100));
}

test "the datagram channel table maps both ways and is cleared on revocation" {
    var manager = try testManager(1);
    defer manager.deinit();

    var conn = QUICConnection{ .inner = @ptrFromInt(0x1000) };
    const ctx = try manager.add(&conn, test_realm, null);

    ctx.bindChannel(0, 100);
    ctx.bindChannel(3, 200);

    // 上行方向：通道号 → 组。
    try std.testing.expectEqual(@as(u64, 100), ctx.channelGroup(0).?);
    try std.testing.expectEqual(@as(u64, 200), ctx.channelGroup(3).?);
    try std.testing.expect(ctx.channelGroup(1) == null);

    // 下行方向：组 → 这条连接自己的通道号。两个方向都要有，因为通道号是连接本地的
    // 资源——不同成员完全可以给同一个组绑不同的号。
    try std.testing.expectEqual(@as(u8, 0), ctx.channelFor(100).?);
    try std.testing.expectEqual(@as(u8, 3), ctx.channelFor(200).?);
    try std.testing.expect(ctx.channelFor(300) == null);
    try std.testing.expect(ctx.channelFor(0) == null);

    // 重绑同一个号即覆盖：客户端换房间时重用通道号是正常操作。
    ctx.bindChannel(0, 400);
    try std.testing.expectEqual(@as(u64, 400), ctx.channelGroup(0).?);
    try std.testing.expect(ctx.channelFor(100) == null);

    // 越界的通道号既写不进也读不出——解码期已经拦过一道，这里是第二道。
    ctx.bindChannel(@intCast(protocol.datagram.max_channels), 500);
    try std.testing.expect(ctx.channelFor(500) == null);

    ctx.unbindChannel(3);
    try std.testing.expect(ctx.channelGroup(3) == null);

    // 吊销准入时必须清空：热路径上没有授权查找，所以权限消失只能落在这张表上。
    ctx.clearChannels();
    try std.testing.expect(ctx.channelGroup(0) == null);
    try std.testing.expect(ctx.channelFor(400) == null);
}
