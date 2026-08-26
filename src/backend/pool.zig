//! 后端传输的共享资源池（每 Worker 一份）
//!
//! 这个模块存在的唯一理由是**把贵的东西从"每条后端连接一份"收敛成"每 Worker 一份"**。
//!
//! ## 它解决的问题
//!
//! 早先每条后端连接（`backend/direct.zig` 的 `BackendConn`）各自持有：
//!
//! - 一个 `AsyncClient` = 一个 UDP socket + 一个 picoquic 上下文（含自己的 TLS
//!   master context 与一次证书解析）+ 一个 xev 定时器 + 一份 64 KiB GSO 缓冲
//! - 一份 `max_recv_queue × 2048` 字节的接收池，默认 **2 MiB**
//!
//! 合计约 **2.1 MiB + 1 fd + 1 定时器 + 1 picoquic 上下文**。而后端连接数不是
//! "配置里不同 host:port 的个数"——注册表键是 `ScopedRoute(realm, group, route_key)`，
//! 所以真实乘数是 **realm 数 × 路由数 × 副本数**。50 个租户 × 4 个服务 × 3 副本 =
//! 600 条/Worker × 8 Worker ≈ **10 GiB 与 4800 个 fd**。多租户场景下这是致命的。
//!
//! 收敛之后单条连接只剩一个 `picoquic_cnx_t` 加一小块状态。
//!
//! ## 它刻意**不**做的事
//!
//! **不接管连接的所有权。** `BackendConn` 仍然归它的 `DirectTransport`，因此
//! `transport.receive()` 的语义、`inflight` 的键、Worker 的 drain 循环都一行不用改。
//!
//! 这不是保守，是正确性：后端推送帧的 realm **只能**由"是哪个 transport 把它捞上来的"
//! 决定（帧里只有 dest_id，而 dest_id 只在 realm 内唯一）。一旦两个 realm 共用一条
//! 连接，推送的 realm 归属就无法回答；让后端在帧里自称 realm 更糟——那等于 realm A
//! 的后端能推给 realm B 的用户（§12.2 要防的正是这个）。
//!
//! 所以连接按 transport 隔离，共享只到"传输设施"这一层为止。
//!
//! ## 共享一个 AsyncClient 的两个前提
//!
//! 1. **picoquic 天生支持一个上下文承载多条连接**，入站包由它按 CID 自己解复用
//!    （`Endpoint.handleIncomingPacket`），所以多条连接共用一个 socket 不需要我们分流。
//! 2. **TLS 参数必须是全局一致的**：alpn / verify_cert / root_cert_file 来自
//!    `RuntimeConfig.direct` 这一份模板，每条路由只替换 `endpoints`。若将来要按路由
//!    配不同的证书，就必须按证书分组建多个池——`acquireClient` 会在参数不一致时报错，
//!    而不是静默用第一次的配置。
//!
//! 回调只带 `conn: *QUICConnection`，而共享客户端只有一个 `user_context`，
//! 因此池里有一张 cnx 指针 → 连接的 O(1) 索引（`CnxIndex`）。它对 `BackendConn`
//! 这个类型零知识：注册方交一个 `*anyopaque` 加一张 `ConnHooks`，池只管转交。
//! 这让将来的对等节点出站链路可以复用同一个池。

const std = @import("std");
const xev = @import("xev");

const foundation = @import("../foundation/mod.zig");
const quic = @import("../quic/mod.zig");
const QUICConnection = quic.connection.Connection;
const QUICConfig = quic.config.QUICConfig;
const reactor = @import("../reactor/mod.zig");
const AsyncClient = reactor.client.AsyncClient;

const RealmId = foundation.realm.RealmId;

/// 单个接收槽位的字节容量。
///
/// picoquic 一次流数据回调通常只带来几 KB；超过槽位容量的分片会被拆到多个槽位，
/// 顺序不变、语义不变（后端响应对网关就是一条字节流）。
pub const slot_bytes: usize = 2048;

/// 池的容量配置。
pub const Config = struct {
    /// 本 Worker 允许的后端连接总数上限。
    ///
    /// 它同时是 cnx 索引的容量。超限时建连明确失败，而不是让索引退化成线性扫描。
    max_conns: usize = 512,
    /// 共享接收池的槽位总数。
    ///
    /// 默认 4096 × 2 KiB = **8 MiB，整个 Worker 一共**。对比早先的"每条连接 2 MiB"，
    /// 600 条连接是 1.2 GiB → 8 MiB。
    recv_slots: usize = 4096,
    /// 单条连接最多能占用的槽位数。
    ///
    /// 没有它，一个卡住不取的后端会把共享池吃干，把所有其他后端的响应一起拖死
    /// ——这正是"共享定容池"必须配一条公平上限的地方（见 protocol_design §12.4）。
    max_slots_per_conn: usize = 256,
};

pub const Error = error{
    /// 后端连接数超过 `max_conns`。
    TooManyConnections,
    /// 已存在一个 TLS 参数不同的客户端；按证书分组另建池。
    ClientConfigMismatch,
    OutOfMemory,
};

/// 一个接收槽位：数据本体在 arena 的字节缓冲里，槽位只记长度与流语义。
const Slot = struct {
    stream_id: u64 = 0,
    len: u32 = 0,
    is_fin: bool = false,
    /// 这一格算在哪个 realm 头上。
    ///
    /// 取自入队时队列的 realm，一直留到归还为止。存在槽位上而不是靠调用方回忆：
    /// 归还只有一个入口（`releaseRecvImpl` → `release(index)`），那里手里只有下标。
    /// 让它去反查"这个下标属于哪条连接"就得多一张表，而且一旦反查失败就是一次
    /// 永久漏还——症状是这个 realm 的接收份额被慢慢蚕食掉。
    realm: RealmId = 0,
    /// 空闲链表或某条连接的待取队列里的下一个槽位。
    next: ?u32 = null,
};

/// 一条连接在共享池上的待取队列。
///
/// 存储共享，**队列不共享**：每条连接一个 FIFO，因此字节序与归属都还是按连接算的
/// ——这是"只共享设施、不共享所有权"落到数据结构上的样子。
pub const SlotList = struct {
    head: ?u32 = null,
    tail: ?u32 = null,
    /// 本连接当前占用的槽位数，用来兑现 `max_slots_per_conn`。
    count: usize = 0,
    /// 这条队列属于哪个 realm；建队列时定死，之后不变。
    ///
    /// 一条后端连接归一个 `DirectTransport`，而 transport 的注册键是
    /// `ScopedRoute(realm, group, route_key)`——所以一条队列里绝不会混两个 realm。
    /// 把 realm 钉在队列上（而不是让 `enqueue` 每次传一个参数）意味着调用点没有
    /// 传错的机会。
    realm: RealmId = 0,
};

/// 共享接收槽位池。
const SlotArena = struct {
    slots: []Slot,
    buffers: []u8,
    free_head: ?u32,
    free_count: usize,
    max_per_conn: usize,
    /// 槽位池的按 realm 公平上限（见 foundation/quota.zig）。
    ///
    /// `max_per_conn` 只按连接算，挡不住"一个 realm 开一百条后端连接"：
    /// 100 × 256 槽位远超整池 4096，于是 A 的响应把 B 的挤光（设计文档 §12.4）。
    quota: foundation.quota.Quota,

    fn init(allocator: std.mem.Allocator, count: usize, max_per_conn: usize) !SlotArena {
        const effective = @max(count, 1);
        const slots = try allocator.alloc(Slot, effective);
        errdefer allocator.free(slots);
        const buffers = try allocator.alloc(u8, effective * slot_bytes);
        errdefer allocator.free(buffers);
        var quota = try foundation.quota.Quota.init(
            allocator,
            foundation.quota.max_tracked_realms,
            effective,
            foundation.quota.default_watermark_percent,
        );
        errdefer quota.deinit(allocator);

        for (slots, 0..) |*slot, i| {
            slot.* = .{ .next = if (i + 1 < effective) @intCast(i + 1) else null };
        }
        return .{
            .slots = slots,
            .buffers = buffers,
            .free_head = 0,
            .free_count = effective,
            .max_per_conn = @max(@min(max_per_conn, effective), 1),
            .quota = quota,
        };
    }

    fn deinit(self: *SlotArena, allocator: std.mem.Allocator) void {
        allocator.free(self.slots);
        allocator.free(self.buffers);
        self.quota.deinit(allocator);
    }

    fn slotBytes(self: *SlotArena, index: u32) []u8 {
        const start = @as(usize, index) * slot_bytes;
        return self.buffers[start .. start + slot_bytes];
    }

    /// 取一格并记账。计数与取格贴在同一个函数里，理由见 foundation/quota.zig。
    fn take(self: *SlotArena, realm: RealmId) u32 {
        const index = self.free_head.?;
        self.free_head = self.slots[index].next;
        self.free_count -= 1;
        self.slots[index].next = null;
        self.slots[index].realm = realm;
        self.quota.acquire(realm);
        return index;
    }

    /// 把一次回调带来的分片拷进池，必要时拆成多个槽位。
    ///
    /// 容量不足时**整段拒绝**并返回 false：只入一半会让上层拿到被截断的字节流，
    /// 那是静默数据损坏，比明确失败糟得多。判据有三条——共享池的剩余量、本连接
    /// 自己的公平上限、以及本 realm 在争用时的公平份额。
    ///
    /// realm 份额只在整段入队之前判一次，因此一段多槽位的分片可以略微越过份额。
    /// 这是有意的：为了守住一个整数把一条可靠流截断，代价远大于超出的那几格。
    fn enqueue(self: *SlotArena, list: *SlotList, stream_id: u64, data: []const u8, is_fin: bool) bool {
        const chunks = @max((data.len + slot_bytes - 1) / slot_bytes, 1);
        if (chunks > self.free_count) return false;
        if (list.count + chunks > self.max_per_conn) return false;
        if (!self.quota.allows(list.realm)) return false;

        var offset: usize = 0;
        var remaining = chunks;
        while (remaining > 0) : (remaining -= 1) {
            const end = @min(offset + slot_bytes, data.len);
            const index = self.take(list.realm);
            const chunk = data[offset..end];
            @memcpy(self.slotBytes(index)[0..chunk.len], chunk);
            self.slots[index].stream_id = stream_id;
            self.slots[index].len = @intCast(chunk.len);
            // fin 只能落在最后一段，否则上层会提前认为这条流结束了。
            self.slots[index].is_fin = is_fin and remaining == 1;

            if (list.tail) |tail| {
                self.slots[tail].next = index;
            } else {
                list.head = index;
            }
            list.tail = index;
            list.count += 1;
            offset = end;
        }
        return true;
    }

    /// 取出某条连接队头的槽位下标；队列为空返回 null。
    fn pop(self: *SlotArena, list: *SlotList) ?u32 {
        const index = list.head orelse return null;
        list.head = self.slots[index].next;
        if (list.head == null) list.tail = null;
        self.slots[index].next = null;
        list.count -= 1;
        return index;
    }

    /// 归还槽位并记账。
    ///
    /// realm 从槽位上读，而不是从调用方拿：归还发生在数据被消费之后，那时调用栈上
    /// 已经没有队列了（见 `Slot.realm`）。
    fn release(self: *SlotArena, index: u32) void {
        const realm = self.slots[index].realm;
        self.slots[index] = .{ .next = self.free_head };
        self.free_head = index;
        self.free_count += 1;
        self.quota.release(realm);
    }

    /// 把某条连接队列里剩下的槽位全部归还（连接销毁时用）。
    fn drop(self: *SlotArena, list: *SlotList) void {
        while (self.pop(list)) |index| self.release(index);
    }
};

/// 池向注册方回调的三个事件。
///
/// 池不认识 `BackendConn` 这个类型：注册方交一个 `*anyopaque` 加这张表，池只转交。
/// 这样 `pool.zig` 与 `direct.zig` 之间没有循环依赖，将来对等节点出站链路也能
/// 挂进同一个池。
pub const ConnHooks = struct {
    on_connected: *const fn (ctx: *anyopaque, conn: *QUICConnection) void,
    on_stream_data: *const fn (ctx: *anyopaque, conn: *QUICConnection, stream_id: u64, data: []const u8, is_fin: bool) void,
    on_close: *const fn (ctx: *anyopaque, conn: *QUICConnection, event: quic.c.CallbackEvent) void,
};

/// cnx 指针 → 注册方的定容开放寻址索引。
///
/// 共享客户端只有一个 `user_context`，而回调只带 cnx，所以必须有这张表。
/// 线性扫描不行：几百条连接下它会落在每一次收包的热路径上。
///
/// 空槽用 `cnx == null` 标记。删除用回移法，不留墓碑——墓碑会让长期运行的进程
/// （连接反复建立/关闭）的探测链无限增长。
const CnxIndex = struct {
    entries: []Entry,
    mask: usize,

    const Entry = struct {
        cnx: ?quic.c.QuicCnx = null,
        ctx: ?*anyopaque = null,
        hooks: ?*const ConnHooks = null,
    };

    fn init(allocator: std.mem.Allocator, capacity: usize) !CnxIndex {
        var size: usize = 8;
        while (size < capacity * 2) size *= 2;
        const entries = try allocator.alloc(Entry, size);
        @memset(entries, .{});
        return .{ .entries = entries, .mask = size - 1 };
    }

    fn deinit(self: *CnxIndex, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
    }

    /// 指针低位受分配器对齐影响（几乎恒为 0），直接取模会让所有键挤在少数桶里，
    /// 所以先做一次 Fibonacci 散列再取高位。
    fn hash(self: *const CnxIndex, cnx: quic.c.QuicCnx) usize {
        const mixed = @intFromPtr(cnx) *% 0x9E3779B97F4A7C15;
        return @as(usize, @intCast(mixed >> 32)) & self.mask;
    }

    fn distance(self: *const CnxIndex, from: usize, to: usize) usize {
        return (to -% from) & self.mask;
    }

    fn find(self: *CnxIndex, cnx: quic.c.QuicCnx) ?*Entry {
        var i = self.hash(cnx);
        while (self.entries[i].cnx != null) {
            if (self.entries[i].cnx == cnx) return &self.entries[i];
            i = (i + 1) & self.mask;
        }
        return null;
    }

    fn put(self: *CnxIndex, cnx: quic.c.QuicCnx, ctx: *anyopaque, hooks: *const ConnHooks) void {
        var i = self.hash(cnx);
        while (self.entries[i].cnx != null) {
            if (self.entries[i].cnx == cnx) break;
            i = (i + 1) & self.mask;
        }
        self.entries[i] = .{ .cnx = cnx, .ctx = ctx, .hooks = hooks };
    }

    fn remove(self: *CnxIndex, cnx: quic.c.QuicCnx) void {
        var i = self.hash(cnx);
        var found = false;
        while (self.entries[i].cnx != null) {
            if (self.entries[i].cnx == cnx) {
                found = true;
                break;
            }
            i = (i + 1) & self.mask;
        }
        if (!found) return;

        var hole = i;
        var j = (i + 1) & self.mask;
        while (self.entries[j].cnx) |other| {
            const ideal = self.hash(other);
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

/// 每 Worker 一份的后端传输设施。
pub const BackendPool = struct {
    allocator: std.mem.Allocator,
    event_loop: *xev.Loop,
    config: Config,

    /// 全池共用的 QUIC 客户端；懒建——一个后端连接都没有时不占 socket。
    client: ?AsyncClient,
    /// 建 client 时用的 TLS 参数，用来拒绝参数不一致的第二次 acquire。
    client_config: ?ClientIdentity,

    index: CnxIndex,
    arena: SlotArena,

    /// 已注册的连接数，用来兑现 `max_conns`。
    live: usize,
    /// 下一个连接 id。
    ///
    /// 只需在**本 Worker 内**唯一：回程映射（`inflight`）是每 Worker 一份的。
    /// 早先它是一个进程级 atomic u16，硬上限 65536 条，而乘数是
    /// realm × 路由 × 副本 × Worker——500 租户规模下会真的耗尽，且是运行期硬失败。
    next_conn_id: u16,

    /// 决定"能否共用同一个 client"的那几个 TLS 参数。
    ///
    /// 客户端证书也在其中，而且它是这张表**最不能漏**的一项：漏掉它意味着两条配了不同
    /// 客户端证书的路由会静默共用第一个 client，第二条路由配的证书被悄悄忽略——那正是
    /// 一次网关向后端出示错误身份的降级，而且没有任何报错。
    const ClientIdentity = struct {
        alpn: [:0]const u8,
        verify_cert: bool,
        root_cert_file: ?[:0]const u8,
        cert_file: ?[:0]const u8,
        key_file: ?[:0]const u8,
        idle_timeout_ms: u64,

        fn eql(a: ClientIdentity, b: ClientIdentity) bool {
            if (a.verify_cert != b.verify_cert) return false;
            if (a.idle_timeout_ms != b.idle_timeout_ms) return false;
            if (!std.mem.eql(u8, a.alpn, b.alpn)) return false;
            if (!samePath(a.root_cert_file, b.root_cert_file)) return false;
            if (!samePath(a.cert_file, b.cert_file)) return false;
            if (!samePath(a.key_file, b.key_file)) return false;
            return true;
        }

        fn samePath(a: ?[:0]const u8, b: ?[:0]const u8) bool {
            if (a == null and b == null) return true;
            const left = a orelse return false;
            const right = b orelse return false;
            return std.mem.eql(u8, left, right);
        }

        fn of(config: QUICConfig) ClientIdentity {
            return .{
                .alpn = config.base.alpn,
                .verify_cert = config.base.verify_cert,
                .root_cert_file = config.base.root_cert_file,
                .cert_file = config.cert_file,
                .key_file = config.key_file,
                .idle_timeout_ms = config.base.idle_timeout_ms,
            };
        }
    };

    pub fn init(allocator: std.mem.Allocator, event_loop: *xev.Loop, config: Config) !BackendPool {
        var index = try CnxIndex.init(allocator, @max(config.max_conns, 1));
        errdefer index.deinit(allocator);
        var arena = try SlotArena.init(allocator, config.recv_slots, config.max_slots_per_conn);
        errdefer arena.deinit(allocator);

        return .{
            .allocator = allocator,
            .event_loop = event_loop,
            .config = config,
            .client = null,
            .client_config = null,
            .index = index,
            .arena = arena,
            .live = 0,
            .next_conn_id = 0,
        };
    }

    /// 释放池。
    ///
    /// 调用方必须先销毁所有后端连接（它们会 `unregister` 并把槽位还回来）。
    /// 池不主动关连接：连接的所有权不在这里（见文件头）。
    pub fn deinit(self: *BackendPool) void {
        if (self.client) |*client| client.deinit();
        self.client = null;
        self.index.deinit(self.allocator);
        self.arena.deinit(self.allocator);
    }

    /// 取得共享客户端，必要时建立。
    ///
    /// 第二次调用若 TLS 参数与第一次不同则报错，**不静默复用**：静默复用意味着
    /// 某条路由配的 root_cert 或 verify_cert 被悄悄忽略，那是一次证书校验的降级。
    pub fn acquireClient(self: *BackendPool, config: QUICConfig) Error!*AsyncClient {
        const identity = ClientIdentity.of(config);
        if (self.client) |*client| {
            if (!self.client_config.?.eql(identity)) return Error.ClientConfigMismatch;
            return client;
        }

        // 共享客户端的回调统一进池，再由 cnx 索引转交给具体注册方。
        self.client = AsyncClient.init(self.allocator, config, self.event_loop) catch |err| {
            return switch (err) {
                error.OutOfMemory => Error.OutOfMemory,
                else => Error.TooManyConnections,
            };
        };
        self.client_config = identity;

        const client = &self.client.?;
        client.setCallbacks(self, dispatchConnected, dispatchStreamData, dispatchClose);
        client.start();
        return client;
    }

    /// 分配一个 Worker 内唯一的连接 id。
    pub fn allocConnId(self: *BackendPool) Error!u16 {
        if (self.next_conn_id == std.math.maxInt(u16)) return Error.TooManyConnections;
        const id = self.next_conn_id;
        self.next_conn_id += 1;
        return id;
    }

    /// 把一条已建立的 QUIC 连接登记到索引上。
    pub fn register(self: *BackendPool, cnx: quic.c.QuicCnx, ctx: *anyopaque, hooks: *const ConnHooks) Error!void {
        if (self.index.find(cnx) == null) {
            if (self.live >= self.config.max_conns) return Error.TooManyConnections;
            self.live += 1;
        }
        self.index.put(cnx, ctx, hooks);
    }

    pub fn unregister(self: *BackendPool, cnx: quic.c.QuicCnx) void {
        if (self.index.find(cnx) == null) return;
        self.index.remove(cnx);
        self.live -= 1;
    }

    /// 把一次流数据入队到调用方自己的队列上。
    pub fn enqueue(self: *BackendPool, list: *SlotList, stream_id: u64, data: []const u8, is_fin: bool) bool {
        return self.arena.enqueue(list, stream_id, data, is_fin);
    }

    /// 取出队头槽位；返回的 data 是池内缓冲的借用，处理完必须 `release`。
    pub fn pop(self: *BackendPool, list: *SlotList) ?Ready {
        const index = self.arena.pop(list) orelse return null;
        const slot = self.arena.slots[index];
        return .{
            .index = index,
            .stream_id = slot.stream_id,
            .is_fin = slot.is_fin,
            .data = self.arena.slotBytes(index)[0..slot.len],
        };
    }

    pub fn release(self: *BackendPool, index: u32) void {
        self.arena.release(index);
    }

    /// 把某条连接队列里剩下的槽位全部归还。
    pub fn dropQueued(self: *BackendPool, list: *SlotList) void {
        self.arena.drop(list);
    }

    /// 池里一个待取槽位都没有。
    ///
    /// 给 Worker 的 drain 循环当快速判据：空闲时不必遍历注册表逐个 `receive()`。
    /// 200 条路由 × 每 10ms 一次 tick = 每秒 2 万次无效轮询，而这一次比较就够替掉它们。
    ///
    /// 判据是"全部槽位都在空闲链表上"，因此它精确、不是估算：只要有任何一条连接
    /// 队列里还挂着东西，`free_count` 就一定小于总数。
    pub fn idle(self: *const BackendPool) bool {
        return self.arena.free_count == self.arena.slots.len;
    }

    /// 从共享池取出的一个待处理分片。
    pub const Ready = struct {
        index: u32,
        stream_id: u64,
        data: []const u8,
        is_fin: bool,
    };

    // ------------------------------------------------------------------------
    // 共享客户端的回调 → 按 cnx 转交给注册方
    //
    // 查不到注册方就丢弃：连接可能刚刚被销毁而 picoquic 还在派发它的尾部事件。
    // ------------------------------------------------------------------------

    fn dispatchConnected(ctx: ?*anyopaque, conn: *QUICConnection) void {
        const self = castSelf(ctx);
        const entry = self.index.find(conn.inner) orelse return;
        entry.hooks.?.on_connected(entry.ctx.?, conn);
    }

    fn dispatchStreamData(ctx: ?*anyopaque, conn: *QUICConnection, stream_id: u64, data: []const u8, is_fin: bool) void {
        const self = castSelf(ctx);
        const entry = self.index.find(conn.inner) orelse return;
        entry.hooks.?.on_stream_data(entry.ctx.?, conn, stream_id, data, is_fin);
    }

    fn dispatchClose(ctx: ?*anyopaque, conn: *QUICConnection, event: quic.c.CallbackEvent) void {
        const self = castSelf(ctx);
        const entry = self.index.find(conn.inner) orelse return;
        // 先转交再摘链：注册方在回调里还要读自己的状态。
        entry.hooks.?.on_close(entry.ctx.?, conn, event);
        self.unregister(conn.inner);
    }

    inline fn castSelf(ctx: ?*anyopaque) *BackendPool {
        return @ptrCast(@alignCast(ctx.?));
    }
};

// ============================================================================
// 测试
// ============================================================================

fn testArena(slots: usize, per_conn: usize) !SlotArena {
    return SlotArena.init(std.testing.allocator, slots, per_conn);
}

test "the shared arena keeps each connection's byte order" {
    var arena = try testArena(16, 16);
    defer arena.deinit(std.testing.allocator);

    var a: SlotList = .{};
    var b: SlotList = .{};

    // 两条连接交错入队；各自的 FIFO 必须互不干扰。
    try std.testing.expect(arena.enqueue(&a, 0, "a1", false));
    try std.testing.expect(arena.enqueue(&b, 4, "b1", false));
    try std.testing.expect(arena.enqueue(&a, 0, "a2", true));

    const a1 = arena.pop(&a).?;
    try std.testing.expectEqualStrings("a1", arena.slotBytes(a1)[0..arena.slots[a1].len]);
    const a2 = arena.pop(&a).?;
    try std.testing.expectEqualStrings("a2", arena.slotBytes(a2)[0..arena.slots[a2].len]);
    try std.testing.expect(arena.slots[a2].is_fin);
    try std.testing.expect(arena.pop(&a) == null);

    const b1 = arena.pop(&b).?;
    try std.testing.expectEqualStrings("b1", arena.slotBytes(b1)[0..arena.slots[b1].len]);
}

test "a fragment larger than one slot is split, and fin lands only on the last piece" {
    var arena = try testArena(8, 8);
    defer arena.deinit(std.testing.allocator);

    const payload = try std.testing.allocator.alloc(u8, slot_bytes + 7);
    defer std.testing.allocator.free(payload);
    @memset(payload, 'x');

    var list: SlotList = .{};
    try std.testing.expect(arena.enqueue(&list, 0, payload, true));
    try std.testing.expectEqual(@as(usize, 2), list.count);

    const first = arena.pop(&list).?;
    try std.testing.expectEqual(@as(u32, slot_bytes), arena.slots[first].len);
    // 关键：fin 不能落在第一段，否则上层会提前认为这条流结束了。
    try std.testing.expect(!arena.slots[first].is_fin);

    const second = arena.pop(&list).?;
    try std.testing.expectEqual(@as(u32, 7), arena.slots[second].len);
    try std.testing.expect(arena.slots[second].is_fin);
}

test "one stalled connection cannot eat the shared pool" {
    // 这是"共享定容池"必须配公平上限的理由：没有它，一个不取响应的后端会把
    // 所有其他后端的响应一起拖死。
    var arena = try testArena(64, 2);
    defer arena.deinit(std.testing.allocator);

    var greedy: SlotList = .{};
    try std.testing.expect(arena.enqueue(&greedy, 0, "1", false));
    try std.testing.expect(arena.enqueue(&greedy, 0, "2", false));
    // 到达本连接上限：拒绝，即使共享池还有 62 个空槽。
    try std.testing.expect(!arena.enqueue(&greedy, 0, "3", false));

    // 别的连接不受影响。
    var other: SlotList = .{};
    try std.testing.expect(arena.enqueue(&other, 0, "ok", false));
}

test "a partially fitting fragment is rejected whole, never truncated" {
    // 截断可靠流上的字节是静默数据损坏——后续帧的长度与内容会全部错位。
    var arena = try testArena(2, 8);
    defer arena.deinit(std.testing.allocator);

    const payload = try std.testing.allocator.alloc(u8, slot_bytes * 3);
    defer std.testing.allocator.free(payload);
    @memset(payload, 'y');

    var list: SlotList = .{};
    try std.testing.expect(!arena.enqueue(&list, 0, payload, false));
    // 一个槽位都不该被占用。
    try std.testing.expectEqual(@as(usize, 0), list.count);
    try std.testing.expectEqual(@as(usize, 2), arena.free_count);
}

test "released slots come back to the shared pool" {
    var arena = try testArena(4, 4);
    defer arena.deinit(std.testing.allocator);

    var list: SlotList = .{};
    var i: usize = 0;
    while (i < 4) : (i += 1) try std.testing.expect(arena.enqueue(&list, 0, "x", false));
    try std.testing.expectEqual(@as(usize, 0), arena.free_count);
    try std.testing.expect(!arena.enqueue(&list, 0, "y", false));

    // dropQueued 的语义：连接销毁时把它队列里剩下的全部还回来。
    arena.drop(&list);
    try std.testing.expectEqual(@as(usize, 4), arena.free_count);
    try std.testing.expectEqual(@as(usize, 0), list.count);
    try std.testing.expect(arena.enqueue(&list, 0, "y", false));
}

test "one realm cannot eat the shared pool by opening more connections" {
    // `max_per_conn` 只按连接算，一个租户多开几条后端连接就能绕过它。这条钉住的是
    // realm 份额：它是"共享定容池 + 多租户"唯一有效的那道闸（§12.4）。
    var arena = try testArena(100, 10);
    defer arena.deinit(std.testing.allocator);

    // realm 1 开 8 条连接，每条都老老实实待在 max_per_conn 以内，合计 80 格。
    var greedy: [8]SlotList = @splat(.{ .realm = 1 });
    for (&greedy) |*list| {
        var i: usize = 0;
        while (i < 10) : (i += 1) try std.testing.expect(arena.enqueue(list, 0, "x", false));
    }
    try std.testing.expectEqual(@as(u32, 80), arena.quota.count(1));

    // realm 2 第一次进来：活跃 realm 还是 1，份额 = 全池，放行。
    var newcomer: SlotList = .{ .realm = 2 };
    try std.testing.expect(arena.enqueue(&newcomer, 0, "y", false));

    // 此刻活跃变 2，份额腰斩到 50，realm 1 已占 80 → 被拒，尽管池里还有 19 个空槽。
    try std.testing.expect(!arena.enqueue(&greedy[0], 0, "z", false));
    // 而 realm 2 照常放行——只拒超额的那个。
    try std.testing.expect(arena.enqueue(&newcomer, 0, "y2", false));
}

test "realm slot counters return to zero after a full churn cycle" {
    // 漏掉一条归还路径的症状是这个 realm 的接收份额被慢慢蚕食，几天后才显现。
    // 归还只有两条路径：逐格 release（正常消费完）与 drop（连接销毁）。
    var arena = try testArena(32, 32);
    defer arena.deinit(std.testing.allocator);

    var round: usize = 0;
    while (round < 5) : (round += 1) {
        var a: SlotList = .{ .realm = 1 };
        var b: SlotList = .{ .realm = 2 };
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            try std.testing.expect(arena.enqueue(&a, 0, "a", false));
            try std.testing.expect(arena.enqueue(&b, 0, "b", false));
        }

        // 路径一：正常消费完逐格归还。
        while (arena.pop(&a)) |index| arena.release(index);
        // 路径二：连接销毁时整队归还。
        arena.drop(&b);

        try std.testing.expectEqual(@as(usize, 32), arena.free_count);
    }

    try std.testing.expectEqual(@as(usize, 0), arena.quota.total);
    try std.testing.expectEqual(@as(usize, 0), arena.quota.active_realms);
}

test "the cnx index survives insert, lookup and removal" {
    var index = try CnxIndex.init(std.testing.allocator, 8);
    defer index.deinit(std.testing.allocator);

    const hooks = ConnHooks{
        .on_connected = struct {
            fn f(_: *anyopaque, _: *QUICConnection) void {}
        }.f,
        .on_stream_data = struct {
            fn f(_: *anyopaque, _: *QUICConnection, _: u64, _: []const u8, _: bool) void {}
        }.f,
        .on_close = struct {
            fn f(_: *anyopaque, _: *QUICConnection, _: quic.c.CallbackEvent) void {}
        }.f,
    };

    var owners: [8]usize = @splat(0);
    var handles: [8]quic.c.QuicCnx = undefined;
    for (&handles, 0..) |*handle, i| {
        handle.* = @ptrFromInt(0x1000 + i * 0x40);
        index.put(handle.*, &owners[i], &hooks);
    }
    for (handles, 0..) |handle, i| {
        try std.testing.expectEqual(@as(*anyopaque, &owners[i]), index.find(handle).?.ctx.?);
    }

    // 摘掉中间一个之后，其余的仍然都能查到——回移法不能打断别人的探测链。
    index.remove(handles[3]);
    try std.testing.expect(index.find(handles[3]) == null);
    for (handles, 0..) |handle, i| {
        if (i == 3) continue;
        try std.testing.expectEqual(@as(*anyopaque, &owners[i]), index.find(handle).?.ctx.?);
    }
}
