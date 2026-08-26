//! 隔离域（Realm）
//!
//! realm 回答一个问题：**这条连接上的标识属于谁的命名空间。** `dest_id`、路由键
//! `(group, route_key)`、组播组标识都只在一个 realm 内部有意义，跨 realm 同名的两个
//! 标识必须互不可见（设计文档 §12.2）。
//!
//! ## 为什么叫 realm 而不是 tenant
//!
//! tenant 是计费与商务视角的词，而网关不关心谁付钱、谁是客户。realm 取自 Kerberos 与
//! HTTP 认证里的同名概念，含义正是"标识只在其内部唯一的管理边界"——这恰好是网关需要
//! 的语义，且对所有权保持中立：自用部署就是"一个 realm"，不带 SaaS 味道。
//!
//! ## 从哪来
//!
//! 从 TLS 的 SNI 来，在握手完成时确定，**绝不取自帧内容**（理由见设计文档 §12.3）：
//! SNI 由证书链背书，而帧里的字段是客户端自称的。
//!
//! ## 为什么不直接哈希 SNI 当 id
//!
//! 哈希会在一条安全边界上引入碰撞可能：两个不同域名撞到同一个 id 就是跨 realm 消息
//! 泄露，而且是静默的。显式分配的 id 碰撞概率为零，代价只是多一段配置。

const std = @import("std");

/// 隔离域编号。
///
/// 宽度取 u16（与 `node_id` 一致）：它的基数是"接入方数量"，几百到几千量级。
pub const RealmId = u16;

/// 自用部署（整个网关只有一个隔离域）时的取值。
pub const default_realm: RealmId = 0;

pub const Error = error{
    /// 登记表已满（`slots` 用尽）。
    TableFull,
    /// 这个 SNI 已经登记过了。
    DuplicateName,
    /// 单域部署不允许动态登记（见 `register`）。
    SingleRealmDeployment,
};

/// SNI -> RealmId 的解析表。
///
/// 每条连接只解析一次（握手完成时），不在收包热路径上，因此线性扫描足够——realm 的
/// 数量级是配置规模，不是流量规模。
///
/// ## 为什么是定容 slab + 原子长度
///
/// 新增接入方必须不重启（设计文档 §12.5），所以表要能在运行期追加，而读它的是全部
/// Worker 线程。做法是启动期按容量一次分配好槽位，运行期只填后面的空位：
///
/// - **已登记的部分只读、永不移动、永不释放**，所以正在扫表的读者不可能踩到搬迁或悬垂；
/// - `len` 用原子发布：写者先填好槽位内容，再用 release 序把长度加一；读者用 acquire
///   序读长度，因此**读到的长度所覆盖的槽位内容必定已经写完**。
///
/// 这样就不需要锁、不需要 RCU、也不需要回收宽限期——代价是不支持删除。删除也不该支持：
/// 一个还有连接和路由挂着的 realm 没有安全的移除时机，而"上线一个新接入方"只需要追加。
///
/// 只有一个写者（处理 SIGHUP 的那条线程，见 app/reload.zig），所以追加不需要 CAS。
/// `sni` 借用登记簿的字节，那块内存进程生命周期内不释放。
pub const Table = struct {
    /// 定容槽位；下标小于 `len` 的部分只读。
    slots: []Entry = &.{},
    /// 已登记条目数，原子发布（见上文）。
    len: std.atomic.Value(usize) = .init(0),
    /// 未登记的 SNI（或客户端没发 SNI）归入哪个 realm；null 表示拒绝该连接。
    ///
    /// 两个状态都是真实配置形态：
    /// - 自用部署：`default_realm`，所有连接同属一个域，不需要登记任何 SNI。
    /// - 多 realm 部署：null，**失败关闭**——来源不明的 SNI 不该被服务，否则一个
    ///   拼错的域名会静默落进别人的命名空间。
    ///
    /// 它在启动期由配置定死、**运行期不可变**：把它从 `default_realm` 翻成 null 会让
    /// 每个 SNI 未登记的客户端在下一次连接时被拒。
    fallback: ?RealmId = default_realm,

    pub const Entry = struct {
        sni: []const u8 = &.{},
        realm: RealmId = 0,
    };

    /// 已登记的条目（只读视图）。
    pub fn entries(self: *const Table) []const Entry {
        return self.slots[0..self.len.load(.acquire)];
    }

    /// 解析这条连接属于哪个 realm；返回 null 表示应当拒绝该连接。
    ///
    /// 比较**不区分大小写**：DNS 主机名本身大小写无关（RFC 6066 也要求 SNI 按
    /// 大小写无关比较），客户端发 `A.GW.Example.COM` 是合法的。区分大小写会让这类
    /// 客户端静默落进 fallback 或被拒，而原因极难定位。
    pub fn resolve(self: *const Table, sni: ?[]const u8) ?RealmId {
        const name = sni orelse return self.fallback;
        for (self.entries()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.sni, name)) return entry.realm;
        }
        return self.fallback;
    }

    /// 追加一条登记。`sni` 必须在进程生命周期内有效（本表只借用）。
    ///
    /// 只允许单一写者调用。写槽位与发布长度的顺序不能调换——先发布长度就等于让读者
    /// 看见一个还没填好的槽位。
    ///
    /// **单域部署下拒绝追加。** 启动时没有登记任何域名意味着这个部署宣称"只有一个命名
    /// 空间"，`fallback` 因此是 `default_realm`；此刻登记第一个 realm 会把 fallback 的
    /// 语义从"全部归 0"变成"未登记就拒连"，于是所有现有客户端的下一次连接都被拒。
    /// 这是部署形态的改变，只能重启，不能热加载。
    pub fn register(self: *Table, sni: []const u8, realm: RealmId) Error!void {
        if (self.fallback != null) return Error.SingleRealmDeployment;
        for (self.entries()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.sni, sni)) return Error.DuplicateName;
        }
        const at = self.len.load(.monotonic);
        if (at == self.slots.len) return Error.TableFull;
        self.slots[at] = .{ .sni = sni, .realm = realm };
        self.len.store(at + 1, .release);
    }
};

// ============================================================================
// 测试
// ============================================================================

test "a single-realm deployment needs no SNI entries" {
    const table = Table{};
    try std.testing.expectEqual(default_realm, table.resolve("anything.example.com").?);
    // 客户端不发 SNI 也归入默认域。
    try std.testing.expectEqual(default_realm, table.resolve(null).?);
}

test "registered SNI maps to its own realm" {
    var slots = [_]Table.Entry{
        .{ .sni = "a.gw.example.com", .realm = 7 },
        .{ .sni = "b.gw.example.com", .realm = 9 },
    };
    const table = Table{ .slots = &slots, .len = .init(slots.len), .fallback = null };

    try std.testing.expectEqual(@as(RealmId, 7), table.resolve("a.gw.example.com").?);
    try std.testing.expectEqual(@as(RealmId, 9), table.resolve("b.gw.example.com").?);
    // 主机名大小写无关：客户端发大写是合法的，不能落进 fallback。
    try std.testing.expectEqual(@as(RealmId, 7), table.resolve("A.GW.Example.COM").?);
}

test "an unregistered SNI is rejected when there is no fallback" {
    // 失败关闭：多 realm 部署下，来源不明的 SNI 不能静默落进任何人的命名空间。
    var slots = [_]Table.Entry{.{ .sni = "a.gw.example.com", .realm = 7 }};
    const table = Table{ .slots = &slots, .len = .init(slots.len), .fallback = null };

    try std.testing.expect(table.resolve("typo.gw.example.com") == null);
    try std.testing.expect(table.resolve(null) == null);
    // 子串不算命中：必须整体相等。
    try std.testing.expect(table.resolve("a.gw.example.co") == null);
    try std.testing.expect(table.resolve("xa.gw.example.com") == null);
}

test "a realm can be registered at runtime and resolves immediately" {
    var slots: [4]Table.Entry = @splat(.{});
    slots[0] = .{ .sni = "a.gw.example.com", .realm = 7 };
    var table = Table{ .slots = &slots, .len = .init(1), .fallback = null };

    try table.register("b.gw.example.com", 9);
    try std.testing.expectEqual(@as(RealmId, 9), table.resolve("b.gw.example.com").?);
    // 已登记的那条不受影响——追加永不移动已有槽位。
    try std.testing.expectEqual(@as(RealmId, 7), table.resolve("a.gw.example.com").?);

    // 重名要拒绝，而且大小写无关：否则同一个域名会有两条登记，
    // 解析命中哪条取决于插入顺序，是一条静默的跨 realm 泄露路径。
    try std.testing.expectError(Error.DuplicateName, table.register("B.GW.Example.COM", 11));

    try table.register("c.gw.example.com", 11);
    try table.register("d.gw.example.com", 13);
    try std.testing.expectError(Error.TableFull, table.register("e.gw.example.com", 15));
}

test "a single-realm deployment refuses runtime registration" {
    // 这条钉住的是一次会打翻所有现有客户端的操作：fallback 从 default_realm 变成 null
    // 之后，每个 SNI 未登记的客户端下一次连接都会被拒。它是部署形态的改变，只能重启。
    var slots: [4]Table.Entry = @splat(.{});
    var table = Table{ .slots = &slots };
    try std.testing.expectError(Error.SingleRealmDeployment, table.register("a.gw.example.com", 1));
}
