//! 帧格式定义
//!
//! 设计决议见 `docs/protocol_design.md`，本文件只实现其中"流上的部分"。
//!
//! ## 两条主线
//!
//! 1. **一条 QUIC 流 = 一次交换**：首帧是 OPEN，声明目的地；后续帧是 DATA，
//!    只带长度；带 `eof` 的帧是最后一帧。目的地是流级属性，不在每帧重复，
//!    因此伪造后续帧也改不了投递目标。
//! 2. **不重复 QUIC 已有的能力**：多路复用交给 stream id，请求/响应关联交给
//!    双向流，流内有序与流控交给 QUIC 自身。所以帧头里没有通道号、没有序号、
//!    没有窗口，也没有魔数——ALPN 在握手层已经保证了协议一致。
//!
//! ## 帧结构
//!
//! ```
//! OPEN（一次交换的第一帧，8 字节）
//! ┌────────────┬───────┬────────────────┬───────────┬──────────┬───────┬───────────┐
//! │ frame_type │ flags │ body_len (u16) │ dest_kind │ response │ group │ route_key │
//! │ (1B)       │ (1B)  │ (2B)           │ (1B)      │ (1B)     │ (1B)  │ (1B)      │
//! └────────────┴───────┴────────────────┴───────────┴──────────┴───────┴───────────┘
//!
//! DATA（同一次交换的后续帧，4 字节）
//! ┌────────────┬───────┬────────────────┐
//! │ frame_type │ flags │ body_len (u16) │
//! │ (1B)       │ (1B)  │ (2B)           │
//! └────────────┴───────┴────────────────┘
//! ```
//!
//! ## 解码一律白名单
//!
//! `frame_type`、`dest_kind` 都是穷尽枚举 + 显式白名单解码函数，不用
//! `@enumFromInt`。非穷尽枚举会让未定义取值悄悄通过，落到"所有判定函数都返回
//! false"的未定义语义上；白名单让将来扩展协议时旧网关明确报错，而不是误投递。
//! 保留位同理：非 0 直接拒绝，这样它们将来才真的可用。

const std = @import("std");

// ============================================================================
// 尺寸常量
// ============================================================================

/// OPEN 帧头长度
pub const OPEN_HEADER_SIZE: usize = 8;

/// DATA 帧头长度
pub const DATA_HEADER_SIZE: usize = 4;

/// DATAGRAM 帧头长度（不可靠通路，见 protocol/datagram.zig）
pub const DATAGRAM_HEADER_SIZE: usize = 2;

/// 单帧 Body 上限。
///
/// `body_len` 是 u16，所以上限是类型自带的，不需要额外校验。选 u16 而不是 u32
/// 是有意的：它让重组缓冲可以做成定容池，是"启动期一次分配、运行期零分配"的
/// 前置条件。超过这个长度的内容由发送方切成多帧。
pub const MAX_BODY_SIZE: usize = std.math.maxInt(u16);

/// 单帧总长上限（最长的帧头 + 最大 Body）。
pub const MAX_FRAME_SIZE: usize = OPEN_HEADER_SIZE + MAX_BODY_SIZE;

// ============================================================================
// 帧类型
// ============================================================================

/// 帧类型：决定帧头有多长、以及这一帧在交换里的位置。
pub const FrameType = enum(u8) {
    /// 一次交换的第一帧，携带目的地
    open = 0x00,
    /// 同一次交换的后续帧
    data = 0x01,
    /// 不可靠通路上的帧（不出现在 QUIC 流上）
    datagram = 0x02,

    /// 该类型的帧头长度。
    pub fn headerSize(self: FrameType) usize {
        return switch (self) {
            .open => OPEN_HEADER_SIZE,
            .data => DATA_HEADER_SIZE,
            .datagram => DATAGRAM_HEADER_SIZE,
        };
    }

    /// 白名单解码；未定义取值一律拒绝。
    pub fn decode(byte: u8) FrameError!FrameType {
        return switch (byte) {
            @intFromEnum(FrameType.open) => .open,
            @intFromEnum(FrameType.data) => .data,
            @intFromEnum(FrameType.datagram) => .datagram,
            else => error.UnknownFrameType,
        };
    }
};

// ============================================================================
// 目的地
// ============================================================================

/// 目的地类型：客户端只说"发给谁"，网关按配置决定走哪条传输路径。
///
/// 权限不对称（见 `docs/protocol_design.md` §5.4）：客户端只能寻址 `.gateway`
/// 与 `.service`，`.peer` / `.multicast` 只对后端开放，否则客户端可以绕过业务层
/// 直接骚扰任意用户。权限判定需要知道发送方是谁，因此不在解码期做，而在分派时做。
pub const DestKind = enum(u8) {
    /// 网关自身：`route_key` 复用为 ControlType
    gateway = 0x00,
    /// 后端服务：`(group, route_key)` 查传输注册表
    service = 0x01,
    /// 一个或多个具体客户端：body 前缀是目标列表
    peer = 0x02,
    /// 一个组播组：body 前缀是组标识
    multicast = 0x03,

    /// 白名单解码；未定义取值一律拒绝。
    pub fn decode(byte: u8) FrameError!DestKind {
        return switch (byte) {
            @intFromEnum(DestKind.gateway) => .gateway,
            @intFromEnum(DestKind.service) => .service,
            @intFromEnum(DestKind.peer) => .peer,
            @intFromEnum(DestKind.multicast) => .multicast,
            else => error.UnknownDestKind,
        };
    }

    /// `(group, route_key)` 在该目的地下是否构成路由键。
    ///
    /// `.peer` / `.multicast` 的目标在 body 前缀里，这两个字节没有含义。
    pub fn hasRouteKey(self: DestKind) bool {
        return self == .gateway or self == .service;
    }
};

// ============================================================================
// 路由标识
// ============================================================================

/// 完整路由键（RouteId）：Group + RouteKey 组合
///
/// - **Group（服务分组）**：路由空间的一级分组，用于组织服务
/// - **RouteKey（组内路由）**：组内的具体路由；`dest_kind = .gateway` 下
///   复用为 ControlType
///
/// 这是**配置规模**的命名空间——它的基数等于"系统里有多少个后端 handler"，
/// 几百量级，65536 足够；所有节点加载同一份配置，因此不存在跨节点冲突。
///
/// 网关本身不预定义具体数值的含义，而是通过配置文件把组合键映射到具体的
/// 服务名或 topic 名。例如：
/// - (0x01, 0x00) → "ai-service"（服务发现 key）
/// - (0x02, 0x01) → "im.messages"（NATS topic）
///
/// 走直连还是中继由注册关系决定，客户端无感。
pub const RouteId = packed struct(u16) {
    route_key: u8 = 0x00,
    group: u8 = 0x00,

    pub fn init(group: u8, route_key: u8) RouteId {
        return .{ .group = group, .route_key = route_key };
    }
};

// ============================================================================
// 响应模式
// ============================================================================

/// OPEN 发起方是否需要应用层响应。
///
/// 两种模式都会正常结束 QUIC 双向流的两个发送方向；区别只在返回方向有没有应用帧：
///
/// - `.required`：接收方必须返回一个或多个应用帧，最后以 FIN 收尾；
/// - `.none`：接收方成功接纳后只发送空 FIN，业务处理结果不再返回。
///
/// `.none` 不是可靠业务确认。空 FIN 只表示本端已经完成准入并把请求交给下一层；
/// 需要 message_id、持久化结果或业务错误的请求必须使用 `.required`。
pub const ResponseMode = enum(u8) {
    required = 0x00,
    none = 0x01,

    pub fn decode(byte: u8) FrameError!ResponseMode {
        return switch (byte) {
            @intFromEnum(ResponseMode.required) => .required,
            @intFromEnum(ResponseMode.none) => .none,
            else => error.UnknownResponseMode,
        };
    }
};

// ============================================================================
// 控制帧类型
// ============================================================================

/// 控制帧类型
///
/// 当 `dest_kind == .gateway` 时，`route_key` 字段的语义变为 ControlType。
/// 用于区分网关层面需要处理的不同控制操作。
///
/// ## 类型分区
///
/// | 范围        | 类别         | 说明                           |
/// |-------------|--------------|--------------------------------|
/// | 0x00 - 0x0F | 心跳类       | heartbeat, ping/pong           |
/// | 0x10 - 0x1F | 认证类       | auth_request, auth_response    |
/// | 0x20 - 0x2F | 连接控制类   | kick_off, disconnect, redirect |
/// | 0x30 - 0x3F | 会话类       | session_resume                 |
/// | 0x40 - 0x4F | 组播类       | join_group, leave_group        |
/// | 0xF0 - 0xFF | 系统类       | error, maintenance             |
pub const ControlType = enum(u8) {
    // =========================================================================
    // 心跳类 (0x00 - 0x0F)
    // =========================================================================

    /// 心跳请求（Client → Gateway）
    heartbeat = 0x00,
    /// 心跳响应（Gateway → Client）
    heartbeat_ack = 0x01,
    /// Ping 请求（延迟测量）
    ping = 0x02,
    /// Pong 响应
    pong = 0x03,

    // =========================================================================
    // 认证类 (0x10 - 0x1F)
    // =========================================================================

    /// 认证请求（Client → Gateway，Body 携带 Token）
    auth_request = 0x10,
    /// 认证成功响应（Gateway → Client）
    auth_success = 0x11,
    /// 认证失败响应（Gateway → Client，Body 携带错误信息）
    auth_failure = 0x12,

    // =========================================================================
    // 连接控制类 (0x20 - 0x2F)
    // =========================================================================

    /// 踢下线（Gateway → Client，Body 携带原因）
    kick_off = 0x20,
    /// 客户端主动断开（Client → Gateway）
    disconnect = 0x21,
    /// 强制关闭连接（Gateway → Client，用于异常情况）
    force_close = 0x22,
    /// 重定向：请连到另一个节点（Gateway → Client，Body 见 body.RedirectHint）
    ///
    /// 亲和策略（设计文档 §8.5 策略 B）的执行手段。它不是"建议"而是**强制**：
    /// 网关发出它之后立刻关闭连接，因为不变量是「每条带 `dest_id` 的活连接都在
    /// `hash(realm, dest_id)` 算出的位置上」。留在错位置继续服务，后续按 hash 定向
    /// 转发的推送就会漏掉这条连接，而漏掉的表现是消息静默丢失。
    ///
    /// 客户端 SDK 必须实现它：收到就缓存 body 里的 home 地址与 placement hint，
    /// 立刻重连过去并重新认证。
    redirect = 0x23,
    /// 把一个 datagram 通道绑定到一个组播组（Client → Gateway，Body 见 body.ChannelBinding）
    ///
    /// datagram 没有流，无法用 OPEN 声明目的地。改成"先绑定、后发送"：绑定一次，
    /// 之后每个 datagram 只带 1 字节通道号（设计文档 §6.1）。**授权因此从每包检查
    /// 收敛成绑定时一次**，热路径上没有任何权限判断。
    ///
    /// 授权判据是**这条连接已经是该组的成员**——而成员关系只能由后端的 `join_group`
    /// 建立，所以网关在这里做的是一次真实的本地判断，而不是采信客户端的自述。
    ///
    /// 通道号由客户端自选（它是这条连接上的本地资源，与流号同理），所以绑定成功
    /// 不需要网关回传任何编号。
    bind_channel = 0x24,
    /// 解除一个 datagram 通道的绑定（Client → Gateway，Body 是 1 字节通道号）
    unbind_channel = 0x25,

    // =========================================================================
    // 会话类 (0x30 - 0x3F)
    // =========================================================================

    /// 会话恢复请求（Client → Gateway）
    session_resume = 0x30,
    /// 会话恢复成功（Gateway → Client）
    session_resume_ack = 0x31,
    /// 会话恢复失败（Gateway → Client）
    session_resume_fail = 0x32,
    /// 认证成功后由 Gateway 发给后端的连接级上线事件。
    session_online = 0x33,
    /// 连接关闭、被踢或准入过期时由 Gateway 发给后端的连接级下线事件。
    session_offline = 0x34,

    // =========================================================================
    // 组播类 (0x40 - 0x4F)
    // =========================================================================

    /// 把若干连接加入一个组播组（Backend → Gateway，Body 见 body.GroupBinding）
    ///
    /// **只有后端能发。** 成员关系的权威在后端：谁能进哪个协作文档、哪局游戏、
    /// 哪个直播间，是业务判断，网关没有任何判据（设计文档 §8.1）。客户端要进组，
    /// 走的仍是"客户端 → `.service` → 后端校验 → 后端 → 网关"这条两跳路径。
    join_group = 0x40,
    /// 把若干连接从一个组播组里移出（Backend → Gateway）
    leave_group = 0x41,

    // =========================================================================
    // 系统类 (0xF0 - 0xFF)
    // =========================================================================

    /// 网关错误（Gateway → Client）
    gateway_error = 0xF0,
    /// 服务维护通知（Gateway → Client）
    maintenance = 0xF1,

    /// 允许未定义的值。
    ///
    /// 这里与 `FrameType` / `DestKind` 的白名单策略不同是有意的：控制类型是
    /// 一个开放空间，解码期无法穷举，未知取值由分派处回一个业务级错误帧
    /// （而不是关连接）——它不影响字节流的可信度。
    _,

    /// 判断是否为心跳类
    pub fn isHeartbeat(self: ControlType) bool {
        const v = @intFromEnum(self);
        return v <= 0x0F;
    }

    /// 判断是否为认证类
    pub fn isAuth(self: ControlType) bool {
        const v = @intFromEnum(self);
        return v >= 0x10 and v <= 0x1F;
    }

    /// 判断是否为连接控制类
    pub fn isConnectionControl(self: ControlType) bool {
        const v = @intFromEnum(self);
        return v >= 0x20 and v <= 0x2F;
    }

    /// 判断是否为会话类
    pub fn isSession(self: ControlType) bool {
        const v = @intFromEnum(self);
        return v >= 0x30 and v <= 0x3F;
    }

    /// 判断是否为组播类
    pub fn isMulticast(self: ControlType) bool {
        const v = @intFromEnum(self);
        return v >= 0x40 and v <= 0x4F;
    }

    /// 判断是否为系统类
    pub fn isSystem(self: ControlType) bool {
        const v = @intFromEnum(self);
        return v >= 0xF0;
    }
};

// ============================================================================
// 标志位
// ============================================================================

/// 帧标志位
///
/// 旧协议里的 `sof` 消失了：OPEN 本身就是交换的起点，不需要额外标志。
/// `compressed` / `encrypted` / `need_ack` 也一并删除——压缩与加密是 Body
/// 内部的事（网关不解析 Body），ACK 语义属于 QUIC 或业务层。
pub const Flags = packed struct(u8) {
    /// 本次交换的最后一帧；网关据此给后端流发 fin。
    eof: bool = false,
    /// 请求投递回报（仅 OPEN 有意义，见设计文档 §5.5）。
    ///
    /// 置位表示希望网关回写"投不出去的目标列表"。这是后端扇出场景的需求：它是后端
    /// 判断"该不该把这条消息转去离线存储"的唯一信号。
    report: bool = false,
    /// 投给成员时改走不可靠通路（仅 `.multicast` 的 OPEN 有意义，见设计文档 §6）。
    ///
    /// 置位表示"这一帧的 body 是一段状态负载，请以 QUIC DATAGRAM 而不是推送流投给
    /// 组成员"。它让**不可靠投递复用整套可靠扇出的选路机制**——本位置、同机其他
    /// Worker、其他节点三条路一个字节都不用改，因为标志位就在帧头里跟着帧走。
    ///
    /// 只有已经绑定了对应通道的成员会收到（§6.1）：绑定既是授权也是"我要不可靠投递"
    /// 这个意愿的表达。没绑的成员被跳过，而不是降级成可靠推送——降级会让 60Hz 的
    /// 状态流在那条连接上堆成队头阻塞，正是本通路存在的理由的反面。
    unreliable: bool = false,
    /// 保留位（必须为 0，解码时校验）
    _reserved: u5 = 0,

    /// 白名单解码：保留位非 0 一律拒绝。
    pub fn decode(byte: u8) FrameError!Flags {
        const flags: Flags = @bitCast(byte);
        if (flags._reserved != 0) return error.ReservedBitsSet;
        return flags;
    }

    /// 一次性交换的唯一一帧 / 流式交换的末帧。
    pub fn last() Flags {
        return .{ .eof = true };
    }
};

// ============================================================================
// 帧头
// ============================================================================

/// 帧头结构体（OPEN 与 DATA 共用）
///
/// `dest_kind` / `group` / `route_key` 只在 `frame_type == .open` 时有意义，
/// DATA 帧上它们保持默认值且不参与编码。之所以不做成 tagged union，是因为
/// 分派路径需要频繁读 `flags` 与 `body_len`（两种帧都有），union 会让每次读
/// 都要先解标签，而收益只是把"DATA 上读 dest_kind"这个不会发生的错误挪到编译期。
pub const FrameHeader = struct {
    frame_type: FrameType,
    flags: Flags = .{},
    body_len: u16 = 0,
    dest_kind: DestKind = .gateway,
    response_mode: ResponseMode = .required,
    group: u8 = 0x00,
    route_key: u8 = 0x00,

    /// 构造一个 OPEN 帧头。
    pub fn initOpen(dest_kind: DestKind, route: RouteId, response_mode: ResponseMode, flags: Flags, body_len: u16) FrameHeader {
        return .{
            .frame_type = .open,
            .flags = flags,
            .body_len = body_len,
            .dest_kind = dest_kind,
            .response_mode = response_mode,
            .group = route.group,
            .route_key = route.route_key,
        };
    }

    /// 构造一个 DATA 帧头。
    pub fn initData(flags: Flags, body_len: u16) FrameHeader {
        return .{ .frame_type = .data, .flags = flags, .body_len = body_len };
    }

    /// 构造一个与网关的控制交换首帧。
    ///
    /// 控制交换目前都是一次性的（心跳、认证、断开），所以默认带 `eof`。
    pub fn initControl(ctrl_type: ControlType, body_len: u16) FrameHeader {
        return initOpen(.gateway, RouteId.init(0, @intFromEnum(ctrl_type)), .required, Flags.last(), body_len);
    }

    /// 序列化到缓冲区（大端序），返回写入的字节数。
    pub fn encode(self: FrameHeader, buf: []u8) FrameError!usize {
        if (self.frame_type == .datagram) return error.DatagramOnStream;

        const size = self.frame_type.headerSize();
        if (buf.len < size) return error.BufferTooSmall;

        buf[0] = @intFromEnum(self.frame_type);
        buf[1] = @bitCast(self.flags);
        std.mem.writeInt(u16, buf[2..4], self.body_len, .big);

        if (self.frame_type == .open) {
            buf[4] = @intFromEnum(self.dest_kind);
            buf[5] = @intFromEnum(self.response_mode);
            buf[6] = self.group;
            buf[7] = self.route_key;
        }
        return size;
    }

    /// 从缓冲区解析（大端序）。
    ///
    /// 帧头是变长的，所以调用方无法在读到第一个字节之前知道要准备多少缓冲：
    /// 先用 `FrameType.decode(buf[0])` 拿到长度，再把这一段整体交给本函数。
    /// buf 不足时返回 `BufferTooSmall`，由调用方决定是继续等字节还是终止。
    pub fn decode(buf: []const u8) FrameError!FrameHeader {
        if (buf.len < 1) return error.BufferTooSmall;

        const frame_type = try FrameType.decode(buf[0]);
        // datagram 不经过分帧路径：它没有 body_len 字段，2 字节头的第 2 个字节
        // 是通道号。出现在流上说明对端把两条通路搞混了。
        if (frame_type == .datagram) return error.DatagramOnStream;
        if (buf.len < frame_type.headerSize()) return error.BufferTooSmall;

        const flags = try Flags.decode(buf[1]);
        // report 请求的是"这次交换的投递回报"，是交换级属性，只能出现在 OPEN 上。
        // DATA 上置位说明编码器搞错了语义，按保留位违规处理。
        if (frame_type == .data and flags.report) return error.ReservedBitsSet;

        var header = FrameHeader{
            .frame_type = frame_type,
            .flags = flags,
            .body_len = std.mem.readInt(u16, buf[2..4], .big),
        };

        if (frame_type == .open) {
            header.dest_kind = try DestKind.decode(buf[4]);
            header.response_mode = try ResponseMode.decode(buf[5]);
            header.group = buf[6];
            header.route_key = buf[7];
        }
        return header;
    }

    /// 本帧帧头占的字节数。
    pub fn headerSize(self: FrameHeader) usize {
        return self.frame_type.headerSize();
    }

    /// 本帧总长（帧头 + Body）。
    pub fn frameSize(self: FrameHeader) usize {
        return self.headerSize() + self.body_len;
    }

    /// 是否为一次交换的首帧。
    pub fn isOpen(self: FrameHeader) bool {
        return self.frame_type == .open;
    }

    /// 是否为本次交换的最后一帧。
    pub fn isLast(self: FrameHeader) bool {
        return self.flags.eof;
    }

    /// 完整路由键；仅 OPEN 且目的地按路由键寻址时有效。
    pub fn routeId(self: FrameHeader) ?RouteId {
        if (self.frame_type != .open or !self.dest_kind.hasRouteKey()) return null;
        return .{ .group = self.group, .route_key = self.route_key };
    }

    /// 控制帧类型；仅 `dest_kind == .gateway` 的 OPEN 有效。
    ///
    /// 要求 `group == 0`：控制类型只占 `route_key` 一个字节，group 是这个
    /// 目的地下的保留字节。非 0 返回 null，由分派处当作未知控制类型回业务错误。
    pub fn controlType(self: FrameHeader) ?ControlType {
        if (self.frame_type != .open or self.dest_kind != .gateway or self.group != 0) return null;
        return @enumFromInt(self.route_key);
    }

    /// `.peer` / `.multicast` 的 OPEN 上，`group + route_key` 那两字节承载的隔离域。
    ///
    /// 这两字节在这两种目的地下本来就是保留的（`hasRouteKey()` 为 false），而
    /// `RealmId` 恰好是 u16，正好放得进去——因此**节点间投递不需要新增线格式**。
    ///
    /// **只在对等网关节点的连接上才这样解释。** 客户端与后端的连接上这两字节仍然
    /// 是保留字节，网关不读它：客户端连接的 realm 由 SNI 定（§12.3），后端连接的
    /// realm 由注册表键定。允许它们自称 realm 就等于把隔离边界交给帧内容。
    pub fn realmHint(self: FrameHeader) ?u16 {
        if (self.frame_type != .open) return null;
        if (self.dest_kind.hasRouteKey()) return null;
        return (@as(u16, self.group) << 8) | self.route_key;
    }
};

// ============================================================================
// 错误类型
// ============================================================================

pub const FrameError = error{
    /// 缓冲不足一个帧头（可能只是字节还没到齐）
    BufferTooSmall,
    /// 未定义的 frame_type
    UnknownFrameType,
    /// 未定义的 dest_kind
    UnknownDestKind,
    /// 未定义的响应模式
    UnknownResponseMode,
    /// 保留位/保留字节非 0
    ReservedBitsSet,
    /// datagram 帧出现在 QUIC 流上
    DatagramOnStream,
    /// datagram 通道号超出 `datagram.max_channels`
    InvalidChannel,
    /// Body 超过 `MAX_BODY_SIZE`（编码侧；解码侧由 u16 天然封顶）
    BodyTooLarge,
    /// 声明的帧长超过配置上限
    FrameTooLarge,
    /// 缓冲长度与声明的帧长不符
    FrameLengthMismatch,
};

// ============================================================================
// QUIC 应用层错误码
// ============================================================================

/// `picoquic_close` 的 application_error_code。
///
/// 协议违规关连接时带上它，客户端才能区分"网关正常下线"和"我发的字节被判违规"。
pub const AppError = enum(u64) {
    /// 正常关闭
    no_error = 0x00,
    /// 分帧/编码违规（详见设计文档 §7.5 的连接级错误清单）
    protocol_violation = 0x01,
    /// 被后端要求下线（kick_off）。
    ///
    /// 与 `kick_off` 控制帧重复是有意的：帧在关连接的竞态里可能送不到，而错误码
    /// 一定随 CONNECTION_CLOSE 到达。客户端靠它区分"该重新认证"和"网关下线了，
    /// 直接重连即可"。
    kicked = 0x02,
    /// 被重定向到别的节点（`redirect` 控制帧的伴随错误码）。
    ///
    /// 与 `kicked` 分开是因为客户端的正确反应不同：`kicked` 意味着"该重新认证"，
    /// `redirected` 意味着"换个地址重连，凭据还有效"。合成一个会让 SDK 在被重定向
    /// 之后白走一遍完整的认证失败路径。
    redirected = 0x03,
};

// ============================================================================
// 测试
// ============================================================================

test "OPEN header encode/decode roundtrip" {
    const original = FrameHeader.initOpen(.service, RouteId.init(0x02, 0x01), .required, .{ .report = true }, 1024);

    var buf: [OPEN_HEADER_SIZE]u8 = undefined;
    try std.testing.expectEqual(OPEN_HEADER_SIZE, try original.encode(&buf));

    const decoded = try FrameHeader.decode(&buf);
    try std.testing.expectEqual(FrameType.open, decoded.frame_type);
    try std.testing.expectEqual(DestKind.service, decoded.dest_kind);
    try std.testing.expectEqual(ResponseMode.required, decoded.response_mode);
    try std.testing.expectEqual(RouteId.init(0x02, 0x01), decoded.routeId().?);
    try std.testing.expectEqual(@as(u16, 1024), decoded.body_len);
    try std.testing.expect(decoded.flags.report);
    try std.testing.expect(!decoded.flags.eof);
    try std.testing.expectEqual(OPEN_HEADER_SIZE + 1024, decoded.frameSize());
}

test "DATA header encode/decode roundtrip" {
    const original = FrameHeader.initData(Flags.last(), 7);

    var buf: [DATA_HEADER_SIZE]u8 = undefined;
    try std.testing.expectEqual(DATA_HEADER_SIZE, try original.encode(&buf));

    const decoded = try FrameHeader.decode(&buf);
    try std.testing.expectEqual(FrameType.data, decoded.frame_type);
    try std.testing.expect(decoded.isLast());
    try std.testing.expectEqual(@as(u16, 7), decoded.body_len);
    // 目的地是流级属性，DATA 上不重复声明，因此这里没有路由键可查。
    try std.testing.expectEqual(@as(?RouteId, null), decoded.routeId());
    try std.testing.expectEqual(DATA_HEADER_SIZE + 7, decoded.frameSize());
}

test "decode rejects everything outside the whitelist" {
    // 未定义的 frame_type
    try std.testing.expectError(error.UnknownFrameType, FrameHeader.decode(&[_]u8{ 0x7F, 0, 0, 0 }));

    // datagram 不该出现在流上
    try std.testing.expectError(error.DatagramOnStream, FrameHeader.decode(&[_]u8{ 0x02, 0 }));

    // flags 高位保留
    try std.testing.expectError(error.ReservedBitsSet, FrameHeader.decode(&[_]u8{ 0x01, 0x80, 0, 0 }));

    // report 只在 OPEN 上有意义
    try std.testing.expectError(error.ReservedBitsSet, FrameHeader.decode(&[_]u8{ 0x01, 0x02, 0, 0 }));

    // 未定义的 dest_kind
    try std.testing.expectError(error.UnknownDestKind, FrameHeader.decode(&[_]u8{ 0x00, 0, 0, 0, 0x09, 0, 0, 0 }));

    // 未定义的响应模式
    try std.testing.expectError(error.UnknownResponseMode, FrameHeader.decode(&[_]u8{ 0x00, 0, 0, 0, 0x01, 0x02, 0, 0 }));
}

test "OPEN response mode roundtrip" {
    const original = FrameHeader.initOpen(.service, RouteId.init(1, 2), .none, Flags.last(), 0);
    var buf: [OPEN_HEADER_SIZE]u8 = undefined;
    _ = try original.encode(&buf);
    try std.testing.expectEqual(@as(u8, 1), buf[5]);
    try std.testing.expectEqual(ResponseMode.none, (try FrameHeader.decode(&buf)).response_mode);
}

test "decode reports BufferTooSmall until the variable-length header is complete" {
    const open = FrameHeader.initOpen(.service, RouteId.init(1, 2), .required, .{}, 0);
    var buf: [OPEN_HEADER_SIZE]u8 = undefined;
    _ = try open.encode(&buf);

    // OPEN 需要 8 字节，7 个还不够；DATA 只需要 4 个，所以同样的前缀长度对
    // 两种帧的判定不同——这正是"帧头变长"必须由第一个字节先定型的原因。
    try std.testing.expectError(error.BufferTooSmall, FrameHeader.decode(buf[0 .. OPEN_HEADER_SIZE - 1]));
    try std.testing.expectError(error.BufferTooSmall, FrameHeader.decode(&.{}));

    const data = FrameHeader.initData(.{}, 0);
    var data_buf: [DATA_HEADER_SIZE]u8 = undefined;
    _ = try data.encode(&data_buf);
    try std.testing.expectError(error.BufferTooSmall, FrameHeader.decode(data_buf[0 .. DATA_HEADER_SIZE - 1]));
}

test "control exchanges are OPEN frames addressed at the gateway" {
    const header = FrameHeader.initControl(.auth_request, 100);
    try std.testing.expectEqual(FrameType.open, header.frame_type);
    try std.testing.expectEqual(DestKind.gateway, header.dest_kind);
    try std.testing.expectEqual(ControlType.auth_request, header.controlType().?);
    try std.testing.expectEqual(@as(u16, 100), header.body_len);
    // 控制交换是一次性的，首帧即末帧。
    try std.testing.expect(header.isLast());

    // 非 gateway 目的地没有控制类型。
    const service = FrameHeader.initOpen(.service, RouteId.init(0, 0x10), .required, .{}, 0);
    try std.testing.expectEqual(@as(?ControlType, null), service.controlType());

    // DATA 帧同样没有——控制类型在 route_key 里，而 DATA 不带 route_key。
    try std.testing.expectEqual(@as(?ControlType, null), FrameHeader.initData(.{}, 0).controlType());

    // group 是 .gateway 下的保留字节，非 0 视为未知控制类型。
    var stray = FrameHeader.initControl(.heartbeat, 0);
    stray.group = 0x01;
    try std.testing.expectEqual(@as(?ControlType, null), stray.controlType());
}

test "peer and multicast carry their targets in the body, not in the route key" {
    try std.testing.expect(DestKind.gateway.hasRouteKey());
    try std.testing.expect(DestKind.service.hasRouteKey());
    try std.testing.expect(!DestKind.peer.hasRouteKey());
    try std.testing.expect(!DestKind.multicast.hasRouteKey());

    const peer = FrameHeader.initOpen(.peer, RouteId.init(0xAA, 0xBB), .none, .{}, 0);
    try std.testing.expectEqual(@as(?RouteId, null), peer.routeId());
}

test "peer and multicast reuse the reserved route bytes as a realm hint" {
    // 节点间投递靠这条：那两字节在 .peer / .multicast 下本来是保留的，
    // 而 RealmId 是 u16，正好放得进去，因此不需要新增线格式。
    const peer = FrameHeader.initOpen(.peer, RouteId.init(0x07, 0x09), .none, .{}, 0);
    try std.testing.expectEqual(@as(u16, 0x0709), peer.realmHint().?);

    const multicast = FrameHeader.initOpen(.multicast, RouteId.init(0x00, 0x01), .none, .{}, 0);
    try std.testing.expectEqual(@as(u16, 1), multicast.realmHint().?);

    // 有路由键的目的地没有 realm 提示——那两字节在那里另有含义。
    try std.testing.expectEqual(@as(?u16, null), FrameHeader.initOpen(.service, RouteId.init(1, 2), .required, .{}, 0).realmHint());
    try std.testing.expectEqual(@as(?u16, null), FrameHeader.initControl(.heartbeat, 0).realmHint());
    // DATA 上不重复目的地，因此也没有 realm 提示。
    try std.testing.expectEqual(@as(?u16, null), FrameHeader.initData(.{}, 0).realmHint());
}

test "ControlType category detection" {
    // 心跳类
    try std.testing.expect(ControlType.heartbeat.isHeartbeat());
    try std.testing.expect(ControlType.heartbeat_ack.isHeartbeat());
    try std.testing.expect(ControlType.ping.isHeartbeat());
    try std.testing.expect(ControlType.pong.isHeartbeat());
    try std.testing.expect(!ControlType.heartbeat.isAuth());

    // 认证类
    try std.testing.expect(ControlType.auth_request.isAuth());
    try std.testing.expect(ControlType.auth_success.isAuth());
    try std.testing.expect(ControlType.auth_failure.isAuth());
    try std.testing.expect(!ControlType.auth_request.isHeartbeat());

    // 连接控制类
    try std.testing.expect(ControlType.kick_off.isConnectionControl());
    try std.testing.expect(ControlType.disconnect.isConnectionControl());
    try std.testing.expect(ControlType.force_close.isConnectionControl());
    try std.testing.expect(!ControlType.kick_off.isAuth());

    // 会话类
    try std.testing.expect(ControlType.session_resume.isSession());
    try std.testing.expect(ControlType.session_resume_ack.isSession());
    try std.testing.expect(ControlType.session_resume_fail.isSession());

    // 系统类
    try std.testing.expect(ControlType.gateway_error.isSystem());
    try std.testing.expect(ControlType.maintenance.isSystem());
}
