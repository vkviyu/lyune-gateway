//! 客户端接入传输的最小会话接口。
//!
//! 本文件只定义传输无关契约。Raw QUIC 的适配器在 `quic/session.zig`，WSS 的适配器
//! 在 `wss/listener.zig`；因此新增 binding 只需实现同一张 vtable，不需要给这里增加
//! 一个新的 union 分支，也不会让 WSS 间接依赖 picoquic。

const std = @import("std");

/// Worker 可观察到的接入传输类型。业务分支不得依据它改变协议行为；它只用于日志、
/// 指标和诊断。增加 binding 时可以扩展枚举，但不需要改变 TransportSession 的布局。
pub const Kind = enum {
    raw_quic,
    wss,
};

pub const TransportError = error{
    StreamWriteFailed,
    EphemeralSendFailed,
};

/// 一条客户端传输会话的非拥有、类型擦除引用。
///
/// `ptr` 的实现对象与生命周期归具体 binding 所有；Worker 只保存这份能力表。服务端
/// 主动 exchange id 的分配属于所有 binding 共享的协议不变量，因此集中在本结构内，
/// 固定生成 1、5、9……，避免每种传输各自复制一套计数器。
pub const TransportSession = struct {
    transport_kind: Kind,
    ptr: *anyopaque,
    vtable: *const VTable,
    /// 仅供传输 driver 的原生回调定位会话。null 表示该 binding 直接携带
    /// SessionHandle，不需要二次索引；业务代码不得把它当作会话身份。
    callback_key: ?usize = null,
    next_outbound_exchange_id: u64 = 1,

    pub const Error = TransportError;

    pub const VTable = struct {
        /// 声明一条新的 client-initiated exchange。原生多流传输可以直接返回 true；
        /// 复用在单连接上的 binding 必须显式拒绝 logical stream id 复用。
        claim_inbound_exchange: *const fn (*anyopaque, u64) bool,
        write: *const fn (*anyopaque, u64, []const u8, bool) Error!void,
        send_ephemeral: *const fn (*anyopaque, []const u8) Error!void,
        reset_send: *const fn (*anyopaque, u64, u64) void,
        stop_receive: *const fn (*anyopaque, u64, u64) void,
        /// 必须同时收敛 exchange 的收发方向；具体传输不能只完成其中一半。
        discard: *const fn (*anyopaque, u64, u64) void,
        close: *const fn (*anyopaque, u64) void,
    };

    pub fn init(
        transport_kind: Kind,
        ptr: *anyopaque,
        vtable: *const VTable,
        callback_key: ?usize,
    ) TransportSession {
        return .{
            .transport_kind = transport_kind,
            .ptr = ptr,
            .vtable = vtable,
            .callback_key = callback_key,
        };
    }

    pub fn kind(self: *const TransportSession) Kind {
        return self.transport_kind;
    }

    pub fn callbackKey(self: *const TransportSession) ?usize {
        return self.callback_key;
    }

    /// 在业务层接纳 OPEN 前声明这个 exchange id 的首次使用。
    pub fn claimInboundExchange(self: *TransportSession, stream_id: u64) bool {
        return self.vtable.claim_inbound_exchange(self.ptr, stream_id);
    }

    /// 在已有 exchange 上追加数据；`is_fin` 结束本端发送方向。
    pub fn write(self: *TransportSession, stream_id: u64, data: []const u8, is_fin: bool) Error!void {
        try self.vtable.write(self.ptr, stream_id, data, is_fin);
    }

    /// 由网关主动创建一次 exchange，并写入第一段数据。
    ///
    /// 即使首次写入失败，标识也不会复用。这样失败重试不会把两个业务推送误认为同一
    /// 次 exchange，也与原 Raw QUIC 的 `nextPushStream()` 行为一致。
    pub fn open(self: *TransportSession, data: []const u8, is_fin: bool) Error!u64 {
        const stream_id = self.reserveOutboundExchange();
        try self.write(stream_id, data, is_fin);
        return stream_id;
    }

    fn reserveOutboundExchange(self: *TransportSession) u64 {
        const stream_id = self.next_outbound_exchange_id;
        self.next_outbound_exchange_id += 4;
        return stream_id;
    }

    /// 发送不保证可靠、有序或必达的临时消息。
    pub fn sendEphemeral(self: *TransportSession, data: []const u8) Error!void {
        try self.vtable.send_ephemeral(self.ptr, data);
    }

    pub fn resetSend(self: *TransportSession, stream_id: u64, app_error_code: u64) void {
        self.vtable.reset_send(self.ptr, stream_id, app_error_code);
    }

    pub fn stopReceive(self: *TransportSession, stream_id: u64, app_error_code: u64) void {
        self.vtable.stop_receive(self.ptr, stream_id, app_error_code);
    }

    pub fn discard(self: *TransportSession, stream_id: u64, app_error_code: u64) void {
        self.vtable.discard(self.ptr, stream_id, app_error_code);
    }

    pub fn close(self: *TransportSession, app_error_code: u64) void {
        self.vtable.close(self.ptr, app_error_code);
    }
};

const FakeTransport = struct {
    last_stream_id: u64 = 0,
    writes: usize = 0,
    ephemeral: usize = 0,
    resets: usize = 0,
    stops: usize = 0,
    discards: usize = 0,
    closes: usize = 0,

    const vtable: TransportSession.VTable = .{
        .claim_inbound_exchange = claimInboundExchange,
        .write = write,
        .send_ephemeral = sendEphemeral,
        .reset_send = resetSend,
        .stop_receive = stopReceive,
        .discard = discard,
        .close = close,
    };

    fn cast(ptr: *anyopaque) *FakeTransport {
        return @ptrCast(@alignCast(ptr));
    }

    fn claimInboundExchange(_: *anyopaque, _: u64) bool {
        return true;
    }

    fn write(ptr: *anyopaque, stream_id: u64, _: []const u8, _: bool) TransportError!void {
        const self = cast(ptr);
        self.last_stream_id = stream_id;
        self.writes += 1;
    }

    fn sendEphemeral(ptr: *anyopaque, _: []const u8) TransportError!void {
        cast(ptr).ephemeral += 1;
    }

    fn resetSend(ptr: *anyopaque, _: u64, _: u64) void {
        cast(ptr).resets += 1;
    }

    fn stopReceive(ptr: *anyopaque, _: u64, _: u64) void {
        cast(ptr).stops += 1;
    }

    fn discard(ptr: *anyopaque, _: u64, _: u64) void {
        cast(ptr).discards += 1;
    }

    fn close(ptr: *anyopaque, _: u64) void {
        cast(ptr).closes += 1;
    }
};

test "transport session delegates operations and owns outbound exchange numbering" {
    var fake = FakeTransport{};
    var session = TransportSession.init(.wss, &fake, &FakeTransport.vtable, null);
    try std.testing.expectEqual(Kind.wss, session.kind());
    try std.testing.expect(session.callbackKey() == null);
    try std.testing.expect(session.claimInboundExchange(0));

    try session.write(4, "response", true);
    try std.testing.expectEqual(@as(u64, 4), fake.last_stream_id);
    try std.testing.expectEqual(@as(u64, 1), try session.open("push-1", false));
    try std.testing.expectEqual(@as(u64, 5), try session.open("push-2", true));
    try session.sendEphemeral("typing");
    session.resetSend(4, 1);
    session.stopReceive(4, 2);
    session.discard(4, 3);
    session.close(4);

    try std.testing.expectEqual(@as(usize, 3), fake.writes);
    try std.testing.expectEqual(@as(u64, 5), fake.last_stream_id);
    try std.testing.expectEqual(@as(usize, 1), fake.ephemeral);
    try std.testing.expectEqual(@as(usize, 1), fake.resets);
    try std.testing.expectEqual(@as(usize, 1), fake.stops);
    try std.testing.expectEqual(@as(usize, 1), fake.discards);
    try std.testing.expectEqual(@as(usize, 1), fake.closes);
}
