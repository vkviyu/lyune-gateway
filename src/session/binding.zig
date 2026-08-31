//! 客户端传输 binding 与 Worker 之间的双向端口。
//!
//! `Handler` 把已建立会话上的逻辑事件送进 Worker；`Acceptor` 则让 Worker 在自己的
//! 事件循环里启停、维护一个外部监听器。两者都是非拥有引用，具体 TCP/TLS/QUIC
//! 对象及其销毁顺序仍由 app 装配层管理。

const SessionHandle = @import("handle.zig").SessionHandle;
const TransportSession = @import("transport.zig").TransportSession;

/// 对端终止一条 logical stream 某个方向的传输事件。
pub const StreamControl = enum {
    reset,
    stop,
};

/// 具体客户端 binding 向 Worker 报告会话事件的窄回调面。
///
/// 所有回调都必须发生在所属 Worker 的事件循环线程。binding 不持有 Worker，只有
/// 这个非拥有引用；Worker 也不需要知道事件来自 Raw QUIC、WSS 或未来其他传输。
pub const Handler = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        accept: *const fn (*anyopaque, TransportSession, ?[]const u8) anyerror!SessionHandle,
        stream_data: *const fn (*anyopaque, SessionHandle, u64, []const u8, bool) void,
        control: *const fn (*anyopaque, SessionHandle, u64, StreamControl) void,
        ephemeral: *const fn (*anyopaque, SessionHandle, []const u8) void,
        closed: *const fn (*anyopaque, SessionHandle) void,
        now_us: *const fn (*anyopaque) u64,
    };

    pub fn accept(self: Handler, session: TransportSession, server_name: ?[]const u8) !SessionHandle {
        return self.vtable.accept(self.ptr, session, server_name);
    }

    pub fn streamData(self: Handler, handle: SessionHandle, stream_id: u64, bytes: []const u8, fin: bool) void {
        self.vtable.stream_data(self.ptr, handle, stream_id, bytes, fin);
    }

    pub fn control(self: Handler, handle: SessionHandle, stream_id: u64, event: StreamControl) void {
        self.vtable.control(self.ptr, handle, stream_id, event);
    }

    pub fn ephemeral(self: Handler, handle: SessionHandle, bytes: []const u8) void {
        self.vtable.ephemeral(self.ptr, handle, bytes);
    }

    pub fn closed(self: Handler, handle: SessionHandle) void {
        self.vtable.closed(self.ptr, handle);
    }

    pub fn nowUs(self: Handler) u64 {
        return self.vtable.now_us(self.ptr);
    }
};

/// 由 app 创建、交给 Worker 驱动的外部客户端监听器。
///
/// `Acceptor` 不负责销毁实现对象；事件循环停止后，app 必须按具体 binding 的规则完成
/// deinit。把生命周期控制缩成这三个操作后，Worker 不再 import 任何具体监听器模块。
pub const Acceptor = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        start: *const fn (*anyopaque) anyerror!void,
        stop_accepting: *const fn (*anyopaque) void,
        poll: *const fn (*anyopaque, u64) void,
    };

    pub fn start(self: Acceptor) !void {
        try self.vtable.start(self.ptr);
    }

    pub fn stopAccepting(self: Acceptor) void {
        self.vtable.stop_accepting(self.ptr);
    }

    pub fn poll(self: Acceptor, now_us: u64) void {
        self.vtable.poll(self.ptr, now_us);
    }
};
