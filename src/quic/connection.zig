//! QUIC 连接封装
//!
//! 封装单个 QUIC 连接的操作。

const std = @import("std");
const quic_c = @import("c.zig");

pub const Connection = struct {
    /// inner 存储 picoquic 的 C 连接指针（picoquic_cnx_t*）。这是对 C 结构体的包装
    inner: quic_c.QuicCnx,

    /// 可选的用户数据指针，用于关联自定义数据到连接上。?*anyopaque 是 Zig 的可空任意指针类型。
    user_ctx: ?*anyopaque = null,

    /// 工厂方法：把 C 指针包装成 Zig 的 Connection 结构
    pub fn fromRaw(cnx: quic_c.QuicCnx) Connection {
        return .{ .inner = cnx };
    }

    /// 获取连接状态
    ///
    /// 调用 C 函数获取链接状态，然后用 @enumFromInt 把整数转换为我们定义的枚举类型
    pub fn getState(self: *const Connection) quic_c.ConnectionState {
        const state = quic_c.c.picoquic_get_cnx_state(self.inner);
        return @enumFromInt(state);
    }

    /// 连接是否已建立
    pub fn isConnected(self: *const Connection) bool {
        return self.getState().isConnected();
    }

    /// 连接是否已断开
    pub fn isDisconnected(self: *const Connection) bool {
        return self.getState().isDisconnected();
    }

    /// 获取本地连接 ID
    pub fn getLocalConnectionId(self: *const Connection) quic_c.ConnectionId {
        return quic_c.c.picoquic_get_local_cnxid(self.inner);
    }

    /// 获取远端连接 ID
    pub fn getRemoteConnectionId(self: *const Connection) quic_c.ConnectionId {
        return quic_c.c.picoquic_get_remote_cnxid(self.inner);
    }

    /// 向 stream 写入数据
    pub fn streamWrite(
        self: *Connection,
        stream_id: u64,
        data: []const u8,
        is_fin: bool,
    ) Error!void {
        const rc = quic_c.c.picoquic_add_to_stream(
            self.inner,
            stream_id,
            data.ptr,
            data.len,
            if (is_fin) 1 else 0, // bool 转 C int
        );
        if (rc != 0) {
            return Error.StreamWriteFailed;
        }
    }

    /// 发送一个 QUIC DATAGRAM（RFC 9221，设计文档 §6）。
    ///
    /// **不排队重传、不分片。** 一个 datagram 必须整体装进一个 QUIC 包，超过对端
    /// 通告的 `max_datagram_frame_size` 时 picoquic 直接返回错误——这是正确行为，
    /// 上层应当把它当成"这一包发不出去"并丢弃，而不是尝试切开：切开就需要分片 id、
    /// 乱序重组、超时回收，等于在不可靠通路上重新实现一遍流。
    ///
    /// 对端没有通告 `max_datagram_frame_size`（不支持或没开）时同样返回错误。
    pub fn sendDatagram(self: *Connection, data: []const u8) Error!void {
        const rc = quic_c.c.picoquic_queue_datagram_frame(self.inner, data.len, data.ptr);
        if (rc != 0) return Error.DatagramSendFailed;
    }

    /// 标记 stream 为活跃状态
    ///
    /// picoquic 会在下次发送时处理该 stream
    pub fn markStreamActive(
        self: *Connection,
        stream_id: u64,
        is_active: bool,
        context: ?*anyopaque,
    ) Error!void {
        const rc = quic_c.c.picoquic_mark_active_stream(
            self.inner,
            stream_id,
            if (is_active) 1 else 0,
            context,
        );
        if (rc != 0) {
            return Error.MarkStreamFailed;
        }
    }

    /// 关闭 stream
    ///
    /// 发送 RESET_STREAM 帧关闭 stream
    pub fn closeStream(self: *Connection, stream_id: u64) void {
        _ = quic_c.c.picoquic_reset_stream(self.inner, stream_id, 0);
    }

    /// 废弃一条双向 stream，但保留承载它的 QUIC 连接。
    ///
    /// RESET_STREAM 只终止本端的发送方向；STOP_SENDING 才会要求对端停止响应。
    /// picoquic_discard_stream 同时完成两者并清除该 stream 的应用上下文，适合
    /// request deadline、主动取消等不应扩大到整条复用连接的场景。
    pub fn discardStream(self: *Connection, stream_id: u64) void {
        _ = quic_c.c.picoquic_discard_stream(self.inner, stream_id, 0);
    }

    /// 关闭连接（正常关闭，application error code = 0）
    pub fn close(self: *Connection) void {
        self.closeWithError(0);
    }

    /// 带应用层错误码关闭连接。
    ///
    /// 协议违规必须带上错误码，否则客户端只看到一次普通关闭，无法区分
    /// "网关正常下线"和"我发出的字节被判违规"——后者需要修客户端，
    /// 前者只需要重连。错误码取值见 protocol.frame.AppError。
    pub fn closeWithError(self: *Connection, app_error_code: u64) void {
        _ = quic_c.c.picoquic_close(self.inner, @intCast(app_error_code));
    }

    /// 设置连接的回调函数，用于接收事件通知
    pub fn setCallback(
        self: *Connection,
        callback: quic_c.c.picoquic_stream_data_cb_fn,
        context: ?*anyopaque,
    ) void {
        quic_c.c.picoquic_set_callback(self.inner, callback, context);
    }

    /// 客户端在 TLS ClientHello 里请求的 SNI（server_name）；没发则为 null。
    ///
    /// 网关用它确定这条连接属于哪个隔离域（见 foundation.realm）。它由证书链背书，
    /// 因此可以当作可信输入——这是它比"客户端在帧里自称身份"强的地方。
    ///
    /// 可用时机：握手完成之后（`.ready` 回调里已经可读）。更早的阶段 picoquic 不向
    /// 应用层暴露，所以隔离域只能在连接就绪时确定，不能更早。
    ///
    /// 返回的切片由 picotls 持有，生命周期跟随连接；需要跨连接保存必须自己拷贝。
    pub fn getServerName(self: *const Connection) ?[]const u8 {
        const raw = quic_c.c.picoquic_tls_get_sni(self.inner) orelse return null;
        return std.mem.span(raw);
    }

    /// 获取连接所属的 QUIC 上下文（Server/Client 实例）
    pub fn getQuicContext(self: *const Connection) quic_c.QuicCtx {
        return quic_c.c.picoquic_get_quic_ctx(self.inner);
    }

    pub const Error = error{
        StreamWriteFailed,
        MarkStreamFailed,
        DatagramSendFailed,
        ConnectionClosed,
    };
};
