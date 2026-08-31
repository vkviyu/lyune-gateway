//! 基于 libxev + BoringSSL 的 WSS 接入监听器。
//!
//! 这里拥有 TCP、TLS、HTTP Upgrade、WebSocket framing 与每会话发送队列；它只通过
//! `session.Handler` 把逻辑 stream 事件交给 Worker。反方向则由 `TransportSession` 的 WSS
//! vtable 回到本文件。因此认证、路由、Exchange、推送和生命周期都不在这里复制。

const std = @import("std");
const xev = @import("xev");

const foundation = @import("../foundation/mod.zig");
const protocol = @import("../protocol/mod.zig");
const client_session = @import("../session/mod.zig");
const SessionHandle = client_session.SessionHandle;
const transport = client_session.transport;
const TransportSession = client_session.TransportSession;
const Handler = client_session.Handler;
const envelope = @import("envelope.zig");
const output_queue = @import("output_queue.zig");
const tls = @import("tls.zig");
const websocket = @import("websocket.zig");

const encrypted_buffer_size: usize = 16 * 1024;
const max_client_frame_size = envelope.max_record_size + 14;
const plain_buffer_size = @max(websocket.max_http_head_size, max_client_frame_size);
const close_normal: u16 = 1000;
const close_protocol_error: u16 = 1002;
const close_internal_error: u16 = 1011;

pub const Config = struct {
    bind_address: [4]u8,
    bind_port: u16,
    cert_file: [:0]const u8,
    key_file: [:0]const u8,
    allowed_origins: []const []const u8,
    allow_missing_origin: bool,
    max_connections: usize,
    max_queued_bytes: usize,
    max_queued_records: usize,
    tls_bio_capacity: usize,
    handshake_timeout_ms: u64,
};

pub const Listener = struct {
    allocator: std.mem.Allocator,
    loop: *xev.Loop,
    config: Config,
    handler: Handler,
    tls_context: tls.Context,
    tcp: xev.TCP,
    supplied_socket: bool,
    listener_fd_open: bool = true,
    accepting: bool = false,
    accept_completion: xev.Completion = undefined,
    connections: ?*Connection = null,
    connection_count: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        loop: *xev.Loop,
        config: Config,
        handler: Handler,
        socket_fd: ?std.posix.socket_t,
    ) !Listener {
        var tls_context = try tls.Context.init(config.cert_file, config.key_file);
        errdefer tls_context.deinit();

        const address = foundation.net.initIp4(config.bind_address, config.bind_port);
        const tcp = if (socket_fd) |fd| xev.TCP.initFd(fd) else try xev.TCP.init(address);
        errdefer _ = std.c.close(tcp.fd);

        return .{
            .allocator = allocator,
            .loop = loop,
            .config = config,
            .handler = handler,
            .tls_context = tls_context,
            .tcp = tcp,
            .supplied_socket = socket_fd != null,
        };
    }

    /// 暴露给 Worker 的非拥有生命周期端口；具体 Listener 仍由 app 装配层持有。
    pub fn asAcceptor(self: *Listener) client_session.Acceptor {
        return .{ .ptr = self, .vtable = &acceptor_vtable };
    }

    const acceptor_vtable: client_session.Acceptor.VTable = .{
        .start = startFromAcceptor,
        .stop_accepting = stopFromAcceptor,
        .poll = pollFromAcceptor,
    };

    fn fromAcceptor(ptr: *anyopaque) *Listener {
        return @ptrCast(@alignCast(ptr));
    }

    fn startFromAcceptor(ptr: *anyopaque) anyerror!void {
        try fromAcceptor(ptr).start();
    }

    fn stopFromAcceptor(ptr: *anyopaque) void {
        fromAcceptor(ptr).stopAccepting();
    }

    fn pollFromAcceptor(ptr: *anyopaque, now_us: u64) void {
        fromAcceptor(ptr).poll(now_us);
    }

    /// 绑定并开始循环 accept。调用后 Listener 地址必须保持稳定。
    pub fn start(self: *Listener) !void {
        if (self.accepting) return;
        const address = foundation.net.initIp4(self.config.bind_address, self.config.bind_port);
        if (!self.supplied_socket) try self.tcp.bind(address);
        try self.tcp.listen(256);
        self.accepting = true;
        self.tcp.accept(self.loop, &self.accept_completion, Listener, self, acceptCallback);
        std.log.info("[WSS] listener started on {}.{}.{}.{}:{}", .{
            self.config.bind_address[0],
            self.config.bind_address[1],
            self.config.bind_address[2],
            self.config.bind_address[3],
            self.config.bind_port,
        });
    }

    /// 停止接新 TCP，不影响已经完成 Upgrade 的存量会话。
    pub fn stopAccepting(self: *Listener) void {
        self.accepting = false;
        if (self.listener_fd_open) {
            _ = std.c.close(self.tcp.fd);
            self.listener_fd_open = false;
        }
    }

    /// 由 Worker 的既有周期泵调用，避免为 WSS 再引入一套定时器。
    pub fn poll(self: *Listener, now_us: u64) void {
        var current = self.connections;
        while (current) |connection| {
            current = connection.next;
            if (!connection.upgradeComplete() and now_us >= connection.handshake_deadline_us) {
                std.log.warn("[WSS] TLS/Upgrade handshake timed out", .{});
                connection.beginImmediateClose();
            }
            if (connection.readyToDestroy()) connection.finishClose();
        }
    }

    /// 只可在所属事件循环已经停止之后调用。未决 completion 此后不会再回调，因此
    /// 可以同步关闭并回收；每条已注册会话仍先通知 Worker，使 SessionHandle 正常失效。
    pub fn deinitAfterLoopStopped(self: *Listener) void {
        self.stopAccepting();
        while (self.connections) |connection| connection.destroyAfterLoopStopped();
        self.tls_context.deinit();
        self.* = undefined;
    }

    fn acceptCallback(
        userdata: ?*Listener,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.AcceptError!xev.TCP,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        const self = userdata orelse return .disarm;
        const client = result catch |err| {
            if (self.accepting) std.log.warn("[WSS] accept failed: {s}", .{@errorName(err)});
            return if (self.accepting) .rearm else .disarm;
        };

        if (!self.accepting or self.connection_count >= self.config.max_connections) {
            _ = std.c.close(client.fd);
            return if (self.accepting) .rearm else .disarm;
        }

        const connection = Connection.create(self, client) catch |err| {
            std.log.warn("[WSS] cannot initialize accepted connection: {s}", .{@errorName(err)});
            _ = std.c.close(client.fd);
            return .rearm;
        };
        connection.startRead();
        return .rearm;
    }

    fn insert(self: *Listener, connection: *Connection) void {
        connection.next = self.connections;
        if (self.connections) |head| head.prev = connection;
        self.connections = connection;
        self.connection_count += 1;
    }

    fn remove(self: *Listener, connection: *Connection) void {
        if (connection.prev) |prev| {
            prev.next = connection.next;
        } else {
            self.connections = connection.next;
        }
        if (connection.next) |next| next.prev = connection.prev;
        self.connection_count -= 1;
        connection.prev = null;
        connection.next = null;
    }
};

const Connection = struct {
    listener: *Listener,
    tcp: xev.TCP,
    tls_connection: tls.Connection,
    output: output_queue.Queue,
    encrypted_in: []u8,
    encrypted_in_len: usize = 0,
    encrypted_in_offset: usize = 0,
    encrypted_out: []u8,
    encrypted_out_len: usize = 0,
    encrypted_out_offset: usize = 0,
    plain: []u8,
    plain_len: usize = 0,
    message_scratch: []u8,
    assembler: websocket.MessageAssembler,
    state: State = .tls_handshake,
    session: ?SessionHandle = null,
    /// WSS 没有 QUIC 的 stream 状态机。客户端新 exchange 的首次 OPEN 必须严格按
    /// 逻辑 stream id 单调递增，才能用一个定长字段永久拒绝复用而不积累无界集合。
    highest_client_exchange_id: ?u64 = null,
    /// Gateway 主动 logical stream 由 TransportSession 按 1/5/9… 顺序分配。记录已
    /// 真正写出的最高值，用于拒绝客户端伪造尚未由 Gateway 创建的反向半边。
    highest_server_exchange_id: ?u64 = null,
    handshake_deadline_us: u64,
    close_after_flush: bool = false,
    /// Worker 在处理入站 record 时可能同步写响应。此时只入队，由外层 driver 继续泵；
    /// 若递归进入 `drive`，尚未 consume 的同一 WebSocket frame 会被重复分派。
    driving: bool = false,
    read_active: bool = false,
    write_active: bool = false,
    socket_closed: bool = false,
    read_completion: xev.Completion = undefined,
    write_completion: xev.Completion = undefined,
    prev: ?*Connection = null,
    next: ?*Connection = null,

    const State = enum { tls_handshake, http_upgrade, open, closing };

    const transport_vtable: TransportSession.VTable = .{
        .claim_inbound_exchange = transportClaimInboundExchange,
        .write = transportWrite,
        .send_ephemeral = transportEphemeral,
        .reset_send = transportReset,
        .stop_receive = transportStop,
        .discard = transportDiscard,
        .close = transportClose,
    };

    fn create(listener: *Listener, tcp: xev.TCP) !*Connection {
        const allocator = listener.allocator;
        const self = try allocator.create(Connection);
        errdefer allocator.destroy(self);

        var tls_connection = try tls.Connection.init(&listener.tls_context, listener.config.tls_bio_capacity);
        errdefer tls_connection.deinit();
        var output = try output_queue.Queue.init(
            allocator,
            listener.config.max_queued_bytes,
            listener.config.max_queued_records,
        );
        errdefer output.deinit();

        const encrypted_in = try allocator.alloc(u8, encrypted_buffer_size);
        errdefer allocator.free(encrypted_in);
        const encrypted_out = try allocator.alloc(u8, encrypted_buffer_size);
        errdefer allocator.free(encrypted_out);
        const plain = try allocator.alloc(u8, plain_buffer_size);
        errdefer allocator.free(plain);
        const message_scratch = try allocator.alloc(u8, envelope.max_record_size);
        errdefer allocator.free(message_scratch);

        self.* = .{
            .listener = listener,
            .tcp = tcp,
            .tls_connection = tls_connection,
            .output = output,
            .encrypted_in = encrypted_in,
            .encrypted_out = encrypted_out,
            .plain = plain,
            .message_scratch = message_scratch,
            .assembler = websocket.MessageAssembler.init(message_scratch),
            .handshake_deadline_us = listener.handler.nowUs() +|
                listener.config.handshake_timeout_ms *| std.time.us_per_ms,
        };
        listener.insert(self);
        return self;
    }

    fn upgradeComplete(self: *const Connection) bool {
        return self.state == .open or self.state == .closing;
    }

    fn startRead(self: *Connection) void {
        if (self.read_active or self.state == .closing) return;
        self.read_active = true;
        self.tcp.read(
            self.listener.loop,
            &self.read_completion,
            .{ .slice = self.encrypted_in },
            Connection,
            self,
            readCallback,
        );
    }

    fn readCallback(
        userdata: ?*Connection,
        loop: *xev.Loop,
        completion: *xev.Completion,
        tcp: xev.TCP,
        buffer: xev.ReadBuffer,
        result: xev.ReadError!usize,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        _ = tcp;
        _ = buffer;
        const self = userdata orelse return .disarm;
        self.read_active = false;
        const count = result catch {
            self.beginImmediateClose();
            return .disarm;
        };
        if (count == 0 or self.state == .closing) {
            self.beginImmediateClose();
            return .disarm;
        }

        self.encrypted_in_len = count;
        self.encrypted_in_offset = 0;
        self.drive() catch |err| {
            std.log.warn("[WSS] connection failed: {s}", .{@errorName(err)});
            self.beginImmediateClose();
        };
        if (self.state != .closing) self.startRead();
        return .disarm;
    }

    /// 推进 BIO、TLS、HTTP/WS 明文和发送队列，直到当前输入耗尽或 BoringSSL 需要 I/O。
    fn drive(self: *Connection) !void {
        if (self.driving) return;
        self.driving = true;
        defer self.driving = false;

        var rounds: usize = 0;
        while (rounds < 128 and self.state != .closing) : (rounds += 1) {
            var progressed = false;

            if (self.encrypted_in_offset < self.encrypted_in_len) {
                const pending = self.encrypted_in[self.encrypted_in_offset..self.encrypted_in_len];
                const consumed = self.tls_connection.provideEncrypted(pending);
                if (consumed != 0) {
                    self.encrypted_in_offset += consumed;
                    progressed = true;
                }
            }

            if (self.state == .tls_handshake) {
                if (try self.tls_connection.handshake()) {
                    self.state = .http_upgrade;
                    progressed = true;
                }
            }

            if ((self.state == .http_upgrade or self.state == .open) and !self.close_after_flush) {
                if (self.plain_len == self.plain.len) return error.PlainInputTooLarge;
                switch (try self.tls_connection.readPlain(self.plain[self.plain_len..])) {
                    .bytes => |count| {
                        self.plain_len += count;
                        try self.processPlain();
                        progressed = true;
                    },
                    .would_block => {},
                    .closed => {
                        self.beginImmediateClose();
                        return;
                    },
                }
            }

            if (self.output.peek()) |part| {
                switch (try self.tls_connection.writePlain(part)) {
                    .bytes => |count| {
                        self.output.consume(count);
                        progressed = true;
                    },
                    .would_block => {},
                    .closed => {
                        self.beginImmediateClose();
                        return;
                    },
                }
            }

            if (!self.write_active) {
                const count = try self.tls_connection.takeEncrypted(self.encrypted_out);
                if (count != 0) {
                    self.encrypted_out_len = count;
                    self.encrypted_out_offset = 0;
                    self.startWrite();
                    progressed = true;
                }
            }

            if (self.close_after_flush and self.output.queuedBytes() == 0 and !self.write_active) {
                // 再探一次 BIO：队列为空不代表最后一条 TLS record 已经取完。
                const count = try self.tls_connection.takeEncrypted(self.encrypted_out);
                if (count != 0) {
                    self.encrypted_out_len = count;
                    self.encrypted_out_offset = 0;
                    self.startWrite();
                } else {
                    self.beginImmediateClose();
                }
                return;
            }

            if (!progressed) break;
        }
        if (rounds == 128) return error.TlsProgressLoopExceeded;
        if (self.encrypted_in_offset != self.encrypted_in_len) return error.TlsBioCapacityExhausted;
        self.encrypted_in_len = 0;
        self.encrypted_in_offset = 0;
    }

    fn processPlain(self: *Connection) !void {
        if (self.close_after_flush) return;
        while (self.plain_len != 0 and self.state != .closing) {
            switch (self.state) {
                .http_upgrade => {
                    const request = websocket.parseUpgrade(self.plain[0..self.plain_len]) catch |err| {
                        if (err == error.NeedMore) return;
                        return err;
                    };
                    const policy = websocket.OriginPolicy{
                        .allowed = self.listener.config.allowed_origins,
                        .allow_missing = self.listener.config.allow_missing_origin,
                    };
                    if (!policy.allows(request.origin)) return error.OriginRejected;
                    const server_name = self.tls_connection.serverName();
                    if (!hostMatchesServerName(request.host, server_name)) return error.HostSniMismatch;

                    var response: [256]u8 = undefined;
                    const bytes = try websocket.buildUpgradeResponse(&response, request.key);
                    try self.output.enqueueRaw(bytes);

                    const handle = self.listener.handler.accept(
                        TransportSession.init(.wss, self, &transport_vtable, null),
                        server_name,
                    ) catch return error.SessionRejected;
                    self.session = handle;
                    self.state = .open;
                    self.consumePlain(request.consumed);
                },
                .open => {
                    const parsed = websocket.parseClientFrame(
                        self.plain[0..self.plain_len],
                        envelope.max_record_size,
                    ) catch |err| {
                        if (err == error.NeedMore) return;
                        self.protocolClose(close_protocol_error);
                        return;
                    };
                    const message = self.assembler.accept(parsed.frame) catch {
                        self.protocolClose(close_protocol_error);
                        return;
                    };
                    try self.handleMessage(message);
                    self.consumePlain(parsed.consumed);
                    if (self.close_after_flush) return;
                },
                .tls_handshake => unreachable,
                .closing => return,
            }
        }
    }

    fn handleMessage(self: *Connection, message: websocket.Message) !void {
        const handle = self.session orelse return error.SessionMissing;
        switch (message) {
            .incomplete, .pong => {},
            .ping => |payload| {
                self.output.enqueueControl(.pong, payload) catch {
                    self.beginImmediateClose();
                    return;
                };
            },
            .close => |payload| {
                if (!validClosePayload(payload)) {
                    self.protocolClose(close_protocol_error);
                    return;
                }
                self.output.enqueueControl(.close, payload) catch {
                    self.beginImmediateClose();
                    return;
                };
                self.close_after_flush = true;
            },
            .binary => |bytes| {
                const record = envelope.decode(bytes) catch {
                    self.protocolClose(close_protocol_error);
                    return;
                };
                if (record.record_type != .ephemeral and record.stream_id & 0x02 != 0) {
                    self.protocolClose(close_protocol_error);
                    return;
                }
                if (record.record_type != .ephemeral and record.stream_id & 0x03 == 1) {
                    const highest = self.highest_server_exchange_id orelse {
                        self.protocolClose(close_protocol_error);
                        return;
                    };
                    if (record.stream_id > highest or
                        (record.record_type == .stream and (!record.fin or record.payload.len != 0)))
                    {
                        self.protocolClose(close_protocol_error);
                        return;
                    }
                }
                switch (record.record_type) {
                    .stream => self.listener.handler.streamData(handle, record.stream_id, record.payload, record.fin),
                    .reset => self.listener.handler.control(handle, record.stream_id, .reset),
                    .stop => self.listener.handler.control(handle, record.stream_id, .stop),
                    .ephemeral => self.listener.handler.ephemeral(handle, record.payload),
                }
            },
        }
    }

    fn consumePlain(self: *Connection, count: usize) void {
        std.debug.assert(count <= self.plain_len);
        const remaining = self.plain_len - count;
        std.mem.copyForwards(u8, self.plain[0..remaining], self.plain[count..self.plain_len]);
        self.plain_len = remaining;
    }

    fn startWrite(self: *Connection) void {
        std.debug.assert(!self.write_active);
        std.debug.assert(self.encrypted_out_offset < self.encrypted_out_len);
        self.write_active = true;
        self.tcp.write(
            self.listener.loop,
            &self.write_completion,
            .{ .slice = self.encrypted_out[self.encrypted_out_offset..self.encrypted_out_len] },
            Connection,
            self,
            writeCallback,
        );
    }

    fn writeCallback(
        userdata: ?*Connection,
        loop: *xev.Loop,
        completion: *xev.Completion,
        tcp: xev.TCP,
        buffer: xev.WriteBuffer,
        result: xev.WriteError!usize,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        _ = tcp;
        _ = buffer;
        const self = userdata orelse return .disarm;
        self.write_active = false;
        const count = result catch {
            self.beginImmediateClose();
            return .disarm;
        };
        if (count == 0) {
            self.beginImmediateClose();
            return .disarm;
        }
        self.encrypted_out_offset += count;
        if (self.encrypted_out_offset < self.encrypted_out_len and self.state != .closing) {
            self.startWrite();
            return .disarm;
        }
        self.encrypted_out_len = 0;
        self.encrypted_out_offset = 0;
        if (self.state != .closing) {
            self.drive() catch {
                self.beginImmediateClose();
            };
        }
        return .disarm;
    }

    fn protocolClose(self: *Connection, code: u16) void {
        var payload: [2]u8 = undefined;
        std.mem.writeInt(u16, &payload, code, .big);
        self.output.enqueueControl(.close, &payload) catch {
            self.beginImmediateClose();
            return;
        };
        self.close_after_flush = true;
    }

    fn beginImmediateClose(self: *Connection) void {
        if (self.state == .closing) return;
        self.state = .closing;
        self.tls_connection.shutdown();
        _ = std.posix.system.shutdown(self.tcp.fd, std.posix.SHUT.RDWR);
    }

    fn readyToDestroy(self: *const Connection) bool {
        return self.state == .closing and !self.read_active and !self.write_active and !self.socket_closed;
    }

    /// libxev 的 kqueue `TCP.close` 需要可选 thread pool，而 Gateway 的 Loop 刻意没有
    /// 配它。等 read/write completion 都已回调后，close(2) 本身不会阻塞；由 Listener
    /// 的周期 poll 同步关闭还能保证不在当前 completion 栈上释放 `self`。
    fn finishClose(self: *Connection) void {
        std.debug.assert(self.readyToDestroy());
        _ = std.c.close(self.tcp.fd);
        self.socket_closed = true;
        self.destroy();
    }

    fn notifySessionClosed(self: *Connection) void {
        if (self.session) |handle| {
            self.session = null;
            self.listener.handler.closed(handle);
        }
    }

    fn destroy(self: *Connection) void {
        const listener = self.listener;
        const allocator = listener.allocator;
        self.notifySessionClosed();
        listener.remove(self);
        self.tls_connection.deinit();
        self.output.deinit();
        allocator.free(self.encrypted_in);
        allocator.free(self.encrypted_out);
        allocator.free(self.plain);
        allocator.free(self.message_scratch);
        allocator.destroy(self);
    }

    fn destroyAfterLoopStopped(self: *Connection) void {
        if (!self.socket_closed) _ = std.c.close(self.tcp.fd);
        self.socket_closed = true;
        self.destroy();
    }

    fn cast(ptr: *anyopaque) *Connection {
        return @ptrCast(@alignCast(ptr));
    }

    fn transportClaimInboundExchange(ptr: *anyopaque, stream_id: u64) bool {
        const self = cast(ptr);
        if (self.state != .open or stream_id & 0x03 != 0) return false;
        return claimMonotonic(&self.highest_client_exchange_id, stream_id);
    }

    fn transportWrite(ptr: *anyopaque, stream_id: u64, bytes: []const u8, fin: bool) transport.TransportError!void {
        const self = cast(ptr);
        if (self.state != .open) return error.StreamWriteFailed;
        if (stream_id & 0x03 == 1 and !noteServerExchange(&self.highest_server_exchange_id, stream_id)) {
            self.beginImmediateClose();
            return error.StreamWriteFailed;
        }
        _ = self.output.enqueueRecord(.{
            .record_type = .stream,
            .stream_id = stream_id,
            .fin = fin,
            .payload = bytes,
        }, .reliable) catch {
            self.beginImmediateClose();
            return error.StreamWriteFailed;
        };
        self.drive() catch {
            self.beginImmediateClose();
            return error.StreamWriteFailed;
        };
    }

    fn transportEphemeral(ptr: *anyopaque, bytes: []const u8) transport.TransportError!void {
        const self = cast(ptr);
        if (self.state != .open) return error.EphemeralSendFailed;
        _ = self.output.enqueueRecord(.{
            .record_type = .ephemeral,
            .payload = bytes,
        }, .ephemeral) catch {
            // 只有 RecordTooLarge/InvalidRecord 会到这里；队列满时 ephemeral 在入队前丢弃。
            return error.EphemeralSendFailed;
        };
        self.drive() catch {
            self.beginImmediateClose();
            return error.EphemeralSendFailed;
        };
    }

    fn transportReset(ptr: *anyopaque, stream_id: u64, app_error_code: u64) void {
        cast(ptr).enqueueDirectionControl(.reset, stream_id, app_error_code);
    }

    fn transportStop(ptr: *anyopaque, stream_id: u64, app_error_code: u64) void {
        cast(ptr).enqueueDirectionControl(.stop, stream_id, app_error_code);
    }

    fn transportDiscard(ptr: *anyopaque, stream_id: u64, app_error_code: u64) void {
        const self = cast(ptr);
        if (self.state != .open) return;
        self.output.enqueueDiscard(stream_id, narrowAppError(app_error_code)) catch {
            self.beginImmediateClose();
            return;
        };
        self.drive() catch self.beginImmediateClose();
    }

    fn transportClose(ptr: *anyopaque, app_error_code: u64) void {
        const self = cast(ptr);
        if (self.state == .closing) return;
        self.protocolClose(websocketCloseCode(app_error_code));
        self.drive() catch self.beginImmediateClose();
    }

    fn enqueueDirectionControl(self: *Connection, record_type: envelope.RecordType, stream_id: u64, app_error_code: u64) void {
        if (self.state != .open) return;
        _ = self.output.enqueueRecord(.{
            .record_type = record_type,
            .stream_id = stream_id,
            .app_error_code = narrowAppError(app_error_code),
        }, .reliable) catch {
            self.beginImmediateClose();
            return;
        };
        self.drive() catch self.beginImmediateClose();
    }
};

fn narrowAppError(value: u64) u32 {
    return @intCast(@min(value, std.math.maxInt(u32)));
}

fn websocketCloseCode(app_error_code: u64) u16 {
    return switch (app_error_code) {
        @intFromEnum(protocol.frame.AppError.no_error) => close_normal,
        @intFromEnum(protocol.frame.AppError.protocol_violation) => close_protocol_error,
        @intFromEnum(protocol.frame.AppError.kicked) => 4002,
        @intFromEnum(protocol.frame.AppError.redirected) => 4003,
        else => close_internal_error,
    };
}

fn claimMonotonic(highest: *?u64, stream_id: u64) bool {
    if (highest.*) |previous| {
        if (stream_id <= previous) return false;
    }
    highest.* = stream_id;
    return true;
}

fn noteServerExchange(highest: *?u64, stream_id: u64) bool {
    const previous = highest.* orelse {
        if (stream_id != 1) return false;
        highest.* = stream_id;
        return true;
    };
    if (stream_id <= previous) return true;
    if (stream_id != previous + 4) return false;
    highest.* = stream_id;
    return true;
}

fn hostMatchesServerName(host: []const u8, server_name: ?[]const u8) bool {
    const expected = server_name orelse return false;
    if (std.ascii.eqlIgnoreCase(host, expected)) return true;
    if (host.len <= expected.len + 1 or host[expected.len] != ':') return false;
    if (!std.ascii.eqlIgnoreCase(host[0..expected.len], expected)) return false;
    const port_text = host[expected.len + 1 ..];
    for (port_text) |byte| if (!std.ascii.isDigit(byte)) return false;
    const port = std.fmt.parseInt(u16, port_text, 10) catch return false;
    return port != 0;
}

fn validClosePayload(payload: []const u8) bool {
    if (payload.len == 0) return true;
    if (payload.len == 1) return false;
    const code = std.mem.readInt(u16, payload[0..2], .big);
    if (code < 1000 or code >= 5000 or code == 1004 or code == 1005 or code == 1006 or code == 1015) return false;
    if (code >= 1016 and code <= 2999) return false;
    return std.unicode.utf8ValidateSlice(payload[2..]);
}

test "HTTP Host must match the TLS SNI while allowing an explicit port" {
    try std.testing.expect(hostMatchesServerName("gateway.example", "gateway.example"));
    try std.testing.expect(hostMatchesServerName("GATEWAY.EXAMPLE:8444", "gateway.example"));
    try std.testing.expect(!hostMatchesServerName("gateway.example.evil", "gateway.example"));
    try std.testing.expect(!hostMatchesServerName("gateway.example:", "gateway.example"));
    try std.testing.expect(!hostMatchesServerName("gateway.example:bad", "gateway.example"));
    try std.testing.expect(!hostMatchesServerName("gateway.example:0", "gateway.example"));
    try std.testing.expect(!hostMatchesServerName("gateway.example:65536", "gateway.example"));
    try std.testing.expect(!hostMatchesServerName("gateway.example", null));
}

test "WebSocket close payload validation rejects reserved codes and invalid UTF-8" {
    var normal: [2]u8 = undefined;
    std.mem.writeInt(u16, &normal, 1000, .big);
    try std.testing.expect(validClosePayload(&normal));
    var reserved: [2]u8 = undefined;
    std.mem.writeInt(u16, &reserved, 1006, .big);
    try std.testing.expect(!validClosePayload(&reserved));
    try std.testing.expect(!validClosePayload(&.{0}));
    try std.testing.expect(!validClosePayload(&.{ 0x03, 0xE8, 0xFF }));
}

test "WSS logical stream identities cannot be reused or forged" {
    var client_highest: ?u64 = null;
    try std.testing.expect(claimMonotonic(&client_highest, 0));
    try std.testing.expect(claimMonotonic(&client_highest, 4));
    try std.testing.expect(!claimMonotonic(&client_highest, 4));
    try std.testing.expect(!claimMonotonic(&client_highest, 0));
    try std.testing.expect(claimMonotonic(&client_highest, 12));

    var server_highest: ?u64 = null;
    try std.testing.expect(!noteServerExchange(&server_highest, 5));
    try std.testing.expect(noteServerExchange(&server_highest, 1));
    try std.testing.expect(noteServerExchange(&server_highest, 1));
    try std.testing.expect(!noteServerExchange(&server_highest, 9));
    try std.testing.expect(noteServerExchange(&server_highest, 5));
}

test "Transport close preserves application reason in WebSocket close codes" {
    try std.testing.expectEqual(@as(u16, 1000), websocketCloseCode(0));
    try std.testing.expectEqual(@as(u16, 1002), websocketCloseCode(1));
    try std.testing.expectEqual(@as(u16, 4002), websocketCloseCode(2));
    try std.testing.expectEqual(@as(u16, 4003), websocketCloseCode(3));
    try std.testing.expectEqual(@as(u16, 1011), websocketCloseCode(99));
}
