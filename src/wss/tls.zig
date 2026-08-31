//! BoringSSL 的非阻塞服务端封装。
//!
//! 不把 SSL 直接绑到 socket，而使用定容 BIO pair：libxev 负责异步收发密文字节，
//! BoringSSL 只读写 BIO。小型 C shim 隔离 BoringSSL 的宏密集型公共头，Zig 侧只看到
//! 不透明句柄和明确状态码。

const std = @import("std");

const c = @cImport({
    @cInclude("wss/tls_shim.h");
});

pub const Context = struct {
    inner: *c.lyune_tls_context,

    pub const Error = error{
        ContextCreateFailed,
        CertificateLoadFailed,
        PrivateKeyLoadFailed,
        PrivateKeyMismatch,
        TlsConfigurationFailed,
    };

    pub fn init(cert_file: [:0]const u8, key_file: [:0]const u8) Error!Context {
        var inner: ?*c.lyune_tls_context = null;
        return switch (c.lyune_tls_context_create(cert_file.ptr, key_file.ptr, &inner)) {
            c.LYUNE_TLS_CONTEXT_OK => .{ .inner = inner.? },
            c.LYUNE_TLS_CERTIFICATE_LOAD_FAILED => error.CertificateLoadFailed,
            c.LYUNE_TLS_PRIVATE_KEY_LOAD_FAILED => error.PrivateKeyLoadFailed,
            c.LYUNE_TLS_PRIVATE_KEY_MISMATCH => error.PrivateKeyMismatch,
            c.LYUNE_TLS_CONFIGURATION_FAILED => error.TlsConfigurationFailed,
            else => error.ContextCreateFailed,
        };
    }

    pub fn deinit(self: *Context) void {
        c.lyune_tls_context_free(self.inner);
        self.* = undefined;
    }
};

pub const Connection = struct {
    inner: *c.lyune_tls_connection,

    pub const Error = error{
        ConnectionCreateFailed,
        TlsFailed,
        TlsClosed,
    };

    pub const Progress = union(enum) {
        bytes: usize,
        would_block,
        closed,
    };

    pub fn init(ctx: *const Context, bio_capacity: usize) Error!Connection {
        const inner = c.lyune_tls_connection_create(ctx.inner, bio_capacity) orelse return error.ConnectionCreateFailed;
        return .{ .inner = inner };
    }

    pub fn deinit(self: *Connection) void {
        c.lyune_tls_connection_free(self.inner);
        self.* = undefined;
    }

    pub fn provideEncrypted(self: *Connection, bytes: []const u8) usize {
        return c.lyune_tls_provide_encrypted(self.inner, bytes.ptr, bytes.len);
    }

    pub fn takeEncrypted(self: *Connection, out: []u8) Error!usize {
        const result = c.lyune_tls_take_encrypted(self.inner, out.ptr, out.len);
        if (result >= 0) return @intCast(result);
        return error.TlsFailed;
    }

    pub fn handshake(self: *Connection) Error!bool {
        return switch (c.lyune_tls_handshake(self.inner)) {
            1 => true,
            c.LYUNE_TLS_IO_WOULD_BLOCK => false,
            c.LYUNE_TLS_IO_CLOSED => error.TlsClosed,
            else => error.TlsFailed,
        };
    }

    pub fn serverName(self: *const Connection) ?[]const u8 {
        const raw = c.lyune_tls_server_name(self.inner) orelse return null;
        return std.mem.span(@as([*:0]const u8, @ptrCast(raw)));
    }

    pub fn readPlain(self: *Connection, out: []u8) Error!Progress {
        return classify(c.lyune_tls_read_plain(self.inner, out.ptr, out.len));
    }

    pub fn writePlain(self: *Connection, bytes: []const u8) Error!Progress {
        return classify(c.lyune_tls_write_plain(self.inner, bytes.ptr, bytes.len));
    }

    pub fn shutdown(self: *Connection) void {
        c.lyune_tls_shutdown(self.inner);
    }

    fn classify(result: c_long) Error!Progress {
        if (result > 0) return .{ .bytes = @intCast(result) };
        return switch (result) {
            c.LYUNE_TLS_IO_WOULD_BLOCK => .would_block,
            c.LYUNE_TLS_IO_CLOSED => .closed,
            else => error.TlsFailed,
        };
    }
};

test "TLS shim exposes the bounded BIO driver surface" {
    try std.testing.expect(@hasDecl(c, "lyune_tls_context_create"));
    try std.testing.expect(@hasDecl(c, "lyune_tls_provide_encrypted"));
    try std.testing.expect(@hasDecl(c, "lyune_tls_take_encrypted"));
}
