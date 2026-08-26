const std = @import("std");
const xev = @import("xev");

const foundation = @import("../mod.zig");
const net = foundation.net;
const resolver = @import("mod.zig");

const c = @cImport({
    @cInclude("ares.h");
});

const PROCESS_INTERVAL_MS = 10;

pub const CaresResolver = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    loop: *xev.Loop,
    channel: *c.ares_channel_t,
    timer: xev.Timer,
    timer_completion: xev.Completion = undefined,
    pending: std.AutoHashMap(u64, *Request),
    watchers: std.AutoHashMap(c.ares_socket_t, *SocketWatcher),
    next_id: u64 = 1,
    running: bool = false,
    shutting_down: bool = false,
    /// 仍有 poll completion 在 loop 队列中、必须等回调后才能释放的 watcher 数。
    /// deinit 用它决定要驱动 loop 多久才能安全收回全部 watcher。
    watchers_in_flight: usize = 0,

    const SocketWatcher = struct {
        resolver: *Self,
        fd: c.ares_socket_t,
        tcp: xev.TCP,
        completion: xev.Completion = undefined,
        readable: bool = false,
        /// poll completion 已提交给 loop、尚未回调。
        ///
        /// 这是释放该 watcher 的门禁：completion 在飞时释放内存，
        /// 回调（以及 io_uring 后端的内核写回）会访问已释放内存。
        active: bool = false,
        processing: bool = false,
        removed: bool = false,
    };

    const Request = struct {
        resolver: *Self,
        id: u64,
        host: [:0]u8,
        port: u16,
        callback: resolver.ResolveCallback,
        ctx: ?*anyopaque,
        completed: bool = false,
        canceled: bool = false,

        fn deinit(self: *Request, allocator: std.mem.Allocator) void {
            allocator.free(self.host);
            allocator.destroy(self);
        }
    };

    pub fn init(allocator: std.mem.Allocator, loop: *xev.Loop) resolver.ResolveError!*Self {
        const self = allocator.create(Self) catch return error.OutOfMemory;
        errdefer allocator.destroy(self);

        const init_rc = c.ares_library_init(c.ARES_LIB_INIT_ALL);
        if (init_rc != c.ARES_SUCCESS) return error.ResolverFailed;

        var options: c.struct_ares_options = std.mem.zeroes(c.struct_ares_options);
        options.timeout = 1000;
        options.tries = 3;
        options.sock_state_cb = socketStateCallback;
        options.sock_state_cb_data = self;

        var channel: ?*c.ares_channel_t = null;
        const rc = c.ares_init_options(&channel, &options, c.ARES_OPT_TIMEOUTMS | c.ARES_OPT_TRIES | c.ARES_OPT_SOCK_STATE_CB);
        if (rc != c.ARES_SUCCESS) return error.ResolverFailed;

        const timer = xev.Timer.init() catch return error.ResolverFailed;

        self.* = .{
            .allocator = allocator,
            .loop = loop,
            .channel = channel orelse return error.ResolverFailed,
            .timer = timer,
            .pending = std.AutoHashMap(u64, *Request).init(allocator),
            .watchers = std.AutoHashMap(c.ares_socket_t, *SocketWatcher).init(allocator),
        };

        return self;
    }

    pub fn deinit(self: *Self) void {
        const allocator = self.allocator;
        self.running = false;
        self.shutting_down = true;

        var it = self.pending.valueIterator();
        while (it.next()) |req| {
            req.*.canceled = true;
        }
        c.ares_cancel(self.channel);

        // 标记全部 watcher 待回收；completion 仍在飞的不能就地释放。
        var watcher_it = self.watchers.valueIterator();
        while (watcher_it.next()) |watcher| {
            watcher.*.readable = false;
            watcher.*.removed = true;
            if (!watcher.*.active and !watcher.*.processing) {
                allocator.destroy(watcher.*);
            }
        }
        self.watchers.clearRetainingCapacity();

        // 先销毁 channel：它会关闭全部 c-ares socket，使在飞的 poll 立刻完成，
        // 从而触发 pollCallback。此时 shutting_down 已置位，回调会走
        // 「直接返回 + defer 释放 watcher」的分支，不会再触碰 channel。
        c.ares_destroy(self.channel);

        // 驱动 loop 收割这些回调。调用方保证 loop 的生命周期长于 resolver
        // （bootstrap 里 resolver 的 defer 早于 worker 的 defer 执行）。
        // 加自旋上限兜底：极端情况下宁可泄漏几个 watcher，也不能让
        // completion 悬垂到 resolver 释放之后。
        var spins: usize = 0;
        while (self.watchers_in_flight > 0 and spins < 1024) : (spins += 1) {
            self.loop.run(.no_wait) catch break;
        }
        if (self.watchers_in_flight > 0) {
            std.log.warn(
                "[Cares] {} socket watcher(s) still in flight at shutdown; leaking to avoid use-after-free",
                .{self.watchers_in_flight},
            );
        }

        self.watchers.deinit();
        self.pending.deinit();

        self.timer.deinit();
        c.ares_library_cleanup();
        allocator.destroy(self);
    }

    pub fn asResolver(self: *Self) resolver.Resolver {
        return resolver.Resolver.init(Self, self);
    }

    pub fn resolve(
        self: *Self,
        host: []const u8,
        port: u16,
        callback: resolver.ResolveCallback,
        ctx: ?*anyopaque,
    ) resolver.ResolveError!resolver.ResolveHandle {
        const id = self.next_id;
        self.next_id += 1;

        const req = try self.allocator.create(Request);
        errdefer self.allocator.destroy(req);

        const host_copy = try self.allocator.dupeSentinel(u8, host, 0);
        errdefer self.allocator.free(host_copy);

        req.* = .{
            .resolver = self,
            .id = id,
            .host = host_copy,
            .port = port,
            .callback = callback,
            .ctx = ctx,
        };

        try self.pending.put(id, req);
        errdefer _ = self.pending.remove(id);

        var service_buf: [16]u8 = undefined;
        const service = std.fmt.bufPrintZ(&service_buf, "{}", .{port}) catch return error.InvalidHost;
        var hints: c.struct_ares_addrinfo_hints = std.mem.zeroes(c.struct_ares_addrinfo_hints);
        hints.ai_family = std.posix.AF.UNSPEC;
        hints.ai_socktype = std.posix.SOCK.DGRAM;
        hints.ai_flags = c.ARES_AI_ADDRCONFIG;

        c.ares_getaddrinfo(self.channel, host_copy.ptr, service.ptr, &hints, onAddrInfo, req);
        self.ensureTimer();
        return .{ .id = id };
    }

    pub fn cancel(self: *Self, handle: resolver.ResolveHandle) void {
        if (self.pending.get(handle.id)) |req| {
            req.canceled = true;
        }
    }

    fn ensureTimer(self: *Self) void {
        if (self.running) return;
        self.running = true;
        self.scheduleTimer();
    }

    fn scheduleTimer(self: *Self) void {
        var tv: c.struct_timeval = undefined;
        const timeout = c.ares_timeout(self.channel, null, &tv);
        const delay_ms: u64 = if (timeout) |t|
            @max(1, @as(u64, @intCast(t.*.tv_sec)) * 1000 + @as(u64, @intCast(@divTrunc(t.*.tv_usec, 1000))))
        else
            PROCESS_INTERVAL_MS;
        self.timer.run(self.loop, &self.timer_completion, delay_ms, Self, self, timerCallback);
    }

    fn timerCallback(
        ud: ?*Self,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        _ = result catch {};
        const self = ud orelse return .disarm;
        if (!self.running) return .disarm;

        _ = c.ares_process_fds(self.channel, null, 0, c.ARES_PROCESS_FLAG_NONE);
        if (self.pending.count() == 0) {
            self.running = false;
            return .disarm;
        }

        self.scheduleTimer();
        return .disarm;
    }

    fn socketStateCallback(data: ?*anyopaque, socket_fd: c.ares_socket_t, readable: c_int, writable: c_int) callconv(.c) void {
        const self: *Self = @ptrCast(@alignCast(data.?));
        if (self.shutting_down) return;

        const wants_read = readable != 0;
        const wants_write = writable != 0;

        if (!wants_read and !wants_write) {
            if (self.watchers.fetchRemove(socket_fd)) |entry| {
                entry.value.readable = false;
                entry.value.removed = true;
                // active 表示 poll completion 仍在 loop 队列里；此时释放会让
                // 回调访问已释放内存。留给 pollCallback 在最后一次回调里释放。
                if (!entry.value.active and !entry.value.processing) {
                    self.allocator.destroy(entry.value);
                }
            }
            return;
        }

        const watcher = if (self.watchers.get(socket_fd)) |existing| existing else blk: {
            const created = self.allocator.create(SocketWatcher) catch return;
            created.* = .{
                .resolver = self,
                .fd = socket_fd,
                .tcp = xev.TCP.initFd(socket_fd),
            };
            self.watchers.put(socket_fd, created) catch {
                self.allocator.destroy(created);
                return;
            };
            break :blk created;
        };

        watcher.readable = wants_read;
        if (watcher.readable and !watcher.active) {
            armWatcher(watcher);
        }
        self.ensureTimer();
    }

    /// 提交一次读事件 poll。active 从 false 变 true 时登记在飞计数，
    /// 供 deinit 判断还需驱动 loop 多久才能安全回收 watcher。
    fn armWatcher(watcher: *SocketWatcher) void {
        if (!watcher.active) {
            watcher.active = true;
            watcher.resolver.watchers_in_flight += 1;
        }
        watcher.tcp.poll(watcher.resolver.loop, &watcher.completion, .read, SocketWatcher, watcher, pollCallback);
    }

    fn pollCallback(
        ud: ?*SocketWatcher,
        loop: *xev.Loop,
        completion: *xev.Completion,
        tcp: xev.TCP,
        result: xev.PollError!xev.PollEvent,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        _ = tcp;
        _ = result catch {};

        const watcher = ud orelse return .disarm;
        const self = watcher.resolver;
        // completion 已被消耗，注销在飞计数。
        if (watcher.active) {
            watcher.active = false;
            self.watchers_in_flight -= 1;
        }
        watcher.processing = true;
        defer {
            watcher.processing = false;
            if (watcher.removed) {
                self.allocator.destroy(watcher);
            }
        }

        if (self.shutting_down or watcher.removed or self.watchers.get(watcher.fd) != watcher) {
            return .disarm;
        }

        _ = c.ares_process_fd(self.channel, watcher.fd, c.ARES_SOCKET_BAD);
        if (self.pending.count() == 0) {
            self.running = false;
            return .disarm;
        }

        if (!watcher.removed and self.watchers.get(watcher.fd) == watcher and watcher.readable) {
            armWatcher(watcher);
        }
        self.ensureTimer();
        return .disarm;
    }

    fn onAddrInfo(arg: ?*anyopaque, status: c_int, timeouts: c_int, res: ?*c.struct_ares_addrinfo) callconv(.c) void {
        _ = timeouts;
        const req: *Request = @ptrCast(@alignCast(arg.?));
        const self = req.resolver;
        if (req.completed) return;

        _ = self.pending.remove(req.id);
        req.completed = true;

        if (req.canceled or self.shutting_down) {
            req.deinit(self.allocator);
            return;
        }

        if (status != c.ARES_SUCCESS) {
            req.callback(req.ctx, .{ .err = mapStatus(status) });
            req.deinit(self.allocator);
            return;
        }

        const addrinfo = res orelse {
            req.callback(req.ctx, .{ .err = error.NoAddress });
            req.deinit(self.allocator);
            return;
        };
        defer c.ares_freeaddrinfo(addrinfo);

        if (extractAddress(addrinfo, req.port)) |addr| {
            req.callback(req.ctx, .{ .address = addr });
        } else |err| {
            req.callback(req.ctx, .{ .err = err });
        }
        req.deinit(self.allocator);
    }

    fn mapStatus(status: c_int) resolver.ResolveError {
        return switch (status) {
            c.ARES_ETIMEOUT => error.Timeout,
            c.ARES_ECANCELLED => error.Canceled,
            c.ARES_ENOTFOUND, c.ARES_ENONAME, c.ARES_ENODATA => error.NoAddress,
            c.ARES_ENOMEM => error.OutOfMemory,
            else => error.ResolverFailed,
        };
    }

    fn extractAddress(addrinfo: *c.struct_ares_addrinfo, port: u16) resolver.ResolveError!net.Address {
        var node = addrinfo.nodes;
        while (node != null) : (node = node.?.*.ai_next) {
            const addr = node.?.*.ai_addr orelse continue;
            const family = node.?.*.ai_family;
            if (family == std.posix.AF.INET) {
                const sa: *const std.posix.sockaddr.in = @ptrCast(@alignCast(addr));
                return net.initIp4(@as(*const [4]u8, @ptrCast(&sa.addr)).*, port);
            }
            if (family == std.posix.AF.INET6) {
                const sa: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(addr));
                return net.initIp6(sa.addr, port);
            }
        }
        return error.NoAddress;
    }
};

test "CaresResolver resolves localhost asynchronously" {
    const allocator = std.testing.allocator;
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    const dns = try CaresResolver.init(allocator, &loop);
    defer dns.deinit();

    const TestCtx = struct {
        done: bool = false,
        result: ?resolver.ResolveResult = null,

        fn onResolved(ctx: ?*anyopaque, result: resolver.ResolveResult) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.result = result;
            self.done = true;
        }
    };

    var ctx = TestCtx{};
    _ = try dns.resolve("localhost", 4433, TestCtx.onResolved, &ctx);

    var attempts: usize = 0;
    while (!ctx.done and attempts < 200) : (attempts += 1) {
        try loop.run(.no_wait);
        try std.Io.sleep(
            std.Io.Threaded.global_single_threaded.io(),
            std.Io.Duration.fromMilliseconds(5),
            .awake,
        );
    }

    try std.testing.expect(ctx.done);
    switch (ctx.result.?) {
        .address => {},
        .err => |err| return err,
    }
}
