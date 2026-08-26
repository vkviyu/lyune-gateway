//! membership 真实运行器。
//!
//! 运行器把非阻塞 UDP transport、纯 SWIM 状态机和外部单调时钟连接起来。
//! 它独占协议线程；数据面只通过 Swim.view() 读取成员快照。

const std = @import("std");
const membership = @import("mod.zig");
const codec = @import("codec.zig");
const swim_mod = @import("swim.zig");
const transport_mod = @import("transport.zig");
const foundation = @import("../../foundation/mod.zig");
const net = foundation.net;

/// 真实 membership runner 配置；地址是 gossip bind/advertise 地址，seeds 在启动时注入并 join。
pub const Config = struct {
    node_id: membership.NodeId,
    address: net.Address,
    max_nodes: u16 = 1024,
    seed: u64,
    secret: []const u8 = &.{},
    previous_secret: []const u8 = &.{},
    params: membership.Params = .{},
    seeds: []const Seed = &.{},
};

/// 静态引导节点的身份与 gossip 地址。
pub const Seed = struct {
    node_id: membership.NodeId,
    address: net.Address,
};

/// 独占 SWIM 写侧的 UDP 协议线程；其他线程只能通过原子命令和只读 Table 与其交互。
pub const Runner = struct {
    allocator: std.mem.Allocator,
    config: Config,
    swim: swim_mod.Swim,
    transport: transport_mod.UdpTransport,
    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = .init(false),
    leave_requested: std.atomic.Value(bool) = .init(false),
    leave_completed: std.atomic.Value(bool) = .init(false),
    io: std.Io,
    start_ms: i64,

    /// 绑定非阻塞 UDP socket 并初始化状态机；端口为 0 时记录内核实际分配的通告地址。
    pub fn init(allocator: std.mem.Allocator, io: std.Io, config: Config) !Runner {
        var runtime_config = config;
        var transport = try transport_mod.UdpTransport.init(config.address);
        errdefer transport.deinit();
        // 测试或临时部署可绑定端口 0；gossip 必须通告内核实际分配的端口。
        runtime_config.address = try transport.localAddress();
        var swim = try swim_mod.Swim.init(allocator, .{
            .node_id = runtime_config.node_id,
            .address = runtime_config.address,
            .max_nodes = runtime_config.max_nodes,
            .seed = runtime_config.seed,
            .secret = runtime_config.secret,
            .previous_secret = runtime_config.previous_secret,
            .params = runtime_config.params,
        });
        errdefer swim.deinit();
        return .{
            .allocator = allocator,
            .config = runtime_config,
            .swim = swim,
            .transport = transport,
            .io = io,
            .start_ms = std.Io.Clock.awake.now(io).toMilliseconds(),
        };
    }

    /// 停止并 join 协议线程，然后释放 UDP transport 与 SWIM 状态。
    pub fn deinit(self: *Runner) void {
        self.stop();
        self.transport.deinit();
        self.swim.deinit();
        self.* = undefined;
    }

    /// 注入所有静态 seeds、发起 anti-entropy join，并启动唯一协议线程。
    pub fn start(self: *Runner) !void {
        if (self.thread != null) return error.AlreadyStarted;
        for (self.config.seeds) |seed| {
            try self.swim.addPeer(seed.node_id, seed.address);
            try self.swim.joinSeed(seed.address);
        }
        self.stopping.store(false, .release);
        self.thread = try std.Thread.spawn(.{}, runThread, .{self});
    }

    /// 请求协议线程退出并等待完成；可重复调用。
    pub fn stop(self: *Runner) void {
        self.stopping.store(true, .release);
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
    }

    /// 请求协议线程广播 left，并等待首轮发送完成。
    ///
    /// Swim 保持严格单写者模型：调用线程只写原子命令位，绝不直接修改状态机。
    /// 等待上限为 2 秒；超时返回 LeaveTimedOut，调用方不得据此假定 left 已发出。
    pub fn leave(self: *Runner) !void {
        if (self.thread == null) {
            try self.swim.leave();
            self.flushOutgoing();
            return;
        }
        self.leave_completed.store(false, .release);
        self.leave_requested.store(true, .release);
        for (0..2000) |_| {
            if (self.leave_completed.load(.acquire)) return;
            try std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(1), .awake);
        }
        return error.LeaveTimedOut;
    }

    /// 返回 runner 实际绑定并通告的 gossip 地址。
    pub fn localAddress(self: *const Runner) net.Address {
        return self.config.address;
    }

    /// 返回可跨线程读取的成员表；其生命周期不超过 Runner。
    pub fn view(self: *const Runner) *const membership.Table {
        return self.swim.view();
    }

    fn runThread(self: *Runner) void {
        var buffer: [codec.max_message_size + codec.auth_tag_size]u8 = undefined;
        while (!self.stopping.load(.acquire)) {
            if (self.leave_requested.swap(false, .acq_rel)) {
                self.swim.leave() catch {};
                self.flushOutgoing();
                self.leave_completed.store(true, .release);
            }
            while (self.transport.recv(&buffer) catch null) |packet| {
                const now = self.nowMs();
                self.swim.handleMessage(now, packet.from, buffer[0..packet.len]) catch {};
                self.failOnIdentityConflict();
            }
            self.swim.tick(self.nowMs()) catch {};
            self.flushOutgoing();
            std.Io.sleep(
                self.io,
                std.Io.Duration.fromMilliseconds(1),
                .awake,
            ) catch break;
        }
    }

    fn flushOutgoing(self: *Runner) void {
        for (self.swim.pendingOutgoing()) |outgoing| {
            self.transport.send(outgoing.to, outgoing.bytes()) catch {};
        }
        self.swim.clearOutgoing();
    }

    /// 静态 node_id 冲突会破坏 CID 路由唯一性，继续服务比立即失败更危险。
    fn failOnIdentityConflict(self: *const Runner) void {
        if (self.swim.identityConflict()) |conflict| {
            std.log.err(
                "cluster node_id {} address conflict: expected {any}, observed {any}; terminating",
                .{ conflict.node_id, conflict.expected_address, conflict.observed_address },
            );
            std.process.exit(1);
        }
    }

    fn nowMs(self: *const Runner) u64 {
        const now = std.Io.Clock.awake.now(self.io).toMilliseconds();
        const elapsed = now - self.start_ms;
        return @intCast(@max(elapsed, 0));
    }
};

test "runner initializes with seeds and can stop" {
    var runner = try Runner.init(std.testing.allocator, std.testing.io, .{
        .node_id = 1,
        .address = net.initIp4(.{ 127, 0, 0, 1 }, 0),
        .seed = 1,
    });
    defer runner.deinit();
    try runner.start();
    runner.stop();
}

test "two authenticated UDP runners join and propagate left" {
    const secret = "0123456789abcdef";
    const params: membership.Params = .{
        .protocol_period_ms = 50,
        .probe_timeout_ms = 20,
        .sync_interval_ms = 200,
    };
    var first = try Runner.init(std.testing.allocator, std.testing.io, .{
        .node_id = 1,
        .address = net.initIp4(.{ 127, 0, 0, 1 }, 0),
        .seed = 1,
        .secret = secret,
        .params = params,
    });
    defer first.deinit();
    try first.start();

    const seeds = [_]Seed{.{ .node_id = 1, .address = first.localAddress() }};
    var second = try Runner.init(std.testing.allocator, std.testing.io, .{
        .node_id = 2,
        .address = net.initIp4(.{ 127, 0, 0, 1 }, 0),
        .seed = 2,
        .secret = secret,
        .params = params,
        .seeds = &seeds,
    });
    defer second.deinit();
    try second.start();

    for (0..2000) |_| {
        if (first.view().lookup(2) != null and second.view().lookup(1) != null) break;
        try std.Io.sleep(std.testing.io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(membership.NodeStatus.alive, first.view().lookup(2).?.status);
    try std.testing.expectEqual(membership.NodeStatus.alive, second.view().lookup(1).?.status);

    try second.leave();
    for (0..2000) |_| {
        if (first.view().lookup(2)) |member| {
            if (member.status == .left) break;
        }
        try std.Io.sleep(std.testing.io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(membership.NodeStatus.left, first.view().lookup(2).?.status);
}
