//! 上行分帧
//!
//! QUIC 只保证流内字节有序，不保证一次回调恰好是一帧：一次可能带来多帧、
//! 半帧，或若干帧再加半帧。本模块把字节流切成完整帧逐个交给上层，并把跨回调
//! 的残帧暂存下来。
//!
//! ## 只切帧，不做判断
//!
//! 本模块不看目的地、不看控制类型、不查任何表——那些都依赖认证配置、路由
//! 注册表和在途表，是 Worker 的状态。这里唯一的职责是"从哪到哪是一帧"。
//!
//! 帧头是变长的（OPEN 8 字节、DATA 4 字节），长度由第一个字节决定，因此
//! 补齐残帧要分两步：先把第一个字节等到手定型帧头长度，再按帧头里的
//! `body_len` 定型整帧长度。
//!
//! ## 性能取向
//!
//! 绝大多数消息一次回调就是一整帧，此时全程零拷贝零分配——直接在 picoquic 的
//! 接收缓冲上扫描。只有真正出现跨回调的残帧时才分配 spill，并且只拷贝那一个
//! 跨界帧：补齐它之后，同一次回调里后续的完整帧仍然走就地扫描。
//!
//! ## 分帧违规
//!
//! 帧类型未定义、保留位非 0、目的地未定义时直接返回错误，不做任何重同步。
//! 字节流一旦失去边界，继续猜测边界只会把 Body 里的任意字节当成帧头，
//! 反而给帧走私开了口子。调用方收到错误后应当关闭整条连接（见设计文档 §7.5），
//! 不要试图恢复。

const std = @import("std");

const codec = @import("codec.zig");
const frame = @import("frame.zig");

const FrameType = frame.FrameType;
const FrameHeader = frame.FrameHeader;

/// 跨回调的残帧缓冲。
///
/// 空 ArrayList 不持有堆内存，因此"当前没有残帧"是零成本状态，
/// 调用方可以按流懒创建、残帧消失后立即释放。
pub const Spill = std.ArrayList(u8);

/// 把 data 切成完整帧逐个交给 onFrame，未构成整帧的尾部留在 spill 里。
///
/// onFrame 返回 false 表示"这条流不用再往下处理了"（例如刚处理完 disconnect
/// 控制帧），drain 立即停止并丢弃本次剩余字节。
///
/// 调用约定：onFrame 期间不得释放 spill 或它所属的连接上下文。解出的帧指向
/// spill 或 data 内部，提前释放会让后续迭代读到已释放内存。需要关闭连接时
/// 应当置位标志并返回 false，等本函数返回后再真正关闭。
pub fn drainFrames(
    comptime Ctx: type,
    ctx: *Ctx,
    comptime onFrame: fn (*Ctx, codec.Frame) bool,
    spill: *Spill,
    allocator: std.mem.Allocator,
    data: []const u8,
    max_frame_size: usize,
) !void {
    var rest = data;

    // 慢路径：先把上次留下的残帧补齐，补齐后它是唯一需要拷贝的帧。
    if (spill.items.len > 0) {
        const pending = try completePending(spill, allocator, data, max_frame_size) orelse return;
        const keep_going = onFrame(ctx, .{
            .header = pending.header,
            .body = spill.items[pending.header.headerSize()..],
            .bytes = spill.items,
        });
        spill.clearRetainingCapacity();
        if (!keep_going) return;
        rest = data[pending.consumed..];
    }

    // 快路径：就地扫描，完整帧直接交出去，不复制。
    var scanner = codec.FrameScanner{ .data = rest, .max_frame_size = max_frame_size };
    while (try scanner.next()) |parsed| {
        if (!onFrame(ctx, parsed)) return;
    }

    const leftover = scanner.remainder();
    if (leftover.len > 0) try spill.appendSlice(allocator, leftover);
}

/// 补齐结果：从 data 消费了多少字节，以及补齐后那一帧的帧头。
///
/// 带上 header 是为了不让调用方再解析一次——帧头已经在这里解出来了。
const Completed = struct {
    consumed: usize,
    header: FrameHeader,
};

/// 从 data 取字节把 spill 里的残帧补足到恰好一帧。
///
/// 返回从 data 消费的字节数；仍然不足一帧时返回 null（全部字节已进 spill）。
/// 成功时 spill 的长度精确等于该帧总长，多余字节留在 data 里由快路径就地扫描。
///
/// 前置条件：spill 非空。第一个字节决定帧头长度，没有它连"还差多少"都算不出来，
/// 而 drainFrames 只在 spill 非空时调用本函数。
fn completePending(
    spill: *Spill,
    allocator: std.mem.Allocator,
    data: []const u8,
    max_frame_size: usize,
) !?Completed {
    const frame_type = try FrameType.decode(spill.items[0]);
    if (frame_type == .datagram) return error.DatagramOnStream;
    const header_size = frame_type.headerSize();

    var consumed: usize = 0;

    // 帧头还没齐：先补到 header_size，否则算不出这一帧有多长。
    if (spill.items.len < header_size) {
        // 取「还差多少字节」与「这次一共来了多少字节」的较小值：
        //   - data 不够补齐帧头 -> take = data.len，全部吃进来，下一行返回 null 等下次
        //   - data 有余 -> take = 缺口，只补到帧头刚好齐，多余字节留给后面的步骤
        // 两个方向都不能省：前者会切片越界，后者会破坏"spill 恰好一帧"的不变量。
        const take = @min(header_size - spill.items.len, data.len);
        try spill.appendSlice(allocator, data[0..take]);
        consumed += take;
        if (spill.items.len < header_size) return null;
    }

    // 帧头齐了就能定长。这里顺带完成保留位与目的地校验，非法帧不会先被攒起来。
    const header = try codec.parseHeader(spill.items[0..header_size]);
    const total = header.frameSize();
    if (total > max_frame_size) return error.FrameTooLarge;

    if (spill.items.len < total) {
        // 同一个取法换到正文阶段：「还差多少才够一整帧」对「data 里还剩多少没吃」。
        //
        // 这里绝不能多取。补齐后 spill.items 会被整体当成一帧交给上层并原样转发给
        // 后端（见 drainFrames），多一个字节就成了"一帧 + 尾随字节"，也就是帧走私。
        const take = @min(total - spill.items.len, data.len - consumed);
        try spill.appendSlice(allocator, data[consumed..][0..take]);
        consumed += take;
        if (spill.items.len < total) return null;
    }

    return .{ .consumed = consumed, .header = header };
}

// ============================================================================
// 测试
// ============================================================================

const RouteId = frame.RouteId;
const Flags = frame.Flags;
const OPEN_HEADER_SIZE = frame.OPEN_HEADER_SIZE;
const DATA_HEADER_SIZE = frame.DATA_HEADER_SIZE;

const Collector = struct {
    frames: std.ArrayList([]u8),
    allocator: std.mem.Allocator,
    stop_after: ?usize = null,

    fn init(allocator: std.mem.Allocator) Collector {
        return .{ .frames = .{ .items = &.{}, .capacity = 0 }, .allocator = allocator };
    }

    fn deinit(self: *Collector) void {
        for (self.frames.items) |f| self.allocator.free(f);
        self.frames.deinit(self.allocator);
    }

    fn onFrame(self: *Collector, parsed: codec.Frame) bool {
        const copy = self.allocator.dupe(u8, parsed.bytes) catch return false;
        self.frames.append(self.allocator, copy) catch {
            self.allocator.free(copy);
            return false;
        };
        if (self.stop_after) |limit| return self.frames.items.len < limit;
        return true;
    }
};

test "aligned frames are dispatched without touching the spill buffer" {
    const allocator = std.testing.allocator;
    var collector = Collector.init(allocator);
    defer collector.deinit();

    var buf: [256]u8 = undefined;
    var encoder = codec.FrameEncoder.init(&buf);
    const one = try encoder.encodeOpen(.service, RouteId.init(1, 2), Flags.last(), "payload");

    var spill: Spill = .{ .items = &.{}, .capacity = 0 };
    defer spill.deinit(allocator);

    try drainFrames(Collector, &collector, Collector.onFrame, &spill, allocator, one, codec.MAX_FRAME_SIZE);

    try std.testing.expectEqual(@as(usize, 1), collector.frames.items.len);
    // 帧边界对齐时不应该有任何堆分配：这是热路径的性能前提。
    try std.testing.expectEqual(@as(usize, 0), spill.capacity);
}

test "a frame split across callbacks is reassembled exactly once" {
    const allocator = std.testing.allocator;
    var collector = Collector.init(allocator);
    defer collector.deinit();

    var buf: [256]u8 = undefined;
    var encoder = codec.FrameEncoder.init(&buf);
    const one = try encoder.encodeOpen(.service, RouteId.init(3, 4), .{}, "split-me");

    var spill: Spill = .{ .items = &.{}, .capacity = 0 };
    defer spill.deinit(allocator);

    // 逐字节喂入，最坏情况：连帧头都被切成 8 段。
    for (one) |byte| {
        try drainFrames(Collector, &collector, Collector.onFrame, &spill, allocator, &.{byte}, codec.MAX_FRAME_SIZE);
    }

    try std.testing.expectEqual(@as(usize, 1), collector.frames.items.len);
    try std.testing.expectEqualSlices(u8, one, collector.frames.items[0]);
    try std.testing.expectEqual(@as(usize, 0), spill.items.len);
}

test "a straddling DATA frame is reassembled with the shorter header" {
    // DATA 的帧头只有 4 字节，补齐逻辑必须按第一个字节定型，不能沿用 OPEN 的 8。
    const allocator = std.testing.allocator;
    var collector = Collector.init(allocator);
    defer collector.deinit();

    var buf: [256]u8 = undefined;
    var encoder = codec.FrameEncoder.init(&buf);
    const one = try encoder.encodeData(Flags.last(), "tail-chunk");

    var spill: Spill = .{ .items = &.{}, .capacity = 0 };
    defer spill.deinit(allocator);

    // 切在帧头中间：此时 spill 里只有 2 个字节，长度信息还没到齐。
    try drainFrames(Collector, &collector, Collector.onFrame, &spill, allocator, one[0..2], codec.MAX_FRAME_SIZE);
    try std.testing.expectEqual(@as(usize, 0), collector.frames.items.len);

    try drainFrames(Collector, &collector, Collector.onFrame, &spill, allocator, one[2..], codec.MAX_FRAME_SIZE);
    try std.testing.expectEqual(@as(usize, 1), collector.frames.items.len);
    try std.testing.expectEqualSlices(u8, one, collector.frames.items[0]);
}

test "frames following a straddling frame stay on the zero-copy path" {
    const allocator = std.testing.allocator;
    var collector = Collector.init(allocator);
    defer collector.deinit();

    var stream: [512]u8 = undefined;
    var buf: [256]u8 = undefined;
    var encoder = codec.FrameEncoder.init(&buf);

    const first = try encoder.encodeOpen(.service, RouteId.init(1, 1), .{}, "first");
    @memcpy(stream[0..first.len], first);
    const first_len = first.len;
    const second = try encoder.encodeData(Flags.last(), "second");
    @memcpy(stream[first_len..][0..second.len], second);
    const total = first_len + second.len;

    var spill: Spill = .{ .items = &.{}, .capacity = 0 };
    defer spill.deinit(allocator);

    // 第一次只给出第一帧的一部分，第二次给出剩余部分 + 完整的第二帧。
    const split = first_len - 3;
    try drainFrames(Collector, &collector, Collector.onFrame, &spill, allocator, stream[0..split], codec.MAX_FRAME_SIZE);
    try std.testing.expectEqual(@as(usize, 0), collector.frames.items.len);

    try drainFrames(Collector, &collector, Collector.onFrame, &spill, allocator, stream[split..total], codec.MAX_FRAME_SIZE);
    try std.testing.expectEqual(@as(usize, 2), collector.frames.items.len);
    // spill 只承载过那个跨界帧；第二帧是直接从入参切片上就地扫描出来的。
    try std.testing.expectEqual(@as(usize, 0), spill.items.len);
    try std.testing.expectEqualSlices(u8, stream[first_len..total], collector.frames.items[1]);
}

test "malformed header aborts the stream instead of resyncing" {
    const allocator = std.testing.allocator;
    var collector = Collector.init(allocator);
    defer collector.deinit();

    var spill: Spill = .{ .items = &.{}, .capacity = 0 };
    defer spill.deinit(allocator);

    const garbage: [OPEN_HEADER_SIZE]u8 = @splat(0x5A);
    try std.testing.expectError(
        error.UnknownFrameType,
        drainFrames(Collector, &collector, Collector.onFrame, &spill, allocator, &garbage, codec.MAX_FRAME_SIZE),
    );
}

test "a violation inside the spill is caught while completing the frame" {
    // 违规字节可能落在残帧里，而残帧走的是慢路径——两条路径都必须校验。
    const allocator = std.testing.allocator;
    var collector = Collector.init(allocator);
    defer collector.deinit();

    var spill: Spill = .{ .items = &.{}, .capacity = 0 };
    defer spill.deinit(allocator);

    // 先喂一个合法的 DATA 首字节，让它进 spill。
    try drainFrames(Collector, &collector, Collector.onFrame, &spill, allocator, &.{0x01}, codec.MAX_FRAME_SIZE);
    try std.testing.expectEqual(@as(usize, 1), spill.items.len);

    // 再喂一个把保留位置满的 flags 字节：补齐帧头后必须当场判违规。
    try std.testing.expectError(
        error.ReservedBitsSet,
        drainFrames(Collector, &collector, Collector.onFrame, &spill, allocator, &.{ 0xFF, 0x00, 0x00 }, codec.MAX_FRAME_SIZE),
    );
}

test "an oversized frame is rejected from its header alone" {
    const allocator = std.testing.allocator;
    var collector = Collector.init(allocator);
    defer collector.deinit();

    var buf: [256]u8 = undefined;
    var encoder = codec.FrameEncoder.init(&buf);
    const one = try encoder.encodeOpen(.service, RouteId.init(1, 1), Flags.last(), "0123456789");

    var spill: Spill = .{ .items = &.{}, .capacity = 0 };
    defer spill.deinit(allocator);

    // 上限压到比这一帧还小：必须在帧头阶段就拒绝，而不是先把 Body 攒起来。
    try std.testing.expectError(
        error.FrameTooLarge,
        drainFrames(Collector, &collector, Collector.onFrame, &spill, allocator, one, OPEN_HEADER_SIZE + 4),
    );
}

test "onFrame can stop the drain and leave the rest unprocessed" {
    const allocator = std.testing.allocator;
    var collector = Collector.init(allocator);
    collector.stop_after = 1;
    defer collector.deinit();

    var stream: [512]u8 = undefined;
    var buf: [256]u8 = undefined;
    var encoder = codec.FrameEncoder.init(&buf);

    const first = try encoder.encodeDisconnect();
    @memcpy(stream[0..first.len], first);
    const first_len = first.len;
    const second = try encoder.encodeOpen(.service, RouteId.init(1, 1), Flags.last(), "never-seen");
    @memcpy(stream[first_len..][0..second.len], second);
    const total = first_len + second.len;

    var spill: Spill = .{ .items = &.{}, .capacity = 0 };
    defer spill.deinit(allocator);

    try drainFrames(Collector, &collector, Collector.onFrame, &spill, allocator, stream[0..total], codec.MAX_FRAME_SIZE);
    try std.testing.expectEqual(@as(usize, 1), collector.frames.items.len);
}
