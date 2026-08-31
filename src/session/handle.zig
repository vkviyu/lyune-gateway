//! Worker-local 的传输无关会话身份。
//!
//! 它只定位当前 Worker 的 ConnectionManager 槽位，不暴露 QUIC 指针、TCP fd 或
//! WebSocket 对象地址。`generation` 防止槽位归还后旧的 inflight/auth 回程命中新会话。
//! 跨节点可见的业务身份仍是 `ConnToken`，两者不能混用。

const std = @import("std");

pub const SessionHandle = struct {
    slot: u32,
    generation: u16,

    pub fn eql(self: SessionHandle, other: SessionHandle) bool {
        return self.slot == other.slot and self.generation == other.generation;
    }
};

test "session handle includes slot generation" {
    const current = SessionHandle{ .slot = 7, .generation = 3 };
    try std.testing.expect(current.eql(.{ .slot = 7, .generation = 3 }));
    try std.testing.expect(!current.eql(.{ .slot = 7, .generation = 4 }));
    try std.testing.expect(!current.eql(.{ .slot = 8, .generation = 3 }));
}
