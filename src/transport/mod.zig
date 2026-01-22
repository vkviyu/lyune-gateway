//! 传输层抽象
//!
//! 提供基于 libxev 的高性能 I/O 抽象，包括事件循环、缓冲区管理和内存池。

pub const IoLoop = @import("io.zig").IoLoop;
pub const MAX_PACKET_SIZE = @import("io.zig").MAX_PACKET_SIZE;
pub const RecvCallback = @import("io.zig").RecvCallback;

// 以下模块尚未实现完整功能
pub const buffer = @import("buffer.zig");
pub const pool = @import("pool.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
