//! 传输层抽象
//!
//! 提供基于 libxev 的高性能 I/O 抽象，包括事件循环、缓冲区管理和内存池。

pub const buffer = @import("buffer.zig");
pub const io = @import("io.zig");
pub const pool = @import("pool.zig");

// 以下模块尚未实现完整功能
test {
    @import("std").testing.refAllDecls(@This());
}
