//! QUIC 模块
//!
//! 封装 picoquic 库，提供 Zig 友好的 QUIC 客户端和服务端 API。
//!
//! ## 使用示例
//!
//! ### 服务端（使用 libxev 高性能事件循环）
//! ```zig
//! const quic = @import("quic.zig");
//!
//! var server = try quic.Server.init(allocator, .{
//!     .cert_file = "server.crt",
//!     .key_file = "server.key",
//!     .port = 4433,
//! });
//! defer server.deinit();
//!
//! server.onStreamData(handleData);
//! try server.runWithXev();  // 使用 libxev (io_uring/kqueue/IOCP)
//! // 或者 try server.run(); // 使用 picoquic 原生循环
//! ```
//!
//! ### 客户端
//! ```zig
//! const quic = @import("quic.zig");
//!
//! var client = try quic.Client.init(allocator, .{
//!     .server_host = "localhost",
//!     .server_port = 4433,
//! });
//! defer client.deinit();
//!
//! const conn = try client.connect();
//! var buf: [4096]u8 = undefined;
//! const response = try client.sendAndReceive("Hello", &buf);
//! ```

pub const c = @import("quic/c.zig");
pub const Config = @import("quic/config.zig");
pub const Connection = @import("quic/connection.zig").Connection;
pub const ConnectionManager = @import("quic/connection.zig").ConnectionManager;
pub const Stream = @import("quic/stream.zig").Stream;
pub const StreamType = @import("quic/stream.zig").StreamType;
pub const StreamEvent = @import("quic/stream.zig").StreamEvent;
pub const Server = @import("quic/server.zig").Server;
pub const Client = @import("quic/client.zig").Client;
pub const QuicEventLoop = @import("quic/event_loop.zig").QuicEventLoop;

// 重导出常用类型
pub const ServerConfig = Config.ServerConfig;
pub const ClientConfig = Config.ClientConfig;
pub const BaseConfig = Config.Config;
pub const CongestionAlgorithm = Config.Config.CongestionAlgorithm;

// 重导出 C 层常用类型和函数
pub const CallbackEvent = c.CallbackEvent;
pub const ConnectionState = c.ConnectionState;
pub const currentTime = c.currentTime;

test {
    // 运行所有子模块的测试
    @import("std").testing.refAllDecls(@This());
}
