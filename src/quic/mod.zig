pub const c = @import("c.zig");
pub const Config = @import("config.zig");
pub const Connection = @import("connection.zig").Connection;
pub const Stream = @import("stream.zig").Stream;
pub const StreamType = @import("stream.zig").StreamType;
pub const StreamEvent = @import("stream.zig").StreamEvent;
pub const Endpoint = @import("endpoint.zig").Endpoint;
pub const CallbackContext = @import("endpoint.zig").CallbackContext;
pub const Client = @import("client.zig").Client;

// 重导出常用类型
pub const QuicConfig = Config.QuicConfig;
pub const ClientConfig = Config.ClientConfig;
pub const BaseConfig = Config.Config;
pub const CongestionAlgorithm = Config.Config.CongestionAlgorithm;

// 重导出 C 层常用类型和函数
pub const CallbackEvent = c.CallbackEvent;
pub const ConnectionState = c.ConnectionState;
pub const currentTime = c.currentTime;

test {
    @import("std").testing.refAllDecls(@This());
}
