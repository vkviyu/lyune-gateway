//! QUIC 模块
//!
//! 封装 picoquic 库，提供 Zig 友好的 QUIC 客户端和服务端 API。
//!
//! 这是 quic/ 目录的入口文件，重导出 quic/mod.zig 的内容。

const mod = @import("quic/mod.zig");

// 重导出 mod.zig 中的所有公共内容
pub const c = mod.c;
pub const Config = mod.Config;
pub const Connection = mod.Connection;
pub const ConnectionManager = mod.ConnectionManager;
pub const Stream = mod.Stream;
pub const StreamType = mod.StreamType;
pub const StreamEvent = mod.StreamEvent;
pub const Endpoint = mod.Endpoint;
pub const CallbackContext = mod.CallbackContext;

// 重导出常用类型别名
pub const ServerConfig = mod.ServerConfig;
pub const ClientConfig = mod.ClientConfig;
pub const BaseConfig = mod.BaseConfig;
pub const CongestionAlgorithm = mod.CongestionAlgorithm;

// 重导出 C 层常用类型和函数
pub const CallbackEvent = mod.CallbackEvent;
pub const ConnectionState = mod.ConnectionState;
pub const currentTime = mod.currentTime;

pub const Client = mod.Client;

test {
    @import("std").testing.refAllDecls(@This());
}
