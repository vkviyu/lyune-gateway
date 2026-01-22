//! 后端传输模块
//!
//! 提供网关与后端服务通信的抽象接口和实现。
//!
//! ## 核心组件
//!
//! - `BackendTransport`: 传输接口抽象
//! - `TransportRegistry`: 路由注册表
//! - `MemoryTransport`: 内存实现（测试/开发用）
//!
//! ## 使用示例
//!
//! ```zig
//! const mq = @import("mq");
//!
//! // 创建内存传输（测试用）
//! var mem_transport = mq.MemoryTransport.init(allocator);
//! defer mem_transport.deinit();
//!
//! // 注册到注册表（按 TransportPath 分组）
//! var registry = mq.TransportRegistry.init();
//! registry.register(.relay, 0x01, mem_transport.asTransport());   // 中继模式
//! registry.register(.direct, 0x01, mem_transport.asTransport()); // 直连模式
//!
//! // 获取并使用（需指定路径类型）
//! if (registry.get(.relay, 0x01)) |transport| {
//!     try transport.send(0x01, body_data);
//! }
//! ```

// ============================================================================
// 核心模块
// ============================================================================

/// 传输接口定义
pub const client = @import("backend.zig");

/// 传输注册表
pub const registry = @import("registry.zig");

/// 内存传输实现
pub const memory = @import("memory.zig");

/// 直连 QUIC 传输实现
pub const direct = @import("direct.zig");

// ============================================================================
// 便捷导出
// ============================================================================

/// 后端传输接口
pub const BackendTransport = client.BackendTransport;

/// 传输错误类型
pub const TransportError = client.TransportError;

/// 传输注册表
pub const TransportRegistry = registry.TransportRegistry;

/// 传输路径类型（relay/direct）
pub const TransportPath = registry.TransportPath;

/// 内存传输（测试/开发用）
pub const MemoryTransport = memory.MemoryTransport;

/// 发送消息记录
pub const SentMessage = memory.SentMessage;

/// 直连 QUIC 传输
pub const DirectTransport = direct.DirectTransport;

/// 直连传输配置
pub const DirectConfig = direct.DirectConfig;

/// 获取全局注册表
pub const getGlobalRegistry = registry.getGlobalRegistry;

/// 重置全局注册表
pub const resetGlobalRegistry = registry.resetGlobalRegistry;

// ============================================================================
// 未来扩展（占位）
// ============================================================================

/// NATS 传输实现（待实现）
pub const nats = @import("nats.zig");

/// 消息发布器（待实现）
pub const publisher = @import("publisher.zig");

// ============================================================================
// 测试
// ============================================================================

test {
    const std = @import("std");
    std.testing.refAllDecls(@This());

    // 确保所有子模块的测试都被执行
    _ = client;
    _ = registry;
    _ = memory;
    _ = direct;
}
