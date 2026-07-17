//! backend —— 后端出口组件层
//!
//! 抽象网关到后端服务的通信方式，向 Worker 提供统一的 BackendTransport 接口：
//!   - transport：BackendTransport 接口定义（vtable + 类型擦除）；
//!   - registry：TransportPath + RouteKey → BackendTransport 的路由注册表；
//!   - direct：直连 QUIC 后端的实现（可按服务发现选择实例）。
//!
//! 未来的中继实现（NATS 等）只需新增一个实现文件并在此导出，Worker 无需改动。

pub const transport = @import("transport.zig");
pub const registry = @import("registry.zig");
pub const direct = @import("direct.zig");

pub const BackendTransport = transport.BackendTransport;
pub const TransportError = transport.TransportError;
pub const TransportRegistry = registry.TransportRegistry;
pub const TransportPath = registry.TransportPath;
pub const DirectTransport = direct.DirectTransport;
pub const DirectConfig = direct.DirectConfig;

test {
    @import("std").testing.refAllDecls(@This());
}
