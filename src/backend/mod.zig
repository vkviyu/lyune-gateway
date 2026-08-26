//! backend —— 后端出口组件层
//!
//! 抽象网关到后端服务的通信方式，向 Worker 提供统一的 BackendTransport 接口：
//!   - transport：BackendTransport 接口定义（vtable + 类型擦除）；
//!   - registry：TransportPath + ScopedRoute → BackendTransport 的路由注册表；
//!   - pool：每 Worker 一份的共享传输设施（一个 QUIC 客户端 + 一份接收槽位池）；
//!   - catalog：进程级共享的路由声明目录（定容 + 原子长度，支持运行期追加）；
//!   - factory：每 Worker 一份的直连实例工厂与仓库（实例只能在自己线程上创建）；
//!   - direct：直连 QUIC 后端的实现（一个实例对应一条路由/一个逻辑服务，内部连接池管理其副本连接）。
//!
//! 未来的中继实现（NATS 等）只需新增一个实现文件并在此导出，Worker 无需改动。

pub const transport = @import("transport.zig");
pub const registry = @import("registry.zig");
pub const pool = @import("pool.zig");
pub const catalog = @import("catalog.zig");
pub const factory = @import("factory.zig");
pub const direct = @import("direct.zig");

pub const BackendTransport = transport.BackendTransport;
pub const TransportError = transport.TransportError;
pub const TransportRegistry = registry.TransportRegistry;
pub const TransportPath = registry.TransportPath;
pub const RouteId = transport.RouteId;
pub const ScopedRoute = registry.ScopedRoute;
pub const RealmId = registry.RealmId;
pub const BackendPool = pool.BackendPool;
pub const RouteCatalog = catalog.RouteCatalog;
pub const RouteEntry = catalog.RouteEntry;
pub const DirectFactory = factory.DirectFactory;
pub const DirectTransport = direct.DirectTransport;
pub const DirectConfig = direct.DirectConfig;

test {
    @import("std").testing.refAllDecls(@This());
}
