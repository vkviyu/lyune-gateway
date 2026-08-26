//! foundation —— 基础设施组件层
//!
//! 本层不依赖任何业务/协议代码，向上提供最通用的能力：配置、错误处理、
//! 网络地址、时间、异步 DNS 解析。所有其它组件都可依赖 foundation，
//! 但 foundation 不反向依赖它们，保证依赖始终自上而下、无环。

pub const config = @import("config.zig");
pub const err = @import("errors.zig");
pub const net = @import("net.zig");
/// 选址：`(realm, dest_id)` 必须落在哪个 (节点, Worker) 上（见 protocol_design §8.5）。
pub const placement = @import("placement.zig");
/// 按 realm 的加权准入：共享定容池上的公平上限（见 protocol_design §12.4）。
pub const quota = @import("quota.zig");
/// 隔离域：标识只在其内部唯一的管理边界，由 TLS SNI 确定（见 protocol_design §12）。
pub const realm = @import("realm.zig");
/// 异步 DNS 解析组件：接口 Resolver + c-ares 实现 resolver.Cares（见 resolver/ 子目录）。
pub const resolver = @import("resolver/mod.zig");
pub const time = @import("time.zig");

test {
    @import("std").testing.refAllDecls(@This());
    _ = resolver;
}
