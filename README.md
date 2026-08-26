# Lyune Gateway

Lyune Gateway 是一个使用 Zig 构建的分布式 QUIC 实时通信网关。它负责连接接入、QUIC 收发、流分发、在线推送和后端转发，只解析网关帧协议，不解析业务 Body。

项目当前处于持续迭代阶段：核心数据面、单机多 Worker 和主要分布式链路已经形成可运行基线，但尚未发布版本，也没有生产环境使用者。当前重点是收敛正确性、资源上界、可观测性和真实 Linux 集成验证，而不是对外发布。

## 当前基线

已经实现的主路径包括：

- Zig 0.16.0、picoquic/picotls/BoringSSL、libxev 与 c-ares 的构建集成；
- Thread-per-Core Worker、Linux `SO_REUSEPORT` cBPF 分流和有界跨 Worker 交接；
- ALPN `lyune/1`、OPEN/DATA/CONTROL/DATAGRAM 帧协议；
- 客户端请求、流式转发、后端响应、认证委托和在线推送闭环；
- `.peer`、`.multicast`、流式推送与 QUIC DATAGRAM；
- SNI → realm、多 realm 命名空间隔离和共享资源的 realm 级公平准入；
- `BackendTransport`、`DirectTransport`、按 `ScopedRoute` 隔离的路由实例，以及每 Worker 共享的后端 QUIC 设施；
- SWIM membership、anti-entropy、Lifeguard、HMAC 双密钥和真实 UDP runner；
- CID v1、跨 Worker 原始包交接、跨节点 forward tunnel；
- 节点间 QUIC+mTLS peer link、HRW affinity/broadcast、双查与 rehome；
- SIGHUP 增量热加载（仅允许新增 realm 与路由）和 drain 生命周期。

当前基线仍有明确缺口，主要是长流回程映射的空闲超时、端到端背压、认证响应缓冲上限、热加载提交原子性、生产安全配置强制、指标导出，以及 Linux 多进程/netem 验证。完整清单见 [当前实现状态](docs/status.md)，演进顺序见 [Roadmap](docs/roadmap.md)。

## 架构边界

Lyune Gateway 是在线传输网关，不是业务消息系统：

- QUIC stream 对应一次交换，多路复用、有序、ACK 和连接级流控交给 QUIC；
- 客户端通过 `dest_kind + RouteId` 表达目的地，不指定 direct/relay 等部署路径；
- realm 由 TLS SNI 确定，客户端不能通过帧切换隔离域；
- 网关不保存好友关系、房间成员权威、离线消息或业务幂等状态；
- 在线推送采用 at-most-once 语义，持久化、重试和离线补偿属于后端；
- 集群只对成员视图要求最终一致，不引入 Raft 或外部连接目录；
- 节点故障后客户端重连，不复制或迁移 QUIC/TLS 连接状态。

运行时主路径：

```text
client QUIC
  -> SO_REUSEPORT / CID(node_id, worker_id)
  -> GatewayWorker (one event loop per worker)
  -> frame ingress / auth / routing
  -> ScopedRoute(realm, group, route_key)
  -> DirectTransport
  -> backend QUIC service

cluster side paths:
  SWIM UDP/HMAC        -> membership and failure detection
  forward UDP tunnel  -> misrouted encrypted QUIC packets
  peer QUIC/mTLS      -> cross-node .peer/.multicast delivery
```

详细设计见 [架构设计](docs/architecture.md)、[帧协议设计](docs/protocol_design.md) 和 [集群设计](docs/cluster_design.md)。

## 构建与测试

最低 Zig 版本为 `0.16.0`。依赖由 `build.zig.zon`、`build/` 和 `libs/` 管理。

```bash
zig build
zig build test --summary all
zig build -Doptimize=ReleaseSafe
```

需要外部服务的集成测试默认关闭：

```bash
zig build test -Denable-integration-tests=true --summary all
```

当前冻结前验证结果：

- `zig fmt --check build.zig src` 通过；
- 默认测试 245 个：244 通过、1 跳过；
- `ReleaseSafe` 构建 9/9 步通过。

这些结果覆盖单元测试、确定性模拟和部分 loopback UDP 测试，但不能替代 Linux 内核 cBPF、多网关进程和长时间网络故障测试。

## 配置与运行

默认配置文件为 `config/gateway.json`：

```bash
zig build run -- server --config config/gateway.json
```

构建后的可执行文件只提供服务端命令：

```bash
./zig-out/bin/lyune_gateway server [--config PATH]
```

配置覆盖 Worker 数量、客户端 QUIC、后端直连、认证、realm、热加载容量和集群参数。JSON 使用严格解析，未知字段与非法组合会在启动时拒绝。

仓库中的 `server.crt`、`server.key` 和默认 `gateway.json` 仅用于本地开发。默认配置关闭后端证书验证、客户端认证和集群能力，不是生产安全模板。

## 集群部署模式

`cluster.enabled=false` 时不创建 membership/forward socket 或协议线程。启用后支持三种入口模型：

- `direct`：客户端直接选择节点，不启用跨节点原始包纠偏；
- `anycast`：允许入口漂移，owner 节点可以直接向客户端回包；
- `l4_lb`：响应必须通过认证 forward tunnel 回到原入口 Worker，再由服务 socket 返回客户端/LB。

`.peer`/`.multicast` 的跨节点应用投递不走 forward tunnel，而是走独立集群端口上的 QUIC+mTLS peer link。原始包纠偏和应用消息转发具有不同的安全边界与流控语义，不能合并。

## 项目结构

```text
lyune-gateway/
├── build.zig / build.zig.zon
├── config/gateway.json
├── docs/
├── libs/                       # picoquic / picotls submodules
└── src/
    ├── app/                    # configuration and composition root
    ├── worker/                 # per-core data plane
    ├── control/                # lifecycle and membership
    ├── backend/                # backend transport abstraction
    ├── reactor/                # QUIC/libxev drivers
    ├── protocol/               # gateway frame protocol
    ├── quic/                   # picoquic wrapper
    ├── io/                     # UDP, CID, reuseport and handoff
    └── foundation/             # config, realm, quota, DNS and utilities
```

完整目录职责见 [目录设计](docs/directory_design.md)。

## 文档

文档入口与权威关系见 [docs/README.md](docs/README.md)：

- [当前实现状态](docs/status.md)：当前代码事实、验证结果和已知缺口；
- [Roadmap](docs/roadmap.md)：迭代优先级，不代表发布日期承诺；
- [架构设计](docs/architecture.md)：组件边界与核心模型；
- [帧协议设计](docs/protocol_design.md)：应用层线格式与设计决策；
- [集群设计](docs/cluster_design.md)：membership、CID、forward tunnel 与故障模型；
- [目录设计](docs/directory_design.md)：源码结构和模块职责。

## 发布状态

当前没有正式版本、兼容性承诺或生产发布计划。协议仍可能在迭代中调整；发生不兼容变更时应提升 ALPN 版本，而不是在同一个 `lyune/1` 下静默改变线格式。
