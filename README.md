# Lyune Gateway

Lyune Gateway 是一个使用 Zig 构建的分布式实时通信网关。它负责 Raw QUIC/WSS 连接接入、流分发、在线推送和后端转发，只解析网关帧协议，不解析业务 Body。

项目当前处于源码审计阶段：核心数据面、单机多 Worker 和主要分布式链路已经形成代码基线，但尚未发布版本，也没有生产环境使用者。客户端 I/O 已抽象为传输无关的 `TransportSession`；保持现有 `lyune/2` 线格式的 Raw QUIC 与新的 `lyune.v2` WSS binding 均已完成 Mac 自动化 M0–M18。WSS/Raw 真实 SQLite 群聊、协议并发与取消、慢消费者、断线补偿、presence、120 秒长流、双 Worker、反复进程故障和混合 soak 均已通过。人工浏览器验证已经确认 WSS 与 Raw QUIC 共享真实用户、SQLite 历史和在线推送路径，但完整双向实时/UI 负例清单尚未关闭。当前冻结功能演进和远程 Linux 验证，先由项目所有者逐行审计源码，再决定后续方向。审计范围见 [源码逐行审计](docs/code_audit.md)，真实运行证据见 [两阶段真实环境验证](docs/validation.md)。

## 当前基线

已经实现的主路径包括：

- Zig 0.16.0、picoquic/picotls/BoringSSL、libxev 与 c-ares 的构建集成；
- 类型擦除 `TransportSession` 客户端接入边界、保持 `lyune/2` 行为的 Raw QUIC adapter，以及 TLS/TCP 上的 `lyune.v2` WSS adapter；
- Thread-per-Core Worker、Linux `SO_REUSEPORT` cBPF 分流和有界跨 Worker 交接；
- ALPN `lyune/2`、OPEN/DATA/CONTROL/DATAGRAM 帧协议，以及 OPEN 上显式的 required/none 响应模式；
- 客户端请求、流式转发、后端响应、认证委托和在线推送闭环；
- 客户端发起请求与网关发起推送的双向流权限分离，以及 RESET_STREAM/STOP_SENDING 取消传播；
- 128 位进程隔离 `conn_token`、严格递增 lifecycle sequence 和可续期的连接级 presence 租约；
- `.peer`、`.multicast`、流式推送与 QUIC DATAGRAM；
- SNI → realm、多 realm 命名空间隔离和共享资源的 realm 级公平准入；
- `BackendTransport`、`DirectTransport`、按 `ScopedRoute` 隔离的路由实例，以及每 Worker 共享的后端 QUIC 设施；
- SWIM membership、anti-entropy、Lifeguard、HMAC 双密钥和真实 UDP runner；
- CID v1、跨 Worker 原始包交接、跨节点 forward tunnel；
- 节点间 QUIC+mTLS peer link、HRW affinity/broadcast、双查与 rehome；
- SIGHUP 增量热加载（仅允许新增 realm 与路由）和 drain 生命周期。

当前基线仍有明确缺口，主要是端到端主动背压、认证响应缓冲上限、UDP 有界发送队列、热加载提交原子性、生产安全配置强制、指标导出，以及 Linux 多进程/netem/soak 验证。这些是已知风险，不代表已经批准的下一轮实现计划；应先经过源码审计和证据排序。完整清单见 [当前实现状态](docs/status.md)，当前门禁见 [源码逐行审计](docs/code_audit.md)，演进顺序见 [Roadmap](docs/roadmap.md)。

## 架构边界

Lyune Gateway 是在线传输网关，不是业务消息系统：

- 一条 transport stream 对应一次交换：Raw QUIC 使用真实 stream，WSS 使用 logical stream；多路复用与有序性由各 binding 保证，但 TCP/WSS 不具备 QUIC 的独立流控与丢包隔离；
- 客户端通过 `dest_kind + RouteId` 表达目的地，不指定 direct/relay 等部署路径；
- realm 由 TLS SNI 确定，客户端不能通过帧切换隔离域；
- 网关不保存好友关系、房间成员权威、离线消息或业务幂等状态；
- 在线推送采用 at-most-once 语义，持久化、重试和离线补偿属于后端；
- 集群只对成员视图要求最终一致，不引入 Raft 或外部连接目录；
- 节点故障后客户端重连，不复制或迁移 QUIC/TLS 连接状态。

运行时主路径：

```text
Raw QUIC client -> UDP SO_REUSEPORT / CID(node_id, worker_id) ─┐
Browser / TCP fallback -> WSS TLS/TCP listener ────────────────┤
                                                               v
  GatewayWorker (one event loop per worker)
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

当前验证结果：

- `zig fmt --check build.zig src` 通过；
- 默认测试 285 个：284 通过、1 跳过；
- Reactor 与 client-agent 的 Go 测试通过，React 生产构建通过；
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

单 realm 配置可以省略 route 上的 `realm`，此时默认值为 `0`；因此默认 `backend.direct.routes` 中没有显式 `realm` 是有意行为。配置非空 `realms` 列表后，每条后端 route 必须用 `realm` 指向已经声明的域，注册表实际键始终是 `ScopedRoute(realm, group, route_key)`。

仓库中的 `server.crt`、`server.key` 和默认 `gateway.json` 仅用于本地开发。默认配置使用 UDP 8443 接入 Raw QUIC、把后端路由指向本机 Reactor 的 UDP 9443，并关闭 WSS、后端证书验证、客户端认证和集群能力；真实 IM 验证配置才额外启用 TCP 8444 的 WSS。默认配置不是生产安全模板。

Mac 真实 IM 验证使用独立配置，不修改默认配置：

```bash
go -C ../lyune-reactor/reactor run . \
  --listen 127.0.0.1:9443 \
  --cert ../../lyune-gateway/server.crt \
  --key ../../lyune-gateway/server.key \
  --db /private/tmp/lyune-im-mac-stage.sqlite
zig build run -- server --config config/validation-im-macos.json
go -C validation/client-agent run . --listen 127.0.0.1:8787
npm --prefix validation/web-client install
npm --prefix validation/web-client run dev
```

浏览器打开 `http://127.0.0.1:5173`，可注册两个用户、建群、凭邀请码入群并实时互发消息。页面默认直接使用 `wss://localhost:8444/lyune/v2`，也可以切换为经 client-agent 建立的真实 `lyune/2` Raw QUIC，用于对照两种 binding 的业务语义。完整的 Reactor 命令、密码/成员授权判据、M0–M18 验收矩阵和逐次证据见 [两阶段真实环境验证](docs/validation.md)。

Mac 上也可以从本项目根目录一键启动全部四个进程：

```bash
./run-im-demo.sh
```

脚本自动构建、检查 UDP 8443/TCP 8444 等端口、按依赖顺序启动并打开浏览器；日志写入 `/private/tmp/lyune-im-demo/`，消息持久化到 `/private/tmp/lyune-im-demo.sqlite`，按 `Ctrl+C` 会有序停止全部子进程。需要全新数据时使用 `./run-im-demo.sh --reset`，不希望自动打开浏览器时增加 `--no-open`；Mac 多 Worker/reuseport 门禁使用 `./run-im-demo.sh --workers 2`。

`server.crt` 是只覆盖 `localhost` 与 `127.0.0.1` 的自签名开发证书。首次使用浏览器 WSS 前，需要在 macOS“钥匙串访问”中导入它并仅对本地开发设为信任，然后重新打开页面；浏览器不能通过 JavaScript 绕过证书校验。Raw QUIC 对照不依赖浏览器的证书信任。

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
├── comate_chat_export/          # 只读 AI IDE 历史会话归档，不是当前规范
├── config/gateway.json
├── config/validation-*.json     # Mac 真实链路与压力诊断配置
├── docs/
├── libs/                       # picoquic / picotls submodules
├── validation/
│   ├── client-agent/           # browser-adjacent Go QUIC client
│   ├── web-client/             # React real-IM UI（直连 WSS / Raw QUIC 对照）
│   ├── wss-smoke.mjs           # 无第三方依赖的 WSS 协议探针
│   ├── wss-mixed-im.mjs        # WSS↔WSS↔Raw QUIC 真实 SQLite 群聊验证
│   ├── wss-negative.mjs        # logical stream 与 WebSocket 违规负门禁
│   ├── wss-capacity.mjs        # 每 Worker WSS 连接容量负门禁
│   ├── wss-protocol.mjs        # ping/streaming/32 并发/none/RESET/STOP
│   ├── wss-reconnect-im.mjs    # 离线持久化与重连历史补偿
│   ├── wss-slow-consumer.mjs   # 单会话背压与慢消费者隔离
│   ├── wss-presence.mjs        # 双连接 presence 与 15 秒续租
│   ├── wss-long-stream.mjs     # 120 秒长流与静默 sibling 隔离
│   └── wss-fault-recovery.mjs  # Reactor/Gateway 反复故障与身份隔离
└── src/
    ├── app/                    # configuration and composition root
    ├── worker/                 # per-core data plane
    ├── session/                # transport-neutral client session contracts
    ├── control/                # lifecycle and membership
    ├── backend/                # backend transport abstraction
    ├── reactor/                # QUIC/libxev drivers
    ├── protocol/               # gateway frame protocol
    ├── quic/                   # picoquic wrapper
    ├── wss/                    # TLS、WebSocket、envelope 与有界队列
    ├── io/                     # UDP, CID, reuseport and handoff
    └── foundation/             # config, realm, quota, DNS and utilities
```

完整目录职责见 [目录设计](docs/directory_design.md)。

## 文档

文档入口与权威关系见 [docs/README.md](docs/README.md)：

- [当前实现状态](docs/status.md)：当前代码事实、验证结果和已知缺口；
- [源码逐行审计](docs/code_audit.md)：当前冻结规则、审计顺序、发现分类和完成条件；
- [两阶段真实环境验证](docs/validation.md)：MacBook 与远程 Linux 的真实验证计划、退出条件和执行记录；
- [Roadmap](docs/roadmap.md)：迭代优先级，不代表发布日期承诺；
- [架构设计](docs/architecture.md)：组件边界与核心模型；
- [运行时执行流](docs/execution_flow.md)：启动、接入、认证、Exchange、回程、推送与关闭；
- [帧协议设计](docs/protocol_design.md)：应用层线格式与设计决策；
- [多传输客户端会话设计](docs/transport_session_design.md)：TransportSession 边界与门禁；
- [WSS 传输 binding](docs/wss_transport.md)：TLS/Upgrade、逻辑流 envelope 与资源边界；
- [集群设计](docs/cluster_design.md)：membership、CID、forward tunnel 与故障模型；
- [目录设计](docs/directory_design.md)：源码结构和模块职责。

## 发布状态

当前没有正式版本、兼容性承诺或生产发布计划。协议仍可能继续破坏性调整；每次改变线格式都必须提升 ALPN 版本，不能在同一个 ALPN 下静默改变含义。本轮 OPEN 响应模式与 128 位连接身份已经把 ALPN 从 `lyune/1` 提升为 `lyune/2`。
