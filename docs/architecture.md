# Lyune Gateway 架构设计文档

## 1. 系统概述

Lyune Gateway 是面向实时通信场景的分布式传输网关。客户端可以通过 Raw QUIC 或
WSS/TCP 接入；网关到后端与节点间数据面当前仍使用 QUIC。两种客户端 binding 共享
同一份认证、Exchange、路由、推送和生命周期状态，不形成两套业务实现。

### 1.1 核心定位

- **在线传输网关**：只关心“数据怎么传、传给谁”，不拥有业务消息、好友或房间权威状态
- **协议解耦**：网关层帧协议与业务层应用协议分离
- **双向传输抽象**：客户端侧使用 `TransportSession`，后端侧使用 `BackendTransport`
- **可扩展后端路径**：当前实现 DirectTransport；走哪条路径由服务端注册关系决定，客户端无感

### 1.2 核心能力

| 能力 | 说明 |
| --- | --- |
| 多传输接入 | 原生客户端走 Raw QUIC；浏览器与 UDP 不可用环境走 WSS/TCP |
| Exchange | 一次性与多帧流式交换、required/none 回应、双向取消 |
| 灵活路由 | `ScopedRoute(realm, RouteId)` 命中唯一后端 Transport 实例 |
| 在线投递 | 按连接投递、同一身份的多会话索引、组播、临时消息、连接级 lifecycle/presence；业务聚合由后端负责 |
| 分布式数据面 | Thread-per-Core、CID 归属、跨 Worker 交接、跨节点 forward/peer link |
| 异步 I/O | Zig + libxev，macOS kqueue / Linux io_uring；QUIC 使用 picoquic |

## 2. 整体架构

```text
Native client -- lyune/2 Raw QUIC ---------+
                                             +-> session contract
Browser/fallback -- lyune.v2 WSS/TCP -------+        |
                                                     v
                                             GatewayWorker
                                   connection / auth / ingress / egress
                                                     |
                                      ScopedRoute -> Registry
                                                     |
                                              BackendTransport
                                                     |
                                    DirectTransport -> Reactor service

cluster control: SWIM/HMAC membership
packet ownership: CID -> local handoff / forward UDP tunnel
application delivery: local MessageRouter / peer QUIC+mTLS
```

完整的逐事件调用链见 [运行时执行流](execution_flow.md)。

## 3. 运行时架构

### 3.1 Thread-per-Core 模型

网关采用 Thread-per-Core 架构。每个 Worker 独占事件循环、客户端会话、QUIC 上下文、
WSS listener 和后端 transport 状态。正常数据面不共享可变业务状态；跨 Worker 的原始包
与应用消息分别通过两条进程级有界队列交接：

```
UDP SO_REUSEPORT + CID/BPF             TCP SO_REUSEPORT
              |                               |
   +----------+----------+          +---------+---------+
   |          |          |          |         |         |
Worker 0   Worker 1  ... Worker N  Worker 0 Worker 1 ... Worker N
   |          |          |             |       |
   + xev.Loop + ServerDriver            + WSS Listener
   + ConnectionManager                  + session contract
   + ingress/egress/inflight/auth/lifecycle
   + TransportRegistry/DirectFactory/BackendPool
```

- 主线程按 Worker ID 顺序创建 `SO_REUSEPORT` socket 组，socket index 与 Worker ID 固定对应
- Linux classic reuseport BPF 按服务端 CID 在内核态选择 socket；Initial 和未知 CID 回退内核默认哈希
- TCP accept 后连接终身留在接住它的 Worker；认证后的 dest_id 不能用来迁移 TLS 状态
- 每个 Worker 的 `ConnectionManager`、picoquic 上下文、WSS 队列和后端池完全本地化
- 线程数由 `config/gateway.json` 的 `runtime.threads` 显式指定，范围为 1-256

### 3.2 客户端接入与 QUIC 驱动结构

Raw QUIC 的每个线程内部处理分为三层；WSS 则在同一 `xev.Loop` 上完成 TCP/TLS/Upgrade，
随后两者都进入 `session.Handler`：

```
┌──────────────────────────────────────────────────────┐
│                  GatewayWorker (业务层)                │
│  职责：连接管理、认证、逐帧分派、上下行路由             │
│  组件：ConnectionManager, framing.drainFrames          │
├──────────────────────────────────────────────────────┤
│                  ServerDriver (驱动层)                 │
│  职责：组装 Endpoint + IoLoop，驱动事件循环             │
│  核心：收包 → 协议处理 → 发包 → 定时器更新              │
│  发送：GSO 缓冲区 64KB，批量最多 64 包                  │
├──────────────────────────────────────────────────────┤
│                  IoLoop (传输层)                       │
│  职责：基于 libxev 的 UDP 收发、定时器、异步通知        │
│  平台：macOS kqueue / Linux io_uring                   │
│  优化：Linux sendmmsg 批量发送                          │
└──────────────────────────────────────────────────────┘
```

事件驱动流程：

```
UDP 包到达
  → IoLoop.recvCallback (libxev kqueue/io_uring 事件)
    → ServerDriver.internalOnUdpRecv
      → Endpoint.handleIncomingPacket (picoquic 协议栈处理)
      → ServerDriver.processQuicEvents
        → flushPendingPackets (批量发包)
        → updateTimer (调度下一次唤醒)
      → 回调 GatewayWorker.handleNewConnection / handleStreamData / handleConnectionClose
```

WSS 对应流程为 `TCP accept → TLS → HTTP Upgrade → WebSocket binary → envelope record →
session.Handler`。反向发送统一经 `TransportSession` vtable；因此 ingress/egress 不知道本次
Exchange 使用真实 QUIC stream 还是 WebSocket logical stream。

### 3.3 Connection ID 线程路由

picoquic 的 Connection ID 回调生成固定 12 字节 CID v1：

```
magic(2) | version=1(1) | node_id(2) | worker_id(1) | entropy(6)
```

Linux reuseport BPF 校验 magic/version 后直接返回 `worker_id` 对应的 socket index。Worker 收包时
解析同一 CID：node_id 为本机但 Worker 不同则进入有界 `LocalPacketRouter`；node_id 属于其他
alive/suspect 成员则通过独立 UDP 隧道转发到归属节点；无法识别的 Initial/外部 CID 回退本地
picoquic 处理。连接状态始终只存在于签发 CID 的 Endpoint。

### 3.4 进程级协调与控制面

`Coordinator` 是进程级生命周期边界，负责节点状态、Worker 状态和集群运行器：

- 节点状态：`configured -> running -> draining -> stopped`
- Worker 状态：`starting -> running -> stopped`
- 集群启用时持有独立 membership v1 UDP runner 和双向 forward tunnel v1；单机模式不创建额外 socket/线程
- `direct` 模式不创建 forward 隧道；`anycast` 模式由 CID owner 直接回包；`l4_lb` 模式使用 Worker 本地有界回程表，把响应封装回原入口 Worker
- membership v1 使用 SWIM、anti-entropy、Lifeguard 和 HMAC 双密钥维护零锁成员视图
- `draining` 先由协议线程广播 `left`，再拒绝新连接；已有连接仍由原 Worker 持有
- 相同 node_id 出现不同地址时 runner fail-fast，避免 CID 路由身份不唯一
- `LocalPacketRouter` 是固定容量、预分配的 MPSC 队列，只搬运原始 UDP 包，不迁移 picoquic/TLS/拥塞控制状态
- 控制面不参与后端寻址；`DirectTransport` 仍从自身副本列表选择后端并通过异步 DNS 建连
- etcd、Consul 等后端寻址方式将来以新的 Transport 实现类型接入，不进入控制面

## 4. 协议分层模型

### 4.1 分层架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        协议分层                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              业务协议层 (Application Protocol)           │   │
│  │  • 类 HTTP 语义 (请求行/状态行 + 头部 + 数据)            │   │
│  │  • 由后端服务和客户端 SDK 处理                           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                            ▲                                    │
│                            │ Body                               │
│                            │                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              帧协议层 (Frame Protocol)                   │   │
│  │  • 变长帧头（OPEN 8B / DATA 4B）+ 变长 Body               │   │
│  │  • 由网关和客户端 SDK 处理                               │   │
│  └─────────────────────────────────────────────────────────┘   │
│                            ▲                                    │
│                            │                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              客户端 binding                             │   │
│  │  • Raw QUIC：原生 stream / datagram                     │   │
│  │  • WSS/TCP：envelope logical stream / ephemeral record  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 各端职责划分

| 角色         | 解析协议层        | 核心职责                                 |
| ------------ | ----------------- | ---------------------------------------- |
| **客户端**   | 帧协议 + 业务协议 | 封装/解析完整帧，构造/处理业务负载       |
| **网关**     | 仅帧协议          | 解析帧头做路由决策，默认透传完整帧       |
| **后端服务** | 帧协议 + 业务协议 | 使用帧元数据关联请求，处理 Body 业务负载 |

### 4.3 设计优势

1. **职责清晰**：网关专注传输路由，后端专注业务逻辑
2. **路由一致**：RouteId（Group + RouteKey）、Flags 和 Exchange 信息在全链路保留
3. **协议稳定**：后端只依赖固定帧头，不需要理解网关内部实现
4. **扩展灵活**：新增服务只需配置 RouteId 映射

## 5. 路由模型：RouteId 与 Transport 实例

这是网关路由最核心的语义拆分，所有路由相关的设计与实现都必须遵守，避免跑题。

### 5.1 两层语义，一个交汇点

路由涉及两层彼此独立的语义：

- **Transport 实现类型 = 传输方式的语义**，只回答"数据怎么传"。
  `BackendTransport` 是纯 vtable 接口（resolve / send / receive / close）；`DirectTransport`（直连 QUIC）、将来的中继实现（经 NATS）等是它的实现类型。实现类型只表达传输方式，**不携带任何使用场景/业务语义**。
- **RouteId = 使用场景的语义**，只回答"哪个业务、哪个场景"。
  `RouteId = Group（业务组）+ RouteKey（组内场景）`，是帧头携带的复合路由键；网关
  再加上握手确定的 realm 得到 `ScopedRoute`。

两层语义的**唯一交汇点**是 `TransportRegistry`：维护
`ScopedRoute → Transport 实例` 的一一映射。交汇只发生在这一处，两边可以独立演化。

### 5.2 ScopedRoute 对应"实例"，而不是"实现类型"

- 在**同一个 Worker 内**，相同 realm、相同 RouteId 命中同一个 `ScopedRoute`，因而命中同一个 Transport 实例；不同 realm 不共享这个逻辑实例。不同 Worker 各自拥有线程私有实例，不跨线程共享 transport 状态。
- 不同 `ScopedRoute` 即使都采用直连方式（同为 DirectTransport 这一实现类型），也各自对应**独立的 Worker-local 实例**。例如同一 realm 内 RouteId 1+0（聊天）与 2+0（支付）都走直连，但它们是两个逻辑服务，各有独立的 DirectTransport 实例、后端副本集合、连接状态与接收队列；同一 Worker 内只共享 BackendPool 的底层 QUIC 设施。
- 因此实现类型是可多次实例化的"类"；每个 Worker 的实例数量由 realm 与 RouteId 的有效组合决定，与实现类型的种类无关。

### 5.3 实例内部是黑盒

一个 DirectTransport 实例 = 一个逻辑服务的直连出口：

- 实例的配置就是该服务的全部后端副本（endpoints 列表），内部按 host:port 去重管理本路由的 BackendConn；
- 如何寻址、建连、选副本、复用连接，全部是实现的私事，注册表和 Worker 不感知、不参与；
- 路由语义不进入实现内部：resolve / send 的 route 参数只是接口契约，实现内不用它做二次分流。

### 5.4 与集群服务发现的边界

控制面（Coordinator）层面的"服务发现"指网关**集群本身**的节点成员与生命周期管理；"实例内部寻址后端副本"是 Transport 实现的内部行为。两者是不同层级的概念，互不相干。etcd / Consul 等后端寻址方式将来以新的 Transport 实现类型接入，不进入控制面。

### 5.5 演化规则

- 新增一个业务场景：在目标 realm 下配置 RouteId 及其副本列表，装配时注册一个新的 `ScopedRoute` 实例，不改任何传输代码；
- 新增一种传输方式：加一个实现类型，不改路由逻辑；
- 当前热加载只允许新增 realm 和 route；修改既有 RouteId 的绑定、参数或 endpoint 会整次拒绝。
  将来若扩展为完整动态配置，仍应通过注册表与 Transport 实例边界实现，不把部署策略写入帧协议。

## 6. 连接管理策略

### 6.1 Gateway-initiated 模式

采用**网关主动连接后端**的模式：

```
┌────────────────────────────────────────────────────────────────┐
│                     连接管理流程                                │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│   网关启动                                                      │
│      │                                                         │
│      ▼                                                         │
│   读取配置，按 ScopedRoute 装配并注册 Transport 实例              │
│   ┌─────────────────────────────────────────────┐              │
│   │ TransportRegistry（ScopedRoute → 实例）      │              │
│   │ ┌─────────────────────────────────────────┐ │              │
│   │ │ 1+0 → DirectTransport 实例 A（聊天）    │ │              │
│   │ │ 2+0 → DirectTransport 实例 B（支付）    │ │              │
│   │ │ 3+0 → RelayTransport  实例 C（规划中） │ │              │
│   │ └─────────────────────────────────────────┘ │              │
│   └─────────────────────────────────────────────┘              │
│      │                                                         │
│      ▼                                                         │
│   收到客户端帧                                                  │
│      │                                                         │
│      ├─── 解析帧头，取 RouteId（Group + RouteKey）              │
│      │                                                         │
│      ▼                                                         │
│   注册表按 ScopedRoute(realm, RouteId) 命中唯一 Transport 实例    │
│      │                                                         │
│      ▼                                                         │
│   实例内部完成寻址/建连/连接复用（对上层黑盒），                  │
│   向后端透传完整帧；中继实例则发布到对应 topic                    │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 6.2 路由状态与共享传输设施

每个 `DirectTransport` 实例私有地管理本路由的 endpoint 列表、连接状态机与接收队列；
同一 Worker 内所有实例共享一个 `BackendPool` 提供的 QUIC client/socket/picoquic context、
GSO 缓冲和有界接收槽位。共享的是昂贵设施，不是 RouteId、stream 或队列归属：

```
┌──────────────────────────────────────────┐
│ Worker-local BackendPool                  │
│  ├── shared AsyncClient / QUIC context    │
│  ├── cnx -> owning BackendConn index      │
│  └── bounded receive slot arena           │
│        ▲                         ▲         │
│        │                         │         │
│ DirectTransport A          DirectTransport B│
│ Route A conns/queues       Route B conns/queues│
└──────────────────────────────────────────┘
```

BackendPool 根据 cnx 把 callback 精确交回拥有它的 BackendConn；每条连接的字节顺序、
realm 配额和队列仍独立。所有共享者的 TLS client identity 必须一致，不一致时明确拒绝，
避免静默复用错误证书。

## 7. 扩展性设计

### 7.1 新增后端服务

在对应配置的目标 realm 下新增一条路由（RouteId + 该服务的 endpoints 副本列表），装配时会在每个 Worker 的注册表中为这个 `ScopedRoute` 建立独立 Transport 实例；热加载路由则由实际命中的 Worker 惰性创建。

**网关代码无需修改。**

### 7.2 目的地类型（dest_kind）

传输路径（直连/中继）不在帧头编码——那是服务端的部署决策，由 RouteId 的注册关系决定，客户端无感。帧头只表达"发给谁"：

| dest_kind    | 值   | 说明                                 |
| ------------ | ---- | ------------------------------------ |
| `.gateway`   | 0x00 | 网关本地处理，不转发（控制交换）     |
| `.service`   | 0x01 | 按 RouteId 转给后端服务              |
| `.peer`      | 0x02 | 投递给一个或多个客户端（已实现）     |
| `.multicast` | 0x03 | 投递给一个组播组（已实现）           |
| 其余         | -    | 解码时拒绝（白名单），不留未定义语义 |

"怎么传"由帧数表达而不是由字段表达：一次性交换是一个带 `eof` 的 OPEN，流式交换是 OPEN + N×DATA。详见 `docs/protocol_design.md` §5.2。

### 7.3 RouteId 空间

RouteId = Group（u8，业务组）+ RouteKey（u8，组内场景），共 65536 个使用场景标识，对绝大多数系统足够。

## 8. 组件分层与依赖

网关由自上而下、无环依赖的组件层组成，组装集中在最上层 `app/`（组合根）：

```text
main -> app (composition root)
          |
          +-> wss -----------+
          |                   v
          +-> worker -----> session (pure client-session contract)
          |      |
          |      +-> control / backend / protocol / reactor
          |                                  |
          +--------------------------------> quic <-> io
                                               |      |
                                               +--+---+
                                                  v
                                             foundation
```

- app：加载配置、装配组件、拉起进程（`app/config.zig` 装配 RuntimeConfig，`app/bootstrap.zig` 编排 Coordinator/socket 组/多 Worker）
- worker：数据面 per-core，传输无关客户端会话、流分发、认证、消息聚合
- session：无具体 I/O 依赖的客户端会话身份、I/O vtable 与 binding/Worker 双向端口
- wss：TLS/TCP/WebSocket/envelope binding，只依赖 session 契约，不导入 Worker
- control：控制面，节点/Worker 生命周期、SWIM membership 与集群运行器
- backend：后端出口，BackendTransport 接口 + 直连实现 + 路由注册表
- reactor：事件反应堆，组装 Endpoint + IoLoop 驱动收发循环
- protocol：帧头编解码与流处理器
- quic：picoquic 引擎封装，并提供 Raw QUIC 到 session 契约的 adapter
- io：事件循环、reuseport 分流、CID、本地交接与节点间 UDP 转发隧道
- foundation：配置、错误、网络地址、时间、异步 DNS

具体 binding 和 Worker 不互相导入，由 app 组合根同时持有并连接两侧端口。组件遵循统一
约定：单一 `mod.zig` 暴露接口、依赖注入、`init`/`deinit` 生命周期、可单独测试与替换。
详见 [目录设计](directory_design.md) 与 [运行时执行流](execution_flow.md)。

## 9. 初步结构审计结论与当前审计状态

截至 2026-08-30 的初步结构审查确认以下结构在当前基线中应保留：

- `app` 是唯一组合根，配置转换、socket 组、线程闸门和销毁顺序集中；
- Worker 仍是线程私有状态的唯一 owner，按 connection/ingress/egress/inflight/auth/
  lifecycle 拆分关注点是合理的；不按文件行数机械拆散一个状态所有者；
- 解密前的原始包纠偏与解密后的应用消息投递保持两条线路；
- `ScopedRoute -> BackendTransport` 与集群 membership 保持正交；
- 在线状态按连接发布，不在网关内做多设备聚合或业务房间权威。

本轮已经收敛的结构问题：

- 客户端会话契约从 `worker/` 提升到顶层 `session/`；
- WSS Listener 与 Worker 之间改为 `Handler`/`Acceptor` 端口，消除双向具体依赖；
- `TransportSession` 从写死 Raw QUIC/WSS 的 union 改为类型擦除 vtable，Raw adapter
  归入 `quic/session.zig`，`session/` 不再间接依赖 picoquic；
- DirectFactory 在运行期 route 注册失败时回滚最后创建的实例，避免重试耗尽定容槽位；
- placement/Coordinator 的 Worker 数量使用 `u16`，配置值 256 不再在内部表示层溢出。

2026-09-01 起项目进入由所有者主导的源码逐行审计。上面的结论是当前阅读起点，不是对
全部实现细节的最终背书。认证响应累计上限、UDP 有界发送、两段连接的端到端背压、
membership 快照发布证明、热加载事务化等先作为待审计风险保留；未经证据排序不直接
实施。范围、记录模板与完成条件见 [源码逐行审计](code_audit.md)。
