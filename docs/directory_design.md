# Lyune Gateway 目录结构文档

## 1. 组件化分层思想

整个网关由一层层「组件」组成。每个组件是一个目录，满足：

- 通过一个 `mod.zig` 暴露清晰的公共接口，外部只依赖 `mod.zig`，不直接伸手进内部文件；
- 依赖通过参数注入（allocator、io、config、其它组件的接口），不依赖隐藏的全局单例；
- 有明确生命周期：`init` → 使用 → `deinit`；可单独测试、可替换实现；
- 依赖方向严格自上而下、无环：上层组件依赖下层，下层不反向依赖上层。

组件的「组装」集中在最上层的 `app/`（组合根），业务逻辑分散在各组件内部。

## 2. 分层总览（自上而下）

```
app/          组合根：加载配置、装配组件、拉起进程
  │
worker/       数据面 per-core：QUIC 连接、流分发、消息聚合
control/      控制面：节点/Worker 生命周期（网关集群自身，不含后端寻址）
backend/      后端出口：BackendTransport 接口、直连实现、路由注册表
reactor/      事件反应堆：组装 Endpoint + IoLoop，驱动收发循环
protocol/     帧协议：帧头编解码、流处理器
quic/         QUIC 引擎：picoquic 绑定与封装
io/           I/O 与内核态分流：事件循环、reuseport、CID、跨 Worker 交接
foundation/   基础设施：配置、错误、网络地址、时间、异步 DNS
```

## 3. 目录结构

```
lyune-gateway/
├── build.zig                     # 构建：编译 picoquic/picotls/c-ares/BoringSSL + reuseport.c + 主程序
├── build.zig.zon                 # 固定依赖（libxev / c-ares / boringssl）
├── server.crt / server.key       # 测试用 TLS 证书/私钥
│
├── src/
│   ├── main.zig                  # 仅命令行解析，随后交给 app 装配层
│   │
│   ├── app/                      # 组合根（应用装配层）
│   │   ├── mod.zig               # serve()：加载配置 → 装配 → 运行
│   │   ├── config.zig            # RuntimeConfig：原始配置 → 组件可用配置
│   │   ├── reload.zig            # SIGHUP 热加载：只接受新增的 realm 与路由
│   │   └── bootstrap.zig         # 进程/Worker 编排：Coordinator、socket 组、启动闸门
│   │
│   ├── worker/                   # 数据面 per-core 组件
│   │   ├── mod.zig               # 暴露 GatewayWorker、connection、ingress、egress、inflight、auth
│   │   ├── worker.zig            # GatewayWorker：装配 + 生命周期 + 优雅停机 + 后端回程分派
│   │   ├── ingress.zig           # 客户端上行：分帧、按 dest_kind 分派、交换状态与错误分级
│   │   ├── egress.zig            # 后端下行：接纳后端主动流、.peer/.multicast 扇出、跨位置转投、后端控制交换
│   │   ├── peer_link.zig         # 节点间应用层投递的出站链路（对等网关节点，mTLS）
│   │   ├── inflight.zig          # 在途请求表：回程映射 + 认证等待表 + 上限与三条回收路径
│   │   ├── auth.zig              # 接入认证：委托后端认证服务、判定结果、亲和重定向
│   │   └── connection.zig        # ConnectionContext + 定容会话槽位池 + dest/组播成员索引 + ConnToken
│   │
│   ├── control/                  # 控制面组件
│   │   ├── mod.zig               # 暴露 Coordinator 与 membership
│   │   ├── coordinator.zig       # 进程级控制面：生命周期 + 本机交接器 + membership/forward
│   │   └── membership/           # SWIM/anti-entropy/Lifeguard、codec、UDP runner、模拟器
│   │
│   ├── backend/                  # 后端出口组件
│   │   ├── mod.zig               # 暴露 BackendTransport / Registry / DirectTransport
│   │   ├── transport.zig         # BackendTransport 接口（vtable 多态）
│   │   ├── registry.zig          # TransportPath + ScopedRoute → Transport 实例映射（每 Worker 私有）
│   │   ├── catalog.zig           # 路由声明目录：定容 + 原子长度，进程级共享，可运行期追加
│   │   ├── factory.zig           # 每 Worker 的直连实例工厂与仓库（实例只能在自己线程上建）
│   │   ├── pool.zig              # 每 Worker 一份的共享传输设施：一个 QUIC 客户端 + 一份接收槽位池
│   │   └── direct.zig            # 直连实现：每个 ScopedRoute 一个实例，内部连接池管理副本
│   │
│   ├── protocol/                 # 帧协议组件
│   │   ├── mod.zig
│   │   ├── frame.zig             # 帧头 / FrameType / DestKind / Flags / ControlType 定义
│   │   ├── body.zig              # 网关会解析的 Body 结构：准入前缀、目标列表
│   │   ├── codec.zig             # FrameEncoder / FrameScanner（就地逐帧扫描）
│   │   └── framing.zig          # 上行分帧：逐帧 drain + 跨回调残帧 spill
│   │
│   ├── reactor/                  # 事件反应堆组件
│   │   ├── mod.zig
│   │   ├── server.zig            # ServerDriver：组装 Endpoint + IoLoop，驱动收发循环与 CID 选路
│   │   ├── return_path.zig       # L4 回程状态：owner 侧回程路由 + ingress 侧回包授权
│   │   └── client.zig            # AsyncClient：网关主动连接后端的异步客户端
│   │
│   ├── quic/                     # QUIC 引擎组件（picoquic 封装）
│   │   ├── mod.zig
│   │   ├── c.zig                 # @cImport 绑定、类型别名、DCID 解析
│   │   ├── endpoint.zig          # Endpoint：picoquic 上下文与 C 回调分发、CID 签发
│   │   ├── connection.zig        # Connection：picoquic_cnx_t 封装
│   │   ├── stream.zig            # Stream 操作句柄
│   │   ├── config.zig            # QUICConfig / 拥塞算法
│   │   └── client.zig            # 基于内置循环的同步客户端
│   │
│   ├── io/                       # I/O 与内核态分流组件
│   │   ├── mod.zig
│   │   ├── loop.zig              # IoLoop：libxev UDP 收发 + 定时器 + sendmmsg 批量发送
│   │   ├── reuseport.c / .zig    # Linux classic BPF reuseport 分类器
│   │   ├── cid.zig               # CID v1 编解码（node + Worker 归属）
│   │   ├── handoff.zig           # 跨 Worker 交接：LocalPacketRouter（原始包）+ MessageRouter（应用消息）
│   │   └── forward.zig           # HMAC、防重放、request/response 双向节点隧道 v1
│   │
│   └── foundation/               # 基础设施组件
│       ├── mod.zig
│       ├── config.zig            # GatewayConfig 定义、JSON 加载与校验
│       ├── errors.zig            # 线程本地错误处理框架
│       ├── net.zig               # 地址与 sockaddr 转换
│       ├── placement.zig         # 选址：(realm, dest_id) 必须落在哪个 (节点, Worker)，HRW
│       ├── quota.zig             # 按 realm 的加权准入：共享定容池上的公平上限
│       ├── realm.zig             # 隔离域：SNI → RealmId 解析表
│       ├── time.zig              # 时间戳
│       └── resolver/             # 异步 DNS 子组件
│           ├── mod.zig           # Resolver 接口 + Cares 实现导出
│           └── cares.zig         # c-ares 异步实现
│
├── config/gateway.json           # 唯一运行配置（runtime/server/backend/worker/cluster）
├── docs/                         # 架构、协议、目录文档
└── libs/                         # picoquic / picotls（git submodule）
```

## 4. 各组件职责

### app/ — 组合根

`main.zig` 只解析命令行；`app.serve` 负责加载配置、`app.config.prepare` 装配 `RuntimeConfig`、`app.bootstrap.run` 组装并运行网关。所有组件在此拼装，除装配外不含业务逻辑。

### worker/ — 数据面 per-core

`GatewayWorker` 独占一个事件循环、一套 picoquic 上下文与连接表，注册新连接/流数据/连接关闭三类回调，同时消费本地跨 Worker 交接队列。

按关注点分成几个文件，切分依据是"谁拥有状态"而不是行数：

- `ingress.zig` —— 上行半边：把字节切成完整帧，按 `frame_type` 与 `dest_kind` 分派（`.gateway` 本地处理、`.service` 开后端流并追加、`.peer` / `.multicast` 越权拒绝）。按流维护交换状态，并据此把错误分成"关连接"与"回错误帧"两级，见 `docs/protocol_design.md` §7.5。
- `egress.zig` —— 下行半边：接纳后端主动发起的流（`.peer` / `.multicast` 推送与后端 → 网关控制交换的载体），重组成完整帧后按 `dest_kind` 分派。本位置的目标直接投递，其余按 `placement` 算出的位置转投给同机其他 Worker或远端节点；跨节点走 `peer_link.zig` 的 QUIC+mTLS 链路。转投过来的消息只做本地投递、绝不再次选址——这是防环的核心机制。
- `inflight.zig` —— 拥有后端流到客户端流的回程映射与认证等待表。这两张表是无界内存增长的防线，回收有三条路径（正常 fin、连接关闭、超时兜底），任何一条漏了都不会立刻报错，因此状态与回收逻辑必须放在一起并单独测试。
- `auth.zig` —— 接入认证：原样转发 auth_request 给后端认证服务，网关不解析 token，只从响应的定长前缀里取两个自己的字段（可寻址的 `dest_id` 与准入有效期）。
- `connection.zig` —— 会话上下文、定容槽位池，以及 `dest_id → [connection]` 索引。索引的链表节点就是槽位本身，因此不需要任何额外分配。
- `worker.zig` —— 装配、生命周期、优雅停机，以及把后端回程事件按归属分给三条路径（认证响应 / 请求响应 / 后端推送）。

回程的**分派**留在 `worker.zig` 而不是并进 `egress.zig`：它与上行共享 `inflight` 里的映射，"插入必须配平删除"这条不变量分到两个文件反而更难看清。`egress.zig` 只拥有推送这一条路径的状态。

### control/ — 控制面

`Coordinator` 是所有 Worker 共享的进程级控制面，持有节点身份、集群关系与生命周期状态。它同时承载本机能力与集群能力，因为三者互相依赖，拆开只会变成两个结构体互相持有指针：

- `packet_router` 被两条路径共用——内核 reuseport 误分流的兜底转投，以及 forward 隧道收到跨节点报文后的投递，因此不属于本机侧或集群侧任何一方；
- `forward_tunnel` 需要 membership 才能把 node_id 解析成地址，也需要 packet_router 才能把报文交给目标 Worker；
- `beginDrain` 必须先广播 `left` 再拒绝新连接，这条顺序约束横跨两侧。

两个可选字段只有三种合法组合：单机时都为 null；集群 + `direct` 时只有 membership；集群 + `anycast`/`l4_lb` 时两者都有。「有隧道无成员视图」不成立，`forwardSender()` 在运行期兜底检查该组合并返回 null。

控制面只关心网关集群自身，不参与后端寻址——后端副本寻址是各 Transport 实例的内部私事（见 `docs/architecture.md` 第 5 章路由模型）。

### backend/ — 后端出口

`BackendTransport` 是网关到后端的统一接口（resolve/send/receive/close），实现类型只表达传输方式语义；`TransportRegistry` 维护 RouteId → Transport 实例的一一映射（使用场景语义），是两层语义唯一的交汇点。`DirectTransport` 每个 RouteId 一个独立实例，实例内部用连接池按 host:port 管理本服务的副本连接。中继（NATS 等）实现后续新增文件即可。

### protocol/ — 帧协议

变长帧头（OPEN 8 字节 / DATA 4 字节）+ 编解码。`FrameScanner` 在 QUIC 送来的字节上就地逐帧扫描，`framing.drainFrames` 负责把跨回调的残帧暂存下来。帧头长度由第一个字节（`frame_type`）决定，因此补齐残帧要先等到那个字节再定型。

### reactor/ — 事件反应堆

`ServerDriver` 采用 Reactor 模式：监听 `io/IoLoop` 的 UDP/定时器事件，驱动 `quic/Endpoint` 的「收包 → 协议处理 → 发包 → 定时器」循环，并向上回调连接/流事件；`AsyncClient` 用于网关主动连接后端。

本层不含应用层业务逻辑（认证、路由键、后端选择都在 worker 层），但承担集群数据面选路：`routeInbound` 按 CID 归属把入站报文分派为「本 Worker 处理 / 同机跨 Worker 交接 / 跨节点隧道转发」——归属判断必须在报文进入 picoquic 之前完成，无法上移。

`return_path.zig` 独立承载 L4 回程状态，owner 侧记录「响应经由哪个入口回去」，ingress 侧记录「允许哪个 owner 为该客户端回包」。后者是安全边界：缺少它，任何能向 forward 隧道发包的对端都能让本节点朝任意客户端地址发送任意字节。

### quic/ — QUIC 引擎

picoquic 的 Zig 封装。`Endpoint` 在 CID 回调中调用 `io/cid.zig` 签发同时编码 node_id 与 Worker 归属的 12 字节 CID v1。

### io/ — I/O 与内核态分流

`IoLoop` 基于 libxev（macOS kqueue / Linux io_uring），Linux 下 `sendmmsg` 批量发送。`reuseport` 提供内核态 CID 分流；`cid` 负责 CID v1 编解码；`handoff` 提供误分流兜底的有界包交接；`forward` 负责带 HMAC、目标绑定和防重放的 request/response 双向节点隧道 v1，其 Worker 本地回程状态见 `reactor/return_path.zig`。

### foundation/ — 基础设施

不依赖任何业务代码，提供配置、错误、地址、时间、异步 DNS 等通用能力。

## 5. 依赖关系

```
                    ┌──────────┐
                    │  main    │
                    └────┬─────┘
                         ▼
                    ┌──────────┐
                    │   app    │  组合根
                    └────┬─────┘
        ┌───────────┬────┴──────┬───────────┐
        ▼           ▼           ▼
   ┌────────┐  ┌────────┐  ┌──────────┐
   │ worker │  │control │  │ backend  │
   └───┬────┘  └───┬────┘  └────┬─────┘
       │           │            │
       └─────┬─────┴────────────┤
             ▼                  ▼
        ┌──────────┐      ┌──────────┐
        │ reactor  │      │ protocol │
        └────┬─────┘      └────┬─────┘
             ├─────────┬───────┘
             ▼         ▼
        ┌────────┐ ┌────────┐
        │  quic  │ │   io   │
        └───┬────┘ └───┬────┘
            └────┬─────┘
                 ▼
          ┌────────────┐
          │ foundation │
          └────────────┘
```

> 依赖始终自上而下。`io` 与 `quic` 之间存在少量互引用（`io/loop` 使用 quic 的时间工具，`quic/endpoint` 使用 `io/cid`），属同层协作，Zig 模块级导入允许。

## 6. 实现状态

本文件只维护目录和模块职责，不再复制功能完成清单。当前已实现能力、测试结果、已知缺口与
明确不做的能力统一见 `docs/status.md`，迭代顺序见 `docs/roadmap.md`。

这样可以避免源码目录变化后，README、协议设计、集群设计和本文件各自保留一份相互矛盾的
“已实现/未实现”列表。
