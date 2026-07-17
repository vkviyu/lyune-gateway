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
control/      控制面：节点/Worker 生命周期、服务发现
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
│   │   └── bootstrap.zig         # 进程/Worker 编排：Coordinator、socket 组、启动闸门
│   │
│   ├── worker/                   # 数据面 per-core 组件
│   │   ├── mod.zig               # 暴露 GatewayWorker、connection
│   │   ├── worker.zig            # GatewayWorker：事件循环主控 + 流分发 + 跨 Worker 交接消费
│   │   └── connection.zig        # ConnectionContext / ConnectionManager
│   │
│   ├── control/                  # 控制面组件
│   │   ├── mod.zig               # 暴露 Coordinator、ServiceDiscovery
│   │   ├── coordinator.zig       # 节点/Worker 状态机，持有 discovery 与包交接器
│   │   └── discovery.zig         # 版本化服务发现接口 + 配置驱动 StaticDiscovery
│   │
│   ├── backend/                  # 后端出口组件
│   │   ├── mod.zig               # 暴露 BackendTransport / Registry / DirectTransport
│   │   ├── transport.zig         # BackendTransport 接口（vtable 多态）
│   │   ├── registry.zig          # TransportPath + RouteKey → transport 映射
│   │   └── direct.zig            # 直连 QUIC 后端实现（按服务发现选实例）
│   │
│   ├── protocol/                 # 帧协议组件
│   │   ├── mod.zig
│   │   ├── frame.zig             # 帧头 / TransportMode / Flags 定义
│   │   ├── codec.zig             # FrameEncoder / FrameDecoder（增量解析）
│   │   └── handler.zig           # Buffered / Streaming 流处理器
│   │
│   ├── reactor/                  # 事件反应堆组件
│   │   ├── mod.zig
│   │   ├── server.zig            # ServerDriver：组装 Endpoint + IoLoop，驱动收发循环
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
│   │   ├── cid.zig               # 服务端 CID 编解码（Worker 归属）
│   │   └── handoff.zig           # LocalPacketRouter：误分流时的有界跨 Worker 包交接
│   │
│   └── foundation/               # 基础设施组件
│       ├── mod.zig
│       ├── config.zig            # GatewayConfig 定义、JSON 加载与校验
│       ├── errors.zig            # 线程本地错误处理框架
│       ├── net.zig               # 地址与 sockaddr 转换
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

`GatewayWorker` 独占一个事件循环、一套 picoquic 上下文与连接表，注册新连接/流数据/连接关闭三类回调，对新流创建消息处理器并做路由分发；同时消费本地跨 Worker 交接队列。

### control/ — 控制面

`Coordinator` 管理节点与 Worker 生命周期、持有服务发现快照与本地包交接器；`draining` 时拒绝新连接但保留存量连接。`ServiceDiscovery` 是可替换 provider 接口，当前使用配置驱动的 `StaticDiscovery`，将来可换成 etcd/Consul。

### backend/ — 后端出口

`BackendTransport` 是网关到后端的统一接口（resolve/send/receive/close）；`DirectTransport` 按 RouteKey 从服务发现选择健康实例并建立直连 QUIC；`TransportRegistry` 维护路由映射。中继（NATS 等）实现后续新增文件即可。

### protocol/ — 帧协议

16 字节帧头 + 编解码，`FrameDecoder` 处理 QUIC 流上的粘包拆包；提供 Buffered / Streaming 两种流处理器。

### reactor/ — 事件反应堆

`ServerDriver` 采用 Reactor 模式：监听 `io/IoLoop` 的 UDP/定时器事件，驱动 `quic/Endpoint` 的「收包 → 协议处理 → 发包 → 定时器」循环，并向上回调连接/流事件；`AsyncClient` 用于网关主动连接后端。本层不含业务逻辑，只做事件分发。

### quic/ — QUIC 引擎

picoquic 的 Zig 封装。`Endpoint` 在 CID 回调中调用 `io/cid.zig` 签发编码 Worker 归属的服务端 CID。

### io/ — I/O 与内核态分流

`IoLoop` 基于 libxev（macOS kqueue / Linux io_uring），Linux 下 `sendmmsg` 批量发送。`reuseport` 提供内核态 CID 分流；`cid` 负责 CID 编解码；`handoff` 提供误分流兜底的有界包交接。

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

已实现并含测试：

- foundation：config、errors、net、time、resolver（接口 + c-ares）
- io：loop、reuseport（含 BPF 等价测试）、cid、handoff
- quic：c、endpoint、connection、stream、config、client
- protocol：frame、codec、handler
- reactor：server、client
- backend：transport、registry、direct
- control：coordinator、discovery
- worker：worker、connection
- app：config、bootstrap

尚未实现（需要时新增，不占用当前依赖图）：

- backend 中继实现（NATS 等）
- 远端服务发现 provider（etcd/Consul），替换 `StaticDiscovery`
- 日志 / 监控指标组件
- 多节点连接迁移
