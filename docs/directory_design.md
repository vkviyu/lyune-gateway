# Lyune Gateway 目录结构文档

## 1. 项目结构总览

```
lyune-gateway/
├── build.zig                     # Zig 构建配置（编译 picoquic/picotls C 库 + 主程序）
├── build.zig.zon                 # 依赖管理（libxev）
├── server.crt / server.key       # 测试用 TLS 证书/私钥
│
├── src/                          # 源代码
│   ├── main.zig                  # 程序入口，CLI 参数解析
│   ├── quic.zig                  # QUIC 模块便捷入口（重导出 quic/mod.zig）
│   │
│   ├── gateway/                  # 网关核心
│   │   ├── mod.zig
│   │   ├── worker.zig            # GatewayWorker：核心 per-thread 工作者
│   │   ├── connection.zig        # ConnectionContext + ConnectionManager
│   │   ├── router.zig            # 消息路由              [占位]
│   │   └── session.zig           # 会话管理              [占位]
│   │
│   ├── driver/                   # 驱动器层（组装 Endpoint + IoLoop）
│   │   ├── mod.zig
│   │   ├── server.zig            # ServerDriver：服务端事件驱动器
│   │   └── client.zig            # AsyncClient：异步客户端驱动器
│   │
│   ├── protocol/                 # 协议层
│   │   ├── mod.zig
│   │   ├── frame.zig             # 帧格式定义（FrameHeader, TransportMode, ControlType, Flags）
│   │   ├── codec.zig             # 编解码器（FrameEncoder, FrameDecoder）
│   │   └── handler.zig           # 流处理器（BufferedMessageHandler, StreamingMessageHandler）
│   │
│   ├── quic/                     # QUIC 协议封装（picoquic C 绑定）
│   │   ├── mod.zig
│   │   ├── c.zig                 # @cImport 绑定、类型别名、DCID 解析
│   │   ├── endpoint.zig          # Endpoint：picoquic_quic_t 管理、C 回调分发
│   │   ├── connection.zig        # Connection：picoquic_cnx_t 封装
│   │   ├── stream.zig            # Stream：(Connection, stream_id) 操作句柄
│   │   ├── config.zig            # Config / QUICConfig
│   │   └── client.zig            # Client：基于 picoquic 内置循环的同步客户端
│   │
│   ├── transport/                # 传输层抽象
│   │   ├── mod.zig
│   │   ├── io.zig                # IoLoop：基于 libxev 的 UDP 收发、定时器、异步通知
│   │   └── pool.zig              # ObjectPool + FixedBuffer
│   │
│   ├── mq/                       # 后端传输模块
│   │   ├── mod.zig
│   │   ├── backend.zig           # BackendTransport 接口（vtable 多态）
│   │   ├── direct.zig            # DirectTransport：直连 QUIC 传输实现
│   │   ├── registry.zig          # TransportRegistry：route_key → transport 映射
│   │   ├── nats.zig              # NATS 传输           [占位]
│   │   └── publisher.zig         # 消息发布器           [占位]
│   │
│   ├── cluster/                  # 集群功能
│   │   ├── mod.zig
│   │   ├── migration.zig         # PacketQueue + MigrationManager（连接迁移）
│   │   ├── discovery.zig         # 服务发现              [占位]
│   │   └── coordinator.zig       # 网关协调              [占位]
│   │
│   ├── storage/                  # 存储适配
│   │   ├── mod.zig
│   │   ├── redis.zig             # Redis 客户端          [占位]
│   │   └── route_table.zig       # 路由表操作            [占位]
│   │
│   └── common/                   # 公共工具
│       ├── mod.zig
│       ├── error.zig             # 线程本地错误处理框架（ErrorHandler, ErrorCounters）
│       ├── config.zig            # 配置加载              [占位]
│       ├── log.zig               # 日志模块              [占位]
│       └── metrics.zig           # 监控指标              [占位]
│
├── config/
│   ├── gateway.json              # 网关配置              [占位]
│   └── gateway.dev.json          # 开发环境配置          [占位]
│
├── docs/                         # 文档
│   ├── architecture.md           # 架构设计文档
│   ├── protocol.md               # 协议设计文档
│   └── directory_design.md       # 目录结构文档（本文件）
│
├── tests/
│   ├── unit/                     # 单元测试              [空]
│   ├── integration/              # 集成测试              [空]
│   └── benchmark/                # 性能测试              [空]
│
├── tools/
│   ├── client_simulator.zig      # 客户端模拟器          [占位]
│   └── load_test.zig             # 压测工具              [占位]
│
└── libs/                         # 第三方依赖（git submodule）
    ├── picoquic/                 # QUIC 协议 C 实现
    └── picotls/                  # TLS 1.3 C 实现
```

> 标注 `[占位]` 的文件仅包含模块声明或空实现，待后续开发。

## 2. 模块说明

### 2.1 gateway/ — 网关核心

网关业务逻辑的入口。`GatewayWorker` 是每个线程的主控者，拥有 xev.Loop、ServerDriver 和 ConnectionManager。它注册三个业务回调（新连接、流数据、连接关闭），对新 Stream 创建 `BufferedMessageHandler` 进行消息聚合，在消息完整后分发处理。

### 2.2 driver/ — 驱动器层

将 Endpoint（协议）和 IoLoop（IO）组装在一起，驱动核心循环：收包 → 协议处理 → 发包 → 定时器更新。`ServerDriver` 服务端用，`AsyncClient` 用于网关主动连接后端。驱动器不包含业务逻辑，只负责事件转发。

### 2.3 protocol/ — 协议层

定义 16 字节帧头格式和编解码。帧格式支持 5 种传输模式（relay_buffered / relay_streaming / direct_buffered / direct_streaming / control），通过 RouteKey 标识目标服务。FrameDecoder 使用状态机处理 QUIC 流上的粘包拆包。流处理器提供 Buffered（完整消息回调）和 Streaming（即时转发）两种模式。

### 2.4 quic/ — QUIC 协议封装

picoquic C 库的 Zig 封装层。`c.zig` 通过 `@cImport` 导入头文件并建立类型别名；`Endpoint` 管理 picoquic 上下文的生命周期和 C 回调分发；`Connection` 和 `Stream` 提供类型安全的 Zig API。CID 回调在首字节编码线程 ID，实现无锁路由。

### 2.5 transport/ — 传输层抽象

基于 libxev 封装 UDP 收发、定时器和异步通知。IoLoop 在 macOS 上使用 kqueue，Linux 上使用 io_uring。支持 SO_REUSEPORT 多线程监听同一端口。Linux 下使用 sendmmsg 批量发送，macOS 下 fallback 到逐包 sendto。ObjectPool 提供泛型对象池和固定缓冲区。

### 2.6 mq/ — 后端传输

`BackendTransport` 定义了 vtable 多态接口（resolve/send/receive/close）。`DirectTransport` 实现了基于 AsyncClient 的直连 QUIC 传输。`TransportRegistry` 维护 route_key 到 transport 的映射。NATS 传输待实现。

### 2.7 cluster/ — 集群功能

`MigrationManager` 实现线程间连接迁移的包队列转发。服务发现和网关协调待实现。

### 2.8 common/ — 公共工具

`ErrorHandler` 提供线程本地的错误处理框架，支持分类计数和结构化上报。配置加载、日志和监控指标待实现。

## 3. 模块依赖关系

```
                    ┌──────────────┐
                    │   main.zig   │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   gateway/   │
                    │   worker     │
                    └──────┬───────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │ protocol │    │  driver/ │    │ cluster  │
    │ (frame)  │    │ (server) │    │          │
    └──────────┘    └────┬─────┘    └────┬─────┘
                         │               │
                    ┌────┴────┐          │
                    │         │          │
                    ▼         ▼          │
             ┌──────────┐ ┌──────────┐  │
             │   quic/  │ │transport/│  │
             │(picoquic)│ │ (libxev) │  │
             └──────────┘ └──────────┘  │
                    │         │         │
                    └────┬────┘─────────┘
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
        ┌─────────┐ ┌─────────┐ ┌─────────┐
        │ storage │ │   mq    │ │ common  │
        │ (redis) │ │ (nats)  │ │  (err)  │
        └─────────┘ └─────────┘ └─────────┘
```

## 4. 实现状态

| 模块                    | 状态   | 说明                                                        |
| ----------------------- | ------ | ----------------------------------------------------------- |
| transport/io.zig        | 已实现 | UDP 收发、定时器、异步通知、批量发送                        |
| transport/pool.zig      | 已实现 | 泛型对象池、固定缓冲区，含单元测试                          |
| quic/ (全部)            | 已实现 | picoquic 绑定、Endpoint、Connection、Stream、Config、Client |
| protocol/frame.zig      | 已实现 | 帧格式定义，含单元测试                                      |
| protocol/codec.zig      | 已实现 | 增量编解码器，含单元测试                                    |
| protocol/handler.zig    | 已实现 | Buffered/Streaming 两种流处理器                             |
| driver/server.zig       | 已实现 | 服务端驱动器，批量发包                                      |
| driver/client.zig       | 已实现 | 异步客户端驱动器                                            |
| gateway/worker.zig      | 已实现 | 核心工作者，Thread-per-Core 入口                            |
| gateway/connection.zig  | 已实现 | 连接上下文、连接管理器                                      |
| mq/backend.zig          | 已实现 | BackendTransport vtable 接口，含测试                        |
| mq/direct.zig           | 已实现 | DirectTransport 直连实现，含状态测试                        |
| mq/registry.zig         | 已实现 | route_key 映射表                                            |
| cluster/migration.zig   | 已实现 | 线程间包队列转发                                            |
| common/error.zig        | 已实现 | 线程本地错误处理框架                                        |
| gateway/router.zig      | 占位   | 消息路由待实现                                              |
| gateway/session.zig     | 占位   | 会话管理待实现                                              |
| mq/nats.zig             | 占位   | NATS 传输待实现                                             |
| mq/publisher.zig        | 占位   | 消息发布待实现                                              |
| cluster/discovery.zig   | 占位   | 服务发现待实现                                              |
| cluster/coordinator.zig | 占位   | 网关协调待实现                                              |
| storage/ (全部)         | 占位   | Redis 客户端、路由表待实现                                  |
| common/config.zig       | 占位   | 配置加载待实现                                              |
| common/log.zig          | 占位   | 日志模块待实现                                              |
| common/metrics.zig      | 占位   | 监控指标待实现                                              |
