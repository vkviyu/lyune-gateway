# Lyune Gateway

Lyune Gateway 是一个使用 Zig 编写的 QUIC 实时通信网关项目。它的核心定位是传输层网关：负责连接接入、QUIC 收发、流分发、连接管理和后端转发抽象，而不解析业务 Body 的语义。

当前项目已经具备 QUIC 服务端骨架、libxev 事件循环、picoquic/picotls 集成、Thread-per-Core 工作模型、连接/流处理框架、应用层帧协议和后端传输抽象。路由、NATS、服务发现、Redis、集群协调等模块仍处于预留或早期实现阶段。

## 项目状态

本项目处于早期开发阶段，README 以当前源码实现为准。

已实现或已有主体代码：

- QUIC 服务端入口与 `server` CLI
- picoquic + picotls 静态库构建集成
- libxev 驱动的 UDP 收发、定时器和异步通知
- Thread-per-Core Worker 模型
- 每线程独立 `GatewayWorker`、`ServerDriver`、`Endpoint`、`IoLoop`、`ConnectionManager`
- 基于 QUIC Stream 的缓冲/流式处理器抽象
- 16 字节应用层 Frame Header、编码器、增量解码器
- 后端传输接口 `BackendTransport`
- 直连 QUIC 后端传输 `DirectTransport` 的基础实现
- 传输注册表 `TransportRegistry`
- 连接迁移队列的初步结构
- 协议、路由表、传输注册表、对象池等单元测试

尚未完整落地：

- 配置文件加载，当前 `config/gateway.json` 和 `config/gateway.dev.json` 只是占位
- CLI 客户端命令
- 网关业务路由闭环
- NATS 中继实现
- 服务发现、Redis 路由表、集群协调
- 监控指标、生产级鉴权、管理接口

## 技术栈

| 组件       | 技术                           |
| ---------- | ------------------------------ |
| 语言       | Zig 0.15.2+                    |
| 构建系统   | Zig Build                      |
| 事件循环   | libxev                         |
| QUIC       | picoquic                       |
| TLS 1.3    | picotls + OpenSSL              |
| 系统加密库 | OpenSSL `libssl` / `libcrypto` |

第三方源码位于 `libs/`：

- `libs/picoquic/`：QUIC 协议栈
- `libs/picotls/`：TLS 1.3 实现及加密依赖

Zig 包依赖定义在 `build.zig.zon`，当前依赖 `libxev`。

## 构建要求

### Zig

需要 Zig `0.15.2` 或更高版本。

```bash
zig version
```

### OpenSSL

项目构建会链接 `crypto` 和 `ssl` 系统库。

macOS：

```bash
brew install openssl@3
```

Ubuntu / Debian：

```bash
sudo apt install libssl-dev
```

Fedora：

```bash
sudo dnf install openssl-devel
```

如果 macOS 上 Zig 无法找到 Homebrew 的 OpenSSL，可能需要根据本机环境补充 include/lib 路径或设置相关环境变量。

## 构建与测试

Debug 构建：

```bash
zig build
```

Release 构建：

```bash
zig build -Doptimize=ReleaseFast
```

运行测试：

```bash
zig build test
```

注意：当前测试集中包含 `src/mq/direct.zig` 的真实服务端集成测试，它会尝试连接本机 `127.0.0.1:8443`。如果本机没有匹配 ALPN 的 QUIC 服务端在该端口运行，`zig build test` 会在该集成测试处失败；其他普通单元测试可以正常执行。

`build.zig` 会编译一个静态库 `picoquic`，再构建主程序 `lyune_gateway`。

## 运行服务端

当前可执行文件只支持 `server` 子命令。

```bash
./zig-out/bin/lyune_gateway server
```

指定 Worker 线程数：

```bash
./zig-out/bin/lyune_gateway server --threads 4
```

也可以通过 Zig build 透传参数运行：

```bash
zig build run -- server --threads 4
```

默认情况下，如果不传 `--threads`，线程数会使用 CPU 核数。每个线程会创建独立的 `GatewayWorker` 和 `xev.Loop`，并通过 `SO_REUSEPORT` 绑定同一个 UDP 端口。

### 当前服务端固定配置

当前版本尚未读取 `config/*.json`，服务端配置硬编码在 `src/main.zig`：

- 监听地址：`0.0.0.0`
- 监听端口：`4433`
- 证书文件：`server.crt`
- 私钥文件：`server.key`
- ALPN：`lyune-im`
- 最大连接数：`10000`
- 空闲超时：`30000ms`

注意：启动日志里目前有一处文案写的是 `port 8443`，但实际绑定端口是 `4433`。

### 证书

仓库根目录已经包含开发用测试证书：

- `server.crt`
- `server.key`

如需重新生成自签名证书：

```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
  -days 365 -nodes -subj "/CN=localhost"
```

生产环境请替换为正式证书和更完整的证书校验策略。

## CLI

当前真实 CLI：

```text
lyune_gateway server [--threads N]
```

暂不支持以下命令：

- `client`
- `xev-demo`

如需客户端能力，请查看 `src/driver/client.zig` 和 `tools/client_simulator.zig` 的现有代码状态；它们不是当前主程序 CLI 的子命令。

## 项目结构

```text
lyune-gateway/
├── build.zig              # 构建脚本，集成 picoquic/picotls/libxev 并生成 lyune_gateway
├── build.zig.zon          # Zig 包元数据与 libxev 依赖
├── config/                # 配置文件占位，当前主程序尚未加载
├── docs/                  # 架构、协议和目录设计文档
├── libs/                  # picoquic、picotls 第三方源码
├── server.crt             # 开发用测试证书
├── server.key             # 开发用测试私钥
├── src/
│   ├── main.zig           # CLI 入口和服务端启动逻辑
│   ├── common/            # 错误处理、日志、配置、指标等公共模块
│   ├── cluster/           # 集群协调、服务发现、迁移预留结构
│   ├── driver/            # QUIC ServerDriver / AsyncClient 驱动层
│   ├── gateway/           # GatewayWorker、连接上下文、连接管理
│   ├── mq/                # 后端传输接口、直连传输、注册表、NATS 占位
│   ├── protocol/          # Frame 协议、编解码器、Stream Handler
│   ├── quic/              # picoquic C 绑定、Endpoint、Connection、配置封装
│   ├── storage/           # Redis、RouteTable 占位
│   └── transport/         # libxev UDP I/O、对象池
├── tests/                 # benchmark/integration/unit 目录占位
└── tools/                 # 客户端模拟器、压测工具源码
```

## 架构概览

运行时主要分三层：

```text
GatewayWorker
  负责业务层连接管理、流分发、消息聚合
        |
ServerDriver
  负责组装 Endpoint + IoLoop，驱动 QUIC 状态机
        |
Endpoint + IoLoop
  Endpoint 封装 picoquic，IoLoop 封装 libxev UDP 收发和定时器
```

### Thread-per-Core 模型

`server --threads N` 会启动 N 个 Worker 线程。每个线程拥有：

- 一个 `xev.Loop`
- 一个 `ServerDriver`
- 一个 `Endpoint`
- 一个 `IoLoop`
- 一个线程本地 `ConnectionManager`

所有线程通过 `SO_REUSEPORT` 绑定同一个 UDP 端口，由内核分发入站 UDP 包。当前连接管理是线程局部的，不使用锁；如果未来需要跨线程操作，应通过消息传递或迁移队列完成。

### 数据流

入站路径：

```text
UDP packet
  -> transport.IoLoop
  -> driver.ServerDriver
  -> quic.Endpoint / picoquic
  -> QUIC stream callback
  -> gateway.GatewayWorker
  -> ConnectionManager / StreamHandler
```

当前 `GatewayWorker` 对新 Stream 默认创建 `BufferedMessageHandler`，将同一个 QUIC Stream 上的数据累积到 FIN，再触发 `onMessageComplete`。目前完成后的动作只是打印日志，尚未接入真实 Router 或后端转发闭环。

出站路径：

```text
picoquic pending packet
  -> Endpoint.preparePendingPacket
  -> ServerDriver.flushPendingPackets
  -> IoLoop.sendBatch
  -> UDP socket
```

Linux 下 `IoLoop` 会优先走批量发送路径，其他平台使用 fallback 发送逻辑。

## 应用层帧协议

项目在 QUIC Stream 上定义了一层 16 字节 Frame Header。网关只需要读取帧头做传输控制和路由选择，Body 对网关透明。

帧结构：

```text
0               2   3   4   5   6       8       12      16
+---------------+---+---+---+---+-------+-------+-------+
| Magic         |Ver|Mode|Key|Flg|Reserved       |       |
+---------------+---+---+---+---+-------+-------+-------+
| Sequence                      | Body Length            |
+-------------------------------+------------------------+
| Body ...                                               |
+--------------------------------------------------------+
```

字段说明：

| 字段        | 大小 | 说明                                   |
| ----------- | ---- | -------------------------------------- |
| Magic       | 2B   | 固定 `0xFEFE`                          |
| Version     | 1B   | 当前协议版本 `3`                       |
| Mode        | 1B   | `TransportMode`                        |
| RouteKey    | 1B   | 路由标识；控制帧中复用为 `ControlType` |
| Flags       | 1B   | 压缩、加密、ACK、流式起止标记          |
| Reserved    | 2B   | 保留                                   |
| Sequence    | 4B   | 序列号，大端序                         |
| Body Length | 4B   | Body 长度，大端序                      |

`TransportMode` 编码规则：高 4 位表示传输路径，低 4 位表示传输方式。

| 值     | 名称               | 说明                 |
| ------ | ------------------ | -------------------- |
| `0x00` | `relay_buffered`   | 中继 + 缓冲          |
| `0x01` | `relay_streaming`  | 中继 + 流式          |
| `0x10` | `direct_buffered`  | 直连 + 缓冲          |
| `0x11` | `direct_streaming` | 直连 + 流式          |
| `0xFF` | `control`          | 控制帧，网关本地处理 |

控制帧类型包括心跳、认证、连接控制、会话恢复和系统通知，定义在 `src/protocol/frame.zig` 的 `ControlType`。

编解码实现位于：

- `src/protocol/frame.zig`：帧头、模式、标志位、控制类型
- `src/protocol/codec.zig`：`FrameEncoder`、`FrameDecoder`
- `src/protocol/handler.zig`：`StreamingMessageHandler`、`BufferedMessageHandler`

当前 `FrameDecoder` 支持增量解析，可处理 QUIC Stream 中分片到达的数据。

## 核心模块说明

### `src/main.zig`

负责命令行解析和服务端启动。当前只识别 `server [--threads N]`，并在 `runSingleWorker` 中构造 `GatewayWorker`。

### `src/gateway/worker.zig`

业务层 Worker。负责：

- 创建并持有 `ServerDriver`
- 创建线程本地 `ConnectionManager`
- 注册连接建立、流数据、连接关闭回调
- 为新 QUIC Stream 创建 `BufferedMessageHandler`
- 在完整消息到达时输出日志

### `src/gateway/connection.zig`

维护连接上下文：

- 以 picoquic connection 指针作为连接键
- 记录 `user_id`、连接时间
- 管理 `stream_id -> StreamHandler` 映射

在 Thread-per-Core 模型下，`ConnectionManager` 是线程本地结构，不加锁。

### `src/driver/server.zig`

底层服务端驱动器。它不包含业务逻辑，只负责：

- 组装 `Endpoint` 和 `IoLoop`
- 接收 UDP 包并喂给 picoquic
- 驱动 QUIC 状态机
- 批量发送待发 UDP 包
- 根据 picoquic 下一次唤醒时间更新定时器
- 把 QUIC 连接/流事件转发给上层回调

### `src/driver/client.zig`

异步 QUIC 客户端驱动。主要供直连后端传输使用，支持：

- 复用外部 `xev.Loop`
- 创建客户端 Endpoint
- 解析后端地址并发起 QUIC 连接
- 收包、发包、定时器驱动
- 暴露连接、流数据、关闭回调

当前它不是主程序 CLI 的 `client` 命令。

### `src/quic/`

picoquic 的 Zig 封装层：

- `c.zig`：C 类型、常量、函数绑定和工具函数
- `config.zig`：QUIC 配置结构，包含 ALPN、超时、流窗口、拥塞控制等
- `endpoint.zig`：picoquic 上下文生命周期、回调、收包、待发包准备、CID 生成
- `connection.zig`：QUIC 连接封装，提供连接状态、Stream 写入、关闭等操作
- `stream.zig`：Stream 相关结构

`Endpoint` 初始化时会设置：

- 随机 reset seed
- ALPN buffer
- 拥塞控制算法，默认 BBR
- Transport Parameters
- idle timeout
- 可选的空证书校验器，用于开发环境自签名证书

### `src/transport/io.zig`

libxev UDP I/O 抽象层。负责：

- 创建非阻塞 UDP socket
- 设置 `SO_REUSEPORT`
- 绑定本地地址和端口
- 注册 UDP read、timer、async notify
- 维护发送队列
- 支持 `sendBatch`

它不知道 QUIC 或业务协议，只处理 UDP 数据包和事件循环。

### `src/mq/`

后端传输层抽象。

- `backend.zig`：定义 `BackendTransport` 接口，统一 `resolve/send/receive/close`
- `direct.zig`：基于 `AsyncClient` 的直连 QUIC 后端传输实现
- `registry.zig`：`TransportPath + RouteKey -> BackendTransport` 注册表
- `nats.zig`、`publisher.zig`：当前基本为空，占位中继模式

设计上同一个 `RouteKey` 在 relay 和 direct 路径下可以映射到不同后端。

### `src/cluster/`

集群能力预留模块。

- `migration.zig`：本地线程间包转发队列的初步实现
- `discovery.zig`、`coordinator.zig`：占位

### `src/storage/`

存储能力预留模块。

- `redis.zig`：占位
- `route_table.zig`：占位

### `src/common/`

公共能力模块。

- `error.zig`：线程本地错误处理框架
- `log.zig`、`metrics.zig`、`config.zig`：公共模块预留

## 测试现状

`zig build test` 会以 `src/main.zig` 为根模块运行测试。当前测试主要散落在源码文件中，包括：

- `src/protocol/frame.zig`：帧头编解码、模式判断、控制帧类型
- `src/protocol/codec.zig`：编码器、增量解码器、控制帧 roundtrip
- `src/mq/backend.zig`：后端传输接口
- `src/mq/registry.zig`：注册表基础操作、默认传输、路径隔离
- `src/mq/direct.zig`：直连传输状态和真实服务端集成测试
- `src/transport/pool.zig`：对象池和固定缓冲区

当前 `DirectTransport integration test (Real Server)` 默认会连接本机 `127.0.0.1:8443`，而主程序服务端默认监听 `4433` 且 ALPN 为 `lyune-im`。因此在没有额外启动兼容测试服务端时，完整 `zig build test` 会卡在该集成测试并失败。

`tests/benchmark`、`tests/integration`、`tests/unit` 目录目前为空目录或占位目录。

## 开发注意事项

- 当前主程序未加载 `config/*.json`，修改配置文件不会影响运行行为。
- 当前服务端实际监听 UDP `4433`。
- `GatewayWorker` 目前只完成 Stream 缓冲和日志输出，尚未把消息转入 Router 或 BackendTransport。
- `DirectTransport` 使用的默认 ALPN 是 `lyune-gateway`，服务端入口使用的是 `lyune-im`，对接直连后端时需要确认两端 ALPN 一致。
- `server.crt` 和 `server.key` 适合开发测试，不适合生产环境。
- `src/mq/nats.zig`、`src/storage/redis.zig`、`src/gateway/router.zig` 等仍是占位模块。

## 参考文档

项目内文档：

- `docs/architecture.md`：架构设计
- `docs/protocol.md`：协议设计
- `docs/directory_design.md`：目录设计

外部资料：

- [picoquic](https://github.com/private-octopus/picoquic)
- [picotls](https://github.com/h2o/picotls)
- [libxev](https://github.com/mitchellh/libxev)
- [RFC 9000: QUIC](https://www.rfc-editor.org/rfc/rfc9000.html)
