# Lyune Gateway

基于 QUIC 协议的高性能 IM 网关，使用 Zig 语言开发。

## 特性

- **QUIC 协议** - 基于 UDP，支持连接迁移、0-RTT、多路复用
- **高性能** - 基于 libxev (io_uring/kqueue) 事件驱动，目标单机百万连接
- **无状态设计** - 基于 Connection ID 路由，天然适合分布式部署
- **自定义协议** - 固定 Header + Protobuf Body 的混合协议设计

## 技术栈

| 组件      | 技术                          |
| --------- | ----------------------------- |
| 语言      | Zig 0.15.2+                   |
| 事件循环  | libxev (io_uring/kqueue/IOCP) |
| QUIC 协议 | picoquic                      |
| TLS 1.3   | picotls                       |

## 构建

### 前置依赖

- **Zig** >= 0.15.2
- **OpenSSL** (libssl, libcrypto)

```bash
# macOS
brew install openssl@3

# Ubuntu/Debian
sudo apt install libssl-dev

# Fedora
sudo dnf install openssl-devel
```

### 克隆项目

```bash
# 方式 1: 一步到位（推荐）
git clone --recursive https://github.com/your-username/lyune-gateway.git

# 方式 2: 分步克隆
git clone https://github.com/your-username/lyune-gateway.git
cd lyune-gateway
git submodule update --init --recursive
```

### 编译

```bash
# Debug 构建
zig build

# Release 构建
zig build -Doptimize=ReleaseFast

# 运行
zig build run
```

### 测试

```bash
zig build test
```

## 运行

```bash
# 生成测试证书
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
  -days 365 -nodes -subj "/CN=localhost"

# 启动服务端
./zig-out/bin/lyune_gateway server

# 运行客户端（另一个终端）
./zig-out/bin/lyune_gateway client

# 运行 libxev 演示
./zig-out/bin/lyune_gateway xev-demo
```

## 项目结构

```
lyune-gateway/
├── src/
│   ├── main.zig              # 入口
│   ├── gateway/              # 网关核心
│   ├── protocol/             # 协议处理
│   ├── quic/                 # QUIC 封装
│   └── common/               # 公共工具
├── libs/                     # 第三方依赖 (git submodule)
│   ├── picoquic/             # QUIC 协议实现
│   └── picotls/              # TLS 1.3 实现
├── build.zig                 # 构建配置
└── build.zig.zon             # 依赖管理
```

## 架构设计

```
┌─────────────────────────────────────────────────────────┐
│                     Client                              │
└────────────────────────┬────────────────────────────────┘
                         │ QUIC (UDP)
                         ▼
┌─────────────────────────────────────────────────────────┐
│                   Gateway Layer                         │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐                 │
│  │  GW-1   │  │  GW-2   │  │  GW-3   │  (无状态路由)   │
│  └────┬────┘  └────┬────┘  └────┬────┘                 │
└───────┼────────────┼────────────┼───────────────────────┘
        │            │            │
        └────────────┼────────────┘
                     ▼
┌─────────────────────────────────────────────────────────┐
│                   Message Queue                         │
└─────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                  Business Layer                         │
└─────────────────────────────────────────────────────────┘
```

## 协议格式

```
┌────────────────────────────────────────┐
│  Header (16 bytes)  │  Body (变长)      │
├─────────────────────┼──────────────────┤
│  magic (2)          │                  │
│  version (1)        │  Protobuf 或     │
│  msg_type (1)       │  原始二进制       │
│  flags (1)          │                  │
│  seq (4)            │                  │
│  body_len (4)       │                  │
│  reserved (3)       │                  │
└─────────────────────┴──────────────────┘
```

## 开发状态

🚧 **开发中** - 项目处于早期开发阶段

- [ ] QUIC 基础通信
- [ ] 自定义协议解析
- [ ] 连接管理
- [ ] 消息路由
- [ ] 集群支持
- [ ] 监控指标

## 许可证

MIT License

## 参考

- [picoquic](https://github.com/private-octopus/picoquic) - QUIC 协议实现
- [picotls](https://github.com/h2o/picotls) - TLS 1.3 实现
- [libxev](https://github.com/mitchellh/libxev) - 跨平台事件循环
- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) - QUIC 协议规范
