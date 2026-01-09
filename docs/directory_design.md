项目刚起步，目前只有基础结构。基于我们之前讨论的 QUIC IM 网关架构，我建议这样组织代码：
推荐目录结构

lyune-gateway/
├── build.zig                    # 构建配置
├── build.zig.zon                # 依赖管理
│
├── src/
│   ├── main.zig                 # 入口：启动服务
│   │
│   ├── gateway/                 # 网关核心
│   │   ├── server.zig           # QUIC 服务器，事件循环
│   │   ├── connection.zig       # 连接管理（Connection ID 映射）
│   │   ├── session.zig          # 会话管理（user_id ↔ connection）
│   │   └── router.zig           # 消息路由（本地/跨网关）
│   │
│   ├── protocol/                # 协议层
│   │   ├── frame.zig            # 帧格式（Header + Body）
│   │   ├── codec.zig            # 编解码
│   │   ├── message.zig          # 消息类型定义
│   │   └── handler.zig          # 消息处理分发
│   │
│   ├── quic/                    # QUIC 封装
│   │   ├── endpoint.zig         # QUIC 端点封装
│   │   ├── stream.zig           # Stream 管理
│   │   └── config.zig           # QUIC 配置
│   │
│   ├── transport/               # 传输层抽象
│   │   ├── io.zig               # I/O 抽象（libxev 封装）
│   │   ├── buffer.zig           # 缓冲区管理
│   │   └── pool.zig             # 内存池
│   │
│   ├── cluster/                 # 集群功能
│   │   ├── discovery.zig        # 服务发现
│   │   ├── coordinator.zig      # 网关协调
│   │   └── migration.zig        # 连接迁移
│   │
│   ├── storage/                 # 存储适配
│   │   ├── redis.zig            # Redis 客户端
│   │   └── route_table.zig      # 路由表操作
│   │
│   ├── mq/                      # 消息队列
│   │   ├── client.zig           # MQ 客户端抽象
│   │   ├── nats.zig             # NATS 实现
│   │   └── publisher.zig        # 消息发布
│   │
│   └── common/                  # 公共工具
│       ├── config.zig           # 配置加载
│       ├── log.zig              # 日志
│       ├── metrics.zig          # 监控指标
│       └── error.zig            # 错误定义
│
├── tests/                       # 测试
│   ├── unit/                    # 单元测试
│   ├── integration/             # 集成测试
│   └── benchmark/               # 性能测试
│
├── tools/                       # 工具
│   ├── client_simulator.zig     # 客户端模拟器
│   └── load_test.zig            # 压测工具
│
├── config/                      # 配置文件
│   ├── gateway.json             # 网关配置
│   └── gateway.dev.json         # 开发环境配置
│
└── docs/                        # 文档
    ├── protocol.md              # 协议设计文档
    └── architecture.md          # 架构设计文档
模块依赖关系

                    ┌──────────────┐
                    │    main.zig   │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   gateway/   │
                    │   server     │
                    └──────┬───────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │ protocol │    │   quic   │    │ cluster  │
    └────┬─────┘    └────┬─────┘    └────┬─────┘
         │               │               │
         │               ▼               │
         │        ┌──────────┐           │
         │        │transport │           │
         │        │ (libxev) │           │
         │        └──────────┘           │
         │               │               │
         └───────────────┼───────────────┘
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
        ┌─────────┐ ┌─────────┐ ┌─────────┐
        │ storage │ │   mq    │ │ common  │
        │ (redis) │ │ (nats)  │ │  (log)  │
        └─────────┘ └─────────┘ └─────────┘
核心文件示例
src/main.zig

```zig
const std = @import("std");
const Server = @import("gateway/server.zig").Server;
const Config = @import("common/config.zig").Config;
const log = @import("common/log.zig");

pub fn main() !void {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();
  // 加载配置
  const config = try Config.load(allocator, "config/gateway.json");
  defer config.deinit();

  // 初始化日志
  try log.init(config.log_level);

  log.info("Starting Lyune Gateway...", .{});

  // 创建并启动服务器
  var server = try Server.init(allocator, config);
  defer server.deinit();

  try server.run();
}
```

src/gateway/server.zig

```zig
const std = @import("std");
const xev = @import("xev");
const Connection = @import("connection.zig").Connection;
const Session = @import("session.zig").SessionManager;
const Router = @import("router.zig").Router;
const Protocol = @import("../protocol/handler.zig").Handler;

pub const Server = struct {
  allocator: std.mem.Allocator,
  loop: xev.Loop,
  connections: std.AutoHashMap(u64, *Connection),
  sessions: SessionManager,
  router: Router,
  protocol: Protocol,
  pub fn init(allocator: std.mem.Allocator, config: Config) !Server {
    return .{
      .allocator = allocator,
      .loop = try xev.Loop.init(.{}),
      .connections = std.AutoHashMap(u64, *Connection).init(allocator),
      .sessions = try SessionManager.init(allocator, config),
      .router = try Router.init(allocator, config),
      .protocol = Protocol.init(),
    };
  }

  pub fn run(self: *Server) !void {
    // 启动 QUIC 监听
    // 运行事件循环
    try self.loop.run();
  }

  pub fn deinit(self: *Server) void {
    self.loop.deinit();
    self.connections.deinit();
    self.sessions.deinit();
    self.router.deinit();
  }
};
```

src/protocol/frame.zig

```zig
/// 消息帧格式
/// 
/// ┌────────────────────────────────────────┐
/// │  Header (16 bytes)  │  Body (变长)      │
/// └────────────────────────────────────────┘
pub const FrameHeader = packed struct {
  magic: u16 = 0xFEFE,      // 魔数
  version: u8 = 1,          // 协议版本
  msg_type: MsgType,        // 消息类型
  flags: Flags,             // 标志位
  seq: u32,                 // 序列号
  body_len: u32,            // Body 长度
  reserved: u16 = 0,        // 保留字段
  pub fn parse(buf: []const u8) !*const FrameHeader {
    if (buf.len < @sizeOf(FrameHeader)) {
      return error.BufferTooSmall;
    }
    const header: *const FrameHeader = @ptrCast(@alignCast(buf.ptr));
    if (header.magic != 0xFEFE) {
      return error.InvalidMagic;
    }
    return header;
  }
};

pub const MsgType = enum(u8) {
  // 控制消息
  heartbeat = 0x01,
  ack = 0x02,
  // 业务消息
  chat_text = 0x10,
  chat_image = 0x11,
  chat_voice = 0x12,

  // 群组消息
  group_msg = 0x20,
  group_notify = 0x21,

  // 系统消息
  kick_off = 0xF0,
  server_error = 0xFF,
};
pub const Flags = packed struct {
  compressed: bool = false,
  encrypted: bool = false,
  need_ack: bool = true,
  _reserved: u5 = 0,
};    
```
建议的开发顺序
阶段	模块	目标
1	transport/ + quic/	能收发 UDP/QUIC 包
2	protocol/frame.zig	帧解析和序列化
3	gateway/connection.zig	连接管理
4	gateway/server.zig	基础服务器跑起来
5	protocol/handler.zig	消息处理
6	storage/redis.zig	路由表
7	mq/	跨网关消息
8	cluster/	分布式功能
要我帮你创建这个目录结构和基础文件吗？