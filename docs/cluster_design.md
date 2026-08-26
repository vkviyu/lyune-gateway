# Lyune Gateway 分布式集群设计文档

> 状态：核心代码闭环已完成。§10.2 第 1–7 步均已落地：SWIM + anti-entropy +
> Lifeguard、HMAC 双密钥、真实 UDP runner，以及 membership、CID、forward tunnel 三套 v1
> 线路格式和 reuseport 分类、Coordinator/start-drain-stop 运行时装配。现有测试覆盖确定性分区愈合、
> 真实双节点 gossip 和真实 UDP 隧道注入。第 8 步中的 Linux cBPF 实机验证与多进程长时间
> soak 属于发布前验证项，不能由 macOS 单元测试替代。
>
> 本文档是多节点集群能力的设计与实现说明，覆盖架构决策、协议细节、故障模型、测试策略与实施状态。

## 1. 目标与非目标

### 1.1 目标

- **不依赖任何外部中间件**（etcd / ZooKeeper / Redis / Consul）实现多节点分布式：集群能力全部内嵌进网关二进制。
- **数据面零共享状态**：正常流量的性能上界等于单机性能上界，分布式不付常态代价。
- **故障域隔离**：任何集群组件故障（gossip 分区、节点宕机）只影响局部路径，不产生集群级雪崩。
- 支持 **direct（DNS/客户端侧分流）**、**anycast/ECMP** 与 **L4 LB 后置** 三种部署模型，默认按 direct 设计。

### 1.2 非目标（明确不做）

| 不做的事                             | 理由                                                                                                                                    |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| 内嵌 Raft / 任何强一致共识           | 本架构中不存在需要强一致的状态：连接归属被 CID 编码消灭，node_id 静态配置，路由元数据允许最终一致                                       |
| 连接级状态复制                       | 节点宕机时其连接直接断开、客户端重连即可；复制 QUIC 连接状态（TLS 密钥、拥塞状态、流状态）的成本远超收益，Cloudflare 等生产系统同样不做 |
| 中心注册表 / 每连接查询外部存储      | 每包/每连接一次网络 RTT，是数量级的性能退化，也违背零外部依赖目标                                                                       |
| 跨节点复制/透明迁移存量连接状态       | 需要迁移 TLS 密钥、包号、ACK、流控与拥塞状态，收益远低于复杂度；使用 redirect + 客户端重连完成重新归位，见 §11                          |

## 2. 设计原则：把分布式问题压缩到只剩成员发现

第一性原理拆解：一个 QUIC 网关集群到底需要共享什么状态？

| 状态                                 | 一致性需求 | 本设计的处理方式                                                       |
| ------------------------------------ | ---------- | ---------------------------------------------------------------------- |
| 连接归属（哪个节点/Worker 拥有连接） | —          | **CID 编码消灭**：归属信息编进 CID，任何节点 O(1) 本地判定，无共享状态 |
| 成员与故障检测                       | 最终一致   | SWIM gossip（§5），去中心、无单点                                      |
| 路由/配置元数据                      | 最终一致   | 版本号 + 随 gossip 传播（后续演进项）                                  |
| 连接级会话状态                       | —          | **不复制**（见 §1.2）                                                  |

这是整个设计的核心：**唯一需要协调的只有"成员视图"这一件最终一致的小状态**。
它与单机 Thread-per-Core 模型的哲学一脉相承——单机上 CID 编码 worker_id 实现零锁分发，
集群上 CID 编码 node_id 实现零协调路由；`io/handoff.zig` 的本地交接器处理内核误分流，
节点间转发隧道处理集群误分流，是同一抽象在两个层级的实例。

## 3. 总体架构

```
                        客户端（连接 VIP / anycast 地址）
                                     │
                    ECMP / anycast 路由（可能重哈希漂移）
                     ┌───────────────┼───────────────┐
                     ▼               ▼               ▼
               ┌──────────┐    ┌──────────┐    ┌──────────┐
               │  Node A  │    │  Node B  │    │  Node C  │
               │          │    │          │    │          │
               │ 解析 CID ├───►│ 解析 CID │    │          │
               │ node=B?  │转发│ node=B ✓ │    │          │
               │ 查成员表 │隧道│ 交给     │    │          │
               │          │    │ Worker n │    │          │
               └────┬─────┘    └────┬─────┘    └────┬─────┘
                    │               │               │
                    └───── SWIM gossip 全互联 ──────┘
                    （成员发现 / 故障检测 / 最终一致）
```

三个新组件：

1. **成员管理**（`src/control/membership/`）：SWIM 协议维护 `node_id → (gossip 地址, 状态)` 的最终一致视图；
2. **CID v1**（`src/io/cid.zig`）：在 CID 中编码 node_id，包到达任意节点即可 O(1) 判定归属；
3. **节点间转发隧道**（`src/io/forward.zig`）：使用成员地址的 IP 与集群统一的 `forward_port` 组合目标，封装原始客户端地址后转发给归属节点。

## 4. CID v1 布局

### 4.1 布局

CID v1 从首次发布起固定为 12 字节。QUIC 允许 0–20 字节 CID；短头包不携带 CID 长度，
因此整个集群必须统一使用该长度和版本：

```
┌───────┬───────┬─────────┬──────────────┬─────────┬───────────────────┐
│ 'L'   │ 'Y'   │ version │ node_id (2B) │ worker  │ entropy (6 bytes) │
│ byte0 │ byte1 │ byte2=1 │ byte 3..4    │ byte 5  │ byte 6..11        │
└───────┴───────┴─────────┴──────────────┴─────────┴───────────────────┘
```

- `node_id`：u16 大端，静态配置分配（见 §4.2），0 保留为非法值；
- `worker`：供 reuseport BPF 与本地分发使用，固定在 byte 5；
- `entropy`：6 字节随机熵，用于降低同一 Worker 高连接数下的 CID 碰撞概率。

解码逻辑分层：

```
workerId(cid)   —— 本地路径：魔数/版本/长度校验后取 worker 字节（BPF 与用户态共用语义）
nodeId(cid)     —— 集群路径：同上校验后取 node_id；非本节点签发 → 查成员表决定转发或回退
```

任何校验不通过（外部 CID、握手期 Initial 包、未知版本或错误长度）→ 返回 null，回退到本地处理。

### 4.2 node_id 分配

**静态配置**，即 `config.cluster.node_id`（当前实现为 u16，见 §9 配置）。
理由：网关节点是运维显式部署的（不是弹性容器随意伸缩到数千个），静态分配即可；
这是本设计能砍掉 Raft 的前提之一——不引入"动态 id 分配"这个唯一需要强一致的需求。
节点启动时通过 gossip 广播自己的 `node_id → advertise_address` 绑定；
若从已通过 HMAC 认证的消息中发现本节点 ID 来自其他地址，或已有成员 ID 被绑定到不同地址，进程立即 fail-fast 退出并记录冲突。静态 node_id 绑定不允许运行期漂移。

### 4.3 版本策略

当前 12 字节布局就是项目首个发布格式，线路标识为 `version = 1`，不存在需要兼容的旧 CID。
解码器和 reuseport 分类器都严格拒绝其他版本；未来若出现不兼容布局，再递增版本并单独设计升级策略。

## 5. 成员管理：SWIM 协议

### 5.1 对上接口：MembershipView

上层（转发隧道、drain 逻辑、未来的路由元数据传播）只依赖 `membership.Table` 的读侧 API，不感知 SWIM 协议细节：

```zig
pub const Member = struct {
    node_id: u16,
    address: net.Address, // advertise gossip 地址；转发时保留 IP 并替换为 forward_port
    status: NodeStatus,
    incarnation: u32,
};

pub const Table = struct {
    /// 转发热路径按 node_id 获取一致性快照；未知节点返回 null。
    pub fn lookup(self: *const Table, node_id: u16) ?Member
    /// 诊断/管理路径生成全量快照；调用方释放返回切片。
    pub fn snapshot(self: *const Table, allocator) ![]Member
};
```

成员事件监听通过 `Swim.setListener()` 注册，并在单一协议线程内同步调用。`lookup` 的实现约束是每个迷路包一次且读侧零争用：成员表按 node_id 直接索引固定容量槽位（实际按 `max_nodes` 分配），每槽使用 seqlock；gossip 线程单写，数据面线程无锁读取。

### 5.2 协议核心（SWIM 2002 论文状态机）

**探测循环**（每个协议周期 `protocol_period`，默认 1s）：

1. 随机选一个成员 M，发 `ping`，等待 `ack`（超时 `probe_timeout`，默认 500ms × LHM，见 §5.3）；
2. 超时未收到 → 随机选 `indirect_probes`（默认 3）个其他成员发 `ping-req(M)`，请它们代为探测；
3. 全部失败 → 将 M 标记为 `suspect`，随 gossip 传播；
4. `suspect` 状态持续 `suspicion_timeout`（默认 `protocol_period × log(N) × 倍率`）后仍无反驳 → 标记 `dead`。

**反驳机制（incarnation）**：节点收到关于自己的 `suspect`/`dead` 消息时，递增自身 incarnation
并广播 `alive`。任何成员消息的新旧比较规则：incarnation 高者胜；同 incarnation 时
`dead > suspect > alive`。这是 SWIM 正确性的核心不变量，模拟测试重点覆盖（§8）。

**信息传播（piggyback gossip）**：成员变更事件不单独发包，搭载在 ping/ack 消息尾部，
每条事件最多重传 `retransmit_mult × log(N)` 次。消息编码复用 `protocol/codec.zig` 的风格，
定长头 + TLV 事件列表，单包不超过 1400 字节（避免分片）。

**anti-entropy 全量同步**：每 `sync_interval`（默认 30s）随机选一个成员，通过带游标和
`more` 标志的多片 UDP 响应交换全量状态，兜底 gossip 丢消息导致的视图永久分叉。同步对象
可包含 dead 成员，使网络分区愈合后双方能够重新接触并通过更高 incarnation 收敛。

**加入与退出**：

- 加入：新节点向 `config.cluster.seeds` 静态种子列表逐个发 join，任一成功即拿到全量视图；
- 优雅退出：drain 开始时广播 `left`（区别于 `dead`，不触发 suspicion 流程），见 §7。

### 5.3 Lifeguard 扩展（生产级必需）

直接采纳 HashiCorp Lifeguard 论文的三个机制，解决"自己卡顿却怀疑别人"的误判风暴：

1. **Local Health Multiplier (LHM)**：本地探测失败/被人怀疑时增加自身健康计数，
   按计数放大自己的探测超时与 suspicion 超时（最大 8 倍），卡顿节点自动"少说话、多等待"；
2. **Buddy System**：探测 M 时优先把"M 被怀疑"的消息直接告诉 M，加速反驳；
3. **Dynamic Suspicion Timeout**：收到越多独立来源的 suspect 确认，suspicion 超时越短。

### 5.4 传输与安全

- membership v1 跑在独立 UDP socket（`advertise_address` 端口），不与 QUIC 数据面混用；
- 所有 gossip 消息带 **HMAC-SHA256 认证**（集群预共享密钥 `config.cluster.secret`），
  防止外部伪造成员消息把流量引向恶意节点；发送只使用 current secret，接收依次验证
  current/previous secret，支持不中断轮换；
- 协议线程维护固定容量重放缓存，重复认证报文会被静默丢弃；
- 不加密消息体（成员列表不是机密），只认证完整性；共享密钥不提供集群内部节点之间的隔离。

### 5.5 运行位置

gossip 协议线程独立于 Worker（协议状态机单线程执行，负载与数据面无关），
归 `Coordinator` 持有与生命周期管理，与现有 `NodeState` 状态机集成：
`running → draining` 时触发 `left` 广播。

## 6. 迷路包转发隧道

### 6.1 何时发生

正常情况下客户端的包经 ECMP/anycast 到达签发 CID 的节点，零转发。迷路只发生在：

- ECMP 重哈希（路由器增删下一跳、链路抖动）；
- 客户端网络迁移（WiFi ↔ 蜂窝，QUIC connection migration，源五元组变化）；
- 节点扩缩容导致的 anycast 收敛期。

这些都是**低频事件**，转发路径只需正确，不在关键性能预算内（但实现仍是 O(1) 查表 + 一次 sendmsg）。

### 6.2 隧道协议

节点间使用独立的非阻塞 UDP socket（`forward_port`，与 gossip 端口隔离），forward tunnel v1 封装格式：

```
magic(2) | version(1) | target_worker_id(1) | address_family(1) | client_port(2)
| payload_len(2) | source_node_id(2) | target_node_id(2) | session_id(8)
| sequence(8) | kind(1) | source_worker_id(1) | reserved(1)
| client_ip(4/16) | 原始 QUIC 包 | HMAC-SHA256(32)
```

- `kind=request`：入口节点把误投递的客户端包注入 CID owner Worker；
- `kind=response`：owner 把响应注入原入口 Worker，由其服务 socket 发往客户端/LB；
- HMAC 覆盖方向、节点/Worker 身份、会话、序号、客户端地址和原始负载，接收同样支持 current/previous 双密钥；
- `target_node_id` 必须等于本节点，避免合法报文被反射到错误节点；
- 每个发送进程使用随机 `session_id` 和原子递增 `sequence`，接收端按源节点/会话维护
  固定容量的 64 包滑动窗口，允许 UDP 小范围乱序并拒绝重复与过旧数据报；
- 不做可靠传输：丢失交给 QUIC 自身的丢包恢复处理。

### 6.3 回包路径与部署模型

通过 `cluster.deployment_mode` 选择三种部署模型。模式本身回答两个能力问题——
是否可能收到不属于本节点的报文、响应是否必须经原入口回流——由 `DeploymentMode`
的穷尽 switch 统一给出，避免散落的模式判断漏改：

- **`direct`（默认）**：客户端直连特定节点，来自 DNS 多 A 记录、客户端侧负载均衡或单节点部署。
  客户端记住的是节点自身地址，迁移后目的地址不变，报文永远到同一节点，因此不会错投；
  这种模式下连 forward 隧道的 socket 与接收线程都不会创建；
- **`anycast`**：所有节点绑定同一 VIP（BGP anycast 或机房内 ECMP），归属节点直接以 VIP 为源回包；
  需要跨节点转发纠正错投，但不分配回程表，单向转发、回程直达；
- **`l4_lb`**：入口 Worker 转发请求前记录 `(client address → owner node/Worker)` 授权；owner Worker
  记录 `(client address → ingress node/Worker)` 回程路径。picoquic 的响应命中该路径后封装为 `response`
  回到入口 Worker，再由原 QUIC 服务 socket 发给客户端/LB。

`cluster.enabled=false` 时不创建 forward 隧道，只能搭配 `direct`；配成 `anycast` 或 `l4_lb`
会在 `validate()` 中被拒绝，而不是静默忽略 —— 否则运维会以为回程已启用。

`l4_lb` 的两张表均为 Worker 本地、有界且启动时预分配，默认每 Worker 4096 项；每个已认证 request 刷新时间，
response 不延长授权，超过 QUIC `idle_timeout_ms` 后惰性删除，满表时先清理过期项再淘汰最旧项。入口只接受与已有授权中
owner 节点和 Worker 完全匹配的响应，未建立路径的 response 不会被当作任意 UDP 发包请求。实现见
`src/reactor/return_path.zig`。

### 6.4 决策表

包到达节点 X，解析 CID 后：

| CID 解析结果             | 成员表状态       | 动作                                                            |
| ------------------------ | ---------------- | --------------------------------------------------------------- |
| 本节点签发               | —                | 现有路径（BPF/worker 分发），零变化                             |
| 他节点 N 签发            | N alive/suspect  | 封装转发给 N                                                    |
| 他节点 N 签发            | N dead/left/未知 | 按无效连接处理：丢弃，或有条件回 Stateless Reset 加速客户端重连 |
| 非本集群 CID（校验失败） | —                | 回退本地处理（握手 Initial 包等），现行为                       |

suspect 状态仍然转发（宁可多转一跳，不误杀活节点的连接）。

## 7. 优雅下线（drain）与故障模型

### 7.1 drain 流程

现有 `Coordinator.beginDrain()` 扩展为集群语义：

1. 广播 `left` 消息 → 其他节点把本节点标记为 left（新迷路包不再转发过来，见 §6.4）；
2. 本地拒绝新连接（现有 `acceptsNewConnections` 逻辑）；
3. 存量连接自然存续直到关闭或超时；本节点在 drain 期间**继续处理**已建立连接的包
   （包括别的节点转发来的存量迷路包——left 状态的传播有延迟，drain 节点对已转发到达的包照常服务）；
4. 存量连接归零或超过 `drain_timeout` → `stop()`。

### 7.2 故障爆炸半径分析

本设计的每种故障模式与影响范围（这是"非玩具"的核心论证）：

| 故障                     | 影响                                                                    | 不影响                       |
| ------------------------ | ----------------------------------------------------------------------- | ---------------------------- |
| 节点宕机                 | 该节点的连接断开，客户端重连落到活节点                                  | 其他节点的所有连接           |
| gossip 误判（误标 dead） | 该节点的迷路包被丢弃 → 个别连接退化为重连；Lifeguard + 反驳机制使其自愈 | 该节点自身持有的连接照常服务 |
| gossip 分区              | 分区两侧互相标 dead，跨区迷路包丢失 → 退化为重连                        | 各节点本地连接照常服务       |
| 转发隧道丢包             | 单个包丢失，QUIC 重传恢复                                               | 一切                         |
| 种子节点全挂             | 新节点无法加入集群（存量集群照常运行）                                  | 存量一切                     |

**所有故障的最坏后果都是"某些连接退化为重连"，不存在数据损坏、脑裂、级联失败。**
这是选择最终一致成员协议而非共识协议的结构性收益：协议实现的 bug 爆炸半径同样被限制在这个等级。

## 8. 测试策略：确定性模拟测试

这是从"能跑"到"生产可用"的分界线，与协议实现同步开发，不允许事后补。

### 8.1 网络抽象

SWIM 状态机不做 I/O：输入是消息和单调时钟，输出是待发送数据报。生产 runner 使用真实
非阻塞 UDP socket；测试网络是**内存模拟器**：单线程、虚拟时钟、固定随机种子，可注入
丢包率、延迟分布、消息乱序和双向分区。

转发隧道分为纯 codec 与 UDP `Tunnel`：codec 单测覆盖 IPv4/IPv6、HMAC、篡改和边界；
运行时测试使用真实 loopback UDP socket，验证解封后确实进入 owner Worker 的有界队列。

### 8.2 不变量检查（每轮模拟后断言）

1. **不误杀**：始终响应探测的节点，最终不会停留在 dead 状态（允许瞬时 suspect）；
2. **最终发现**：真正死掉的节点，在分区愈合后 `suspicion_timeout + 传播时间` 内被全员标记 dead；
3. **incarnation 单调**：任何成员视图中同一节点的 incarnation 不回退；
4. **视图收敛**：注入停止后，所有存活节点的成员视图在有限周期内逐项一致；
5. **无幽灵**：left 的节点不会被复活为 alive（除非真的重新 join）。

当前固定种子模拟覆盖分区、愈合、anti-entropy、Lifeguard 和 incarnation 反驳；后续发布验证应
增加 1 万+ 轮随机场景，任一失败可用种子精确复现。转发隧道则已通过真实 loopback 测试
验证“认证包最终到达归属 Worker 或被有据可查地丢弃”。

### 8.3 其他测试

- 消息编解码 fuzz（畸形包不崩溃、不越界）；
- HMAC 认证失败路径（篡改包被静默丢弃并计数）;
- 多进程真实网络 soak 测试（tests/ 下集成测试，3–5 节点跑数小时,配合 tc netem 注入真实丢包）。

## 9. 配置变更

`config.cluster` 段扩展（对应 `foundation/config.zig` 与 `app/config.zig` 的装配）：

配置文件使用 JSON；集群段的最小形状如下：

```json
{
  "cluster": {
    "enabled": false,
    "node_id": 1,
    "advertise_host": "10.0.0.1",
    "advertise_port": 7946,
    "forward_port": 7947,
    "deployment_mode": "anycast",
    "return_path_capacity": 4096,
    "handoff_queue_capacity": 256,
    "secret": "<至少 16 字节的 PSK>",
    "previous_secret": "",
    "max_nodes": 1024,
    "seeds": [{ "node_id": 2, "host": "10.0.0.2", "port": 7946 }]
  }
}
```

`enabled=false` 时不会创建 gossip/forward socket 或线程，CID 仍使用本机 node_id；
本机 `node_id` 必须非零且小于 `max_nodes`。membership、CID 与 forward tunnel 的 v1
标识是源码中的线路格式常量，不是运行时配置字段。启用集群时 `secret` 至少 16 字节，
`forward_port` 必须与 `advertise_port` 不同。`deployment_mode` 可取 `direct`、`anycast`
或 `l4_lb`；`enabled=false` 只能搭配 `direct`，其余组合在启动校验时被拒绝。
`l4_lb` 按每 Worker 的 `return_path_capacity` 预分配两张回程表。`previous_secret` 只用于入站轮换窗口。
每个 seed 的 node_id 必须唯一、不能是本节点，且小于 `max_nodes`。

## 10. 模块划分与实施顺序

### 10.1 代码布局

```
src/control/
  coordinator.zig          # 现有；新增持有 Membership，drain 集成 left 广播
  membership/
    mod.zig                # MembershipView 接口 + 事件定义
    swim.zig               # SWIM 状态机（纯逻辑，不含 I/O）
    crypto.zig             # HMAC-SHA256 原语与 constant-time 验证
    codec.zig              # gossip 消息编解码 + 认证标签
    transport.zig          # 非阻塞 UDP socket
    runner.zig             # 独立协议线程、单调时钟、join/leave 命令
    sim.zig                # 内存网络模拟器（test-only）
src/io/
  cid.zig                  # v1 布局（node_id 字段），version 判别
  forward.zig              # 迷路包转发隧道（封装/解封/注入 LocalPacketRouter）
  reuseport.c              # worker 字节偏移 3 → 5
```

关键分层：`swim.zig` 是**不做任何 I/O 的纯状态机**（输入：消息 + 时钟嘀嗒；输出：待发消息 + 视图变更），
I/O 在 transport 层。这是模拟测试可行的前提，也是协议逻辑可单测到分支级的前提。

### 10.2 实施顺序（按依赖关系）

1. [已完成] `MembershipView`、UDP transport 与内存模拟器；
2. [已完成] SWIM 核心状态机与确定性模拟测试；
3. [已完成] anti-entropy 分片同步与 Lifeguard 三扩展；
4. [已完成] HMAC 双密钥、重放缓存、join/left 与身份冲突检测；
5. [已完成] CID v1 布局、picoquic CID 签发长度与 BPF 偏移更新；
6. [已完成] 带 HMAC/目标绑定/滑动窗口防重放的转发隧道及 Worker 注入；
7. [已完成] `Coordinator` start/drain/stop、配置装配与单机零 socket/线程退化；
8. [部分完成] 文档与真实 UDP loopback 测试已完成；Linux cBPF 实机测试、两个完整网关进程的
   QUIC 跨节点转发和长时间 netem soak 仍属于发布前验证。

## 11. 后续演进

- **加密 CID**：明文 node_id 可被路径观测者用于连接关联，也暴露集群拓扑。
  IETF QUIC-LB（draft-ietf-quic-load-balancers）为此定义了 4 轮 Feistel 加密的 CID 编码。
  若未来采用不兼容布局，再分配新的版本号并设计明确的升级策略；架构本身不变。
- **路由元数据随 gossip 传播**：直连路由表版本化后搭 gossip 下发，实现集群级配置热更新。
- **drain 定向重连**：不迁移 TLS/QUIC 状态；在排除本节点后的成员视图上为已认证连接选择
  新落点，发送 redirect 后由客户端重连。它需要 affinity/broadcast 两种策略下不同的目标
  选择规则，当前尚未实现，详细约束见 `protocol_design.md` §13。

## 12. 设计取舍备忘（为什么不是别的方案）

| 备选方案                                  | 否决理由                                                                                                                                                                            |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 外部中间件（etcd/Redis）记录连接归属      | 每连接/每包一次网络查询，数量级性能退化；引入外部依赖与新故障域                                                                                                                     |
| 内嵌 Raft 做成员管理                      | 成员发现只需最终一致；Raft 实现正确性极难（成员变更/快照/日志截断边界），bug 爆炸半径是数据损坏级，与收益不匹配                                                                     |
| 全网状心跳（每节点 ping 所有节点）        | 曾作为早期候选（N<50 时开销可忽略、实现极简）。项目无存量兼容负担，直接实现 SWIM，省掉一份过渡代码；接口层 `MembershipView` 保留了随时替换实现的自由                                |
| Erlang 式全量状态复制（Mnesia/Mria 路线） | 连接状态复制成本远超收益（§1.2）;网关的正确做法是让状态可丢弃                                                                                                                       |
| C 生态现成 SWIM 库                        | 不存在可直接引入的成熟独立库：memberlist 是 Go；Tarantool 的 C 实现耦合其 fiber/事件循环，剥离后等于维护私有 fork。自研时以 memberlist 为协议行为参考、Tarantool swim 为 C 实现参考 |
