# 当前实现状态

> 基线日期：2026-09-01
>
> 状态：开发中；没有正式 release，没有生产环境使用者。
>
> 本文描述当前源码事实，不构成兼容性或发布时间承诺。

真实 MacBook 单机 Raw QUIC M0–M18 最初冻结在 `425f2a6`。随后加入 `TransportSession` 与 WSS，两种 binding 均已通过 Mac 自动化 M0–M18；WSS 轮还覆盖真实认证/IM、协议并发与取消、慢消费者、断线补偿、presence、120 秒长流、双 Worker、反复进程故障与混合 soak。人工浏览器验证已经确认 WSS 会话能读取 Raw 用户持久化的群消息，且 WSS 发出的消息能实时推送到 Raw 会话；Raw→WSS 同时在线实时推送和完整 UI 负例清单仍待人工关闭。当前不再以“验收完成后立即进入 Linux”为默认顺序，而是冻结功能演进，先完成 [源码逐行审计](code_audit.md)，再由项目所有者决定方向。这里的“冻结”不是 release、兼容性承诺或生产就绪结论；运行证据以 [两阶段真实环境验证](validation.md) 为准。

## 1. 已形成闭环的能力

### 客户端与后端数据面

- picoquic + libxev 服务端、Thread-per-Core Worker 和连接生命周期；
- 客户端业务 I/O 已收口到类型擦除 `TransportSession`，同时提供保持既有线格式的 Raw QUIC adapter 和浏览器直连的 WSS adapter；
- WSS listener 使用 libxev TCP + BoringSSL、严格 HTTP Upgrade/Origin/Host-SNI、RFC 6455 framing、20 字节逻辑流 envelope 和单会话有界发送队列；
- OPEN/DATA 增量分帧、控制交换、QUIC DATAGRAM；
- OPEN 上显式 `response_mode=required|none`；无响应交换在接纳后只回空 FIN，后端响应被明确丢弃；
- `.service` buffered/streaming 请求与后端响应回程；
- 认证委托、`AuthContext`/`AuthGrant`、`dest_id` 绑定和准入 TTL；
- 后端主动 `.peer`/`.multicast` 推送、流式推送、投递回报；
- client-initiated 与 Gateway-initiated 双向流的方向约束；应用单向流额度默认是 0；
- RESET_STREAM/STOP_SENDING 在客户端、Gateway、DirectTransport 之间按方向传播并精确清理 Exchange；
- 128 位带进程 incarnation 的 `conn_token`，连接级 online/offline、严格 sequence 与租约刷新；
- 后端控制的 kick、join_group、leave_group；
- DirectTransport 副本连接、异步 DNS、退避重连；
- 每 Worker 共享 AsyncClient 和后端接收槽位池，同时保持 ScopedRoute/realm 连接语义隔离。
- 后端响应由 Worker 定时器写入客户端 `TransportSession` 后会主动 flush，不再滞留到最长 10 秒的协议 timer；后端连接失败会立即终止该连接上的普通/认证 inflight。
- 后端连接代际已并入流句柄；真实连接故障按副本逐项上报，应用 deadline 则只向对应 QUIC 流发送 RESET_STREAM/STOP_SENDING，不关闭承载其他交换的共享连接。

### 多 Worker 与集群

- 12 字节 CID v1，包含 node_id、worker_id 与随机熵；
- Linux `SO_REUSEPORT` cBPF 分类和用户态本地交接兜底；
- SWIM、anti-entropy、Lifeguard、HMAC 双密钥、真实 UDP runner；
- direct、anycast、l4_lb 三种入口模型；
- HMAC、目标绑定、session/sequence 防重放的双向 forward tunnel；
- 应用消息跨 Worker 转投；
- `.peer` 跨节点按 HRW 选择 home 节点，节点内对全部 Worker 去重交接，兼容 WSS/TCP 与 macOS Raw QUIC 无法按 `dest_id` 迁移连接的事实；
- QUIC+mTLS peer listener 和出站 peer link；
- HRW affinity/broadcast、成员变更双查、宽限期后 rehome；
- drain 时广播 left、停止接收新连接并等待存量连接。

### 多 realm 与运行时配置

- TLS SNI → realm，未登记 SNI 在多 realm 模式下失败关闭；
- `(realm, dest_id)`、`ScopedRoute(realm, group, route_key)`、`(realm, group_id)` 隔离；
- 会话、组播成员边、inflight、后端接收槽位、应用消息队列的 realm 公平准入；
- 后端和 peer link 客户端证书能力；
- SIGHUP 重读配置，只接受新增 realm 和路由；
- 新路由的 Worker-local DirectTransport 惰性创建。

## 2. 已验证范围

当前基线验证结果：

- `zig fmt --check build.zig src`：通过；
- `zig build test --summary all`：284 pass、1 skip，共 285 个测试；
- `zig build -Doptimize=ReleaseSafe --summary all`：9/9 构建步骤通过。
- Reactor、client-agent Go 测试与 React 生产构建：通过。

测试覆盖帧 codec/framing、连接与路由表、realm 配额、DirectTransport、CID、交接队列、SWIM 状态机、分区愈合、Lifeguard、HMAC、真实 loopback gossip、forward tunnel、peer 权限和主要 Worker 分派路径。

真实环境验证状态与仍未完成项：

- Mac 上真实浏览器 + 原生 QUIC client-agent → Gateway → Go Reactor/SQLite 的原始基线和 `TransportSession` Raw-only 回归 M0–M18 均通过；最新复跑覆盖 120 秒活跃长流与同连接静默流隔离、真实双用户群聊、混合 required/none/typing/推送/取消、Gateway/Reactor/agent 重启，以及持续负载后的 RSS/FD/SQLite 趋势；
- WSS 真实 Mac 自动化 M0–M18 已通过：网关 ping、三段流式 echo、请求结束前响应、32 并发、none、RESET/STOP、14 类实际网络负例、64/65 容量、断线历史补偿、同账号 presence、120 秒长流和 1200 条大消息慢消费者隔离均通过；双 Worker 修复了 HRW 首选 Worker 与 reuseport 实际所有者不一致造成的漏投；3 次 Reactor 与 2 次 Gateway 故障循环全部恢复且进程 incarnation 不复用；独立 30 批混合 soak 的 RSS 在第 10 批后平台化，三进程 FD 保持 `15/15/9`；
- 远程 Linux 阶段尚未开始，Mac 结论不能替代 Linux `io_uring`、reuseport/cBPF、跨主机网络和多 Worker 证据；
- Linux 内核真实 cBPF attach 与多 socket 分流；
- 两个完整网关进程的客户端 QUIC、forward tunnel 和 peer link 联调；
- 3–5 节点 `tc netem` 丢包、延迟、重排、分区和长时间 soak；
- socket `EAGAIN`、持续内存压力和发布容量下的 soak；M7 已覆盖受控慢后端、慢客户端与接收池满载；
- 多 realm + 后端 mTLS 的端到端安全测试；
- 进程滚动扩缩容、drain 和大规模同时重连。

## 3. 已知缺口

### 当前演进门禁：源码逐行审计

1. [ ] 按 [源码逐行审计](code_audit.md) 确认模块职责、状态所有权、执行流和失败语义；
2. [ ] 对发现项区分文档偏差、可读性债务、确定缺陷、安全风险和待测量的性能假设；
3. [ ] 在证据和风险排序完成前，不新增功能、不做机会主义重构、不进入远程 Linux；
4. [ ] 审计结束后由项目所有者明确下一阶段，再更新 roadmap。

### 已完成门禁：客户端传输抽象

1. [x] Worker 的客户端写流、主动推送、临时消息、取消和关闭已收口为类型擦除 `TransportSession`；具体 binding 通过 `session.Handler`/`Acceptor` 由 app 装配，Worker 不导入 WSS；
2. [x] `RawQuicSession` 已重新通过 Mac M0–M18；
3. [x] slot/generation-backed `SessionHandle` 与 WSS/TLS/TCP binding 已实现，真实 QUIC↔WSS 双用户群聊第一轮通过；
4. [x] WSS/混合 binding 的反复进程故障、受控 soak、资源趋势和 M18 干净自动化总复跑均已完成；
5. [ ] 人工验收部分完成：用户已手工信任开发证书，并用真实 Raw/WSS 用户验证共享历史和 WSS→Raw 实时推送；Raw→WSS 同时在线实时推送及完整 UI 负例仍待关闭。完整决策见 [多传输客户端会话设计](transport_session_design.md)，当前 WSS 线格式与边界见 [WSS 传输 binding](wss_transport.md)。

### 优先级 A：正确性与资源上界

1. 认证服务响应使用动态缓冲累积到 FIN，缺少最大帧长度上限。
2. 客户端快、后端慢时，上行 QUIC 流控不会自动跨两段连接传导；需要显式背压。
3. UDP socket 忙时的发送队列是动态数组且没有容量上限，需要有界 ring 和过载策略。
4. 后端接收槽位池满时仍会关闭发生溢出的后端连接，并立即失败该连接上的全部 inflight；普通 deadline 已能单流 discard，但把“池满”也缩小为单流故障还需要独立的溢出记账和明确的过载策略。
5. membership.Table 的多缓冲无锁发布依赖“写者不会连续追上读者”的时序假设；生产前需要完成严格内存模型证明或改为可证明安全的快照机制。
6. DirectTransport 连接在空闲关闭边界可能仍短暂处于 ready，首个请求会进入失效连接；需要稳定复现并明确失败请求的重试/重排队语义。

### 优先级 B：安全与配置

1. 网关侧已经支持后端客户端证书，但多 realm 配置尚未强制 `verify_certificate + CA + client cert/key`。
2. 默认配置和仓库证书仅适合开发，不能作为生产模板。
3. peer 连接与普通客户端共享 ConnectionManager 容量和默认 realm 配额，应该隔离或预留内部链路容量。
4. SWIM 的 HMAC 重放缓存是有限窗口；它能挡住近期重复包，但不等价于持久会话序列协议。

### 优先级 C：运维与体验

1. 热加载先校验再逐条提交；提交阶段 OOM 或实际 slab 容量不足时可能部分生效，还不是真正事务。
2. drain 没有定向 redirect，超时后仍存活的客户端由 SDK 自行重连。
3. 已有大量计数器，但没有统一 metrics/exporter、健康检查或诊断快照入口。
4. peer link 首次使用时触发连接并拒绝当前消息；需要评估主动预热，而不是加入无界等待队列。
5. 后端响应采用固定周期轮询，需用基准数据判断是否值得事件化。
6. `.gateway` 流式交换没有消费方；在出现真实需求前不实现。

## 4. 当前不包含的能力

- NATS/RabbitMQ 等 relay transport；
- etcd/Consul 后端服务发现 transport；
- CLI 客户端和官方 SDK；
- 离线消息、消息持久化、业务幂等和好友/房间权威状态；
- QUIC 连接状态跨节点复制或透明迁移；
- 正式安装包、容器镜像、版本 tag 或 release artifact；
- 项目级 CI 流水线。

这些能力并非都必须实现。是否进入 roadmap 应由实际部署和业务需求决定。
