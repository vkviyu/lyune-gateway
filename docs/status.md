# 当前实现状态

> 基线日期：2026-08-27
>
> 状态：开发中；没有正式 release，没有生产环境使用者。
>
> 本文描述当前源码事实，不构成兼容性或发布时间承诺。

## 1. 已形成闭环的能力

### 客户端与后端数据面

- picoquic + libxev 服务端、Thread-per-Core Worker 和连接生命周期；
- OPEN/DATA 增量分帧、控制交换、QUIC DATAGRAM；
- `.service` buffered/streaming 请求与后端响应回程；
- 认证委托、`AuthContext`/`AuthGrant`、`dest_id` 绑定和准入 TTL；
- 后端主动 `.peer`/`.multicast` 推送、流式推送、投递回报；
- 后端控制的 kick、join_group、leave_group；
- DirectTransport 副本连接、异步 DNS、退避重连；
- 每 Worker 共享 AsyncClient 和后端接收槽位池，同时保持 ScopedRoute/realm 连接语义隔离。

### 多 Worker 与集群

- 12 字节 CID v1，包含 node_id、worker_id 与随机熵；
- Linux `SO_REUSEPORT` cBPF 分类和用户态本地交接兜底；
- SWIM、anti-entropy、Lifeguard、HMAC 双密钥、真实 UDP runner；
- direct、anycast、l4_lb 三种入口模型；
- HMAC、目标绑定、session/sequence 防重放的双向 forward tunnel；
- 应用消息跨 Worker 转投；
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
- `zig build test --summary all`：244 pass、1 skip，共 245 个测试；
- `zig build -Doptimize=ReleaseSafe --summary all`：9/9 构建步骤通过。

测试覆盖帧 codec/framing、连接与路由表、realm 配额、DirectTransport、CID、交接队列、SWIM 状态机、分区愈合、Lifeguard、HMAC、真实 loopback gossip、forward tunnel、peer 权限和主要 Worker 分派路径。

尚未完成的发布级验证：

- Linux 内核真实 cBPF attach 与多 socket 分流；
- 两个完整网关进程的客户端 QUIC、forward tunnel 和 peer link 联调；
- 3–5 节点 `tc netem` 丢包、延迟、重排、分区和长时间 soak；
- 超过 60 秒的流式请求/响应；
- socket `EAGAIN`、慢后端、慢客户端和内存压力测试；
- 多 realm + 后端 mTLS 的端到端安全测试；
- 进程滚动扩缩容、drain 和大规模同时重连。

## 3. 已知缺口

### 优先级 A：正确性与资源上界

1. `inflight` 以创建时间执行 60 秒绝对超时，活跃长流不会刷新，可能在传输中丢失回程映射；应改为空闲超时。
2. 认证服务响应使用动态缓冲累积到 FIN，缺少最大帧长度上限。
3. 客户端快、后端慢时，上行 QUIC 流控不会自动跨两段连接传导；需要显式背压。
4. UDP socket 忙时的发送队列是动态数组且没有容量上限，需要有界 ring 和过载策略。
5. 后端接收槽位池满时会关闭整条后端连接；更细粒度的目标是只终止受影响流。
6. membership.Table 的多缓冲无锁发布依赖“写者不会连续追上读者”的时序假设；生产前需要完成严格内存模型证明或改为可证明安全的快照机制。

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
