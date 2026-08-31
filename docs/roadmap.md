# Roadmap

本文只表达迭代顺序，不承诺发布日期。当前没有生产环境和外部兼容性负担，因此优先把现有架构做正确、做有界、做得可验证。

## 阶段 0：冻结开发基线

- [x] 对齐 README 与当前代码事实；
- [x] 建立文档导航、当前状态和 roadmap；
- [x] 修正文档中 `.peer`、`.multicast`、跨节点投递等过时描述；
- [x] 运行 fmt、默认测试和 ReleaseSafe 构建；
- [x] 形成当前源码与文档的可推送基线；
- [x] 本阶段不创建 tag，不生成 release，不承诺协议稳定性。

## 阶段 1：客户端多传输接入与真实环境验证（Mac 自动化已完成，人工验收部分完成）

阶段一在真实 MacBook 上使用 Go Reactor、原生 QUIC client-agent 和轻量 React UI，先完成单机最小闭环，再覆盖并发流、生命周期、慢端与超过 60 秒的长流。阶段二把同一套资产迁移到远程 Linux，验证跨平台构建、真实网络、io_uring、reuseport/cBPF 和多 Worker。

Mac 阶段 M0–M18 已通过并冻结：除真实 SQLite IM 闭环外，`lyune/2` 的 required/none、连接级 lifecycle/presence、流方向约束、reset/stop、128 位跨进程连接身份、混合负载、故障恢复和资源趋势都有真实进程证据。

在迁移到远程 Linux 前插入两道新的 Mac 门禁：

1. （已完成）客户端 I/O 已收口为传输无关的 `TransportSession`；该步骤当时只启用映射到现有 picoquic 的 `RawQuicSession`。ALPN、OPEN/DATA 线格式、QUIC stream、datagram 和全部业务行为不变；Raw-only M0–M18 已重新通过；
2. （自动化门禁已完成）TLS/TCP 上的 WSS binding 已让浏览器可直接连接 Gateway；真实 WSS↔Raw QUIC SQLite 群聊、协议/负例、慢消费者、断线补偿、presence、120 秒长流、双 Worker、反复进程故障、混合 soak 与 M18 干净总复跑均已通过。用户已手工信任开发证书，并验证 WSS 可读取 Raw 用户的历史消息、WSS 消息可实时到达 Raw 会话；Raw→WSS 同时在线实时推送和完整 UI 负例仍待关闭。

详细边界和“无损、无差异”的验收定义见 [多传输客户端会话设计](transport_session_design.md)，命令与逐次证据继续统一记录在 [两阶段真实环境验证](validation.md)。本阶段仍不创建 tag 或 release。

## 阶段 1.5：源码逐行审计（当前）

当前暂停新增功能、机会主义重构和远程 Linux 验证。项目所有者先按 [源码逐行审计](code_audit.md) 审核 composition root、协议、`TransportSession`、Raw/WSS binding、Worker、后端、集群与关闭路径，逐项确认状态所有权、资源上界、错误传播和信任边界。

审计发现必须带代码或运行证据，并区分确定缺陷与性能假设。后续可能继续关闭 Mac 人工验收、进行局部重构、修复正确性问题或进入 Linux，但这些都要等审计结论形成后再排序，不能把下面的阶段编号当成已经批准的执行指令。

## 阶段 2：正确性和有界资源

按以下顺序处理：

1. （已完成）回程映射由绝对超时改为空闲超时；Mac 120 秒活跃流通过，125 秒静默负对照在 60 秒明确返回 `backend response timeout`；deadline 使用 QUIC 单流 discard，不再关闭同连接的正常兄弟流；
2. （已完成）后端响应写回后主动驱动客户端 QUIC；后端连接/接收池失败按连接精确回收 inflight 并立即回显，不再等待客户端 deadline；
3. 限制认证响应累计长度，超限时结束单流并回收 pending auth；
4. 将 UDP 动态发送数组替换为有界队列，明确满载策略和指标；
5. 设计客户端 → 网关 → 后端、后端 → 网关 → 客户端的端到端背压；
6. 审核 membership.Table 并发发布模型，消除不可证明的非原子并发访问；
7. 将热加载改为预分配/staging 后再 publish，兑现全有或全无语义。

## 阶段 3：最小 CI 与可重复集成测试

两阶段验证形成稳定命令后再添加最小 GitHub Actions，第一版只做：

- 固定 Zig 0.16.0；
- checkout submodules；
- `zig fmt --check build.zig src`；
- `zig build test --summary all`。

CI 暂不负责 release、镜像、部署或多平台矩阵。添加前先解决 BoringSSL 本地 path dependency 在干净 runner 上的可复现构建。

随后把成本可控的冒烟场景接入独立集成任务，而不是把高成本场景全部塞进每次提交：

- reuseport/cBPF 内核分流；
- 双网关进程 + 客户端/后端 mock；
- anycast/l4_lb forward request/response；
- peer QUIC+mTLS；
- netem 与长时间 soak。

## 阶段 4：安全和可运维性

- 多 realm 启动时强制后端证书验证与客户端证书；
- 提供生产配置示例和证书/密钥轮换说明；
- 隔离 peer 与客户端容量；
- 导出 connection、inflight、queue、peer、SWIM、drop/refuse 指标；
- 提供只读健康检查和诊断快照，不增加远程写管理面；
- 完善结构化日志中的 realm/route/node/worker 归因；
- 实现或明确放弃 drain 定向 redirect。

## 阶段 5：性能验证与优化

- 建立连接数、吞吐、流式延迟、广播扇出和内存预算基准；
- 根据数据决定后端轮询是否改为事件驱动；
- 评估 exchange/spill/inflight HashMap 的预分配或定容替代；
- 评估 peer link 主动预热；
- 优化发送队列和批量发送，验证 Linux/macOS 行为差异。

## 按需求再决定的能力

以下能力不作为当前主线前置条件：

- NATS 等 relay transport；
- etcd/Consul 服务发现；
- `.gateway` streaming；
- CLI 客户端和公开 SDK；
- 更复杂的动态路由修改/删除。

## 明确不做

- 内嵌 Raft 或全局强一致连接目录；
- 每连接访问 Redis/etcd；
- 在网关中保存业务成员关系或离线消息；
- 跨节点复制 TLS 密钥、包号、拥塞状态和 QUIC stream 状态；
- 用 UDP 应用层分片替代节点间 peer QUIC 链路。
