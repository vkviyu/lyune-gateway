# Roadmap

本文只表达迭代顺序，不承诺发布日期。当前没有生产环境和外部兼容性负担，因此优先把现有架构做正确、做有界、做得可验证。

## 阶段 0：冻结开发基线

- [x] 对齐 README 与当前代码事实；
- [x] 建立文档导航、当前状态和 roadmap；
- [x] 修正文档中 `.peer`、`.multicast`、跨节点投递等过时描述；
- [x] 运行 fmt、默认测试和 ReleaseSafe 构建；
- [x] 形成当前源码与文档的可推送基线；
- [x] 本阶段不创建 tag，不生成 release，不承诺协议稳定性。

## 阶段 1：正确性和有界资源

按以下顺序处理：

1. 回程映射由绝对超时改为空闲超时，并增加超过 60 秒的流式回归测试；
2. 限制认证响应累计长度，超限时结束单流并回收 pending auth；
3. 将 UDP 动态发送数组替换为有界队列，明确满载策略和指标；
4. 设计客户端 → 网关 → 后端、后端 → 网关 → 客户端的端到端背压；
5. 审核 membership.Table 并发发布模型，消除不可证明的非原子并发访问；
6. 将热加载改为预分配/staging 后再 publish，兑现全有或全无语义。

## 阶段 2：最小 CI 与真实集成测试

基线推送后再添加最小 GitHub Actions，第一版只做：

- 固定 Zig 0.16.0；
- checkout submodules；
- `zig fmt --check build.zig src`；
- `zig build test --summary all`。

CI 暂不负责 release、镜像、部署或多平台矩阵。添加前先解决 BoringSSL 本地 path dependency 在干净 runner 上的可复现构建。

随后增加独立的 Linux 集成测试，而不是把高成本场景全部塞进每次提交：

- reuseport/cBPF 内核分流；
- 双网关进程 + 客户端/后端 mock；
- anycast/l4_lb forward request/response；
- peer QUIC+mTLS；
- netem 与长时间 soak。

## 阶段 3：安全和可运维性

- 多 realm 启动时强制后端证书验证与客户端证书；
- 提供生产配置示例和证书/密钥轮换说明；
- 隔离 peer 与客户端容量；
- 导出 connection、inflight、queue、peer、SWIM、drop/refuse 指标；
- 提供只读健康检查和诊断快照，不增加远程写管理面；
- 完善结构化日志中的 realm/route/node/worker 归因；
- 实现或明确放弃 drain 定向 redirect。

## 阶段 4：性能验证与优化

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
