# Lyune Gateway 文档导航

本目录按“当前事实、演进计划、稳定设计”三个层次组织。阅读和维护时应先判断问题属于哪一层，避免把完成状态、历史讨论和协议规范混在一起。

当前门禁摘要：`TransportSession` 的 Raw QUIC 与 WSS binding 均已实现；两者的 Mac 自动化 M0–M18 均已通过，覆盖真实密码认证、混合 SQLite 群聊、协议/负例、慢消费者、断线补偿、presence、120 秒长流、双 Worker、反复进程故障和混合 soak。人工浏览器验证已确认共享 SQLite 历史，并完成 Raw→WSS、WSS→Raw 两个方向的同时在线实时消息；因此多传输双向实时互通的人工证据已经关闭，剩余完整 UI 操作/负例清单单独跟踪。当前主线已经切换为源码逐行审计，功能演进和远程 Linux 验证暂停；仍不创建 tag/release，也不把 Mac 结果外推为 Linux 或生产结论。当前方向以 `code_audit.md` 为准，代码事实和运行证据分别以 `status.md`、`validation.md` 为准。

## 推荐阅读顺序

1. [当前实现状态](status.md)：当前工作树已经实现什么、验证到什么程度、还有哪些已知缺口。
2. [源码逐行审计](code_audit.md)：当前冻结规则、审计顺序、发现分类和完成条件。
3. [两阶段真实环境验证](validation.md)：MacBook 单机、远程 Linux 的执行计划、退出条件和持续记录。
4. [Roadmap](roadmap.md)：下一阶段的优先级和明确暂缓事项。
5. [架构设计](architecture.md)：系统定位、组件边界、线程模型与后端路由模型。
6. [运行时执行流](execution_flow.md)：启动、接入、认证、Exchange、回程、推送、交接与关闭的真实调用链。
7. [帧协议设计](protocol_design.md)：客户端、网关、后端之间的应用层线格式与安全边界。
8. [多传输客户端会话设计](transport_session_design.md)：Raw QUIC 保持不变、WSS 回退和 TransportSession 门禁。
9. [WSS 传输 binding](wss_transport.md)：TLS/Upgrade、逻辑流 envelope、队列边界和当前验证范围。
10. [集群设计](cluster_design.md)：membership、CID、forward tunnel、peer link 与故障模型。
11. [目录设计](directory_design.md)：源码目录、模块所有权和依赖方向。

## 文档权威关系

| 问题 | 权威文档 |
| --- | --- |
| 当前是否已经实现、测试是否通过 | `status.md` |
| 当前为什么冻结、怎样逐行审计、发现如何分类 | `code_audit.md` |
| 真实环境怎样验证、实际结果如何 | `validation.md` |
| 下一步先做什么 | `roadmap.md` |
| 一个事件实际怎样穿过各模块、状态归谁 | `execution_flow.md` |
| 客户端/后端可见线格式 | `protocol_design.md` |
| 客户端 Raw QUIC/WSS binding 与实施门禁 | `transport_session_design.md` |
| WSS 当前线格式、握手和资源边界 | `wss_transport.md` |
| 集群内部协议与故障模型 | `cluster_design.md` |
| 组件职责与依赖方向 | `architecture.md`、`directory_design.md` |

当设计文档里的历史实施清单与 `status.md` 冲突时，以当前源码、测试和 `status.md` 为准。设计文档保留决策背景，不应再承担每日更新的项目看板职责。

[AI IDE 会话归档](../comate_chat_export/README.md) 只用于理解设计背景和判断来源，不是规范或完成证据。归档内容不追溯改写；其中任何结论都必须回到当前源码和本目录权威文档核对。

## 更新约定

- 修改线格式时同步修改 `protocol_design.md`、编解码测试和 ALPN 版本决策。
- 修改集群线路格式时同步修改 `cluster_design.md`、版本常量和 codec 测试。
- 合入功能时只在 `status.md` 更新一次当前状态，不在多个设计章节重复维护“已实现”列表。
- 新发现的缺口进入 `status.md`；确定优先级后再进入 `roadmap.md`。
- 审计发现先进入 `code_audit.md` 并附证据；没有测量的性能判断不得直接写成重构结论。
- 真实环境的命令、证据和结论只进入 `validation.md`，不能用计划项冒充已验证状态。
- 被否决的架构方向保留简短理由，避免后续重复讨论。
- README 只提供入口和摘要，不复制深度设计文档。
