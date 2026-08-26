# Lyune Gateway 文档导航

本目录按“当前事实、演进计划、稳定设计”三个层次组织。阅读和维护时应先判断问题属于哪一层，避免把完成状态、历史讨论和协议规范混在一起。

## 推荐阅读顺序

1. [当前实现状态](status.md)：当前工作树已经实现什么、验证到什么程度、还有哪些已知缺口。
2. [Roadmap](roadmap.md)：下一阶段的优先级和明确暂缓事项。
3. [架构设计](architecture.md)：系统定位、组件边界、线程模型与后端路由模型。
4. [帧协议设计](protocol_design.md)：客户端、网关、后端之间的应用层线格式与安全边界。
5. [集群设计](cluster_design.md)：membership、CID、forward tunnel、peer link 与故障模型。
6. [目录设计](directory_design.md)：源码目录、模块所有权和依赖方向。

## 文档权威关系

| 问题 | 权威文档 |
| --- | --- |
| 当前是否已经实现、测试是否通过 | `status.md` |
| 下一步先做什么 | `roadmap.md` |
| 客户端/后端可见线格式 | `protocol_design.md` |
| 集群内部协议与故障模型 | `cluster_design.md` |
| 组件职责与依赖方向 | `architecture.md`、`directory_design.md` |

当设计文档里的历史实施清单与 `status.md` 冲突时，以当前源码、测试和 `status.md` 为准。设计文档保留决策背景，不应再承担每日更新的项目看板职责。

## 更新约定

- 修改线格式时同步修改 `protocol_design.md`、编解码测试和 ALPN 版本决策。
- 修改集群线路格式时同步修改 `cluster_design.md`、版本常量和 codec 测试。
- 合入功能时只在 `status.md` 更新一次当前状态，不在多个设计章节重复维护“已实现”列表。
- 新发现的缺口进入 `status.md`；确定优先级后再进入 `roadmap.md`。
- 被否决的架构方向保留简短理由，避免后续重复讨论。
- README 只提供入口和摘要，不复制深度设计文档。
