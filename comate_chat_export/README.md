# AI IDE 会话归档

本目录保存从此前 AI IDE 导出的关键会话，目的是保留问题背景、设计推导和历史判断。

这些文件是**只读历史材料**，不是当前实现规范，也不证明其中提到的功能已经完成。会话里的命令、端口、类型名、测试数量和“下一步”都可能对应当时的工作树；引用前必须与当前源码和正式文档重新核对。

当前权威关系：

- 代码事实与已知缺口：`docs/status.md`；
- 当前冻结方向与审计记录：`docs/code_audit.md`；
- 真实运行证据：`docs/validation.md`；
- 线格式：`docs/protocol_design.md` 与 `docs/wss_transport.md`；
- 架构边界与执行流：`docs/architecture.md`、`docs/execution_flow.md`。

为保留原始上下文，导出的会话正文不做追溯性改写；发现不一致时修正正式文档，并在源码审计记录中说明。
