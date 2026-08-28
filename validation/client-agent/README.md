# Lyune Validation Client Agent

这是浏览器旁的轻量 Go 客户端，用于 Mac 与 Linux 两阶段真实环境验证。浏览器不能直接打开自定义 ALPN `lyune/2` 的原生 QUIC，因此 agent 暴露本地 HTTP API，并使用 quic-go 与 Gateway 互操作；Gateway 与 Reactor 之间仍是另一段真实 QUIC。

两类入口同时保留：

- `/api/connect`、`/api/exchange`：M2–M8 的控制帧、echo、长流、并发和慢读取诊断；
- `/api/im/*`：真实用户认证、独立会话、群命令和后端 `.peer` 推送。应用 token 只保存在 agent 内存，浏览器只持有随机 session id。

```bash
go run . --listen 127.0.0.1:8787
```

它只应监听 loopback，不是远程管理 API，也不是生产客户端 SDK。完整启动顺序与验收记录见 `../../docs/validation.md`。
