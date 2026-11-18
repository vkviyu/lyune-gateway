# Lyune Validation Client Agent

这是浏览器旁的轻量 Go 客户端，用于 Mac 与 Linux 两阶段真实环境验证。浏览器不能直接打开自定义 ALPN `lyune/2` 的原生 QUIC，因此 agent 暴露本地 HTTP API，并使用 quic-go 与 Gateway 互操作；Gateway 与 Reactor 之间仍是另一段真实 QUIC。

两类入口同时保留：

- `/api/connect`、`/api/exchange`：M2–M8 的控制帧、echo、长流、并发和慢读取诊断；
- `/api/im/*`：真实用户认证、独立会话、群命令和后端 `.peer` 推送。应用 token 只保存在 agent 内存，浏览器只持有随机 session id。

```bash
go run . --config config/client-agent.json
```

默认配置让 agent 监听 `127.0.0.1:8787` 并连接本机 Gateway。测试云服务器时，复制并修改 `config/client-agent.json`：

```json
{
  "listen": "127.0.0.1:8787",
  "gateway_address": "你的云 Gateway 公网地址:8443",
  "server_name": "证书中的域名",
  "insecure_skip_verify": false,
  "allowed_origins": ["http://127.0.0.1:5173", "http://localhost:5173"]
}
```

`gateway_address` 是 Gateway 的 UDP/QUIC 地址，`server_name` 必须匹配 Gateway 证书的 SAN。只有开发自签名证书无法在本机信任时才使用 `insecure_skip_verify: true`。agent 只应监听 loopback，不是远程管理 API，也不是生产客户端 SDK。
