# Lyune Validation Web Client

这是两阶段真实环境验证使用的轻量 React/Vite IM 客户端，不依赖 `liky`。它不是展示固定测试数据的控制台：页面可以注册/登录真实用户、创建群、凭邀请码加入、读取 SQLite 历史并让两个独立浏览器会话实时互发消息。

浏览器本身不是 `lyune/1` QUIC 端点。页面通过 `/api` 控制相邻的 `validation/client-agent`；每个页面会话由 agent 建立独立 QUIC 连接，经 Gateway 到 Reactor 完成 auth 和 `.service(1,2)` 命令，并监听 Reactor 主动发出的 `.peer` 流。完整拓扑、启动顺序和判定标准见 `../../docs/validation.md`。

```bash
npm install
npm run dev
```

开发服务器监听 `127.0.0.1:5173`，并把 `/api` 代理到 `127.0.0.1:8787`。

为了在同一台机器验证两位在线用户，请打开两个标签页；session id 只保存在各标签页自己的 `sessionStorage`，应用 token 只留在 client-agent 内存，不写入浏览器存储。
