# Lyune Validation Web Client

这是两阶段真实环境验证使用的轻量 React/Vite IM 客户端，不依赖 `liky`。它不是展示固定测试数据的控制台：页面可以注册/登录真实用户、创建群、凭邀请码加入、读取 SQLite 历史并让两个独立浏览器会话实时互发消息。

页面提供两条真实传输路径：默认由浏览器原生 `WebSocket` 直接连接 Gateway 的 `wss://localhost:8444/lyune/v2`；切换到 Raw QUIC 后，页面通过 `/api` 控制相邻的 `validation/client-agent` 建立独立 `lyune/2` QUIC 连接。两条路径都经同一个 Gateway Worker 到 Reactor 完成 auth 和 `.service(1,2)` 命令，并接收 Reactor 主动发出的 `.peer` 流。完整拓扑、启动顺序和判定标准见 `../../docs/validation.md`。

```bash
npm install
npm run dev
```

开发服务器监听 `127.0.0.1:5173`，并把 `/api` 代理到 `127.0.0.1:8787`。

WSS 使用项目根目录的自签名开发证书。它已包含 `localhost` 和 `127.0.0.1` SAN，但浏览器仍要求用户显式信任。macOS 首次运行时：

1. 打开“钥匙串访问”，选择“文件 → 导入项目”；不是“新建钥匙串”或“添加钥匙串”；
2. 导入项目根目录的 `server.crt`，目标钥匙串选择当前用户的“登录”；
3. 在“我的证书”或“证书”中找到名称为 `localhost` 的条目，展开“信任”，把“使用此证书时”设为“始终信任”；
4. 关闭证书窗口并按系统提示验证身份，然后完全退出并重新打开浏览器。

只应把这份证书用于本机开发。可用 `openssl x509 -in ../../server.crt -noout -subject -issuer -dates -fingerprint -sha256` 核对导入项；不要只凭显示名称判断。页面脚本不会也不能跳过 TLS 校验。

为了在同一台机器验证两位在线用户，请打开两个标签页。WSS 的应用 token 与会话只保留在当前页面内存；Raw QUIC 的 session id 只保存在各标签页自己的 `sessionStorage`，应用 token 只留在 client-agent 内存，不写入浏览器存储。
