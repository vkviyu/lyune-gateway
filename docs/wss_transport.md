# WSS 传输 binding

> 首次实现：2026-08-30
>
> 当前状态：代码、浏览器客户端和 Mac 自动化 M0–M18 已完成，覆盖真实混合 IM、
> 协议/畸形输入、慢消费者、断线补偿、presence、120 秒长流、双 Worker、反复故障
> 与混合 soak。人工浏览器已确认共享历史以及 Raw→WSS、WSS→Raw 双向实时消息，
> 完整 UI 操作/负例清单仍开放。当前先暂停演进并进行源码审计。

本文记录 `lyune.v2` WSS binding 的当前线格式、所有权和资源边界。业务层语义仍以
[帧协议设计](protocol_design.md) 为准，抽象决策与门禁顺序见
[多传输客户端会话设计](transport_session_design.md)，真实运行证据见
[两阶段真实环境验证](validation.md)。

## 1. 定位与拓扑

WSS 是普通浏览器直接连接 Gateway 的传输，也是原生客户端在 UDP/QUIC 不可用时的
TCP 回退。它不是另一套业务协议：TLS、HTTP Upgrade、WebSocket framing 和逻辑流
envelope 在 listener 内终止，之后与 Raw QUIC 共用同一个 Worker、认证、Exchange、
路由、推送、lifecycle 和 Reactor 后端路径。

```text
Browser WebSocket ─ TLS/TCP :8444 ─ WSS Connection/adapter ─┐
                                                           ├─ TransportSession ─ Worker ─ Reactor
Native client ─── lyune/2 QUIC :8443 ─ Raw QUIC adapter ───┘
```

默认配置继续关闭 WSS。Mac 验证配置显式监听 `127.0.0.1:8444`，Raw QUIC 仍监听
UDP `127.0.0.1:8443`；两个 listener 可同时工作。

## 2. 握手边界

- TLS 使用与 Raw QUIC listener 相同的证书和私钥；HTTP `Host` 必须与 TLS SNI
  一致，可附带合法的 1–65535 端口；
- 只接受 `GET /lyune/v2 HTTP/1.1`、WebSocket version `13` 和子协议
  `lyune.v2`；
- `Origin` 采用配置中的精确白名单，不支持通配符；缺失 Origin 只有在
  `allow_missing_origin=true` 时才允许；
- HTTP head 上限 8 KiB，TLS/Upgrade 有独立 deadline；重复 Host、key、Origin 或
  version 以及 header folding、非法 token、错误 path/subprotocol 都会拒绝；
- 客户端 WebSocket frame 必须 masked，长度必须是 canonical encoding；只允许
  binary/continuation/close/ping/pong，控制帧和 close payload 会严格校验。

## 3. 二进制 envelope

一条 WebSocket binary message 恰好承载一条 record。固定头为 20 字节，所有多字节
整数使用 big-endian；STREAM 的 payload 仍是原有 Lyune OPEN/DATA 字节，不作改写。

| 偏移 | 长度 | 字段 | 约束 |
|---:|---:|---|---|
| 0 | 1 | version | 当前固定为 `1` |
| 1 | 1 | record type | STREAM=`0x01`、RESET=`0x02`、STOP=`0x03`、EPHEMERAL=`0x04` |
| 2 | 1 | flags | bit 0 为 FIN，其余必须为 0 |
| 3 | 1 | reserved | 必须为 0 |
| 4 | 8 | logical stream id | client bidi 为 0/4/8…，server bidi 为 1/5/9… |
| 12 | 4 | app error code | STREAM/EPHEMERAL 必须为 0 |
| 16 | 4 | payload length | 必须与 message 剩余字节完全一致 |
| 20 | N | payload | 单条不超过 Lyune frame 上限 |

RESET 与 STOP 不带 payload 或 FIN；EPHEMERAL 的 stream id、error code 和 FIN 都必须
为 0。WebSocket ping/pong/close 直接使用 RFC 6455 控制帧，不重复套 envelope。

客户端新 exchange 的首次 OPEN 必须按逻辑 stream id 单调递增；同一个 id 永久不能
复用。Gateway 主动 stream 必须由本端按 1/5/9… 顺序创建，客户端只能在已经创建的
server bidi stream 上发送空 FIN 或方向控制，不能伪造未来 stream。Raw QUIC 由自身
状态机提供这些保证，WSS 用定长 high-water 状态补齐，因此不会为历史 stream id
维护一个随连接寿命无界增长的集合。

WSS 没有再造应用层 WINDOW：TCP/TLS 的写入结果负责连接级反馈，每会话固定容量队列
负责内存上界。这样不会把 TCP 的队头阻塞伪装成 QUIC 的独立 stream flow control。

正常关闭映射为 WebSocket 1000，协议违规映射为 1002；kick 与 redirect 分别保留为
应用 close code 4002/4003，未知内部失败使用 1011。客户端因此仍能区分“修正编码器”、
“重新认证”、“换节点重连”和普通下线。

## 4. 资源和故障边界

每条 WSS 会话在建立时一次性分配 TLS BIO、解析缓冲、消息拼装缓冲、字节环和 record
描述符；运行期不扩容。配置边界为：

- `max_connections_per_worker`：该 Worker 接受的 WSS TCP 连接上限；所有已认证会话
  仍同时受共享 `ConnectionManager` 上限约束；
- `max_queued_bytes` / `max_queued_records`：单会话明文输出队列双重上限；
- `tls_bio_capacity`：每方向 TLS BIO 的固定容量；
- `handshake_timeout_ms`：TLS 与 HTTP Upgrade 共用的完成时限。

可靠 record 入队失败会关闭这一条慢会话，不扩大到其他 WSS 或 QUIC 会话；EPHEMERAL
在入队前允许明确丢弃。RESET+STOP 的 discard 是原子入队，不能只发送一半。TCP 已经
接收的数据无法按逻辑流撤回，这是 WSS binding 的物理限制；持久消息恢复依赖 Reactor
中的 `message_id`/历史游标，typing 等瞬时事件不重放。

Mac/libxev 的 accepted socket 只在 read/write completion 均不活跃后同步关闭并回收，
避免把 kqueue 异步 close 误当成已经完成。本轮 12 路并发 WSS 登录退出后，Gateway
只保留 listener FD，Worker 指标回到 clients/exchanges/inflight/receive-slots 全零。

## 5. 当前验证边界

2026-08-30 的第一轮真实验证已经证明：严格 Upgrade、WSS 真实密码登录、真实 SQLite
群创建与成员授权、WSS↔WSS↔Raw QUIC 三用户持久消息与主动推送、
`response_mode=none` 空 FIN 和历史重读一致性。真实负门禁确认 stream id 复用、未来
server stream 注入、未 masked、保留位、非 canonical 长度、分片控制帧、超大 frame、
错误 envelope/Origin/Host-SNI/path/subprotocol/version 都只关闭违规会话；合法 binary
分片中插入 ping 可正确重组。容量门禁确认 64 条完整 Upgrade 被接纳、第 65 条明确
拒绝，全部退出后只剩 listener FD。

第二轮增量验证还证明：网关 ping、单帧/三帧 streaming echo、请求 EOF 前响应、同一
WSS 32 并发、required/none、RESET/STOP 后继续复用连接均通过；同账号两条 WSS 的
presence 按 `2 → 1 → 跨 16 秒续租仍为 1 → 0` 收敛；暂停真实 TCP reader 后连续
1200 条约 1900 字节持久消息只关闭慢会话，健康 WSS 继续请求和接收推送；离线消息可由
SQLite 历史补偿并恢复实时推送。120 秒活跃长流在 `11/30014/60011/90009/120005 ms`
收到五段响应，60 秒静默 sibling 与 75 秒迟到 DATA 没有误伤它。

双 Worker 首轮曾暴露一个真实缺陷：旧代码把 HRW 首选 Worker 当成实际连接所有者；
而 WSS/TCP reuseport 在认证前已选定 Worker，认证后无法迁移 TLS 状态，macOS Raw QUIC
首包也没有 cBPF 保证。修复后跨节点仍按 HRW，目标节点内对全部 Worker 去重交接；
五轮 WSS↔WSS↔Raw 三用户群聊均为 `targets=3 delivered=3 routed=1`，没有重复或漏投。

最终自动化轮使用新数据库、新进程和双 Worker：20 批综合场景及独立 30 批
WSS↔WSS↔Raw soak 全部通过；后者精确生成 90 用户、30 群、90 成员和 90 条消息。
Gateway/Reactor RSS 在第 10/20/30 批分别为 `22000/188672`、`22448/188832`、
`22464/188880 KiB`，进入平台区；Gateway/Reactor/agent FD 始终为 `15/15/9`，严格
错误日志为 0。3 次 Reactor 中断均在 3–5 ms 内明确失败并于 236–249 ms 恢复；2 次
Gateway `SIGKILL` 后在 125/123 ms 完成重启、WSS 重连和登录，观察到 3 个不同的
`conn_token` incarnation。

WSS 自动化 M0–M18 至此通过。用户随后已手工信任开发证书，并验证 WSS 能读取 Raw
用户持久化的历史；双方同时在线时，Raw→WSS、WSS→Raw 两个方向的新消息也都能实时
到达。因此多传输双向实时互通的人工证据已经关闭。错误密码、注册、建群/入群尚未形成
完整的逐项人工记录；当前先按项目决定进行源码审计，不进入远程 Linux。
