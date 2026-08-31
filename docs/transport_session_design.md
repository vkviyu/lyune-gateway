# 多传输客户端会话设计

> 决策日期：2026-08-29
>
> 当前状态：`TransportSession` 的 Raw QUIC 与 WSS binding 均已实现；两种 binding
> 的 Mac 自动化 M0–M18 均已通过。人工浏览器已确认共享历史和 WSS→Raw 实时推送，
> Raw→WSS 同时在线实时推送及完整 UI 负例仍待关闭；当前先暂停演进并进行源码审计。

本文定义客户端接入从“Worker 直接依赖 picoquic 连接”演进为“传输无关会话”的边界、顺序和验证门禁。目标不是替换已经通过 Mac M0–M18 的 Raw QUIC 协议，而是在逐字节保留它的前提下增加可证明的 TCP/WSS 回退能力。

## 1. 决策

客户端数据面最终提供两种 binding：

```text
Lyune Protocol v2
├── Raw QUIC binding
│   └── UDP，ALPN lyune/2，一条真实 QUIC bidi stream = 一次 Exchange
└── WSS binding
    └── TLS/TCP，WebSocket subprotocol lyune.v2，一个 logical stream = 一次 Exchange
```

Raw QUIC 仍是原生客户端的首选路径；WSS 是普通浏览器的直接入口，也是 UDP/QUIC 不可用时的 TCP 回退。Gateway → Reactor、Gateway peer link 和集群转发不在本轮抽象范围内，继续使用现有协议与传输。

WebTransport 不作为当前前置能力。未来若浏览器和服务端的 HTTP/2 fallback 足够成熟，它只能作为第三个 `TransportSession` binding 加入，不能反向侵入 Exchange、路由或业务协议。

## 2. 不变量

第一阶段只允许结构重构，不允许修改下列事实：

- Raw QUIC ALPN 仍为 `lyune/2`；
- OPEN 8B、DATA 4B 和现有 body 编码逐字节不变；
- client-initiated bidi 承载请求，Gateway-initiated bidi 承载推送；
- `response_mode=required|none`、空 FIN、RESET_STREAM、STOP_SENDING 语义不变；
- QUIC DATAGRAM、认证、`dest_id`、`conn_token`、lifecycle/presence 不变；
- Worker → DirectTransport → Reactor 的路径不变；
- 当前配置默认不开启任何 TCP/WSS 监听器。

Raw-only 抽象完成后必须重新通过现有单元测试、ReleaseSafe 构建和 Mac M0–M18。门禁通过前禁止开始 WSS 实现，避免把结构回归与新传输问题混在一次调试中。

截至 2026-08-30，这道门禁已经关闭：Worker 的客户端写流、主动开流、临时消息、
取消和关闭都经 `src/session/transport.zig` 的类型擦除 `TransportSession`；Raw QUIC
适配器已归位到 `src/quic/session.zig`，WSS 适配器留在自己的 listener，客户端业务路径
不再直接调用 `QUICConnection.fromRaw`。Gateway peer link 和 Gateway → Reactor 属于明确排除的内部
传输，继续直接使用 QUIC。实际复跑和一次 M8 边界故障的修复证据记录在
[两阶段真实环境验证](validation.md)。

## 3. TransportSession 边界

业务层不再把 `picoquic_cnx_t*` 当作连接能力本身。每条客户端会话通过稳定的会话引用和一组方向明确的操作访问传输：

```text
TransportSession
├── claimInboundExchange(stream_id) -> bool
├── write(stream_id, bytes, fin)
├── open(bytes, fin) -> stream_id
├── sendEphemeral(bytes)
├── resetSend(stream_id, error_code)
├── stopReceive(stream_id, error_code)
├── discard(stream_id, error_code)
└── close(error_code)
```

传输驱动向 Worker 归一化输出：

```text
SessionReady
StreamData(stream_id, bytes)
StreamFin(stream_id)
StreamReset(stream_id, error_code)
StopSending(stream_id, error_code)
Ephemeral(bytes)
SessionClosed(reason)
```

`TransportSession` 使用非拥有 `ptr + vtable`，服务端主动 exchange id 的 1/5/9…分配由
契约统一拥有。`quic/session.zig` 只是上述接口到现有 `QUICConnection` 方法的直接映射，
不增加缓存、复制、调度或新的协议状态；新增 binding 不需要修改 TransportSession 的
结构或给 union 增加分支。SNI/realm、CID 路由和 picoquic 生命周期仍由现有
Endpoint/ServerDriver 负责。

## 4. 身份与状态所有权

`conn_token` 表示 Gateway 业务会话，不能永久依赖某一种传输的裸指针布局。演进后应明确区分：

- `SessionHandle`：Worker 内部定位会话的稳定句柄；
- `TransportSession`：对该会话执行 I/O 的能力；
- `stream_id`：在该会话内唯一的 Exchange 方向标识；
- `conn_token`：跨进程可见、带 node/worker/slot/generation/incarnation 的业务身份。

Raw-only 过渡阶段曾允许 `SessionHandle` 内部仍包装 picoquic 句柄，但 Worker 的业务模块不得继续新增长期保存和直接操作裸 `picoquic_cnx_t*` 的代码。最终实现使用 slot/generation-backed `SessionHandle` 定位 Worker 会话，并以类型擦除 `TransportSession` 承载具体 binding 的 I/O 能力；它不是 tagged union。

当前实现已经关闭这一过渡：`ConnectionContext.transport` 是唯一的客户端 I/O 能力，
slot-backed `SessionHandle` 用于 ConnectionManager、inflight 和回调定位；WSS
不伪造 picoquic 指针，Raw 指针也只停留在 Raw binding/transport callback 边界。

## 5. WSS binding 的后续约束

WSS 不改写 Lyune OPEN/DATA，而是在二进制 WebSocket 消息内增加 TCP 所缺少的逻辑多流 envelope：

```text
record_type | flags | logical_stream_id | payload_length | payload
```

其中 payload 仍是当前 Lyune Frame。当前 record 表达 STREAM（含 FIN）、RESET、STOP 和 EPHEMERAL；PING/PONG/CLOSE 直接使用 RFC 6455 控制帧。客户端逻辑流使用 `0/4/8...`，Gateway 推送使用 `1/5/9...`，保持与 Raw QUIC 相同的方向判据。固定 20 字节线格式见 [WSS 传输 binding](wss_transport.md)。

TCP 的连接级队头阻塞和“已进入发送缓冲的数据无法按逻辑流撤回”不能被抽象层伪装成不存在。当前实现采用每会话有界 FIFO：可靠 record 溢出只关闭该慢会话，EPHEMERAL 在入队前允许丢弃；不伪造 QUIC 独立流控或在连接内承诺不存在的公平性。重连后持久消息依靠业务 `message_id`/cursor 补齐，瞬时状态不重放。

## 6. “无损、无差异”的验收定义

Raw QUIC 用户与 WSS 用户必须能够在同一 realm、同一群中通信，并满足：

- 相同认证和授权结果；
- 相同 OPEN/DATA、required/none 和错误分类；
- 相同持久消息 body、sender、group、`message_id` 与历史读取结果；
- 相同 Gateway 主动推送和连接级 lifecycle/presence 语义；
- 不串流、不错投、不重复持久消息；
- 任一慢 WSS 会话不阻塞或扩大故障到其他 QUIC/WSS 会话；
- 断线恢复后持久消息可按游标补齐，瞬时事件不承诺重放。

这里的“无差异”是业务可观察语义一致，不包含把 TCP 的队头阻塞、无连接迁移和无原生 Datagram 伪装成 QUIC 等价性能。

## 7. 实施与门禁顺序

1. [x] 冻结并保留 commit `425f2a6` 的 Raw QUIC Mac M0–M18 证据；
2. [x] 引入 `TransportSession` 与唯一的 `RawQuicSession`，收口客户端写流、推送、取消、datagram 和关闭路径；
3. [x] 只运行 Raw QUIC，完成单元测试、ReleaseSafe 构建和 Mac M0–M18 总复跑；
4. [x] Raw-only 门禁通过，形成新的结构基线；
5. [x] 定义并测试 `lyune.v2` WSS envelope、TLS/Origin/限额和慢消费者策略；
6. [x] 实现 WSS listener、真实浏览器客户端和第一轮 QUIC↔WSS 双用户混合矩阵；
7. [x] 完成两种 binding 的反复进程故障、混合 soak、资源趋势和 M18 干净自动化总复跑；
8. [ ] 人工验收部分完成：用户已信任证书并验证共享历史和 WSS→Raw 实时推送；仍需补 Raw→WSS 同时在线实时推送和完整 UI 负例；
9. [ ] 先完成源码逐行审计，再由项目所有者决定是否补齐人工清单、冻结新的 Mac 多传输基线或进入远程 Linux。

任一步失败都在当前层修复和复跑，不跨过门禁同时引入下一种传输。
