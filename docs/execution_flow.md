# Lyune Gateway 运行时执行流

本文按真实代码入口梳理进程启动、客户端接入、认证、请求转发、后端回程、主动推送、
跨位置投递与关闭。它回答“一个事件接下来经过哪些对象、状态归谁、在哪里收敛”；线格式
仍以 [帧协议设计](protocol_design.md) 为准，当前完成度以 [实现状态](status.md) 为准。

## 1. 一张总图

```text
main -> app.serve -> app.bootstrap
                       |
                       +-> Coordinator / reload thread / socket groups
                       +-> N x Worker thread
                              |
             +----------------+----------------+
             |                                 |
 Raw QUIC: IoLoop -> ServerDriver         WSS: Listener
             |                                 |
             +----> session.Handler <----------+
                           |
                    GatewayWorker
                  /       |        \
         Connection   ingress    lifecycle
          Manager        |          / auth
                         v
                 TransportRegistry
                         |
                  DirectTransport
                         |
                   BackendPool
                         |
                  Reactor backend
                         |
             response / push / control
                         |
               Worker drain -> egress
                         |
               TransportSession -> client
```

核心边界只有两条：

- 客户端 binding 通过 `session.Handler` 向 Worker 报告事件，Worker 通过
  `TransportSession` 回写，不直接依赖 WSS、TLS、socket 或 picoquic 实现；
- Worker 通过 `BackendTransport` 访问后端，路由逻辑不依赖 DirectTransport 的连接细节。

## 2. 状态所有权

| 状态 | 唯一所有者 | 共享方式 |
| --- | --- | --- |
| 客户端会话、exchange、dest/group 索引 | 所属 `GatewayWorker` | 不跨线程直接访问；用有界消息交接 |
| WSS TLS/socket/输出队列 | 所属 Worker 线程上的 `wss.Listener` | `TransportSession` 是非拥有引用 |
| Raw QUIC Endpoint/连接状态 | 所属 Worker 的 `ServerDriver`/picoquic | callback key 只在接入边界翻译成 `SessionHandle` |
| 后端路由实例 | 每 Worker 的 `DirectFactory` | 地址稳定，`TransportRegistry` 保存类型擦除引用 |
| 后端 QUIC client/接收槽位 | 每 Worker 的 `BackendPool` | 同 Worker 的 DirectTransport 共享设施，不共享业务路由状态 |
| 节点/Worker 生命周期、交接器 | 进程级 `Coordinator` | 原子状态或组件内部同步 |
| realm/route 热加载目录 | 进程级定容表 | 单写者追加，release/acquire 发布 |
| membership 状态 | 独立 SWIM runner 线程 | Worker 读取只读视图/周期快照 |

`SessionHandle` 只在一个 Worker 内定位带 generation 的槽位；`ConnToken` 才是可跨
Worker/节点携带的业务身份。底层指针、fd 和两种身份都不能互相替代。

## 3. 进程启动与装配

### 3.1 配置到进程

1. `main.main` 只解析 `server --config PATH`，调用 `app.serve`。
2. `app.serve` 通过 `foundation.config.load` 做严格 JSON 解析和静态校验，再由
   `app.config.prepare` 生成组件直接可用的 `RuntimeConfig`。
3. `app.bootstrap.run` 屏蔽 SIGHUP，创建并启动 `Coordinator`，再启动专职 reload
   线程。SIGINT/SIGTERM 处理器只翻转 Coordinator 的原子停机标志。
4. 单 Worker 直接进入 `runSingleWorker`；多 Worker 先一次性创建完整的 UDP/TCP
   `SO_REUSEPORT` socket 组，再通过启动闸门同时放行线程。这样 socket index 始终等于
   Worker ID，任一线程异常退出会终止进程，避免组重排破坏 CID 归属。

### 3.2 单个 Worker 的构造顺序

`runSingleWorker` 按依赖方向构造：

```text
GatewayWorker
  -> c-ares Resolver
  -> BackendPool
  -> DirectFactory
  -> startup DirectTransport instances + Registry
  -> optional WSS Listener
  -> GatewayWorker.run()
```

销毁依靠 `defer` 逆序进行。WSS 最先下线，因为关闭会话可能发布 offline；
DirectTransport 必须早于 BackendPool 销毁，因为它要注销连接并归还接收槽位；最后才销毁
Worker 的 driver、event loop 和 ConnectionManager。

### 3.3 Worker 进入事件循环

`GatewayWorker.run` 依次完成：

1. 设置 `running`，向两条进程级交接队列登记 notifier；
2. 向 Coordinator 报告 Worker 已运行；
3. 给客户端 Raw QUIC driver、可选 peer driver 注册连接/流/取消回调；
4. 启动 Raw QUIC driver、抽象 `session.Acceptor`（当前为 WSS）和 peer driver；
5. 预解析已登记后端路由，启动统一维护 timer；
6. 阻塞运行本 Worker 独占的 `xev.Loop`。

## 4. 客户端连接建立

### 4.1 Raw QUIC

```text
UDP packet
 -> io.IoLoop
 -> reactor.ServerDriver.routeInbound
 -> local Endpoint / local Worker handoff / cross-node forward
 -> picoquic handshake complete
 -> GatewayWorker.handleNewConnection
 -> quic.session.init(cnx)
 -> GatewayWorker.acceptClientSession
```

`quic.session` 是 picoquic 到 `TransportSession.VTable` 的唯一客户端适配器。原生 cnx
地址只作为 callback key 存进 ConnectionManager 的定容索引，进入业务路径后全部使用
`SessionHandle`。

### 4.2 WSS

```text
TCP accept
 -> BoringSSL handshake / SNI
 -> HTTP WebSocket Upgrade / Origin + Host-SNI validation
 -> WSS Connection creates TransportSession
 -> session.Handler.accept
 -> GatewayWorker.acceptClientSession
```

WebSocket 二进制消息先由 RFC 6455 parser 重组，再由 WSS envelope 还原成 logical stream
事件。WSS Listener 拥有 TCP、TLS 和有界输出队列；Worker 只借用会话能力。Listener
结束连接时先回调 `Handler.closed` 使 `SessionHandle` 失效，再回收实现对象。

### 4.3 统一准入

两种 binding 最终都进入 `acceptClientSession`：

1. Coordinator 已 draining 时拒绝；
2. 用握手 SNI 从 `realm.Table` 解析 realm，客户端帧不能修改；
3. ConnectionManager 检查全局槽位和 realm 公平配额；
4. 从空闲链表取得槽位、递增 generation，写入 `ConnectionContext`；
5. 返回稳定的 `SessionHandle`。

这里只完成传输连接准入，不等于业务认证成功。

## 5. 客户端上行 Exchange

Raw QUIC stream callback 与 WSS STREAM record 都进入
`ingress.handleSessionData(worker, handle, stream_id, bytes, fin)`：

1. generation 校验，迟到事件无法命中已复用槽位；
2. 校验 stream 方向。客户端只能在 client-initiated bidi stream 发起请求；
3. `framing.drainFrames` 就地扫描完整帧，只有跨 callback 的残帧才进入 spill；
4. 首帧必须是 OPEN；同一 exchange 后续只能是 DATA，目的地在 OPEN 后冻结；
5. 按 `dest_kind` 进入对应分支。

### 5.1 `.gateway`

由 Worker 本地处理控制交换：heartbeat/ping、认证、bind/unbind channel、disconnect 等。
控制交换当前必须一次性完成，不创建后端流。认证是例外：请求 body 原样委托到配置的认证
route，`PendingAuth` 记录客户端会话与响应策略。

认证响应完成后，`auth.completeAuth` 才会：

- 解析网关拥有的固定 grant 前缀；
- 设置 `authenticated`、`dest_id`、TTL 与 `ConnToken`；
- 建立 `(realm, dest_id)` 索引；
- 发布 session online；
- 必要时按 placement 返回 redirect。

### 5.2 `.service`

1. 检查业务认证、每连接 exchange 上限和 Worker/realm inflight 上限；
2. 用 `ScopedRoute(realm, group, route_key)` 查询 `TransportRegistry`；热加载的新声明在首次
   使用时由 `DirectFactory` 就地创建并登记，登记失败会回滚最后一个工厂槽位；
3. DirectTransport 选可用 endpoint，打开一条后端 client-initiated bidi stream；
4. `response_mode=required` 时登记“后端复合 stream key → 客户端 SessionHandle/stream”；
   `none` 只登记 discard 路由，用于消费和回收后端意外响应；
5. 原样发送完整 Lyune 帧。OPEN 不带 eof 时把后端 stream 写入客户端 exchange 状态，
   后续 DATA 沿同一后端 stream 追加；eof 才发送 FIN。

客户端不能在上行请求 `.peer` 或 `.multicast`；这两类下行能力只授予可信后端/peer link。

## 6. 后端回程

每个 Worker 的 `BackendPool` 只有一个共享 `AsyncClient`、一个 picoquic context/socket 和
一份有界接收槽位 arena。每个 DirectTransport 仍拥有自己的 endpoint 连接状态与队列，
不会共享 RouteId 语义。

后端 callback 先由 BackendPool 按 cnx 索引交回所属 BackendConn；数据被放进该连接的
有界队列。Worker 的维护 timer 调用 `drainBackendResponses`，再遍历 registry 取事件：

```text
TransportRecv
  -> 命中 PendingAuth        -> auth.collectAuthResponse
  -> 命中 client inflight    -> writeClientResponse / finish mapping
  -> 两者都未命中且 peer-init -> egress.handlePush
  -> reset/stop/connection failure -> 精确失败或清理对应状态
```

required 响应通过客户端 `TransportSession.write` 写回并在 FIN 时删除映射；none 响应只消费
不写回。映射按活动时间续期，正常 FIN、客户端关闭和 deadline 三条路径都能回收。

## 7. 后端主动推送与控制

后端主动流没有 client inflight，进入 `egress.handlePush`：

1. 以 `(transport id, backend stream id)` 重组帧；
2. 首帧必须是 OPEN，后续 DATA 不能修改已冻结目的地；
3. `.peer` 按 `(realm, dest_id)` 投递，`.multicast` 按 `(realm, group_id)` 投递；
4. `.gateway` 只允许后端白名单控制：kick、join_group、leave_group；
5. `.service` 在下行无语义，拒绝。

一次性推送直接扇出完整帧；流式推送在 OPEN 时冻结目标会话集合，给每个本地目标调用
`TransportSession.open`，后续 DATA 沿保存的客户端 stream id 写入。WSS 与 Raw QUIC 在此
之后完全共用同一条业务路径。

## 8. 跨 Worker 与跨节点的两类线路

两类交接不能合并：

- **原始 QUIC 包归属纠偏**：发生在解密前。CID 指向同机其他 Worker 时进
  `LocalPacketRouter`；指向其他节点时走 HMAC/replay-protected forward UDP tunnel。
  picoquic/TLS 状态始终留在 CID owner。
- **已解密应用消息投递**：发生在 egress。节点内走 `MessageRouter`，节点间走
  QUIC+mTLS peer link。目标 Worker 只做本地索引投递，不再次选址，避免环路。

WSS TCP 连接一旦被 reuseport accept 到某个 Worker 就不能迁移。认证后得到 dest_id 也
不能反推它的实际 Worker，所以本节点 `.peer` 投递必须查询所有 Worker 的线程私有索引；
连接只存在于其中一个索引，不会重复命中。

## 9. 取消、错误与关闭

- RESET 表示对端中止输入：清 spill/exchange，必要时给后端补 FIN 或 discard；
- STOP 表示对端拒绝响应：required inflight 降级为 discard，并终止本端发送方向；
- WSS 用 RESET/STOP envelope 补齐相同业务语义，可靠输出队列溢出时只关闭慢会话；
- 客户端编码违规关闭整条客户端连接；路由不存在、配额满等业务失败只结束该 exchange；
- 后端单流违规只丢对应推送/响应，不能关闭承载其他用户的整个后端连接，除非底层连接
  已经发生不可恢复故障；
- `closeClientSession` 的固定顺序是 offline → 结束开放后端流 → 清 inflight →
  ConnectionManager 摘索引并归还槽位。

## 10. 周期维护与停机

Worker 的统一 timer 负责：WSS handshake 超时和延迟销毁、后端响应收割与重连、inflight
过期、presence/准入续期、membership 快照刷新、rehome 和指标日志。

停机由信号处理器置原子标志，Worker timer 在所属线程推进：第一个 Worker 让 Coordinator
广播 left 并进入 draining，所有接入器停止接新连接，存量连接在 deadline 前自然结束；
连接清空或超时后才 `event_loop.stop()`。这保证状态总在其所有者线程内销毁。

## 11. 演化约束

- 新客户端 binding 依赖 `session/` 并实现 `TransportSession.VTable`/`Handler`，由 `app`
  装配；不能把具体 listener 类型重新放进 Worker。
- 新后端传输实现 `BackendTransport` 并注册到 Registry；客户端帧不携带部署路径。
- `worker.zig` 虽然仍较大，但它是单一 Worker 状态所有者，当前拆分已按 ingress、egress、
  auth、lifecycle、inflight、connection 的状态边界进行。继续按行数机械拆结构体会制造
  反向引用；只有出现新的独立状态所有者时才新增组件。
- `status.md` 已列的认证响应上限、UDP 有界发送、端到端背压、membership 发布证明和
  热加载事务化先作为待审计风险保留。当前优先完成 [源码逐行审计](code_audit.md)，
  形成证据和排序后再决定实现，不应混入纯目录重排。
