# 两阶段真实环境验证

> 建立日期：2026-08-27
>
> 当前状态：Raw QUIC 与 WSS 的 Mac 自动化 M0–M18 均已通过。用户已在真实浏览器完成一轮 Raw/WSS 混合 IM 操作，确认共享历史和 WSS→Raw 实时推送；Raw→WSS 同时在线实时推送及完整 UI 负例仍待关闭。当前先暂停验证扩展，进入源码逐行审计；不进入远程 Linux，也不创建 release。

本文既是验证计划，也是持续更新的验证记录。它回答三个问题：当前真实链路怎样搭建、每一项怎样判定通过、实际执行时观察到了什么。设计能力是否存在仍以源码和 `status.md` 为准；本文件只记录真实进程与真实网络中的证据。多传输的代码边界与门禁以 [多传输客户端会话设计](transport_session_design.md) 为准。

## 1. 验证目标与边界

本文保留完整的两阶段验证计划，但当前执行停在 Mac 阶段与源码审计之间：

1. 在真实 MacBook 上启动带 SQLite、真实用户和群成员授权的 Go 后端、Zig 网关与轻量客户端，让浏览器 WSS 与 Raw QUIC 都跑通登录、业务鉴权、持久化群消息和双用户实时推送；
2. Mac 证据和源码审计均通过后，再由项目所有者决定是否把相同组件和场景迁移到远程 Linux，验证跨平台构建、网络 I/O 与 Linux 专属路径；
3. 每次执行保留环境、命令、配置、日志、预期结果、实际结果和问题编号，不能只留下“测试过”的结论；
4. 当前没有生产环境和外部用户。本轮不创建 tag、release、镜像或兼容性承诺。

本轮不是性能宣称，也不以单次 echo 成功代替完整正确性验证。吞吐、长时间 soak、多节点集群和生产安全配置仍需独立证据。

## 2. 组件与真实数据路径

阶段一使用以下四个独立进程。主验收链路不是 echo，而是带真实业务状态的 IM；浏览器可直接走 WSS，也可经轻量 agent 走 Raw QUIC：

```text
Browser / React UI :5173
        ├── WSS + subprotocol lyune.v2 ───────────────> Gateway TCP :8444
        └── HTTP/JSON ─> client-agent :8787
                              └── QUIC + ALPN lyune/2 ─> Gateway UDP :8443
                                                              |
                                                              | 共用 Worker/认证/Exchange/路由
                                                              v
                                                        DirectTransport
        |
        | QUIC + ALPN lyune/2（真实 DirectTransport）
        v
lyune-reactor :9443
```

端口 `8443/UDP` 与 `8444/TCP` 只属于网关；Reactor 固定使用 `9443/UDP`，默认配置与验证配置均保持前后端端口分离。主验收使用 `config/validation-im-macos.json`：WSS 精确 Origin 白名单、认证路由 `.service(1,1)`、IM 路由 `.service(1,2)`、认证门禁和 `.peer` 回推全部开启。`config/validation-macos.json` 只保留为协议 echo/长流诊断配置，`config/validation-pressure-macos.json` 只用于人为缩小队列的 M7 压力负对照；三者都不改写日常默认配置。

### 为什么仍保留 client-agent

浏览器 JavaScript 不能打开任意 UDP socket，也不能直接协商自定义 `lyune/2` QUIC ALPN。现在浏览器默认通过 `lyune.v2` WSS 直接连接 Gateway；client-agent 不再是浏览器使用网关的必需组件，但仍是同一页面切换到 Raw QUIC、对照两种 binding 和验证 UDP 首选路径的必要工具。

两种 binding 的 payload 都是相同 OPEN/DATA：WSS 只在 WebSocket binary message 外增加逻辑 stream envelope，agent 则使用真实 QUIC stream。两者在 Worker 内汇入相同 `TransportSession` 事件，网关到 Reactor 仍走真实 QUIC。WebTransport 当前不在前置路径中。

对应资产：

- `validation/web-client`：浏览器直连 WSS / Raw QUIC 对照的真实登录、建群、邀请码入群、历史消息与实时聊天页面；
- `validation/client-agent`：每个浏览器会话一条独立 QUIC 连接，保存应用 token，并接收后端主动打开的 `.peer` 流；
- `validation/wss-smoke.mjs`：无第三方依赖的 TLS/Upgrade/envelope 登录探针；
- `validation/wss-mixed-im.mjs`：创建两个一次性 WSS 用户与一个 Raw QUIC 用户，执行真实授权、三向群聊、推送和历史一致性检查；
- `validation/wss-negative.mjs`、`validation/wss-capacity.mjs`：逻辑流/WebSocket 违规和每 Worker 连接容量的真实负门禁；
- `validation/wss-protocol.mjs`：WSS ping、单帧/多帧 echo、请求结束前响应、32 并发、required/none 与 RESET/STOP；
- `validation/wss-reconnect-im.mjs`：WSS 接收者离线期间持久化、重新登录后的 SQLite 历史补偿与实时推送恢复；
- `validation/wss-slow-consumer.mjs`：暂停一个真实 WSS TCP 接收端，压满其独立输出边界并确认健康会话继续持久化、请求和接收推送；
- `validation/wss-presence.mjs`：同账号双 WSS 连接聚合、单连接退出、跨续租周期和最终离线；
- `validation/wss-long-stream.mjs`：120 秒活跃流、60 秒静默 sibling、75 秒迟到 DATA 与后续连接复用；
- `validation/wss-fault-recovery.mjs`：自管临时数据库与进程，反复停止 Reactor、强杀 Gateway，并核验恢复时间和 `conn_token` incarnation；
- `../lyune-reactor/reactor`：Go/quic-go + SQLite 后端，负责密码校验、session、群成员授权、消息持久化与推送目标计算；
- `config/validation-im-macos.json`：阶段一真实 IM 主配置；
- `config/validation-macos.json`、`config/validation-pressure-macos.json`：协议诊断与 M7 专用配置。

## 3. 阶段一：真实 MacBook 单机验证

### 3.1 环境基线

每次正式执行前记录：

- Mac 型号、CPU 架构、macOS 版本；
- Zig、Go、Node.js 和 npm 版本；
- 三个仓库或项目的 commit/工作树状态；
- 实际使用的配置文件摘要、证书指纹和监听端口；
- 防火墙、VPN、代理或端口占用等可能影响结果的本机条件。

工作树允许处于开发状态，但记录中必须写出未提交改动；否则后续无法复现同一个结果。

### 3.2 启动顺序

推荐先从 Gateway 根目录使用一键脚本；它构建并启动四个进程、检查端口、保留日志与 SQLite，按 `Ctrl+C` 有序关闭：

```bash
./run-im-demo.sh
```

Mac 多 Worker/reuseport 增量门禁使用 `./run-im-demo.sh --workers 2`。脚本只在
`/private/tmp/lyune-im-demo/gateway-config.json` 生成运行期配置，不修改版本库中的
单 Worker 基线文件。

首次使用浏览器 WSS 前，在 macOS“钥匙串访问”中导入项目根目录的 `server.crt` 并仅用于本地开发。证书包含 `localhost` 和 `127.0.0.1` SAN，但自签名证书仍必须由用户明确设置信任；页面代码不能绕过 TLS 校验。需要逐进程诊断时再从各项目根目录执行：

```bash
# 1. Go 后端，监听 127.0.0.1:9443
cd ../lyune-reactor
go -C reactor run . \
  --listen 127.0.0.1:9443 \
  --cert ../../lyune-gateway/server.crt \
  --key ../../lyune-gateway/server.key \
  --db /private/tmp/lyune-im-mac-stage.sqlite

# 2. Zig 网关，监听 127.0.0.1:8443/UDP 与 :8444/TCP，并连接 Reactor :9443
cd ../lyune-gateway
zig build run -- server --config config/validation-im-macos.json

# 3. 原生 QUIC client-agent
go -C validation/client-agent run . --listen 127.0.0.1:8787

# 4. React 验证页面
cd validation/web-client
npm install
npm run dev
```

正式记录时分别保存 Reactor、Gateway、agent 三份日志，不要只保留浏览器截图。

M7 Raw QUIC 压力负对照另开 Reactor `9444/UDP` 和 Gateway `8444/UDP`；UDP 与主验证的 WSS `8444/TCP` 可共用端口号，但日志必须写明协议。Reactor 增加 `--echo-delay 250ms`，Gateway 使用 `config/validation-pressure-macos.json`。该配置故意把 `max_receive_queue` 设为 8，只用于证明满载时的失败是完整、及时且可解释的，不能拿它做吞吐结论。

### 3.3 场景顺序

必须按下面的顺序逐项推进。前置项失败时不继续叠加后续变量。

| 编号 | 场景 | 最低通过条件 |
| --- | --- | --- |
| M0 | 构建与监听 | 原生进程正常构建；`:9443/UDP`、`:8443/UDP`、`:8444/TCP`、`:8787/TCP` 分别由预期进程监听 |
| M1 | 双 QUIC 握手 | agent → Gateway 与 Gateway → Reactor 均协商 `lyune/2`，没有降级或证书误判 |
| M2 | 网关控制交换 | heartbeat/ping 收到正确 ack/pong；Reactor 不应收到该流量 |
| M3 | 单帧 service echo | `.service(1,0)` 的 OPEN+EOF 到达 Reactor，响应原样回到同一客户端流 |
| M4 | 多帧 streaming echo | OPEN、多个 DATA、末帧 EOF 顺序不变；首包响应可在请求结束前返回 |
| M5 | 单连接并发流 | 同一 QUIC 连接上至少 32 个并发双向流全部正确关联，无串流 |
| M6 | 生命周期 | 主动断开、Reactor 重启、Gateway 重启后的失败与恢复均可观察且无假成功 |
| M7 | 压力与慢端 | 慢 Reactor、慢读取和队列压力产生可解释的流控/拒绝，不出现静默截断 |
| M8 | 长流 | 总时长超过 120 秒且至少每 30 秒有一次应用帧的流完整返回；静默超过 60 秒的负对照明确失败而不继续投递 |
| M9 | 真实 IM | 两个真实注册用户获得不同 `dest_id`；错误密码被拒；未入群用户不能读群历史；邀请入群后，双方经 Gateway 收到同一条后端 `.peer` 实时消息；重读 SQLite 历史与实时消息一致 |
| M10 | 显式响应模式 | `required` 返回完整业务帧；`none` 只回空 FIN且后端不回业务帧；错误模式与未知取值明确拒绝；typing 使用 `none` 仍产生对端推送 |
| M11 | 连接级 lifecycle/presence | online/offline、15 秒续租与严格 sequence 生效；同一用户两条连接聚合为 2，关闭一条后仍在线；Gateway 崩溃后孤儿租约在 45 秒内收敛 |
| M12 | 流方向与单向流 | 客户端请求只在 client-initiated bidi；Gateway 推送只在 server-initiated bidi；客户端向推送流回写会只关闭违规连接；单向流额度为 0且不影响同连接后续合法流 |
| M13 | 流取消 | 请求输入 RESET、响应 STOP_SENDING、后端 reset/stop 都按方向精确清理/传播；无 Exchange 泄漏、无客户端 deadline 悬挂、同连接其他流可继续 |
| M14 | 进程重启身份隔离 | `conn_token` 固定 16 字节且含随机 incarnation；重启前后 token 不同，旧 sequence/kick 不命中新连接；旧 presence 只经租约退出 |
| M15 | 混合负载 | 多真实用户在同一时间混合 required、none、typing、持久消息、推送与取消；成功/拒绝均完整可解释，无串流、错投或长期挂起 |
| M16 | 反复故障恢复 | 多轮 Reactor/Gateway/agent 中断与恢复；记录首请求语义、重连时间、在途结果和租约收敛，不出现假成功、身份碰撞或无法恢复的池状态 |
| M17 | soak 与资源趋势 | 真实 IM 活跃流量和定期故障注入持续运行；RSS、FD、连接、Exchange、inflight、接收槽位和 SQLite 增长符合负载，不单调泄漏 |
| M18 | 干净环境总复跑 | 新数据库、新进程、固定命令完整复跑 M0–M17；源码/文档/配置一致，无阻断项后形成候选 Mac 基线；进入 Linux 还需通过源码审计并由项目所有者明确决定 |

M0–M4 构成“传输最小闭环”，M9 构成有业务意义的应用闭环，M10–M14 固化协议基础能力，M15–M18 才证明这些能力能在混合负载、故障和时间维度下共同工作。阶段一必须 M0–M18 全部通过；echo 成功不能代替身份、授权、持久化、主动推送或资源稳定性。

### 3.4 阶段一退出条件

- M0–M18 有可复现记录，已知失败有稳定复现步骤和问题编号；
- 至少完成一次全新进程启动后的 M0–M5，而不是复用未知状态的长驻进程；
- Web UI 展示的结果与三份原生日志能按时间和 stream 对上；
- Reactor 和 client-agent 的 codec 均有当前线格式单元测试；
- 文档中的启动命令在新的 shell 会话可直接执行；
- 阶段一发现的阻断性协议错误先修复并重新验证；是否进入远程 Linux 还取决于源码审计结论和项目所有者决定。

截至 2026-08-29，commit `425f2a6` 的原始 Raw QUIC M0–M18 和之后的 TransportSession Raw-only M0–M18 均已满足。2026-08-30 加入 WSS 后，又独立完成真实 QUIC↔WSS 混合用户闭环、协议并发/取消、畸形输入、慢消费者、断线补偿、presence、120 秒长流、双 Worker、反复进程故障、混合 soak 与干净 M18 自动化总复跑。2026-08-31 的人工浏览器操作已经证明 WSS 与 Raw 共享用户/历史路径，以及 WSS→Raw 的实时推送；尚未单独记录 Raw→WSS 同时在线实时推送、错误密码、注册和建群/入群的完整人工清单。自动化证据继续有效，但人工门禁目前只能标记为部分完成。

### 3.5 多传输增量门禁

WSS 轮逐项复用 M0–M18 的业务判据，并至少覆盖三种会话组合：WSS↔WSS、WSS↔Raw QUIC、Raw QUIC↔Raw QUIC。除此之外必须增加：

- 有效/缺失/错误 Origin、Host-SNI 不一致、错误 path/subprotocol、未 masked、分片、超大或畸形 frame；
- 单 WSS 会话输出队列打满时只隔离该会话，其他 WSS/QUIC 用户仍可收发；EPHEMERAL 可丢，可靠消息不能静默丢；
- WSS TCP 中断、Gateway/Reactor 重启后失败明确，重连后按 `message_id`/cursor 补齐持久消息，typing 等瞬时事件不重放；
- `threads > 1` 时 TCP reuseport、连接所有权和 SessionHandle generation 正确；
- 混合负载后的 RSS、accepted/listener FD、clients、Exchange、inflight、receive slot 和 SQLite 趋势有明确基线。

### 3.6 人工浏览器验收状态

| 检查项 | 当前状态 | 说明 |
| --- | --- | --- |
| 浏览器信任本地开发证书并建立 WSS | 已完成 | 用户已在 macOS 钥匙串中信任 `server.crt`，真实页面可登录 |
| WSS 读取 Raw 用户已持久化的群消息 | 已完成 | 证明两种 binding 汇入相同认证、路由和 SQLite 历史路径 |
| WSS→Raw 同时在线实时推送 | 已完成 | WSS 用户发送的两条消息均由 Raw 用户实时看到 |
| Raw→WSS 同时在线实时推送 | 待补证据 | 当前观察到的 Raw 消息是在 WSS 登录后从历史中看到，不能据此断言为实时推送 |
| 错误密码、注册、建群/邀请码入群 | 待完整人工记录 | 自动化已覆盖，但仍需 UI 级证据才能关闭人工清单 |

这组未完成项不再自动触发下一阶段。当前先执行 [源码逐行审计](code_audit.md)，之后再决定补齐人工清单、修改实现或进入 Linux 的顺序。

## 4. 阶段二：远程 Linux 真实验证

> 当前暂停。以下内容保留为未来可执行计划，不代表已经批准开始。

阶段二不重新发明测试工具。应固定阶段一通过时的 Gateway、Reactor、client-agent、场景数据和记录格式，只改变操作系统、网络边界和 Linux 专属配置。

### 4.1 第一组拓扑

```text
Mac Browser + client-agent
            |
            | Internet / private network UDP
            v
remote Linux: lyune-gateway
            |
            | loopback QUIC
            v
remote Linux: lyune-reactor
```

先在一个 Linux 主机上验证跨公网或跨私网的真实客户端链路。通过后再把 Reactor 移到另一台主机，区分“客户端跨网”和“后端跨网”的问题。双网关、anycast/l4_lb 和 peer link 属于其后的 Linux 集群验证，不应与第一轮跨平台冒烟同时引入。

### 4.2 Linux 增量检查

除重跑 M0–M18 中适用于远程拓扑的场景外，至少增加：

- 发行版、内核、CPU 架构、libc、文件描述符和 UDP 缓冲区限制；
- `io_uring` 实际启用情况及回退路径；
- `SO_REUSEPORT` 与 cBPF attach，多个 Worker socket 的真实内核分流；
- 主机防火墙、安全组、NAT、MTU 与 UDP 空闲超时；
- `threads > 1` 下 CID owner、内核分流和用户态 handoff 的一致性；
- Mac 与 Linux 上相同场景的握手、错误、延迟和资源趋势对照；
- 服务重启、远端网络中断、丢包/延迟/重排，之后再进入 `tc netem` 与 soak。

### 4.3 阶段二退出条件

- Mac client-agent → Linux Gateway → Linux Reactor 的 M0–M18 适用场景全部完成；
- Linux 多 Worker 的 reuseport/cBPF 有内核层证据，不只依赖应用日志推断；
- 至少一次 Reactor 跨主机部署通过 M3–M6；
- macOS 与 Linux 的差异、规避方式和未解决风险已经写入执行记录；
- 没有阻断性跨平台问题；未完成的集群/netem/soak 项进入后续明确任务。

## 5. 执行记录模板

每次执行在本节追加一条，不覆盖旧记录。大体积原始日志可以放在不入库的临时目录，文档中记录其保存位置和摘要；关键失败片段应去除隐私后随问题保存。

```markdown
### YYYY-MM-DD / run-id / Mx

- 执行人：
- 环境：硬件、OS/内核、工具版本
- 代码：Gateway commit/dirty、Reactor commit/dirty、client commit/dirty
- 配置：文件、关键覆盖项、证书指纹
- 命令：
- 预期：
- 实际：
- 证据：三端日志时间点、UI 截图或统计
- 结果：PASS / FAIL / BLOCKED
- 问题：编号、复现步骤、临时规避
- 下一步：
```

## 6. 执行记录

### 2026-08-27 / baseline-audit / M0

- 环境：macOS arm64；Zig 0.16.0；Go 1.26.2；Node.js 22.23.2；npm 10.9.8。
- 代码：Gateway 冻结基线已存在；Reactor 工作树包含一处未提交的 ALPN 调整。
- 实际：准备检查发现 Reactor 仍使用旧 v3/16B 帧格式，ALPN 为 `lyune-im`；默认 Gateway 和 Reactor 同时使用 `8443`；仓库中的 client simulator 尚未实现；浏览器不能直连 `lyune/1`。
- 结果：M0 尚未执行，准备项 FAIL。
- 下一步：对齐 Reactor codec/ALPN/端口，增加阶段一配置、client-agent 与 React UI 后重新执行 M0。

### 2026-08-27 / macos-smoke-001 / M0–M6、M8

- 环境：MacBook，Apple Silicon arm64；macOS 26.3.1（25D2128）；Zig 0.16.0；Go 1.26.2；Node.js 22.23.2；npm 10.9.8。
- 代码：Gateway `005ff52` + dirty；Reactor `7d18720` + dirty；client-agent 和 Web UI 位于 Gateway 未提交工作树。Gateway 与 Reactor 的改动详情应随本轮提交一同保留。
- 配置：`config/validation-macos.json`；Gateway `127.0.0.1:8443`；Reactor `127.0.0.1:9443`；agent `127.0.0.1:8787`；单 Worker；auth/cluster 关闭；开发证书 SHA-256 `245f48605345f71405a88b5fbc1d649b56e6632dd6a79efcfe3f308d520af7c1`。
- M0：PASS。三个原生进程均成功启动并监听预期端口；Gateway 单元测试 244 pass、1 skip。
- M1：PASS。agent → Gateway 协商 ALPN `lyune/1`；Gateway 创建到 Reactor 的真实 QUIC 连接。
- M2：PASS。ping/pong 用时 0 ms；Reactor 日志没有出现控制帧。
- M3：PASS。`.service(1,0)` 单帧请求用时 2 ms，响应正文为 `echo: hello through lyune`。
- M4：PASS。请求 OPEN、DATA、DATA+EOF 分别在 0/400/801 ms 发出；响应在 55/460/863 ms 到达，顺序正确，且首包早于请求 FIN。
- M5：PASS。同一 QUIC 连接上的 32 个并发流全部返回且无串流；单流完成时间约 7–69 ms。Gateway 日志记录了 32 组独立的 client/backend stream 映射，Reactor 日志记录了 32 次对应请求。
- UI 复验：PASS。真实浏览器依次点击 M2–M5，页面记录 M2/M3/M4 为 1/1、M5 为 32/32 且 0 失败；M4 显示首响应早于请求 FIN，浏览器控制台没有错误。
- M6：PASS，但恢复不是无损的。Reactor 停机后，下一次 M3 在 22 ms 收到网关 `backend unavailable` 并被 agent 正确判为 FAIL；Reactor 重启后第一次请求仍以 `backend unavailable` 失败并触发重连，随后一次请求 PASS。Gateway 停机时，在途 M3 于 10,001 ms 读取截止后 FAIL；quic-go 约一个空闲检测周期后才把连接状态更新为 DISCONNECTED，显式重新握手后 M3 PASS。整个过程没有把错误当成功，但调用方必须承担失败与重试。
- M8：FAIL，已稳定复现。61 秒两帧对照流 PASS：响应分别在 11 ms 和 61,057 ms 返回；这不能关闭缺口，因为回收每 60 秒摊薄执行，实际失效点受清理相位影响。125 秒两帧流中 Reactor 在 0 秒收到 `expiry-open`、125 秒收到 `expiry-final`，Gateway 随后记录 `orphan backend response: backend_stream=8`，agent 于 140,002 ms 以 `context deadline exceeded` 结束。它证明映射按创建时间回收，但两帧之间也静默了 125 秒，因此不能直接作为空闲超时修复后的正向标准。
- 发现并修复：① DirectTransport 写入 picoquic 后没有立即驱动客户端，数据可能等待旧的 10 秒定时器；② libxev 定时器已激活时只更新了内存中的间隔，没有 `reset` 到更早的 picoquic deadline。修复后 M3–M5 重跑通过，原先约 10 秒的延迟消失。
- 仍需跟踪：首次运行时观察到 Reactor 连接在空闲关闭边界仍被池视作 ready，请求可能先超时、下一次才返回 `backend unavailable` 并触发重连。本轮专用配置把空闲超时提高到 120 秒并启用 Reactor keepalive，只用于稳定执行；M6 证明了失败可见和后续恢复，但没有提供首请求透明重试。
- 结果：M0–M6 PASS；M8 FAIL；阶段一尚未完成，M7/M9 未执行，M8 阻断未关闭。
- 下一步：先把普通 service 回程映射改为空闲超时并重跑 125 秒场景，再执行 M7 慢端/压力；M9 认证与推送使用独立配置执行。阶段一退出条件满足前不进入远程 Linux。

### 2026-08-27 / macos-m8-idle-fix-001 / M8

- 代码：Gateway `005ff52` + dirty，在 `inflight.Route` 中以 `last_active_at` 替代创建时间；完整客户端 DATA 被接纳和后端响应成功写回都会刷新。认证等待仍使用 `created_at` 绝对超时。
- 单元验证：新增“活跃 route 刷新而同龄 auth 仍过期”用例；完整 Zig 结果为 245 pass、1 skip，共 246 项。
- 正向场景：同一流发送 `active-0/30/60/90/120` 五帧，分片间隔 30,000 ms，总时长 120,063 ms，超时 150,000 ms。
- 正向实际：请求在 0/30,000/60,002/90,003/120,004 ms 发出；响应在 45/30,012/60,013/90,012/120,063 ms 返回；1/1 PASS。Gateway 没有产生该流的 orphan 日志，Reactor 收到全部五帧。
- 静默负对照：`idle-open` 与 `idle-final` 间隔 125,000 ms。首帧响应在 10 ms 返回；末帧在 125,001 ms 收到 Gateway `request expired`，0/1、按预期 FAIL。Reactor 只收到 `idle-open`，未收到过期后的业务末帧。
- 观测细节：Gateway 给已过期后端流补 FIN 后，Reactor 的空 EOF 响应会被记为一次 orphan；这是收尾响应无客户端映射的日志噪声，不改变“业务末帧未继续投递、客户端收到明确错误”的结果，后续可单独降噪。
- 结果：M8 PASS。普通 service 映射现为应用层空闲超时，不再按总存活时间误杀持续活跃的长流；真实静默流仍能回收。
- 下一步：执行 M7 慢 Reactor、慢客户端读取和队列压力；M9 使用独立认证配置。

### 2026-08-28 / macos-m7-pressure-001 / M7

- 配置：Reactor `127.0.0.1:9444 --echo-delay 250ms`；Gateway `config/validation-pressure-macos.json` 监听 `8444`，单 Worker、后端轮询 10 ms、后端接收池人为限制为 8 槽；agent 使用一条真实 QUIC 连接。
- 慢 Reactor：单请求响应正文完整，约 260 ms 返回。首次执行曾稳定延迟到约 10 秒；根因是 Worker 定时器收割后端响应并写入客户端 picoquic 队列后，没有主动驱动客户端侧 ServerDriver。增加应用写 flush 后重跑通过。
- 队列压力：同一客户端 QUIC 连接发起 32 个并发流。8 个收到完整 echo；24 个因 8 槽上限被拒，全部约 260 ms 收到 `gateway_error: backend connection failed`，没有一项等到 5/10 秒客户端 deadline。
- 失败传播修复：接收池满仍按既有安全策略废弃后端连接，已入池的完整帧先交付；随后 Worker 按失败后端连接 id 精确摘除普通与认证 inflight，分别回 `gateway_error`/`auth_failure` 并回收配额和认证 buffer。同一逻辑 transport 的健康副本不被误伤。
- 恢复：压力触发断连后，第一次请求收到 3 ms 的 `backend unavailable` 并唤醒重连；Gateway 随后重新建立到 Reactor 的 QUIC 连接。
- 慢客户端：agent 延迟 3,000 ms 才开始读响应，最终在 3,001 ms 读到完整帧 `echo: M7 slow client retains full frame`，无截断或错序。
- 结果：M7 PASS。这里证明的是有界压力下的完整成功或明确失败，不是吞吐/容量宣称；跨两段 QUIC 的主动背压仍是后续独立设计项。

### 2026-08-28 / macos-real-im-002 / M9

- 组件：React/Vite 页面、Go client-agent、最新 ReleaseSafe Gateway、Go Reactor、SQLite `/private/tmp/lyune-im-mac-stage.sqlite`；Gateway 使用 `config/validation-im-macos.json`，认证为必需。
- 后端语义：用户密码采用带随机 salt 的 Argon2id；应用 token 随机生成且只以 SHA-256 摘要存库；SQLite 保存用户、session、群、成员关系与消息；所有群历史和发消息操作都在 Reactor 重新校验 token 与成员资格。
- 认证：`alice_final_mac` 注册成功并获 `dest_id=3`、TTL 3600 秒；同一用户错误密码登录得到 HTTP 401 与 `invalid username or password`；`bob_final_mac` 注册成功并获独立的 `dest_id=4`。Gateway 日志分别记录 auth success/failure。
- 授权：Alice 创建群 `Mac 最终真实验证群`；Bob 入群前读取历史得到 `not authorized for this group`，使用邀请码加入后才能读取和发送。
- 双向实时消息：Alice 消息和 Bob 回复都先经 `.service(1,2)` 到 Reactor、写入 SQLite，再由 Reactor 主动开 `.peer` 流回 Gateway。每次 Gateway 都记录 `targets=2 delivered=2 routed=0 unreachable=0`；双方 agent 事件队列收到相同目标 `[3,4]` 与完整 JSON 消息，历史接口按 id 返回同样两条记录。
- 浏览器复验：两个真实浏览器标签页分别登录不同用户、加入同一群并双向发送；页面在对端长轮询周期内实时出现消息。修复了 React effect 把 `scrollIntoView()` 返回的 Promise 误当 cleanup 导致状态更新后崩溃的问题，修复后控制台无错误。
- 结果：M9 PASS；M0–M9 至此全部通过，Mac 阶段完成。SQLite 数据位于临时目录，仅作本地验证证据，不是生产数据。

> 后续协议基础能力扩展使原“Mac 阶段完成”结论失效；该记录仍准确描述当时的 M0–M9，
> 当前阶段门禁已经扩展为 M0–M18，以本文顶部状态和 3.3/3.4 为准。

### 2026-08-28 / macos-protocol-v2-003 / M10–M14

- 代码：Gateway、Reactor、client-agent 与 Web UI 均为 dirty 开发工作树；当前不做兼容层，ALPN 破坏性提升为 `lyune/2`。Gateway 默认测试 254 pass、1 skip，共 255 项；ReleaseSafe 构建通过；Reactor/client-agent Go 测试和 React 生产构建通过。
- M10：PASS。OPEN byte 5 从保留字节改为显式 `response_mode`。required 的持久消息返回业务结果；typing 使用 none，在 0.7 ms 左右只收到空 FIN，而 Bob 收到真实 `.peer` typing 推送。Gateway/peer/lifecycle 的模式白名单和错误模式均有回归覆盖。
- M11：PASS。Gateway 在认证后发 online、关闭时发 offline、每 15 秒发续租；Reactor 默认租约 45 秒并按 sequence 拒绝迟到事件。Alice 两连接聚合为 2，关闭一条后为 1；崩溃来不及发 offline 时由租约收敛。聚合属于 Reactor，Gateway 不关心设备类型或“用户整体在线”。
- M12：PASS。client-initiated bidi 承载请求，server-initiated bidi 承载推送且反向只接受空 FIN。故意让 Alice 在推送流写应用帧后，Gateway 以 protocol violation 只关闭 Alice；Bob 的连接继续 ping/收发。单向流传输额度为 0，尝试打开在 deadline 内失败，之后同连接合法 bidi 仍工作。
- M13：PASS。客户端在首帧竞态中 RESET 输入能立即收到 reset 确认而不悬挂；STOP 返回方向后请求可继续处理，后续同连接 ping 成功。picoquic 的 stream_reset/stop_sending 事件已贯通 ServerDriver、ClientDriver、DirectTransport/BackendPool 和 Worker，后端取消不再只靠超时回收。
- M14 发现：旧 64 位 token 仅含 node/worker/slot/generation，Gateway 重启后确定性复用；旧 presence 的高 sequence 会吞掉新进程的 sequence=1，迟到 kick 也可能误伤新连接。没有清空数据库规避，而是把 token 改成含 64 位随机 incarnation 的 128 位不透明身份，AuthContext 18 字节、SessionLifecycle 51 字节、kick/group 使用独立 TokenList，SQLite 按 BLOB 存储。
- M14 复验：PASS。全新 SQLite 中 token 长度均为 16。Gateway 崩溃前 Alice token 为 `1430C16A752388800001000000010001`，重启后为 `6CFE7886CB4DCF8E0001000000000001`；新 token 的 sequence=1 正常入库。短暂窗口显示 Alice 2 条在线租约，旧租约过期后收敛为 1，Bob 的孤儿租约收敛为 0。
- 真实业务复验：错误密码 HTTP 401；Bob 入群前历史授权失败；入群后 typing 与持久消息均经 Gateway 到达双方；presence 为两用户各一连接。数据库确认消息持久化和 16 字节 token。随后真实 React 页面登录 Alice，展示 `dest_id=2`、`lyune/2`、在线汇总和 SQLite 历史，并从页面发送持久消息 #2。
- 已知行为：长时间挂起/系统休眠使后端 QUIC 空闲关闭后，DirectTransport 仍可能让恢复后的第一个请求明确失败并触发重连，下一次成功；没有假成功，但不是透明恢复。此项纳入 M16，不以本轮成功掩盖。
- 结果：M10–M14 PASS；Mac 阶段整体为 M0–M14 PASS、M15–M18 PENDING，尚不允许进入 Linux。
- 下一步：依次执行 M15 混合负载、M16 多轮故障恢复、M17 soak/资源趋势、M18 干净环境总复跑；不增加新的 IM 产品功能。

### 2026-08-29 / macos-m15-mixed-001 / M15

- 工具：新增 `validation/client-agent/cmd/im-mixed-load`。它只驱动 loopback agent API；每个用户仍由 agent 建立独立原生 QUIC 连接，业务命令仍经 Gateway 到 Reactor/SQLite，不用内存假数据替代任一段链路。
- 单轮负载：8 个真实注册用户加入同一群，并发完成 32 条 required 持久消息、64 个 none typing、32 次 history/presence 查询；每位用户都精确收到 32 条 message push 和 64 条 typing push，SQLite 重读包含全部 32 条消息。
- 同时诊断：16/16 required echo、16/16 none echo、8/8 请求输入 RESET、8/8 响应 STOP_SENDING，取消后的同连接 ping 1/1。没有串流、错投、重复 push、客户端 deadline 挂起或 Exchange 遗留。
- 结果：M15 PASS。真实业务负载与协议取消/无响应模式可以同时工作，不能再用“分别跑过”掩盖组合问题。

### 2026-08-29 / macos-m16-recovery-001 / M16

- Reactor、Gateway、agent 均做过多轮停止/重启，并在每次恢复后继续执行混合负载。后端连接句柄加入 16 位 generation，QUIC 重连从原始 stream 0 重新编号时不会与旧 inflight 发生 ABA。
- Gateway 强制终止时，在途客户端请求于自身 10,001 ms deadline 明确失败，没有假成功；Gateway 重启并重新认证后首个 echo 7 ms 成功。相同用户重启前后 token 分别为 `A5CA992675F9E0E80001000000080003` 与 `76DD95F8CF29A67B0001000000000001`，均为 16 字节且 incarnation 不同。
- Reactor 停机后下一请求 0 ms 收到 `backend unavailable`；Reactor 使用同一 SQLite 重启后首次重试即在 1 ms 成功。agent 重启后第二轮 8 用户、32 消息、64 typing、32 查询混合负载在 802 ms 完成。
- 失败通知不再折叠为一个“全部 transport”标志：DirectTransport 为每个连接代际定容保留并逐项消费 failure selector，多个副本同时失败也不会误杀健康副本或漏掉失败域。
- 结果：M16 PASS。恢复语义仍是“失败可见、调用方重试”，不是承诺在途请求透明重放。

### 2026-08-29 / macos-m17-soak-001 / M17

- 初轮 soak 曾出现 64 个 typing push 偶发只有 63 个。线级诊断定位到 Reactor `protocol.WriteFrame` 把 header/body 分两次写且忽略短写计数；并发 server-initiated push 因而可能在流上出现不完整帧。修复为先 `MarshalFrame` 得到不可变完整线帧，再循环写到全部字节完成，并加入短写 writer 回归测试。
- 修复后连续 70 批真实混合负载全部通过；每批 4 用户、8 条持久消息、64 个 typing、8 次查询，并包含 required/none、RESET、STOP 与取消后 ping。第 10 批后重启 Reactor，第 15 批后重启 Gateway+agent，后续批次仍全部通过。
- 其中连续 50 批资源窗口的 SQLite 计数从 `users/groups/members/messages/sessions/presence = 168/41/164/328/168/168` 精确增长到 `368/91/364/728/368/368`，文件从 139,264 增到 278,528 字节，与 200 个用户、50 个群、400 条消息完全对应。
- 同一窗口 Reactor/Gateway/agent RSS 由 `23248/3456/10016 KiB`，中点 `124496/5216/22800 KiB`，结束时回落到 `26320/4544/21184 KiB`；FD 始终为 `14/9/8`。Gateway 空闲快照始终为 4 条后端连接，Exchange、inflight、recv slot 和 pending failure 全部归零。
- 结果：M17 PASS。该记录证明受控 workload 下没有单调资源泄漏，不是生产容量、无限时长稳定性或 Linux 行为宣称。

### 2026-08-29 / macos-m18-final-001 / M0–M18

- 环境：macOS 26.3.1（25D2128）arm64；Zig 0.16.0；Go 1.27.0；Node 22.23.2；npm 10.9.8。Gateway 基点 `564b897` + 本轮 dirty，Reactor 基点 `00d553e` + 本轮 dirty；全新数据库 `/private/tmp/lyune-im-v2-m18-001.sqlite`，全新 Reactor/Gateway/agent 进程。
- M0–M7：`:9443/:8443/:8787` 归属正确，双段 ALPN 均为 `lyune/2`；ping 0 ms，单帧 echo 11 ms，streaming 在请求完成前逐帧返回，32/32 单连接并发通过。M7 的 8 槽负对照仍为 8 个完整成功、24 个约 278 ms 明确失败；连接恢复后 3,001 ms 慢读取拿到完整响应。
- M8 在总复跑中发现新的复用隔离错误：活跃流与静默流的后端句柄高 32 位相同、低 32 位分别为 stream 0/4；静默流到 deadline 后，旧 `invalidateStream` 关闭了整条后端连接，导致活跃兄弟流在 60 秒被错误终止。修复为 picoquic `discard_stream`，只对目标流发送 RESET_STREAM + STOP_SENDING 并立即 flush，共享连接保持 ready。
- M8 最终复验：活跃流在 `0/30,001/60,003/90,005/120,007 ms` 发出，五个响应在 `8/30,003/60,009/90,012/120,015 ms` 全部返回；同连接静默流在 60,007 ms 收到 `backend response timeout`。此时后端连接仍为 4，随后同一认证连接 ping 0 ms、echo 8 ms。
- M9–M14：错误密码拒绝；未入群历史拒绝；入群后两位用户分别发送消息 33/34，双方收到目标 `[2,11]` 的相同 `.peer` 事件，SQLite 历史一致。同用户双连接 presence 为 2，关一条后为 1。非法向 Gateway-initiated 流回写只关闭违规用户，健康用户 echo 10 ms；单向流在 3,005 ms 被拒，后续 bidi 3 ms 成功。RESET/STOP 混合诊断均通过，Gateway 崩溃前后 16 字节 token 不同。
- M15–M17 代表性复跑：两轮 8 用户、32 消息、64 typing、32 查询均通过；之后 10 批 4 用户短 soak 全部通过。10 批前后 Gateway RSS `5648→5776 KiB`，Reactor `121392→92960 KiB`，agent `25120→23904 KiB`；FD 为 `9/14/8` 不变。SQLite 精确新增 40 用户、10 群、40 成员和 80 条消息，文件 `73728→90112` 字节。
- 最终浏览器：两个 React 标签页分别注册为 `dest_id=60/61`，创建并加入 group 14；两边均显示 2/2 在线、2 条连接，并实时看到对方经 Gateway 发送、SQLite 分配 id 148/149 的双向消息。两个页面控制台均无 error。
- 最终静态门禁：`zig fmt --check build.zig src`、257 pass/1 skip 的 Zig 测试、ReleaseSafe、Reactor/client-agent Go 测试、React production build 和两个仓库 `git diff --check` 全部通过。
- 当时结果：Raw QUIC M0–M18 PASS，并冻结了该验证资产。后续因增加 WSS/TCP 回退而重新打开 Mac 阶段；本条历史记录不再代表当前允许进入远程 Linux。不创建 tag、release 或生产承诺。

### 2026-08-29 / macos-transport-session-raw-001 / M0–M18

- 目标与隔离：只引入 tagged `TransportSession` 和唯一的 `RawQuicSession`。客户端 ALPN、OPEN/DATA 字节、真实 QUIC stream/datagram、Gateway → Reactor 和 peer link 均保持不变；本轮没有 WSS listener、WebSocket envelope 或 TCP 代码。
- 结构结果：`ConnectionContext.transport` 成为 Worker 客户端写流、主动开流、临时消息、RESET/STOP/discard 和关闭的统一入口；服务端主动流号 1/5/9… 的分配也归属 Raw binding。代码扫描确认客户端业务路径不再直接调用 `QUICConnection.fromRaw`，剩余调用只位于 binding 本身和明确排除的 Gateway peer link。
- M0–M7：双段仍协商 `lyune/2`；ping、单帧、请求 FIN 前逐帧响应和同连接 32 并发均通过。修复后单独重跑 M7：250 ms 慢 Reactor 的单请求在 255 ms 完整返回；8 槽负对照仍为 8 个完整成功、24 个在 254 ms 明确 `backend connection failed`；压力后请求 257 ms 恢复，延迟读取 3,000 ms 时在 3,001 ms 得到完整帧。
- M8 首次结果：FAIL，并暴露原实现已有的流/连接故障分类错误。静默 sibling 在 60 秒被周期回收后，client-agent 仍按负对照计划于 75 秒发送迟到 DATA；Gateway 又尝试给已经 discard 的后端流补 FIN。picoquic 正确返回单流 `SendFailed`，但 DirectTransport 把它错误放大为共享后端连接故障，导致同连接上每 30 秒活跃的 120 秒长流在约 90 秒被误杀。
- M8 修复与复验：过期 route 的迟到 DATA 现在只清理本地 inbound 状态，不再二次结束已经 discard 的后端流；已有流上的 `SendFailed/Closed` 视为 exchange-local，只有明确的 `ConnectionFailed` 才使共享连接失效。复验中活跃流在 `0/30,001/60,002/90,003/120,004 ms` 发出，响应在 `10/30,004/60,015/90,016/120,011 ms` 全部返回；静默 sibling 在 `60,013 ms` 明确得到 `backend response timeout`，75 秒迟到 DATA 没有影响活跃流或其他后端连接。
- M9–M15：错误密码 HTTP 401；两名真实用户 `raw_gate_alice/raw_gate_bob` 获得不同 `dest_id=10/11`。Bob 入群前历史授权失败，凭邀请码入群后，双方消息 33/34 经 Gateway 主动推送到目标 `[10,11]` 且 SQLite 历史一致。同用户双连接 presence 为 2，关闭一条后为 1；违规回写 server-initiated 流只关闭 Alice，Bob 后续 ping 0 ms；单向流被拒后合法 bidi 仍为 0 ms。required/none、RESET、STOP、typing、查询和推送混合负载均通过。
- M14/M16：Gateway 重启前后 Bob 的 16 字节 token 分别为 `81FEAF8753503D950001000000080002` 与 `FBC22EE63209B6BB0001000000000001`，incarnation 不同。两轮 Reactor 停止都使下一请求 0 ms 明确 `backend unavailable`，重启后分别在 10/11 ms 成功；强制终止 Gateway 时请求在 5,001 ms deadline 失败，重启、显式重连后 5 ms 成功，无假成功。
- M17：修复后连续 10 批真实混合负载全部通过；每批 4 用户、8 条持久消息、32 typing、8 查询，并同时完成 required 16/16、none 16/16、RESET 8/8、STOP 8/8 和取消后 ping。SQLite 精确增加 40 用户、10 群、40 成员、80 消息、40 session/presence；Gateway 空闲时 Exchange/inflight/recv slot/pending failure 全部归零，FD 维持稳定。
- 静态门禁：`zig fmt --check build.zig src`、259 pass/1 skip 的 Zig 测试、ReleaseSafe、Reactor/client-agent Go 测试、React production build 和两个仓库 `git diff --check` 全部通过。
- 结果：TransportSession Raw-only M0–M18 PASS。该结构基线允许开始 WSS 阶段，但不等于 WSS 已实现，也不允许跳过 WSS 自身的浏览器直连、QUIC↔WSS 混合用户、TCP 回退、慢消费者和断线恢复矩阵；当前不创建 tag 或 release。

### 2026-08-30 / macos-wss-initial-001 / WSS 第一轮混合门禁

- 实现范围：新增 libxev TCP listener、BoringSSL TLS BIO driver、严格 HTTP Upgrade/Origin/Host-SNI、RFC 6455 parser、固定 20 字节逻辑流 envelope、单会话定容输出队列和 `WssSession` vtable；Worker 的认证、Exchange、路由、push、lifecycle 和 Reactor 路径没有复制分叉。默认配置继续关闭 WSS，`validation-im-macos.json` 才显式监听 `127.0.0.1:8444/TCP`。
- 协议边界：有效 Origin 的 Upgrade 返回 HTTP 101 和 `Sec-WebSocket-Protocol: lyune.v2`；缺失 Origin 的原生 WebSocket 被拒绝；重复 Host/version、错误版本、header folding、非法 masking/长度、分片控制帧、错误 envelope 和 close code 均有纯字节测试。新的开发证书沿用现有私钥并补 `DNS:localhost`、`IP:127.0.0.1` SAN，Gateway 实际下发 TLS 1.3 证书已核验；它仍是自签名证书，浏览器必须由用户显式信任。
- 真实登录：无第三方依赖的 Node TLS/WebSocket 客户端经 WSS 使用真实用户 `m15_8decc2797a_01` 登录成功，得到 `dest_id=2`、TTL 3600 秒并读取 1 个 SQLite 群。React 页面已默认选择浏览器直连 `wss://localhost:8444/lyune/v2` 并完成生产构建；实际浏览器登录仍保留为用户手工信任开发证书后的门禁，自动化不得绕过证书安全页。
- 混合 IM：最终验证程序创建两个一次性 WSS 用户 `wss_a_b66c974373`/`wss_b_b66c974373`（`dest_id=60/61`）与 Raw QUIC 用户 `raw_b66c974373`（`dest_id=62`）。WSS A 创建真实 SQLite group 16；WSS B 和 Raw 入群前读取历史均被拒，凭邀请码入群后，三个方向消息 123/124/125 都持久化并分别以 `.peer` 主动流送达三个目标，日志三次均为 `targets=3 delivered=3`；WSS 重读历史同时找到三条消息。typing 使用 `response_mode=none` 得到空 FIN。
- 负门禁：真实 TLS/WebSocket 连接分别尝试复用 client logical stream 0、伪造尚未由 Gateway 创建的 server stream 1、发送未 masked client frame；三者都只关闭自己的会话并收到 close code 1002，随后健康 WSS 登录仍成功。WSS 对首次 OPEN 使用单调 high-water，永久补齐 QUIC 原生的 stream id 不可复用保证；Gateway 主动 stream 也只允许按 1/5/9… 创建。
- 容量与资源回收：修复 macOS/kqueue 下把需要 thread pool 的异步 `xev.TCP.close` 错当成已完成所造成的 accepted FD 残留；现在只在 read/write completion 均不活跃后同步关闭并由 listener 周期泵回收。12 路并发登录退出和 64 条同时完成 TLS+Upgrade 均成功；配置上限为 64 时第 65 条被明确拒绝，全部关闭后 `lsof` 只显示 `8444` listener FD，Worker 指标回到 clients/exchanges/inflight/receive-slots 全零。
- 诊断修复：Raw QUIC 的 `getConnectionIdBytes` 曾返回指向局部 CID 副本的悬空切片，使 close 日志打印栈垃圾；改为在日志调用域内持有按值 CID 后，真实 Raw 会话关闭稳定输出 `4c590100010075592ae06c4c`。
- 静态门禁：`zig build test --summary all` 为 282 pass/1 skip（283 total）；ReleaseSafe、React production build、Node 语法检查和 WSS/Raw 混合真实进程验证通过。
- 结果：WSS 实现与第一轮混合 IM PASS，但不是完整 WSS M0–M18。慢消费者/队列打满、畸形网络输入、断线游标补偿、WSS↔WSS、进程故障矩阵、多 Worker TCP reuseport 和混合 soak 仍需执行；这些完成前不冻结新的 Mac 基线、不进入远程 Linux、不创建 tag/release。

### 2026-08-30 / macos-wss-resilience-002 / WSS 增量门禁

- 协议路径：`validation/wss-protocol.mjs` 在一条真实 WSS 上完成 Gateway ping、单帧 echo、OPEN+DATA+DATA 三帧 streaming echo、同连接 32 并发、required/none 和 RESET/STOP。三段响应的首段在 12 ms 返回且早于请求 FIN；两个取消场景之后的新 ping 均成功，未扩大为连接故障。
- 网络负例：`validation/wss-negative.mjs` 扩展为 14 类实际网络拒绝，包括 stream reuse、未来 server stream、未 masked、RSV、非 canonical length、分片控制帧、超大 frame、错误 envelope version、Origin、Host/SNI、path、subprotocol、WebSocket version 与超大 HTTP head；协议违规均为 1002 或 Upgrade 前 TCP 拒绝，只影响本会话。合法 binary fragments 中插入 ping 可重组，全部负例后真实认证仍成功。
- 断线与慢端：接收者离线期间消息 1346 已先写 SQLite，重连历史补齐后消息 1347 实时推送恢复。真实暂停 TCP reader 后连续写入 1200 条约 1900 字节消息，慢会话在独立输出边界关闭；健康发送者随后请求成功并收到消息 2548 的 push，Gateway 只剩 listener FD。
- lifecycle 与长流：同账号两条 WSS 的 presence 为 `2 → 1 → 跨 16 秒续租仍为 1 → 0`。120,007 ms 活跃流在 `11/30,014/60,011/90,009/120,005 ms` 收到五段响应；静默 sibling 在 60,012 ms 得到 `backend response timeout`，75 秒迟到 DATA 被隔离，之后同连接 ping 成功。
- 双 Worker：`./run-im-demo.sh --workers 2` 启动两套 Raw UDP listener、WSS TCP listener、事件循环和每 Worker 4 条后端连接。首次三用户混合测试暴露旧 `.peer` 路径把 HRW 首选 Worker 当成实际连接所有者：三条会话都由 reuseport 放在 worker 1，但一个目标被错误转投 worker 0，日志为 `targets=3 delivered=2 routed=1` 并最终 push timeout。
- 修复：HRW 继续只决定跨节点 home；目标节点内无论 WSS/Raw 都对其他 Worker 各交接一次，并在发起 Worker 无条件查本地索引。一次性 `.peer`、peer 入站和流式 OPEN 共用这一规则，布尔 RouteSet 保证每个 Worker 每帧最多一份。新增单测专门钉住“HRW 首选为当前 Worker 时仍必须探测其他 Worker”。修复后连续五轮两个 WSS + 一个 Raw 群聊全部通过，四次 push/轮均为 `targets=3 delivered=3 routed=1 unreachable=0`；断线、负例、慢消费者和 64/65 容量随后在双 Worker 配置复跑通过。
- 静态门禁：新增回归后 `zig build test --summary all` 为 283 pass/1 skip（284 total）；代码格式检查通过。完整 ReleaseSafe、Go、React 与文档一致性在本轮最终收口时统一复跑。
- 结果：WSS 的 M2–M5、M7–M13 主要传输语义和多 Worker 增量风险已关闭；仍需反复 Gateway/Reactor/agent 故障恢复、混合 soak/资源趋势、M18 新数据库总复跑，以及用户手工信任开发证书后的真实浏览器双标签页。此前不进入远程 Linux、不创建 tag/release。

### 2026-08-30 / macos-wss-m18-final-003 / WSS M14–M18 与自动化总复跑

- 故障矩阵：`validation/wss-fault-recovery.mjs` 使用独立临时 SQLite 与自管 Reactor/Gateway 进程。连续 3 次停止 Reactor 后，现有 WSS 的下一请求均明确失败，停止到失败为 `3/5/5 ms`；同一 WSS 会话在 Reactor 重启后分别于 `236/245/249 ms` 恢复。随后连续 2 次 `SIGKILL` Gateway，客户端均观察到传输关闭，新 Gateway 启动、WSS 重连、同用户登录和 SQLite 查询分别在 `125/123 ms` 内完成。
- 身份隔离：初始进程和两次 Gateway 重启共观察到 3 个不同的 128 位 `conn_token` incarnation；旧连接身份没有命中新进程会话。失败语义仍是“明确失败、调用方重试”，不承诺在途请求透明重放。
- 干净综合轮：`./run-im-demo.sh --reset --no-open --workers 2` 从新 SQLite 启动。协议、14 类负例、20 轮 WSS↔WSS↔Raw 群聊、断线补偿、presence、64/65 容量、1200 条大消息慢消费者和 120 秒长流全部通过。长流五段响应为 `11/30015/60007/90012/120010 ms`；静默 sibling 在 `60019 ms` 结束，75 秒迟到 DATA 被隔离，后续 ping 正常。慢端退出后 Gateway 只保留两个 reuseport listener FD；两条预期 `StreamWriteFailed` 与慢会话关闭时间一致，健康会话继续收发。
- 独立资源轮：再次清空数据库，以固定的 2 WSS + 1 Raw 三用户群聊连续运行 30 批，精确得到 90 用户、30 群、90 成员、90 条消息。Gateway RSS 在 baseline/10/20/30 批为 `19600/22000/22448/22464 KiB`，Reactor 为 `22160/188672/188832/188880 KiB`，第 10 批后进入平台区；agent 为 `11744/18032/19232/19552 KiB`。三者 FD 始终为 `15/15/9`，Gateway/Reactor 严格 error/fatal/panic 计数为 0。这是受控 M17 趋势，不是生产容量或无限时长稳定性宣称。
- 静态门禁：`zig fmt --check build.zig src`、283 pass/1 skip（284 total）的 Zig 测试、ReleaseSafe 9/9、Reactor/client-agent Go 测试、React production build、全部 Node 脚本语法检查和 `git diff --check` 通过。
- 结果：WSS/混合 binding 自动化 M0–M18 PASS。阶段一仍未最终关闭，因为浏览器证书安全页不能由自动化绕过；用户手工信任本地开发证书后，还需在两个真实标签页完成注册、建群/邀请码、双向实时消息、错误密码和历史重读。该人工门禁通过前不进入远程 Linux、不创建 tag/release。

### 2026-08-30 / macos-session-boundary-refactor-004 / 架构重构回归

- 结构：客户端会话契约提升到顶层 `session/`，WSS Listener 与 Worker 改经
  `Handler`/`Acceptor` 装配；`TransportSession` 改为类型擦除 vtable，Raw QUIC adapter
  归入 `quic/session.zig`。Worker 不再 import WSS，WSS 不再经 session 间接依赖 picoquic。
- 资源修复：运行期 DirectTransport 创建后若注册失败，会回滚最后一个工厂槽位，避免
  后续重试耗尽定容 route capacity；工厂测试覆盖回滚后同一地址可安全复用。
- 静态门禁：`zig fmt --check build.zig src`、284 pass/1 skip（285 total）、ReleaseSafe
  9/9 与 `git diff --check` 通过。
- 真实进程：`./run-im-demo.sh --reset --no-open --workers 2` 启动全新 SQLite、Reactor、
  双 Worker Gateway、client-agent 与 Web；`node validation/wss-mixed-im.mjs` 创建两个 WSS
  用户和一个 Raw QUIC 用户，共同加入 group 1，三方向消息 1/2/3 均持久化并推送到三人，
  `response_mode=none` 返回空 FIN，历史一致。结果 PASS。
- 结论：本次依赖倒置与类型擦除没有改变 Raw/WSS 可观察协议语义；它是结构回归，不替代
  已完成的 M0–M18，也不关闭仍需用户手工完成的真实浏览器双标签页门禁。

### 2026-08-31 / macos-browser-manual-005 / Raw QUIC↔WSS 人工体验

- 环境：用户在 macOS 钥匙串中导入并信任项目开发证书，使用真实 Web UI、Gateway、Reactor 和 SQLite 数据库；Raw 用户为 `raw_deea39849a`，WSS 用户为 `wss_a_deea39849a`。
- 实际：Raw 用户先发送消息；WSS 用户登录后能看到该消息。随后 WSS 用户分别向 `dest_id=3` 和 `dest_id=2` 发送两条消息，Raw 用户均能看到；网关日志显示 Raw/WSS 会话分别认证成功，并出现 `targets=3 delivered=2` 的在线推送记录。SQLite 中对应持久消息连续写入。
- 能证明：真实证书与浏览器 WSS 握手成功；两种 transport binding 汇入同一用户认证、群路由、SQLite 历史和消息投递路径；WSS→Raw 实时投递成功。
- 不能单独证明：Raw 的首条消息是在 WSS 登录前发送，WSS 后来看见它属于历史读取证据，不是 Raw→WSS 同时在线实时推送证据；本轮也没有逐项记录错误密码、注册、建群和邀请码入群 UI 操作。
- 结果：PARTIAL PASS。多传输基础链路已由真实用户确认，完整人工 UI 清单仍开放；当前按项目决定暂停继续扩展测试，先进入源码审计。

## 7. 与 CI、发布和后续演进的关系

CI 不是当前阻断项。当前优先完成源码逐行审计和文档/实现对齐；现有本机脚本与自动化证据已经足够支持审计期间的回归。最小 CI 能固定格式化、单元测试和干净构建，但不能替代真实浏览器、Linux 内核路径或故障验证。

源码审计完成、下一阶段明确后再决定是否引入最小 CI，并逐步接入成本可控的冒烟场景。高成本的 Linux cBPF、netem 和 soak 应使用独立流水线或手工验证窗口，不进入每次提交。任何阶段都不自动发布版本。
