# 两阶段真实环境验证

> 建立日期：2026-08-27
>
> 当前状态：阶段一已完成，Mac M0–M18 全部通过并冻结；下一步进入远程 Linux。两个阶段完成前都不创建 release。

本文既是验证计划，也是持续更新的验证记录。它回答三个问题：当前真实链路怎样搭建、每一项怎样判定通过、实际执行时观察到了什么。设计能力是否存在仍以源码和 `status.md` 为准；本文件只记录真实进程与真实网络中的证据。

## 1. 验证目标与边界

本轮先证明现有代码可以形成真实闭环，再继续补功能：

1. 在真实 MacBook 上启动带 SQLite、真实用户和群成员授权的 Go 后端、Zig 网关与轻量客户端，跑通登录、业务鉴权、持久化群消息和双用户实时推送；
2. 阶段一稳定后，把相同组件和场景迁移到远程 Linux，验证跨平台构建、网络 I/O 与 Linux 专属路径；
3. 每次执行保留环境、命令、配置、日志、预期结果、实际结果和问题编号，不能只留下“测试过”的结论；
4. 当前没有生产环境和外部用户。本轮不创建 tag、release、镜像或兼容性承诺。

本轮不是性能宣称，也不以单次 echo 成功代替完整正确性验证。吞吐、长时间 soak、多节点集群和生产安全配置仍需独立证据。

## 2. 组件与真实数据路径

阶段一使用以下四个独立进程。主验收链路不是 echo，而是带真实业务状态的 IM：

```text
Browser / React UI :5173
        |
        | HTTP/JSON（控制、展示结果）
        v
client-agent :8787
        |
        | QUIC + ALPN lyune/2（真实客户端连接）
        v
lyune-gateway :8443
        |
        | QUIC + ALPN lyune/2（真实 DirectTransport）
        v
lyune-reactor :9443
```

端口 `8443` 只属于网关；Reactor 固定使用 `9443`，避免默认配置中前后端争用同一端口。主验收使用 `config/validation-im-macos.json`：认证路由 `.service(1,1)`、IM 路由 `.service(1,2)`、认证门禁和 `.peer` 回推全部开启。`config/validation-macos.json` 只保留为协议 echo/长流诊断配置，`config/validation-pressure-macos.json` 只用于人为缩小队列的 M7 压力负对照；三者都不改写日常默认配置。

### 为什么浏览器旁需要 client-agent

当前客户端协议是自定义 ALPN `lyune/2` 上的原生 QUIC。浏览器 JavaScript 不能打开任意 UDP socket，也不能直接协商自定义原生 QUIC ALPN；WebTransport 则要求服务端实现相应的 HTTP/3/WebTransport 语义，网关目前没有这层协议。

因此 React 页面负责真实操作和观测，轻量 client-agent 负责浏览器不具备的传输能力。agent 使用独立 QUIC 实现与网关互操作，发送的仍是当前 OPEN/DATA 线格式，网关到 Reactor 也仍走真实 QUIC。这一结构不能被描述为“浏览器直连 QUIC”，但它完整覆盖网关的客户端数据面。为了省掉 agent 而给网关临时增加 WebTransport，不属于本轮冻结验证的范围。

对应资产：

- `validation/web-client`：真实登录、建群、邀请码入群、历史消息与实时聊天页面；
- `validation/client-agent`：每个浏览器会话一条独立 QUIC 连接，保存应用 token，并接收后端主动打开的 `.peer` 流；
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

从各项目根目录执行：

```bash
# 1. Go 后端，监听 127.0.0.1:9443
cd ../lyune-reactor
go -C reactor run . \
  --listen 127.0.0.1:9443 \
  --cert ../../lyune-gateway/server.crt \
  --key ../../lyune-gateway/server.key \
  --db /private/tmp/lyune-im-mac-stage.sqlite

# 2. Zig 网关，监听 127.0.0.1:8443，并连接 Reactor :9443
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

M7 另开 `9444/8444`，不要扰动主 IM 数据库和会话：Reactor 增加 `--echo-delay 250ms`，Gateway 使用 `config/validation-pressure-macos.json`。该配置故意把 `max_receive_queue` 设为 8，只用于证明满载时的失败是完整、及时且可解释的，不能拿它做吞吐结论。

### 3.3 场景顺序

必须按下面的顺序逐项推进。前置项失败时不继续叠加后续变量。

| 编号 | 场景 | 最低通过条件 |
| --- | --- | --- |
| M0 | 构建与监听 | 三个原生进程正常构建；`:9443`、`:8443`、`:8787` 分别由预期进程监听 |
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
| M18 | 干净环境总复跑 | 新数据库、新进程、固定命令完整复跑 M0–M17；源码/文档/配置一致，无阻断项后冻结 Mac 基线并允许进入 Linux |

M0–M4 构成“传输最小闭环”，M9 构成有业务意义的应用闭环，M10–M14 固化协议基础能力，M15–M18 才证明这些能力能在混合负载、故障和时间维度下共同工作。阶段一必须 M0–M18 全部通过；echo 成功不能代替身份、授权、持久化、主动推送或资源稳定性。

### 3.4 阶段一退出条件

- M0–M18 有可复现记录，已知失败有稳定复现步骤和问题编号；
- 至少完成一次全新进程启动后的 M0–M5，而不是复用未知状态的长驻进程；
- Web UI 展示的结果与三份原生日志能按时间和 stream 对上；
- Reactor 和 client-agent 的 codec 均有当前线格式单元测试；
- 文档中的启动命令在新的 shell 会话可直接执行；
- 阶段一发现的阻断性协议错误先修复并重新验证，再进入远程 Linux。

截至 2026-08-29，M0–M18 均已满足，阶段一退出条件已经关闭。Mac 基线冻结后不再增加协议或 IM 产品功能；后续只把相同代码、配置、数据库模型和场景迁移到远程 Linux，发现跨平台阻断时再回到对应层修复并完整回归。

## 4. 阶段二：远程 Linux 真实验证

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
- 结果：M0–M18 PASS，阶段一关闭。冻结当前 Mac 验证资产并允许开始远程 Linux；不创建 tag、release 或生产承诺。

## 7. 与 CI、发布和后续演进的关系

CI 不是当前阻断项。现阶段优先把本机和远程真实路径变成可重复执行的验证步骤；在此之前建立 CI，只会重复已经较成熟的单元测试，不能证明真实链路可用。

两阶段验证稳定后再引入最小 CI，用它固定格式化、单元测试和干净构建，并逐步接入成本可控的冒烟场景。高成本的 Linux cBPF、netem 和 soak 应使用独立流水线或手工验证窗口，不进入每次提交。任何阶段都不自动发布版本。
