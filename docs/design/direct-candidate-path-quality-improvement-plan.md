# Magicsock Direct/DERP 路径稳定性改进方案

## 1. 背景

本方案以 `origin/main` 为实现基线，解决两个实际问题：

1. 当前 direct 路径只有偶发丢包，但容易降级到 DERP；
2. 已经使用 DERP 后，恢复到可用 direct 路径需要较长时间。

实际网络特征是：

```text
Direct：平均延迟很低，平均丢包约 1%
DERP：平均延迟约 400ms，平均丢包接近 0%
```

因此，路径选择不能把“零丢包”作为唯一目标。一个低延迟、1% 丢包的 direct 路径，
综合质量通常明显优于 400ms 的 DERP。偶发一个探针超时不应触发路径降级。

现场还存在 Windows 多 IPv6 地址场景。peer 同时公告多个 IPv6 endpoint，但发往地址
A 的 Disco Ping 可能由地址 B 返回：

```text
requested（Ping 目标） = A
observed（实际 UDP 回包源） = B
```

日志中已观察到：向 `7337...:41641` 发送的 Pong 从 `4de8...:41641` 返回，而直接向
`4de8...:41641` 探测时可以得到源一致 Pong。CLI `tailscale ping` 会报告发包目标，
因此可能显示“via A”，但 `tailscale status --json` 的 `CurAddr` 仍为空，业务数据继续
走 DERP。

## 2. 设计目标

1. Direct 平均延迟低、平均丢包约 1% 时稳定保持 direct。
2. 单次或少量离散 heartbeat 丢包不得清除 direct `bestAddr`。
3. Direct 真正失效时，在有可用 DERP 的前提下有界回退，避免长时间黑洞。
4. 进入 DERP 后立即发现 direct，不等待多个 heartbeat 周期积累基线。
5. 可用 direct 再次出现后，在一个短评估窗口内切回，而不是等待完整长期窗口。
6. 多 IPv6 下只选择经过源一致验证的实际地址，不把 A→B 错配误记为 A 的成功。
7. 路径变化、endpoint 删除、Disco key 变化和网络变化不能留下旧探针或旧决策。
8. 探测开销有界，锁顺序和异步调度无死锁风险，并具有足够可观测性。

## 3. 非目标

- 不要求 direct 零丢包。
- 不修改 `disco/` 消息格式、加密或 `Pong.Src` 语义。
- 不使用 netcheck 的本机到 DERP RTT 替代本机经 DERP 到 peer 的端到端 RTT。
- 不让未认证或来源不明的 UDP 地址直接成为数据面候选。
- 不因追求改动最小而牺牲路径状态正确性；也不引入与本问题无关的全局路由重构。

## 4. `origin/main` 的问题分析

### 4.1 Direct 降级依赖单次时效状态

当前主要参数为：

```text
heartbeatInterval       = 3s
pingTimeoutDuration     = 5s
trustUDPAddrDuration    = 6.5s
discoPingInterval       = 5s
upgradeUDPDirectInterval = 1min
```

`addrForSendLocked` 在 `trustBestAddrUntil` 到期后会同时返回 direct 和 DERP；
`discoPingTimeout` 又可能在 bestAddr 已失去信任后直接清除它。路径是否继续使用 direct
主要由最近一次 Pong 和单次 timeout 驱动，没有表达“最近整体只有约 1% 丢包”的状态。

### 4.2 DERP 状态下恢复探测不够及时

无 direct 时，full discovery 由 3 秒 heartbeat 驱动，同时每个 endpoint 受 5 秒
`lastPing` 节流，实际通常约 6 秒一轮。刚从 direct 进入 DERP 时，旧 `lastPing` 还可能
让第一次 recovery discovery 跳过所有地址，也就不会发送 Call-Me-Maybe。

### 4.3 Wrong-source Pong 被归到发包目标

普通 Pong 处理当前使用 `sp.to` 更新 `endpointState`、`recentPongs`、`wireMTU` 和
`bestAddr`。若发往 A 的 Pong 实际由 B 返回，旧逻辑仍可能把 A 当作可用 direct，
造成选路身份、延迟和 MTU 归属错误。

## 5. 总体架构

每个 peer 使用一个轻量、显式的路径状态机：

```text
DirectHealthy
    │ 单次/少量失败
    ▼
DirectSuspect
    │ direct 恢复 ───────────────┐
    │                             │
    │ 确认失效                    │
    ▼                             │
DERPActive                        │
    │ 发现 direct 候选            │
    ▼                             │
DirectProbing                     │
    │ 通过                         │
    └──────────────→ DirectHealthy
    │ 失败/重试耗尽
    └──────────────→ DERPActive（candidate cooldown）
```

状态含义：

- `DirectHealthy`：direct 数据面正常，只使用 direct；
- `DirectSuspect`：direct 有近期失败，但尚未确认失效；保留 `bestAddr`。第一次有效失败后
  仍只使用 direct，第二次连续有效失败后进入有界的 direct+DERP 冗余发送；
- `DERPActive`：direct 已确认不可用，业务走 DERP，并立即、持续但有界地发现 direct；
  即使当前所有候选都在 cooldown，也由 heartbeat/discovery 周期自驱动检查新 endpoint，
  但不会对相同候选重复发送质量 burst；
- `DirectProbing`：DERP 仍承载业务，对候选 direct 和当前 DERP 做短窗口配对测量。

关键转换必须闭环：

| 当前状态 | 事件 | 下一状态 | 附带动作 |
|---|---|---|---|
| `DirectHealthy` | 第一次有效失败 | `DirectSuspect` | 保持 direct-only |
| `DirectSuspect` | `directFailureStreak == 2` | `DirectSuspect` | direct+DERP 冗余发送 |
| `DirectSuspect` | 第三次有效失败/严重滑窗失败 | `DERPActive` | 清除 direct 独占信任，触发一次 force discovery |
| `DERPActive` | 候选进入评估 | `DirectProbing` | 业务继续走 DERP |
| `DirectProbing` | 准入通过 | `DirectHealthy` | 晋升源一致 candidate |
| `DirectProbing` | 准入失败/重试耗尽 | `DERPActive` | candidate cooldown，等待下一轮 discovery |

`DERPActive` 没有候选不是终态；它由 heartbeat/discovery 周期继续驱动，但 cooldown
只阻止相同地址重复 burst，不阻止新 endpoint 或网络变化触发探测。

状态变更必须通过统一入口完成，统一维护失败计数、质量窗口、generation、定时器和
调试记录，不能由 `trustBestAddrUntil` 单独隐式决定状态。

## 6. Direct 路径质量与降级策略

### 6.1 滚动质量窗口

当前 direct 维护最近 16 个探针结果：

```text
样本：success/timeout/send-error
成功样本：RTT
窗口大小：16
最少有效样本：3
样本最大年龄：45s
```

质量成本建议保持为：

```text
effectiveCost = p50
              + 0.25 × (p95 - p50)
              + 0.25 × jitter
              + 2s × lossRate
```

示例一：若 direct `p50=50ms`、`p95=50ms`、`jitter=0`、`lossRate=1%`，
则成本为 `50 + 20 = 70ms`。示例二：若 `p50=50ms`、`p95=80ms`、`jitter=10ms`、
`lossRate=1%`，则成本为 `50 + 7.5 + 2.5 + 20 = 80ms`；两者都显著低于约
400ms 的 DERP。16 样本中出现一次失败表示该窗口的离散失败比为 6.25%，不代表
真实长期丢包率就是 6.25%。

该成本用于质量观测、direct 候选间排序以及 DERP→direct 准入。`DirectHealthy` 没有
持续测量 DERP 端到端基线，因此不能仅凭该成本触发 direct→DERP；direct 降级只使用
下面明确的可达性失败条件。这避免为了比较质量而长期额外探测 DERP，也保证低延迟、
约 1% 丢包的 direct 不会被“零丢包但 400ms”的 DERP 替代。

### 6.2 失败分层

一次 best heartbeat timeout：

```text
记录一个失败样本
directFailureStreak += 1
DirectHealthy → DirectSuspect
不清除 bestAddr
不把 DERP 设置为新的首选路径
```

当前 bestAddr 的 heartbeat purpose 源一致 Pong：

```text
directFailureStreak = 0
更新质量窗口和 trust
DirectSuspect → DirectHealthy
```

确认失效的初始规则：

```text
连续 3 次有效 best heartbeat timeout
或最近 10 次 best heartbeat 至少失败 6 次，且最近 6.5s 没有源一致成功 Pong
或本地 socket/route 返回明确不可达错误
```

确认失效后才进入 `DERPActive`。连续失败提供完全断网时的快速通道，滚动窗口负责避免
偶发约 1% 丢包造成错误降级。

heartbeat 必须携带 path generation 和单调递增序号，并维护 `lastDirectSuccessAt`。
timeout 只有同时满足下列条件才是
“有效失败”：

- purpose 为 `pingHeartbeat`；
- generation 未变化，`sp.to` 仍是当前 `bestAddr`；
- 该探针序号晚于本 generation 最近一次 heartbeat 成功序号；
- `sp.at` 晚于最近一次来自当前 best 的源一致成功 Pong。

当前 best 的源一致 Pong 在持有 `endpoint.mu` 时先推进相应成功序号、更新
`lastDirectSuccessAt` 并清零失败连续值。若 Pong
先到，随后到达的旧 timeout 不得重新增加失败值；若 timeout 先到、对应的晚到 Pong 后到，
Pong 仍可把 suspect 恢复为 healthy。旧 generation、CLI、普通 discovery、recovery、
candidate quality 和 PMTU 的 timeout 都不能改变当前 direct 的 heartbeat 失败状态。

实现不变量可写成以下伪代码；`heartbeatGeneration` 用于 endpoint/network/key 生命周期，
`heartbeatSeq` 用于同一 generation 内的顺序，二者不与 candidate quality 的 generation
混用。`sentPing` 至少需要携带 `heartbeatGeneration`、`heartbeatSeq`、`at` 和现有的
purpose/path-quality 字段：

```text
onExactPong(sp, src):
    if sp.purpose != pingHeartbeat || sp.heartbeatGeneration != heartbeatGeneration ||
       sp.to != bestAddr || src != sp.to:
        ignore for direct health
    else:
        lastDirectSuccessSeq = max(lastDirectSuccessSeq, sp.heartbeatSeq)
        lastDirectSuccessAt = max(lastDirectSuccessAt, now)
        directFailureStreak = 0
        state = DirectHealthy

onTimeout(sp):
    if sp.purpose != pingHeartbeat || sp.heartbeatGeneration != heartbeatGeneration:
        ignore
    if sp.to != bestAddr || sp.heartbeatSeq <= lastDirectSuccessSeq || sp.at <= lastDirectSuccessAt:
        ignore
    directFailureStreak++
    if directFailureStreak == 2:
        sendMode = directPlusDERP
    if directFailureStreak >= 3:
        state = DERPActive
```

`RotateDiscoKey`、`noteBadEndpoint`、`noteConnectivityChange`、endpoint 删除、reset 和
network epoch 变化都必须推进 `heartbeatGeneration`。此外，`setBestAddrLocked` 发生
direct endpoint 身份变化、`clearBestAddrLocked` 清除当前路径、或重新选出新 best 时，
也必须推进 heartbeat generation；仅更新同一 endpoint 的 RTT 不推进。旧 sentPing 可以
异步自然结束，但其 Pong/timeout 只能被上述门控丢弃，不能改变新状态。

### 6.3 与 `addrForSendLocked` 的关系

失败滞回必须参与实际数据选路，不能只延迟 `clearBestAddrLocked`：

- `DirectHealthy`：返回 direct，不返回 DERP；
- `DirectSuspect` 第一次有效失败（`directFailureStreak == 1`）：即使
  `trustBestAddrUntil` 到期，`addrForSendLocked` 也必须继续返回 direct-only，直到收到
  成功 Pong 或进入 streak==2；不能让旧的 trust expiry 提前触发 direct+DERP；
- `DirectSuspect` 第二次连续有效失败（`directFailureStreak == 2`）：保留 direct `bestAddr`，但在确认窗口内返回
  direct+DERP，限制真实断网时的业务黑洞；
- `DERPActive`：清除失效 direct 的独占信任，返回 DERP；
- `DirectProbing`：业务继续走 DERP，探针单独发往候选。

按 3 秒 heartbeat、5 秒 timeout 估算，完全失效时从首个未响应 heartbeat 算起，约 8 秒
进入冗余发送，约 11 秒确认并进入 DERP-only；实现应定义 scheduler jitter 上限 Δ，验收
使用 `T_redundant <= 8s + Δ`、`T_DERP <= 11s + Δ`，而不是只验证平均值。重复包由
WireGuard 的计数器/重放保护处理。若期间收到新的源一致 Pong，立即恢复 direct-only。

`origin/main` 的 `populatePeerStatus` 只有在“UDP 有效且 DERP 无效”时才填 `CurAddr`。
因此本方案明确状态展示语义：direct-only 时 `CurAddr` 为 direct 地址；冗余发送期间
`CurAddr` 按现有接口为空，因为此时确实不存在唯一传输路径；DERP-only 时也为空。
本地 debug 状态另行输出 `pathState`、`preferredAddr` 和 `sendMode`，用于区分后两者，
不改变现有 `CurAddr` API 的含义。

普通 Discovery、CLI Ping、PMTU 和候选验证的 timeout 不计入当前 direct 的失败连续值；
只统计 `pingHeartbeat` 且目标仍等于当前 `bestAddr` 的结果。

## 7. DERP 到 Direct 的快速恢复

### 7.1 进入 DERP 时立即 discovery

仅在“direct 被确认失效并进入 `DERPActive`”的专用转换中触发一次强制 full discovery。
不能把该行为放进通用 `clearBestAddrLocked`，因为 reset、endpoint 删除和网络更新也会
调用它。

强制 discovery 必须：

- 单次绕过 endpoint 的 5 秒 `lastPing` 限制；
- 使用专用 recovery discovery purpose，固定 `size=0`，禁止 Peer MTU 多尺寸展开；
- 向当前公告的所有 direct endpoint 各发一个最小 Disco Ping；
- 发送一次 Call-Me-Maybe；
- 更新 `lastPing` 和 `lastFullPing`；
- 首轮可对每个 endpoint 绕过 cooldown 一次，后续轮次正常遵守 cooldown；
- 通过 generation/标志避免多个 timeout 重复触发同一轮。

首次强制轮之后恢复普通 5 秒 endpoint 节流，不持续强制。`DERPActive` 在后续 heartbeat
周期仍运行 discovery 调度：cooldown 中的 endpoint 只做 metadata/provenance 状态检查，
不重复发质量 burst；新出现、provenance 变化或 network epoch 变化的 endpoint 才能立即
入队。该周期性 tick 不能通过绕过 cooldown 的方式形成探测风暴。

进入 `DERPActive` 时，先取消或以旧 generation 隔离尚未完成的 direct heartbeat、普通
discovery、PMTU 和 candidate quality 任务，再启动 recovery generation。CLI Ping 保留
自己的回调语义，但不得影响新 generation 的路径状态。

### 7.2 三样本快速准入

收到源一致 direct 候选后，不等待长期 heartbeat 窗口，立即执行一次三轮配对探测。快速
准入必须使用独立于普通 heartbeat 的 `admissionProbeTimeout`，建议按 DERP p95 加裕量
计算并限制在 500--600ms（当前 DERP 约 400ms 时取 500ms）；不能复用 5s 的
`pingTimeoutDuration`，否则丢一个 candidate probe 时无法及时判断 2/3 并重试。

```text
t=0ms    current DERP + candidate direct
t=50ms   current DERP + candidate direct
t=100ms  current DERP + candidate direct
```

两组使用相同时间窗口。一次准入尝试满足以下条件才切换：

1. candidate direct 得到 3/3 个源一致成功 Pong；
2. DERP 得到 3/3 个成功 Pong，或已有不超过 15 秒且至少 3 个样本的新鲜 DERP 基线；
3. 三个成功 RTT 计算出的 direct `effectiveCost <= DERP effectiveCost`；
4. 候选 endpoint 仍有效，generation、Disco key 和网络 epoch 未变化。

快速准入的小样本不把一次丢包直接换算为 33% loss penalty。若 direct 仅得到 2/3 成功，
或 direct 已 3/3 但 DERP 对照样本尚未收齐，本次不切换，但在 200ms 后允许同一候选再
执行一次三轮尝试；每个 candidate、每个 recovery generation 最多两次。direct 只有
0/3 或 1/3 成功时无需立即重试，直接进入 cooldown；direct 成本高于 DERP 时也进入
cooldown。第二次仍不满足完整门槛则进入 30 秒 cooldown。这样既不把不稳定候选直接提升，
也把约 1% 随机丢包造成的额外恢复延迟限制在约 1 秒量级。任一尝试的结果必须在
`admissionProbeTimeout` 内收敛；超时未收齐的结果按该轮失败处理，不得等待普通 5s timer。

以 direct 数十毫秒、DERP 约 400ms 为例，切换通常在约 0.4--0.6 秒内完成，主要由
DERP RTT 和全部配对结果收齐时间决定，而不是等待多个 3 秒 heartbeat；发生一次有界重试
时在单 peer、预算未耗尽且调度抖动不超过 `Δ<=100ms` 的条件下应满足硬上界
`T_recovery <= admissionProbeTimeout + 200ms + admissionProbeTimeout + Δ`；当
`admissionProbeTimeout<=600ms` 时目标为 `T_recovery <= 1.5s`。

切换后用这 3 个 candidate 样本初始化 direct 滚动窗口，后续由正常 heartbeat 扩展到
16 个样本；不需要再用额外 10 样本阻塞首次切换。

## 8. 多 IPv6 与 wrong-source 处理

### 8.1 地址语义

```text
requested = sentPing.to
observed  = 实际 UDP 收包源 src
```

`Pong.Src` 是对端看到的本机源地址，不是对端 endpoint，不能用于选择 remote path。

### 8.2 处理规则

| 条件 | 处理 |
|---|---|
| `observed == requested` | 作为源一致候选，记录该地址自己的 RTT/MTU，进入快速准入。 |
| `observed != requested` 且 observed 有公告来源 | requested 不记成功；向 observed 发一次专用验证 Ping。 |
| `observed != requested` 且 observed 来源不明 | 不提升、不加入数据面候选，只记录诊断。 |

公告来源可由现有状态明确判断：

```text
st.index != indexSentinelDeleted       → 当前 netmap endpoint
de.isCallMeMaybeEP[addr] == true        → 当前 Call-Me-Maybe endpoint 集合
仅 lastGotPing 有值                    → learned-only，不直接提升
```

同一地址可以从 learned-only 升级为 CMM/netmap，但旧状态残留不能反向把 learned-only
误认为公告地址。

### 8.3 专用验证 Ping

wrong-source 发现的 observed 地址使用一个 `size=0`、不触发 PMTU 的专用验证 purpose：

```text
A → B wrong-source
  → 不更新 A 的 recentPongs/latency/wireMTU/trust/bestAddr
  → B 有公告 provenance
  → 向 B 发送一个验证 Ping
  → B → B exact-source Pong
  → B 进入三样本快速准入
```

A→B 的首次 RTT 不能直接记为 B 的质量，也不能参与候选排序。B 必须以目标身份重新
获得源一致样本。

验证 Ping 是异步发送时，不能只依赖发现 wrong-source 时的 provenance 检查。锁内记录
B 的 endpoint generation 后，实际发送前必须重新确认 B 仍在当前 `endpointState` 且来源
仍为 netmap/CMM；generation、Disco key 或 network epoch 已变化则丢弃该任务。发送后即使
endpoint 紧接着被删除，回包也必须通过同一 generation 校验，不能晋升旧候选。

wrong-source 必须按 purpose 分层：

- heartbeat、discovery、recovery 和 candidate quality：立即把 requested A 的本次探针
  记为失败，避免 TxID 已被消费、timer 被移除后 A 的失败状态被掩盖；只有 heartbeat 且
  A 仍是当前 best 时才影响 direct failure streak；
- 所有后台 purpose：不得更新 A 的 `recentPongs`、latency、wireMTU、trust 或 bestAddr；
- CLI Ping：可以完成用户回调并显示诊断信息，但同样不得写入任何路径质量或选路状态。

## 9. 候选调度与资源边界

每个 peer：

```text
最多 1 个活动 DirectProbing
最多 4 个 pending direct 候选
相同完整 AddrPort 去重
```

候选优先级：

1. 源一致且近期成功；
2. wrong-source 后得到的、具有公告 provenance 的 observed；
3. 其他公告但尚未验证的 endpoint。

不能使用 wrong-source RTT 给 observed 排序。活动候选尚无有效样本时，新的源一致候选
可以替换它；否则当前评估完成后再处理队首。

endpoint 删除、Disco key 变化、网络 epoch 变化时，必须清理相关活动评估、pending
候选、定时器和尚未发送的任务。

Conn 级只对质量探针设置资源预算，初始建议：

```text
rate  = 20 quality Ping/s
burst = 40 quality Ping
```

paired round 必须原子预留 current/candidate 两个 token，不能先发一侧再等待另一侧。
调度器不得持有 `Conn.mu` 等待 `endpoint.mu`，锁顺序保持 `Conn.mu → endpoint.mu`；
实际等待和发送在锁外完成，并用 generation 丢弃陈旧任务。

恢复准入任务优先于普通 direct-to-direct quality 任务，但仍受同一 Conn 预算约束；多个
peer 同时等待时采用 round-robin，每个 peer 每轮最多取得一对 token 后重新排队。预算
耗尽时：

- 单 peer、预算未耗尽的恢复准入使用 `admissionProbeTimeout` 和 `T_recovery <= 1.5s`
  上界；
- 多 peer 竞争时记录排队时间，`probeQueueMaxWait` 初始设为 2s；超过该时间的候选
  不发送 burst，保持 DERP 并进入 30s deferred cooldown，等待下一次 discovery；
- 全局 pending 队列上限初始为 256 个 candidate，超过上限丢弃最低优先级且不创建 timer；
- 每个 Conn 只有一个 scheduler goroutine；每个 peer 最多 1 个活动评估、4 个 pending
  candidate。未入活动评估的任务不创建 probe timer。
- 每个活动三轮评估最多 6 个 in-flight probe timer；实现和测试必须给出全局 active
  evaluation/timer/send-task 上限，不能按 candidate 数量无限创建 goroutine。

恢复时延口径定义为：`T_recovery = queue_wait + admission_time`。单 peer 或预算充足时
`queue_wait≈0`，适用 `T_recovery<=1.5s`；并发竞争时只承诺 `queue_wait<=2s`，不再额外
承诺总恢复时间小于 1.5s。超过 queue wait 的任务进入 30s deferred cooldown，禁止立即
重试形成 storm。

例如 20 个 peer 同时各需 6 个 probe token 时，20/s、burst40 的排空时间约为 4s，不能
承诺所有 peer 都在 1.5s 内恢复；1.5s 是单 peer或预算充足场景的上界。并发负载验收
必须同时检查无饥饿、队列上限和超时丢弃行为。

CLI Ping、heartbeat、Call-Me-Maybe 和必要的 NAT 打洞不受质量探针预算限制。

## 10. 重试与 cooldown

后台候选失败后设置 per-endpoint cooldown，避免 DERP 状态下约每 6 秒重复 burst：

```text
wrong-source requested：30s 降权
无 Pong/完全不可达：30s，连续失败退避到最多 2min
质量比 DERP 差：30s 后允许重新比较
```

observed B 不继承 requested A 的 cooldown。以下事件可以清除或绕过：

- endpoint 集合实际变化；
- 本地网络 epoch 变化；
- Disco key 变化；
- 当前 DERP 也失效；
- 候选出现新的源一致、已认证 Pong。

内容相同的重复 Call-Me-Maybe 不解除 cooldown；CLI 诊断也不受 cooldown 限制。因预算
排队超时而进入的 deferred cooldown 固定 30s，不能被普通 discovery tick 立即解除。
进入 `DERPActive` 的首次 force recovery round 可对当前公告 endpoint 绕过 cooldown 一次，
但同一 recovery generation 不得再次绕过。

## 11. 报文频率和大小

质量 Ping 使用 `size=0`，实际是不填充的最小 Disco Ping：

```text
Ping UDP payload：约 124B
Pong UDP payload：约 110B
IPv6 IP 层：约 172B / 158B
```

一次三轮 paired 快速准入共发送 6 个 Ping；发生一次有界重试时最多 12 个，流量仍很小。
日志中的 `pktlen=1360` 是
`pingSizeToPktLen(0)` 返回的安全 WireGuard MTU 记账值，不代表收到 1360B Pong。

Peer MTU Discovery 是独立机制；普通 discovery/CLI 在启用 PMTUD 时可能发送
1280、1360、1400、1500、8000、9000 的填充探针。候选验证和质量探针不得触发这些
大包，也不得把 PMTU 丢包计入路径质量。

## 12. 可观测性

每次状态变化输出一条汇总日志：

```text
peer, old_state, new_state, reason,
current_path, requested, observed, candidate,
failure_streak, samples, success, loss, p50, effective_cost
```

修复 `peer-endpoint-changes` 中 `addrQuality` 序列化为 `{}` 的问题，至少输出地址、路径
类型、延迟和状态变化原因。不要直接 JSON 编码含未导出字段的内部 `addrQuality`；使用
专用 debug DTO 或显式字符串字段。

全局指标保持低基数，不以 IP、端口、主机名或 node key 为标签：

- 状态转换次数及原因；
- exact/wrong-source/timeout/send-error 探针数；
- direct→DERP 和 DERP→direct 时延；
- candidate queue 深度和 cooldown 命中；
- probe scheduler 等待与丢弃；
- 探针字节数。

per-peer 细节只保留在本地 debug 状态和受控日志中。

## 13. 并发与生命周期要求

1. 保持现有锁顺序：`Conn.mu` 后 `endpoint.mu`。
2. token/scheduler 不能在持有任一锁时阻塞等待。
3. 每个评估、验证 Ping 和异步任务携带 generation。
4. endpoint 删除、reset、Disco key 或网络 epoch 变化后，旧 callback、Pong 和 timeout
   只能清理自己的状态，不能改变新路径。
5. `RotateDiscoKey`、`noteBadEndpoint`、`noteConnectivityChange`、`setBestAddrLocked`
   的路径身份变化和 `clearBestAddrLocked` 必须推进 heartbeat generation；必要时调用
   `cancelPathQualityEvaluationLocked`，但不得把强制 recovery discovery 放入通用清理函数。
6. `clearBestAddrLocked` 保持通用清理语义；强制 recovery discovery 只由确认失败的专用
   状态转换触发，避免 reset/网络更新产生探测风暴。

## 14. 实施步骤

### 阶段一：状态与可观测性

1. 引入路径状态、direct 失败连续值和 rolling monitor。
2. 让 `addrForSendLocked`、heartbeat Pong 和 timeout 使用同一状态机。
3. 增加状态转换汇总日志，修复 endpoint change 地址序列化。

### 阶段二：稳定降级与立即恢复

1. 实现 DirectHealthy/DirectSuspect/DERPActive 转换。
2. 实现确认失败后的单次 force full discovery。
3. 实现 heartbeat generation/seq、`lastDirectSuccessAt` 和 1/2/3 streak 发送模式。
4. 验证偶发丢包保持 direct、真实中断有界切 DERP。

### 阶段三：候选验证与快速准入

1. 分离 requested/observed，增加 provenance 判断。
2. 实现 wrong-source observed 的专用单包验证。
3. 实现 3 轮 DERP/direct paired 快速准入和独立 admission timeout。
4. 用候选样本初始化 direct rolling monitor。

### 阶段四：资源与生命周期保护

1. 增加有界候选队列、去重和 cooldown。
2. 增加 Conn 级 probe budget 和 paired 双 token 预留。
3. 补齐 generation、取消、race、budget 上界和网络变化测试。

## 15. 测试矩阵

### 15.1 Direct 稳定性

- direct 50ms、平均 loss 1%，DERP 400ms/0%：持续保持 direct。
- 确定性 1% 模型使用孤立丢包（不得连续三次）验证至少 1000 个 heartbeat；另用 burst-loss
  模型验证连续约 9s 不可达时按设计切换 DERP。
- 单次 heartbeat timeout：进入 suspect，但 `bestAddr`/`CurAddr` 保持 direct。
- 第二次连续有效 timeout：进入有界 direct+DERP 冗余发送，`bestAddr` 保留 direct，
  `CurAddr` 按现有语义为空，debug 状态能与 DERP-only 区分。
- suspect 后收到成功 Pong：恢复 healthy，失败连续值清零。
- 连续 3 次 best heartbeat timeout：切 DERP。
- 最近 10 次至少失败 6 次且 6.5 秒无成功：切 DERP。
- 新 Pong 先于旧 timeout 到达：旧 timeout 不得重新增加 failure streak。
- 旧 timeout 先于对应晚到 Pong：Pong 可恢复 healthy，其他更旧 timeout 不得再次降级。
- CLI/discovery/PMTU timeout：不增加当前 direct 失败连续值。
- 明确 socket/route 不可达：允许快速切 DERP。
- `heartbeatGeneration` 在 RotateDiscoKey、坏 endpoint、网络变化和 reset 后递增；旧
  heartbeat Pong/timeout 不改变新状态。

### 15.2 DERP 恢复

- 切 DERP 后立即发 full discovery，绕过旧 `lastPing` 一次。
- 同一失败事件只能产生一轮 force discovery 和一次 Call-Me-Maybe。
- force discovery 和 candidate quality Ping 均固定为最小包，不展开 PMTU 尺寸。
- candidate admission 使用独立 500--600ms timeout，不使用普通 5s heartbeat timeout。
- direct 50ms、DERP 400ms：candidate 3/3、DERP 3/3 时一次评估内切 direct。
- candidate 2/3：200ms 后只重试一次；第二次 3/3 时切 direct。
- candidate 连续两次未通过：进入 30 秒 cooldown，不继续 burst。
- direct 成本高于 DERP：保持 DERP。
- DERP 基线不足：使用 paired current burst，不等待 3 个 heartbeat 周期。

### 15.3 多 IPv6

- A→A：A 可进入快速准入。
- A→B，B 为 netmap/CMM 地址：A 不记成功，验证 B，最终只选择 B。
- A→B，B 为 learned-only/未公告地址：不提升 B。
- best heartbeat A→B：A 本次记失败，且不会因消费 TxID 而掩盖其 failure streak。
- `bestAddr` 已清空时 A→B：A 不直接 promotion；B 仍需 provenance 检查和 B→B 验证，
  验证成功后才能晋升 B。
- CLI A→B：允许完成诊断回调，但不修改 A/B 的质量、MTU、trust 或 bestAddr。
- wrong-source RTT 不进入 A 或 B 的质量窗口。
- B 验证 Ping 为 124B 最小包，不触发 PMTU 多尺寸探测。
- PMTU 开关关闭或开启时，recovery probe 都保留明确的 candidate/current probe role，
  不因 discovery burst 形状变化而丢失唯一可晋升探针。
- 坏候选 A 不得阻塞有效候选 B。

### 15.4 并发与资源

- endpoint 删除、Disco key 和网络 epoch 变化取消活动与 pending 探针。
- 陈旧 Pong/timeout 不改变新 generation。
- 多 peer 同时 paired probing 不超过全局 budget，且无 peer 饥饿。
- 多 peer 竞争 budget 时按 round-robin 每次取得一对 token。
- 20 个 peer 并发恢复时验证 queueMaxWait、优先级、无饥饿和预算排空行为；不把单 peer
  1.5s SLA 错当成全局 SLA。
- pending candidate 不超过 256、每 peer 不超过 4，且未调度任务不创建 timer/goroutine。
- 活动评估的 in-flight probe、timer 和 send-task 数量不超过 scheduler 配置上限。
- paired current/candidate 在同一小时间窗口发送。
- `go test -race` 不出现 Conn/endpoint/scheduler 锁反转或 timer race。

## 16. 验收标准

1. 使用确定性 1% 丢包模型完成至少 1000 个 heartbeat 决策时，direct 不因离散 timeout
   错误降级 DERP；随机模型作为补充测试。
2. direct 完全失效时，在明确的 scheduler jitter 上限 Δ 下满足
   `T_redundant <= 8s + Δ`、`T_DERP <= 11s + Δ`。
3. 进入 DERP 后立即开始 direct discovery；单 peer 且预算充足时有效候选恢复满足
   `T_recovery <= 1.5s`，预算竞争时满足 `probeQueueMaxWait <= 2s`，超过后保持 DERP
   并放弃本轮 burst。
4. 多 IPv6 wrong-source 场景最终选择源一致的实际地址；direct-only 时 `CurAddr` 显示
   该地址，冗余发送与 DERP-only 由 debug path state 正确区分。
5. 不接受未公告 observed 地址，不混淆 RTT、MTU 和 endpoint 历史归属。
6. PMTU 与路径质量探测互不污染。
7. 每 Conn 一个 scheduler goroutine、全局 pending candidate 不超过 256、每 peer 活动
   评估不超过 1 且 pending 不超过 4；状态、探针、队列和异步任务全部有界并可取消。
8. 定向测试、完整 Magicsock 测试、race、vet 和跨平台构建全部通过。

## 17. 验证命令

```bash
go test ./wgengine/magicsock -run 'Test.*(Path|Disco|Endpoint)' -count=1
go test -race ./wgengine/magicsock -run 'Test.*(Path|Disco|Endpoint)' -count=1
go test ./wgengine/magicsock -count=1
go vet ./wgengine/magicsock
git diff --check
```

## 18. 独立评审结论（2026-07-23，二次收敛）

三方合并审查以目标分支源码为基线，结论为“无 P0，修正后可实施”。本次收敛已将
评审提出的关键问题写入方案：

- DirectProbing 失败回 DERPActive、candidate cooldown，以及 DERPActive 无候选时的
  周期性自驱动 discovery；
- `directFailureStreak == 1/2/3` 的发送模式和 heartbeat generation/seq/
  `lastDirectSuccessAt` 不变量；
- RotateDiscoKey、坏 endpoint、网络变化、reset 和 endpoint 删除的 generation 隔离；
- wrong-source 验证发送前 recheck，以及 bestAddr 已清空时只允许最终晋升 observed B；
- effectiveCost 示例的完整假设和窗口离散失败比的准确表述；
- 独立 500--600ms admission timeout，避免复用 5s heartbeat timeout，保证有界重试可行；
- Conn 预算的 round-robin、队列/计时器/goroutine 上限和预算耗尽行为；
- PMTU 开关下 recovery probe role 保持、mode 转换测试不作为本方案要求。
- 路径身份变化也推进 heartbeat generation；只有当前 best 的 heartbeat Pong 才能清零
  direct failure；queue wait 与 admission time 分开计量并限制 deferred cooldown storm。

方案可进入分阶段实现，但恢复 `1.5s` 上界仅适用于单 peer 或预算充足场景；并发场景
必须遵守 `probeQueueMaxWait` 和有界队列规则，并通过第 15、16 节测试验证。
