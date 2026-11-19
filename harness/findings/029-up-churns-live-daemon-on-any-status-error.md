# FINDING-029: retire_stale_record 把任何 status 失败当"守护已死"——瞬时不可响应即删活 record、切隧道、更替守护（up 的副作用关 gate）

- **编号**: 029
- **严重度**: S4（可用性/状态机语义；与 F-028 复合时放大为守护累积）
- **攻击面**: night-05 修复面回归（F-019 活性判定），attack-surfaces C3/C5 邻域
- **发现时间**: 2026-11-19T08:45Z
- **发现者会话**: R4 (s01)
- **状态**: 待修复

## 复现（必须）

工具：`harness/tools/f019-backlog/filler.rs`（单进程挂起连接器；本次触发源
是读超时而非 backlog 拒绝——macOS 变体见"未验证想法"）。

```sh
creance up && creance gate-open          # 健康守护 + gate open + 隧道活着
kill -STOP <gate-daemon-pid>             # 冻结 accept loop（守护进程健在）
./filler <record.socket> 200 &           # 占住已排队连接（可选）
creance up                               # 旁观测评：应当 early-return Ok
kill -CONT <gate-daemon-pid>
```

- **期望**: 守护进程健在（哪怕暂时不响应）时，`spawn_daemon` 不得退役
  record/切隧道/另抛守护——"up" 对健康环境必须是纯 no-op。
- **实际**（15:39-15:42 实测）:
  - 冻结期间 `creance up`：`retire_stale_record` 的 `client.status()` 连接
    成功但读超时（5s，gate.rs:851 set_read_timeout）→ Err → `!is_ok()` →
    判 stale → **删除 cage-gate.json + 删 tunnel.pid + `tunnel::stop` 切断
    活隧道 + `reap_orphans` + 另抛新守护**（gate.pid 20839→21207）。
  - `creance up` 输出 "Environment is up"——用户看不到任何异常。
  - gate 从 Open 直接跌落到新守护的 Closed（无 reason、无租期语义，
    纯副作用）→ guest 出网静默中断直到人工重新 gate-open。
  - 老守护 CONT 后仍存活（其 in-memory Open 态的 watchdog 继续与新鲜
    Closed 守护乒乓——F-028 的战争窗口）。
  - 对照：`close_gates`（gate.rs:922）只对错误串含 "unreachable" 的失败
    删 record；`retire_stale_record`（gate.rs:741-754）是 `!is_ok()` 全杀。
    同一文件里两套判定标准，前者保守后者激进。

## 根因猜测

- `crates/creance-gate/src/gate.rs:746-751`：`is_ok()` 把"超时/慢/排队"
  等同于"进程已死"。守护被 SIGSTOP、D 状态、机器重载、accept 线程饥饿
  （每连接 spawn 无上限，F-028 未验证想法 2）超 5s 即触发。
- 触发面比 backlog 更宽：**任何**让 status 在 5s 内不返回的瞬态都可复现；
  且 `up` 是高频日常命令（用户脚本常带重试）。
- 修复面（F-019）引入"socket 不答即删 record"时，删除动作捆绑了
  切隧道+抛新守护的组合拳，把一个活性判定问题放大成状态机突变。

## 未验证想法

1. 真 backlog 溢出变体（macOS）：filler 首版 SOCK_NONBLOCK 直接传给
   socket() 在 macOS 无效（fd 创建即败），fcntl O_NONBLOCK 修正后 200 连接
   在 5s 内全部被健康守护 accept（"queued_or_connected=200"），未观察到
   ECONNREFUSED。需要冻结 record 属主 + 更高并发/慢读占用 accept 线程才能
   打满 128 backlog——预算内未再验证。
2. 连锁：retire 路径的 `tunnel::stop` 切隧道瞬间，若 guest 正在长连接传输
   （代理流量）→ 断流；新守护 Closed 后 wire down——用户视角"网络抽风"。
3. `close_gates` 的 "unreachable" 字符串匹配本身也脆（gate.rs:922）：错误
   文案改动（如本地化、重构）会让 stale record 永不清理或活 record 被删
   ——与 G1 文案耦合教训同源。

## 建议修复方向（供第二天的人参考，非结论）

1. stale 判定加证据等级：connect 层失败（ECONNREFUSED/ENOENT）才可判死；
   超时/读失败只降级（重试 1-2 次、拉长 deadline），绝不触发退役组合拳。
2. 退役与重建解耦：`up` 检测到疑似 stale 时只删 record 不切隧道不抛新
   守护（或先抛新守护成功拿到 record 后，再由旧守护自行退场——交接协议
   而非政变协议）。
3. 统一 retire_stale_record 与 close_gates 的判定标准（同一 helper），
   错误分类用 errno 而非错误文案子串。
