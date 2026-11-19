# FINDING-035: spawn_daemon 的 pidfile-alive 去重会命中垂死守护——up 报告成功而终态无守护

- **编号**: 035
- **严重度**: S4
- **攻击面**: R5-1 F-028 修复面回归（stop×up 并发）/ gate.rs spawn_daemon
- **发现时间**: 2026-11-19T10:20:00Z
- **发现者会话**: R5
- **状态**: 待修复

## 复现（必须）

`harness/tools/r5-race-probe/main.rs`（独立 rustc，判定逻辑逐字复制 gate.rs/pidfile.rs，被测守护为真实
release `creance gate-daemon` 子进程）。编译运行：

```sh
rustc --edition 2021 -o /tmp/r5-race-probe harness/tools/r5-race-probe/main.rs
/tmp/r5-race-probe target/release/creance
```

- **期望**: spawn_daemon 返回 Ok ⟹ （刚 spawn 了守护）∨（有一个将继续存活的守护）
- **实际**（确定性复现，非竞态撞运气——rm record 与 spawn_daemon 相隔微秒，守护的死亡 tick 有 ≤500ms 窗口）：
  ```
  r1: spawn_daemon = Ok(())          ← pidfile-alive 去重命中（守护还活着，正走向死亡）
  r1: end state record=false daemons=[]
  VIOLATION: up-reported success with no daemon
  ```
  三组对照全绿：r2 健康去重 → 1 守护+record ✓；r3 全新 spawn → 1 守护+record ✓；
  r4 损坏 record 重生 → retire + 继任者 + 老守护安静退场（disown 生效，继任 record 未被删）✓。

## 根因猜测

`crates/creance-gate/src/gate.rs:722-734` spawn_daemon：`retire_stale_record` 为假（record 已被
close_and_remove 移除）后，`pidfile::alive(gate.pid)` 为真即 `return Ok(())`——但 pid 活着只证明
"进程存在"，不证明"它还会继续服务"。垂死守护（record 被移除后等待下一个 500ms tick 的 NotFound 分支）
恰好两个条件都满足：alive 为真、却注定退场。F-021 的 start-token 防住了 pid 复用，防不住这个时序。

真实 CLI 可达性：`cmd_stop` 先跑 `stop_vm`（慢，秒级）再 `close_and_remove` 移 record，故顺序
stop→up 的窗口窄；但 **stop_vm 失败路径**（record 移除紧随快速的 stop_vm 失败返回）与**并发
stop×up**（up 的 `limactl start` 幂等快路径 + spawn_daemon 落进死亡窗口）可命中。终态自愈：
下一次 up（stale pid 判死 → 全新 spawn）。另有对称风味：stop 的无条件 close_and_remove 可删除
并发 up 刚发布的年轻 record（年轻守护 NotFound 退场）——同根：CLI 层无代际握手。

## 未验证想法

- 年轻 record 被 stop 的 close_and_remove "刺杀"分支未实测（需 up/stop 毫秒级交错编排）。
- gate-daemon.log 里垂死守护的最后状态行可否让 up 事后发现（当前无任何事后核验——up 不做
  spawn 后确认，见 main.rs:600-605）。

## 建议修复方向（供第二天的人参考，非结论）

dedup 命中 pidfile-alive 而 record 缺席时，不要直接 Ok：等 ≤1s 重读 record/进程（垂死守护必退场，
届时走全新 spawn）；或 spawn 后做一次 GateClient 状态确认，失败即回落 tunnel::ensure 并如实告警。
