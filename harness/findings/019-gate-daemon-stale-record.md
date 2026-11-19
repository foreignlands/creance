# FINDING-019: gate-daemon 被 SIGKILL 后 record 残留 — 后续一切 `creance up` 被 spawn_daemon 短路（无 daemon/无 watchdog/fallback 不触发），孤儿 ssh -R 持续供网使 gate-close 无对象（wire 无法关闭，违反 closed=wire down 契约），escape gate 探针假 PASS 掩盖失效

- **编号**: 019
- **严重度**: S4（异常场景下 gate 安全控制失效 + 可用性静默失败 + 探针假 PASS 掩盖；触发需 daemon 非正常终止——OOM/宿主重启/误杀；fail-open 边缘使其接近 S2/S3）
- **攻击面**: R3 → 0.4 gate-daemon（2df07a6）+ C3/C4
- **发现时间**: 2026-11-19T06:50:00Z
- **发现者会话**: r3-s01
- **状态**: 待修复

## 复现（必须）

实测环境：`/tmp/p1` profile 的运行实例。

```sh
pgrep -f gate-daemon            # 92379（daemon 活着）
kill -9 92379                   # SIGKILL：Drop 不执行
sleep 1; pgrep -f gate-daemon   # 0 —— daemon 死
ls /tmp/p1/state/lima/*/cage-gate.json
# record STILL EXISTS           ← GateHandle::drop 未跑，record 残留（gate.rs:197-203 是唯一删除点）

creance up
# Environment is up. …          ← 成功输出，无任何警告
pgrep -f gate-daemon            # 0 —— spawn_daemon 被 record 存在短路（gate.rs:681-683 return Ok(())）
                                #    fallback tunnel::ensure 也不触发（只在 spawn_daemon Err 时跑）
ps aux | grep "[s]sh.*-R"       # ≥1 —— daemon 死前 watchdog 起的孤儿 ssh 仍持隧道
creance escape-test
# ✅ gate-record-private  [gate]   ← 假 PASS：record 文件在，其后没有 daemon/状态机/watchdog
# contained …
```

- **期望**: `spawn_daemon` 在 record 存在时验证其后的 daemon **活性**（如 `GateClient::status()` 经 socket 成功）；socket 不可达即视为 stale record，删除并重新 spawn。`creance stop`/`gate-close` 在 socket 不可达时应**直接删除 record**（file-only 恢复路径）。
- **实际**: record 存在即无条件 `Ok(())`（gate.rs:681）；`close_gates` 只经 `GateClient`（socket）通信，socket 无人听时失败——**无任何 file-only 恢复路径**；escape 的 gate 探针只检查 `cage-gate.json` 是否存在（escape.rs），record 残留=探针绿。

## 危害链（三层叠加）

1. **fail-open**：daemon 死前 gate 为 Open 时，孤儿 `ssh -R` 继续供网；此后 `creance gate-close` → GateClient socket 不可达 → 关闭失败 → **wire 永久开、无法关**——违反 gate 的核心契约 "Closed = wire down"（gate.rs watchdog 注释自述）。
2. **静默失效**：daemon 死前 gate 为 Closed 时，隧道由孤儿续供与否不定（ssh 存活则供网、死亡则 guest 全断）——两种形态下 gate 状态机都不存在，审计/租期/检查全部失效。
3. **假 PASS 掩盖**：escape-test 的 gate-record-private 与 up 的成功输出都指向"一切正常"。

## 根因猜测

`crates/creance-gate/src/gate.rs:681`（spawn_daemon 的 record 去重）与 `gate.rs:197-203`（唯一 record 删除点在 GateHandle::drop）。record 被当作"活 daemon 的证明"，但它只证明"曾经有 daemon"。配合 `cmd_up`（main.rs）的 fallback 条件（仅 spawn_daemon 返回 Err），三处共同构成静默失效链。系统重启是必然触发场景（record 持久化在磁盘、daemon 进程不持久）。

## 未验证想法

- GateClient::status 对死 socket 的失败时延（unix socket connect ENOENT 立即失败——活性检查成本可忽略）。
- 多实例场景（多个 profile 各自 daemon）的 record 交叉（close_gates 遍历 lima home 全实例——只影响本 profile）。
- daemon 正常退出路径本身也不存在（run_daemon 只在 record 消失后 break，而删除 record 的只有它自己的 Drop——**循环依赖**，daemon 实际"服务到进程死亡"为止，与 cmd_stop 注释 "removes cage-gate.json → daemon retires" 的声明不符）。

## 建议修复方向（供第二天的人参考，非结论）

1. `spawn_daemon`：record 存在时先 `GateClient::open + status()`；失败 → `remove_file(record)` → 继续正常 spawn。
2. `close_gates`/`cmd_stop`：socket 不可达时 fallback `remove_file(cage-gate.json)`（file-only 退役路径）。
3. escape gate 探针：record 存在 + socket status 失败 → **Escaped**（"gate record without a live daemon"）。
4. `run_daemon` 补充退出条件：VM 实例消失（limactl list 无该实例）时自退役。
