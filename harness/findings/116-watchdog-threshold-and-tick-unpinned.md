# FINDING-116: F-110 钉可绕：保留全部 verbatim 行但用 `grace` 让每条 down 流的首 tick 不计（阈值实为 4/2.0s），或采样周期 500→800ms（熔断 2.4s）均落在 1.3s–3.0s 测试窗内全绿

- **编号**: 116
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: F-110 修复面（crates/creance-gate/src/gate.rs:333-360, 1802-1880, 1982+）
- **发现者会话**: r30-auditor
- **状态**: 待修复

## 机理

源码钉锁 `from_millis(250),`、阈值行 trim 相等、`let mut core_down_ticks`==1、`core_down_ticks = 0;`==2，但不锁采样周期 `from_millis(500)` 与 `+= 1` 的增量；行为测试窗 [1.3s, 3.0s] 宽到可容纳阈值 4 或周期 800ms。

## 复现

```sh
CREANCE_REPO=$HOME/r30-wt ONLY="NC-WDgrace NC-WDsleep" python3 harness/tools/r30-negative-controls/run.py   # worktree 放 $HOME（git worktree add --detach $HOME/r30-wt v0.6.22）；用例见 harness/tools/r30-negative-controls/cases.py
```

期望：每个用例至少一项测试或 clippy 红。实际：

| 用例 | 注入 | 测试（fmt+cargo test --workspace+clippy -D warnings；裁判双跑） | 后果 |
|---|---|---|---|
| NC-WDgrace | 加 `let mut grace = true;`，恢复时 `grace = true;`，`core_down_ticks += 1 - u32::from(std::mem::take(&mut grace));` | 绿×2 | 熔断延迟 +500ms/次（3→4 tick），代理死期间 Open 闸多放行 0.5s |
| NC-WDsleep | 采样 `from_millis(500)` → `from_millis(800)` | 绿×2 | 熔断 1.5s→2.4s |

## 已尝试未通的路（对照红）

已拒：r29 阈值/超时/遮蔽/截断（NC-WDshS/WDshF/WDto/WDthr10/WDthr4c/WDopenC/WDcutdead 红）；`if 3 <= core_down_ticks` 逆写被阈值行 trim 相等拦（该行必须存在且为 1）。下界 1.3s 稳定性：负载 3.5 下 15/15 通过（harness/tools/r30-watchdog-jitter/result.txt）。

## 建议

钉 `std::thread::sleep(Duration::from_millis(500));` 与 `core_down_ticks += 1;` 整行；行为测试上界收紧到 ~2.2s 并用多次采样中位数。
