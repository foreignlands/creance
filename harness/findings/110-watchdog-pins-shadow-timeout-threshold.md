# FINDING-110: F-102 源码钉可绕：两处 `core_down_ticks = 0;` 改 `let _core_down_ticks = 0;`（子串仍匹配）、`from_millis(250).max(30s)`、`>= 3 && is_multiple_of(4)` 阈值放宽全绿

- **编号**: 110
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: F-102 修复面（crates/creance-gate/src/gate.rs watchdog）
- **发现者会话**: r29-auditor
- **状态**: 待修复

## 机理

钉为子串计数：`let _core_down_ticks = 0;` 含 `core_down_ticks = 0;`；`250` 与 `>= 3` 字面保留即可改变语义。行为测试 ≤2.5s 熔断只界定上限，阈值放宽到 4 tick（2.0s）仍在界内；复位缺失只在“探测时好时坏”的序列下可观测，现无此测试。

## 复现

```sh
CREANCE_REPO=$HOME/r29-wt ONLY="NC-WDshS NC-WDshF NC-WDto NC-WDthr4c" python3 harness/tools/r29-negative-controls/run.py   # worktree 放 $HOME；用例定义见 harness/tools/r29-negative-controls/cases.py
```

| 用例 | 注入 | 测试（cargo test --workspace + clippy -D warnings；裁判双跑） | 后果 |
|---|---|---|---|
| NC-WDshS | 成功分支 `core_down_ticks = 0;` → `let _core_down_ticks = 0;` | 绿×2 | 偶发失败累计，健康核心下也会误熔断 |
| NC-WDshF | 熔断后 `core_down_ticks = 0;` → `let _core_down_ticks = 0;` | 绿×2 | 重开后首个失败 tick 立即再熔断 |
| NC-WDto | `Duration::from_millis(250),` → `Duration::from_millis(250).max(Duration::from_secs(30)),` | 绿×2 | 单次探测可阻塞 30s，熔断延迟到 90s+ |
| NC-WDthr4c | `if core_down_ticks >= 3 {` → `if core_down_ticks >= 3 && core_down_ticks.is_multiple_of(4) {` | 绿×2 | 阈值 4 tick |

对照（红）：NC-WDopenC（Checking 计数）、NC-WDcutdead（closed 分支 tunnel::stop 变死码）、NC-WDthr10（阈值 10 tick=5s）。`rfind("\n#[cfg(test)]")`：gate.rs/gateprobe.rs/provision.rs 现均仅一个行首 test mod 且位于文件尾（gate.rs 1162–2040），当前切片正确。

## 建议

复位钉改为行首锚定 `^\s*core_down_ticks = 0;$` 且禁 `let _core_down_ticks`；超时钉断言整行 `Duration::from_millis(250),\n` 紧随 `connect_timeout(` 实参；行为测试加“核心 2 tick 断 1 tick 通”循环断言不熔断，以及阈值下界（< 1.5s 不熔断）。
