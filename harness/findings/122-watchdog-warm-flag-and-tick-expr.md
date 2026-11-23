# FINDING-122: F-116 钉可绕：`grace` 词禁被改名 `warm` 绕过（每段 down 首 tick 不计，阈值实为 4）；`sleep(Duration::from_millis(500) + Duration::from_millis(300))` 保留 `from_millis(500)` 计数而周期变 800ms，全绿

- **编号**: 122
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: F-116 修复面（crates/creance-gate/src/gate.rs watchdog 源钉）
- **发现者会话**: r31-auditor
- **状态**: 待修复

## 机理

`grace` 是单词禁，任何其他名字的 warmup 标志不受限；新增的 `warm` 不改变 `core_down_ticks` 裸名计数（仍 5），递增写成 `core_down_ticks += 1 - u32::from(std::mem::take(&mut warm));` 后 `core_down_ticks += 1` 子串计数也不变。`from_millis(500)`==2 只数字面，表达式 `from_millis(500) + from_millis(300)` 保留计数但改语义；熔断时间 3×800=2.4s 仍在行为测试 1.3s–3.0s 窗内。

## 复现

```sh
git worktree add --detach $HOME/r31-wt v0.6.23   # worktree 放 $HOME，勿放 /tmp
cd harness/tools/r31-negative-controls
CREANCE_REPO=$HOME/r31-wt ONLY="NC-WDwarm NC-WDsleep2" python3 run.py   # 用例见 cases.py
```

期望：每个用例至少一项测试或 clippy 红。实际（fmt+cargo test --workspace --locked+clippy -D warnings；裁判双跑，见 logs/ 与 logs-ref/；md5 还原 OK）：

| 用例 | 注入 | 测试 | 后果 |
|---|---|---|---|
| NC-WDwarm | 新增 `let mut warm = true;`，复位处 `warm = true;`，递增 `+= 1 - u32::from(std::mem::take(&mut warm))` | 绿×2 | 每段故障第一 tick 不计，熔断推迟 500ms |
| NC-WDsleep2 | `sleep(Duration::from_millis(500))` → `sleep(Duration::from_millis(500) + Duration::from_millis(300))` | 绿×2 | 采样周期 800ms，熔断 2.4s |

## 建议

sleep 行与递增行整行 verbatim 钉（`core_down_ticks += 1;` 含分号）并禁 watchdog 循环内新增 `let mut`；行为测试收紧熔断窗到 [1.5s, 1.8s] 附近，或用注入时钟按 tick 精确断言第 3 个 down tick 熔断。
