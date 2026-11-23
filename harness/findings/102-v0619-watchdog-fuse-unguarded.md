# FINDING-102: v0.6.19 常驻巡检熔断的 6 项语义不被测试守住——阈值放宽到 8、非 Open 态计数、连接超时 30s、计数不复位（两处）、closed 分支不切 wire 全绿

- **编号**: 102
- **严重度**: S5（质量：CHANGELOG [0.6.19] "core unreachable 3 ticks -> gate closes, wire cut <=2s" 只有“死端口 5s 内关闸 + 活端口不关闸”一个测试）
- **攻击面**: v0.6.19 watchdog（crates/creance-gate/src/gate.rs :333-392，测试 :1802 `watchdog_fuses_open_gate_when_core_unreachable`）
- **发现者会话**: r28-auditor（首切）
- **状态**: 已修复（main-session，实机复验）

## 复现

```sh
CARGO_TARGET_DIR=$HOME/r28-wt-target CREANCE_REPO=$HOME/r28-wt ONLY="NC-WDthr8 NC-WDthr20 NC-WDany NC-WDto NC-WDnoreset NC-WDfusereset NC-WDnocut NC-WDreason" sh harness/tools/r28-negative-controls/run.sh
```

| 用例 | 注入 | 测试 | 落空的宣称 |
|---|---|---|---|
| NC-WDthr8 | `core_down_ticks >= 3` → `>= 8` | **绿**（13p） | “3 tick 熔断”：测试 deadline 5s，阈值 ≤9 都能过（≈4.5s） |
| NC-WDthr20 | `>= 20` | 红 | — |
| NC-WDany | `let core_up = !open \|\| connect..` → `let core_up = connect..` | **绿** | Checking 窗口豁免无测试（Checking 态下核心未起即被熔断） |
| NC-WDto | `connect_timeout` 250ms → 30_000ms | **绿** | 测试用 refused 端口（立即失败），超时值不受测；黑洞/挂起的 loopback 连接会让巡检线程每 tick 阻塞 30s，熔断与租期关闸、wire 切断全部推迟 |
| NC-WDnoreset | 成功分支 `core_down_ticks = 0` 删除 | **绿** | 间歇失败累加 → 误熔断 |
| NC-WDfusereset | 熔断后 `core_down_ticks = 0` 删除 | **绿** | 重开后首次失败即熔断 |
| NC-WDnocut | closed 分支删 `tunnel::stop(&profile_dir)`（保留 reap_orphans） | **绿** | “closed 下一 tick 切断 wire”无测试；`reap_orphans` 跳过 pidfile 自有 pid（tunnel.rs:91），自有隧道留存 → 闸已 Closed 但 wire 仍通（fail-open） |
| NC-WDreason | 原因文案 `自动熔断`→`自动关闭` | 红 | — |

当前产品代码本身经阅读未见错误（Open-only 计数、`>=3`、成功复位、熔断复位、closed 分支 stop+reap 均在），本条为守护缺口。

## 建议

测试补：Checking 态死端口不关闸；熔断时刻上界（≤2s）断言；成功 tick 复位；closed 后 tunnel pidfile 被清/进程被杀；以不 accept 的 backlog 满 listener 或 SYN 黑洞模拟挂起连接，断言单 tick 耗时上界。
