# FINDING-089: 1c55b30 给 r14/r15 裁判改签名时传入不可写的 `/nonexistent-flag`——guest_script 现在自己落盘，裁判被切到 SKIP 世界：r15 在 main 上 panic（RC=101），r14 仍绿但已不在判它要判的形态

- **编号**: 089
- **严重度**: S5（质量：裁判工具失效；产品运行时不受影响）
- **攻击面**: harness 裁判 / F-084 修复面（guest_script 签名变更波及面）
- **发现时间**: 2026-11-22T13:20Z
- **发现者会话**: r23-auditor（R23 第九次收敛判词轮）
- **状态**: 待修复

## 复现（必须）

```sh
sh harness/tools/r23-judges/run.sh    # 证据 harness/tools/r23-judges/evidence.log + evidence/*.out
```

| 裁判 | RC ×2 | md5 | 与 R22 对比 |
|---|---|---|---|
| main 上 r14-convergence | 0, 0 | ac301449 | R22 为 2ecbd0c1；[A] 期望 id 27→26（fs-flag-readable 只剩 SKIP 一行），[E] 部分致盲用例退化 |
| main 上 r15-064-recheck | **101, 101** | 输出含线程号，md5 每次不同 | panic `锚点缺失：fs-flag PASS 发射行` |
| R23 副本（只把 flag 参数换成可写临时路径） r14 | 0, 0 | 2ecbd0c1 | 与 R22 逐字节一致 |
| R23 副本 r15 | 0, 0 | 965e444c | 与 R22 逐字节一致 |

- **期望**: 任务书称"r14/r15 原工具已在 main 修复签名，直接 cargo run"——裁判应以 R22 同一形态通过。
- **实际**: harness/tools/r14-convergence/src/main.rs:64 与 harness/tools/r15-064-recheck/src/main.rs:63（1c55b30 改写）调用 `guest_script("/nonexistent-flag", …)`。v0.6.14 的 guest_script 内部 `place_oracle_flag` 写该路径，非 root 写 `/` 失败 ⇒ 渲染 SKIP 片段，没有 PASS/ESCAPE 发射行。r15 找不到锚点直接 panic；r14 不 panic，但它的 [A]/[E] 判的是 SKIP 世界，"绿"不再证明 R14/F-064 的原结论。可写路径副本证明产品渲染本身无回归。
- 附带：guest_script 从纯渲染函数变成带文件系统副作用的函数——单测 `guest_script_is_posix` 每次在 /tmp 留下 `creance-test-flag-<pid>`（不立案，记录）。

## 根因猜测

F-084 修复把 oracle 落盘并入 guest_script，裁判调用点只做了编译层面的签名适配，没有跑裁判核对输出（1c55b30 未附裁判输出）。

## 建议修复方向（供第二天的人参考，非结论）

裁判传入可写的临时路径（见 harness/tools/r23-judges/*-r23/src/main.rs `r23_flag`）并在结束时清理；发版规程把"裁判双跑 RC=0 且 md5 与上轮一致"列为门。
