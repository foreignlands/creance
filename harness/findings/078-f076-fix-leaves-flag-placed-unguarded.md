# FINDING-078: F-076 修复漏一例——main.rs 的 flag_placed 恒真（NC-F）在 v0.6.12 下仍 cargo test 全绿

- **编号**: 078
- **严重度**: S5（质量：当前行为正确；F-076 点名的五例注入只守住四例）
- **攻击面**: E2 / F-074+F-076 修复面
- **发现时间**: 2026-11-22T07:40Z
- **发现者会话**: r21-auditor（R21 第七次收敛判词轮）
- **状态**: 已修复（main-session，实机复验）

## 复现（必须）

```sh
sh harness/tools/r21-negative-controls/run.sh   # 证据：harness/tools/r21-negative-controls/evidence.log
```

v0.6.12（daece7f）实测，与 F-076 同一注入式（r20 原 perl 表达式逐字复用）：

```
NC-F:    inject-grep-c=1 crates=creance test-RC=0 failed=0     # main.rs:360 flag_placed = true
NC-R/R2/073q/073l/074/074b/074c/RO: test-RC=101（均变红，F-076 其余四例与本轮新增变体已被守住）
```

- **期望**: F-076 立案的五例注入在修复后全部变红（F-076「建议修复方向」原文：main.rs 的 flag_placed 计算可抽成小函数以便测）。
- **实际**: 23b0da2 只在 escape.rs 加了 `guest_script(_, false, ..)` 的单判词断言；main.rs:360 `let flag_placed = std::fs::write(&flag, ..).is_ok();` 仍是 cmd 函数里的内联表达式，无任何测试经过它。改成 `true` 后，旗标落盘失败时 guest 会对一个不存在的旗标跑 `[ -f "$FLAG" ]` → 空真 PASS（F-068 原形态），CI 无感。

## 根因猜测

crates/creance/src/main.rs:355-366：oracle 是否就位的判定与 escape-test 的 I/O 编排写在一起，不可单测；F-076 的守护只落在 guest_script 的参数层（escape.rs:769-782），不覆盖"调用方是否把真实落盘结果传进去"。

## 未验证想法

- 无。

## 建议修复方向（供第二天的人参考，非结论）

把"放旗标并返回是否就位"抽成 `escape::place_oracle(path) -> bool`（或返回 Result），main.rs 只调用它；单测分别造可写/不可写（只读目录或父目录不存在）路径，断言返回值，并断言不可写时渲染出的脚本只含 1 行 SKIP。
