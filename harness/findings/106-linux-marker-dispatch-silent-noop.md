# FINDING-106: Linux marker 分发可静默变 noop：vm.rs cfg `macos`↔`linux` 对调、qemu `instance_dir(instance, profile)` 实参对调全绿——restrict=on 第二道防线永不武装

- **编号**: 106
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: F-099 修复面（vm.rs `mark_provisioned` dispatch；qemu/mod.rs 后端）
- **发现者会话**: r29-auditor
- **状态**: 待修复

## 机理

dispatch/后端体守护只禁 `cfg!`、`#[cfg`（在 write_marker 体内）、`.contains(`；dispatch 函数本身的 `#[cfg(target_os = "macos")]` 臂与 `not(...)` 臂互换不触发任何钉；qemu 后端行为测试直接测 `write_marker(dir)`，不经 `mark_provisioned(profile, instance, ..)` 的路径拼装。仅实机 up2 `-netdev … restrict=on` 能发现（本轮 FRESH 腿实测正常）。

## 复现

```sh
CREANCE_REPO=$HOME/r29-wt ONLY="NC-VMcfgswap NC-QMswap" python3 harness/tools/r29-negative-controls/run.py   # worktree 放 $HOME；用例定义见 harness/tools/r29-negative-controls/cases.py
```

| 用例 | 注入 | 测试（cargo test --workspace + clippy -D warnings；裁判双跑） | 后果 |
|---|---|---|---|
| NC-VMcfgswap | vm.rs dispatch 两处 `"macos"` → `"linux"` | 绿×2 | Linux 上 mark_provisioned 恒 false，up 打印成功但从不写 marker |
| NC-QMswap | qemu `write_marker(&instance_dir(profile, instance))` → `instance_dir(instance, profile)` | 绿×2 | marker 写进错误目录（或失败），restrict=on 永不生效 |

## 建议

加行为测试：HOME 指向临时目录，调 `vm::mark_provisioned(profile, instance, &token)`（测试内经 egress_verdict 取令牌）后断言 `qemu::instance_dir(profile, instance)/provisioned` 存在且下次 up 的 netdev 含 `restrict=on`。
