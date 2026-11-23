# FINDING-113: F-107 钉可绕：600 字节窗内把 `Err(e) => return fail(e),` 写进注释或放在守卫臂之后，真实 Err 臂吞拒绝；marker 可经 creance lib.rs 直接写（"provisioned" 字面禁只扫 main.rs）

- **编号**: 113
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: F-107 修复面（crates/creance/src/main.rs:842-876, 281）
- **发现者会话**: r30-auditor
- **状态**: 待修复

## 机理

Err 臂钉是 `arm_region.contains("Err(e) => return fail(e),")`——子串在注释里、或作为某条更早的 `Err(e) if … =>` 守卫臂之后的不可达臂都满足。CHANGELOG/任务书称 creance crate 禁 `"provisioned"` 字面+`instance_dir(&profile`，但测试 `src` 只取 `include_str!("main.rs")`；crate-wide 遍历只数 `mark_provisioned`。lib.rs 可用 `creance_vm::qemu::instance_dir`（pub）+ `paths::join` + `std::fs::write` 直接写 marker。

## 复现

```sh
CREANCE_REPO=$HOME/r30-wt ONLY="NC-UPerr2 NC-UPguard NC-MAINxfile" python3 harness/tools/r30-negative-controls/run.py   # worktree 放 $HOME（git worktree add --detach $HOME/r30-wt v0.6.22）；用例见 harness/tools/r30-negative-controls/cases.py
```

期望：每个用例至少一项测试或 clippy 红。实际：

| 用例 | 注入 | 测试（fmt+cargo test --workspace+clippy -D warnings；裁判双跑） | 后果 |
|---|---|---|---|
| NC-UPerr2 | Err 臂 → `// Err(e) => return fail(e),` + `Err(e) => eprintln!("{e}"),` | 绿×2 | 拒绝被吞，打印 "Environment is up." |
| NC-UPguard | 在钉住的臂前插 `Err(e) if !e.is_empty() => eprintln!("{e}"),` | 绿×2 | 同上（拒绝串恒非空） |
| NC-MAINxfile | lib.rs 加 `pub fn arm_marker` 写 `instance_dir(profile, instance)/provisioned`；main.rs 插 `Err(e) if creance::arm_marker(&profile, &instance) => return fail(e),` | 绿×2 | 拒绝时自写 marker——下次 up 以 restrict=on 运行但防火墙未验证 |

## 已尝试未通的路（对照红）

已拒：main.rs 内 split-literal + `instance_dir(profile.as_str()` 自写（NC-MAINfs2 红，3 测试失败）。600 字节窗：实际钉臂在调用点后约 150 字节，插长注释撑爆窗会红（fail-closed），非绕过。

## 建议

钉 `match` 恰有两臂且 Err 臂整行相等、窗内去注释后比较；`"provisioned"`/`instance_dir(` 禁扩到 creance crate 全部 prod 文件（复用已有的递归遍历）。
