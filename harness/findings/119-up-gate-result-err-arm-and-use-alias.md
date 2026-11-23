# FINDING-119: F-113 钉可绕：守卫臂拼成 `Result::Err(e) if …`（trim 行不以 `Err(` 开头，真实臂仍是“首个 Err(”）；lib.rs 经 `use creance_vm::qemu::instance_dir as idir;` 别名+`concat!("provision","ed")` 直写 marker 全绿

- **编号**: 119
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: F-113 修复面（crates/creance/src/main.rs `up_gate_tests`）
- **发现者会话**: r31-auditor
- **状态**: 已修复（main-session，实机复验）

## 机理

Err 首行钉以 `starts_with("Err(")` 识别臂，路径限定 `Result::Err(`、`std::result::Result::Err(` 都不被识别，守卫臂可放在真实臂之前吞掉拒绝；crate 扫描只禁 `"provisioned"` 字面与非 gate 前缀的 `instance_dir(` 调用文本，`use … as idir` 别名后调用 `idir(` 与 `concat!` 拆分字面量均不命中。

## 复现

```sh
git worktree add --detach $HOME/r31-wt v0.6.23   # worktree 放 $HOME，勿放 /tmp
cd harness/tools/r31-negative-controls
CREANCE_REPO=$HOME/r31-wt ONLY="NC-UPguard2 NC-MAINxfile2" python3 run.py   # 用例见 cases.py
```

期望：每个用例至少一项测试或 clippy 红。实际（fmt+cargo test --workspace --locked+clippy -D warnings；裁判双跑，见 logs/ 与 logs-ref/；md5 还原 OK）：

| 用例 | 注入 | 测试 | 后果 |
|---|---|---|---|
| NC-UPguard2 | Ok 臂后插 `Result::Err(e) if !e.is_empty() => eprintln!("{e}"),` | 绿×2 | 所有非空拒绝只打印，up 继续成功 |
| NC-MAINxfile2 | lib.rs `use … instance_dir as idir;` + `arm_marker()` 写 `concat!("provision","ed")`；main.rs `Result::Err(e) if creance::arm_marker(…) => return fail(e),` | 绿×2 | 拒绝路径反而写 marker（下次 up 起 restrict=on 却未验证） |

## 建议

以 match 臂 AST 粒度（或至少在 trim 行上剥掉 `Result::`/`std::result::Result::` 前缀）识别 Err 臂，并要求窗内 match 仅两臂；crate 扫描禁 `instance_dir` 标识符本身（含 `as` 别名）与 `provision` 子串，而非完整调用文本。
