# FINDING-107: main.rs `match verify_and_mark … Ok(wrote)` 新形状未钉：`Err(e) => eprintln!` 吞拒绝、Err 臂内 `std::fs::write(instance_dir/provisioned)` 自写 marker 全绿

- **编号**: 107
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: v0.6.21 main.rs up-gate（`cmd_up`）
- **发现者会话**: r29-auditor
- **状态**: 已修复（main-session，实机复验）：调用点 600 字节窗内钉 `Err(e) => return fail(e),`；main.rs 禁 `"provisioned"` 字面与 `instance_dir(&profile`

## 机理

up-gate 源码钉只数 `verify_and_mark(`==1 与 `mark_provisioned`==0；不钉 `Err(e) => return fail(e)` 的拒绝语义，也不禁 main.rs 直接写 `provisioned` 文件。

## 复现

```sh
CREANCE_REPO=$HOME/r29-wt ONLY="NC-UPerr NC-MAINfs" python3 harness/tools/r29-negative-controls/run.py   # worktree 放 $HOME；用例定义见 harness/tools/r29-negative-controls/cases.py
```

| 用例 | 注入 | 测试（cargo test --workspace + clippy -D warnings；裁判双跑） | 后果 |
|---|---|---|---|
| NC-UPerr | `Err(e) => return fail(e),` → `Err(e) => eprintln!("{e}"),` | 绿×2 | 防火墙验证失败（VM 已被 stop）后 up 仍 RC=0 并打印 "Environment is up" |
| NC-MAINfs | Err 臂内 `std::fs::write(paths::join(&qemu::instance_dir(&profile,&instance), "provisioned"), b"ok\n")` 再 fail | 绿×2 | 绕开令牌直接武装 marker |

## 建议

源码钉加 `Err(e) => return fail(e)` 字面与 main.rs prod 区禁 `"provisioned"`/`instance_dir(`；或行为测试以假 runner 驱动 cmd_up 失败路径断言 RC≠0。
