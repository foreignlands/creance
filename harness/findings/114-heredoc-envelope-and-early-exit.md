# FINDING-114: F-108 `sh -n` 校验仍可绕：外层 `: <<'SKIPRULES'` 无终止 heredoc 被 dash 接受（EOF 终止），`exit 0` 前置早退亦全绿——rules.v4/unit/锁闭全不执行

- **编号**: 114
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: F-108 修复面（crates/creance-vm/src/provision.rs:390-430）
- **发现者会话**: r30-auditor
- **状态**: 待修复

## 机理

dash/POSIX sh 允许 heredoc 在 EOF 终止（仅警告），所以 `{prefix}\nexit 0\n` 与整脚本都过 `sh -n`；切片执行段从 `cat > /etc/iptables/rules.v4` 起，段外包裹/早退不进入执行段。`sh -n` 只是语法检查，不能证明语义上执行到了 cat 行。

## 复现

```sh
CREANCE_REPO=$HOME/r30-wt ONLY="NC-HDnull2 NC-HDexit" python3 harness/tools/r30-negative-controls/run.py   # worktree 放 $HOME（git worktree add --detach $HOME/r30-wt v0.6.22）；用例见 harness/tools/r30-negative-controls/cases.py
```

期望：每个用例至少一项测试或 clippy 红。实际：

| 用例 | 注入 | 测试（fmt+cargo test --workspace+clippy -D warnings；裁判双跑） | 后果 |
|---|---|---|---|
| NC-HDnull2 | 在 `cat > /etc/iptables/rules.v4` 前插 `: <<'SKIPRULES'`，在其后插 `SKIPRULES`（r29 NC-HDnull 复跑） | 绿×2 | rules.v4 heredoc 及后续都成为 `:` 的数据 |
| NC-HDexit | 在 `cat > /etc/iptables/rules.v4` 前插 `exit 0` | 绿×2 | bootstrap 在写规则前退出，guest 无防火墙 |

## 已尝试未通的路（对照红）

已拒：`if false; then` 包裹（NC-HDiffalse 红）；前缀内未闭合引号会让 `sh -n` 报错（手验）。

## 建议

执行整份渲染脚本（以 chroot 化/替换 systemctl,iptables-restore 等的 stub PATH），断言 rules.v4/unit/stamp 落盘；或钉前缀不含 `exit`、`<<` 计数==固定值。
