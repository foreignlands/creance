# FINDING-120: F-114 跨度/早退钉可绕：span 解析器 trim 后比较终止行，` SKIPRULES`（前导空格）对测试是终止、对 dash 不是；`exec true`、`true && exit 0`、`false`（脚本自身 set -e）均在 rules.v4 前终止脚本且全绿

- **编号**: 120
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: F-114 修复面（crates/creance-vm/src/provision.rs heredoc 跨度映射 + 行首动词禁）
- **发现者会话**: r31-auditor
- **状态**: 已修复（main-session，实机复验）

## 机理

跨度映射寻找 `x.trim() == tag` 的终止行；POSIX `<<` 只认与 tag 完全相同的行（`<<-` 只剥 tab），因此 `: <<'SKIPRULES'` + ` SKIPRULES` 在测试看来已闭合，dash 则吞到 EOF（dash 接受 EOF 终止）。早退禁只列行首 `exit`/`return`，漏 `exec`、`&& exit`、以及 set -e 下任一失败命令（`false`）。语义已用 harness/tools/r31-shell-semantics/check.sh 在 dash/bash 下实测：四种注入均 NOT-REACHED，对照 REACHED。

## 复现

```sh
git worktree add --detach $HOME/r31-wt v0.6.23   # worktree 放 $HOME，勿放 /tmp
cd harness/tools/r31-negative-controls
CREANCE_REPO=$HOME/r31-wt ONLY="NC-HDindent NC-HDexec NC-HDandexit NC-HDfalse" python3 run.py   # 用例见 cases.py
```

期望：每个用例至少一项测试或 clippy 红。实际（fmt+cargo test --workspace --locked+clippy -D warnings；裁判双跑，见 logs/ 与 logs-ref/；md5 还原 OK）：

| 用例 | 注入 | 测试 | 后果 |
|---|---|---|---|
| NC-HDindent | rules heredoc 前插 `: <<'SKIPRULES'\n SKIPRULES` | 绿×2 | rules.v4/unit/enable 全被吞，不执行 |
| NC-HDexec | rules heredoc 前插 `exec true` | 绿×2 | shell 被替换，后续不执行 |
| NC-HDandexit | rules heredoc 前插 `true && exit 0` | 绿×2 | exit 0 早退 |
| NC-HDfalse | rules heredoc 前插 `false` | 绿×2 | set -e 以 RC=1 中止，rules.v4/unit 不写（测试不感知；是否 fail-closed 取决于调用方） |

## 建议

终止行改为不 trim 的精确相等（`<<-` 仅剥前导 tab）；不靠动词黑名单，改为对渲染脚本用 dash 在 stub 根下真实执行并断言 rules.v4/unit 文件被写出、systemctl stub 收到 enable/restart。
