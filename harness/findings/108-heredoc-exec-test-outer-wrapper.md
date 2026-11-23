# FINDING-108: F-098 执行测试从 cat 行起切段：cat 行前 `if false; then`（fi 放段后）、外层 `: <<'SKIPRULES'` 吞整段全绿——rules.v4 从不写入；CHANGELOG "`if false` wrapping breaks the syntax" 被证伪

- **编号**: 108
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: F-098 修复面（provision.rs heredoc 执行测试）
- **发现者会话**: r29-auditor
- **状态**: 待修复

## 机理

`seg_start` 取 cat 行起点、`seg_end` 取终止行后一行之末；段外的包裹结构（条件、外层 heredoc）不进入 `sh -ec`，段内语法完整故 RC=0、写出文件内容正确。这与 R28 F-098 记录的 `if false` 包裹同族，修复只覆盖了“包裹跨越段内”的形状。

## 复现

```sh
CREANCE_REPO=$HOME/r29-wt ONLY="NC-HDiffalse NC-HDnull" python3 harness/tools/r29-negative-controls/run.py   # worktree 放 $HOME；用例定义见 harness/tools/r29-negative-controls/cases.py
```

| 用例 | 注入 | 测试（cargo test --workspace + clippy -D warnings；裁判双跑） | 后果 |
|---|---|---|---|
| NC-HDiffalse | cat 行前插 `if false; then`，终止行后一行（注释）之后插 `fi` | 绿×2 | bootstrap 跳过 rules.v4 写入；egress-lock.service 开机 restore 无文件 |
| NC-HDnull | cat 行前插 `: <<'SKIPRULES'`，同位置插 `SKIPRULES` | 绿×2 | 整段成为 `:` 的数据，从不执行 |

对照（红）：NC-HDws2（段后第二行插 `  EGRESSRULES`，EGRESSRULES 行数 3 红）。后果为 fail-closed（up 探针 fw-armed 判失败），故 S5。

## 建议

执行整个渲染后的 bootstrap（路径重定向到临时根、外部命令以 PATH 桩替代），断言 rules.v4 写出；或断言 cat 行之前的 bootstrap 前缀在 sh 下为“顶层”（`sh -n` 前缀+`exit 0` 不留未闭合结构）。
