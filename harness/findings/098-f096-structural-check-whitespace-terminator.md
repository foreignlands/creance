# FINDING-098: F-096 结构校验只数“裸” `EGRESSRULES` 行——前导/尾随空白的多余终止行、`if false` 包裹均让 bootstrap 复现 RC=127/变砖而 CI 全绿

- **编号**: 098
- **严重度**: S5（质量：CHANGELOG [0.6.20] F-096 宣称 "the heredoc is now checked STRUCTURALLY" 不能守住 F-096 本类回归）
- **攻击面**: F-096 修复面（crates/creance-vm/src/provision.rs 结构测试）
- **发现者会话**: r28-auditor（R28 第十三次收敛判词轮）
- **状态**: 待修复

## 复现

```sh
git worktree add --detach $HOME/r28-wt HEAD
CARGO_TARGET_DIR=$HOME/r28-wt-target CREANCE_REPO=$HOME/r28-wt ONLY="NC-SSindent NC-SStab NC-SStrail NC-SSiffalse NC-METAcount NC-METAbody NC-METApfx" sh harness/tools/r28-negative-controls/run.sh
sh harness/tools/r28-heredoc-ws/run.sh     # 真实 v0.6.20 渲染 bootstrap + 变体 → sh -e 执行
```

| 用例 | 注入（provision.rs bootstrap 模板） | 测试 | 运行期 |
|---|---|---|---|
| NC-SSindent | 终止行后追加 `  EGRESSRULES` | 绿（65p/0f） | `EGRESSRULES: not found` RC=127（r28-heredoc-ws） |
| NC-SStab | 追加 `\tEGRESSRULES` | 绿 | RC=127 |
| NC-SStrail | 追加 `EGRESSRULES `（尾空格） | 绿 | RC=127 |
| NC-SSiffalse | `if false; then cat > rules.v4 <<'EGRESSRULES' … EGRESSRULES fi` | 绿 | rules.v4 不写 → iptables-restore 失败 → 变砖（fail-closed） |

根因：`s.lines().filter(|l| *l == "EGRESSRULES").count() == 1` 只认逐字节裸行；`find("\nEGRESSRULES\n")` 取第一个终止行做 body 比对，终止行之后的任何“像终止行”的行不被检查；`sh -n` 也不报（r28-heredoc-ws：sh-n=0）。F-096 的实际失效机理（终止行之后多一行被当命令执行）对空白变体同样成立。

对照（红，守护有效）：NC-SSterm2（第二裸行）、NC-SSnoterm、NC-SSunq（`<<EGRESSRULES` 未引用）、NC-SSdash（`<<-`）、NC-SScomment（body 内 `# EGRESSRULES end`）、NC-SSdrift/SSdrop。

另记（元变异，单点依赖）：把计数断言改 `>= 1` + 注入第二裸行（NC-METAcount）、body 比对改 `contains`（NC-METAbody）/前缀（NC-METApfx，并删 `COMMIT`）均绿——每条结构断言是唯一防线，无执行级（实际跑 heredoc 段）的第二道校验。

## 建议

结构校验改为“终止行之后的下一行必须是固定的注释行 `# The boot replay…`”或直接在 CI 中把 heredoc 段 `sh -e` 执行到临时目录并 cmp 输出（r28-heredoc-ws 即样板）。
