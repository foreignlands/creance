# STATE-r28 — creance 第十三次收敛判词轮（终稿）

- 对象：main = v0.6.20 tag `d5d3853`（v0.6.19..v0.6.20 单 commit）；release 二进制 `creance 0.6.20` md5 `eb6d17c9`
- 审查员：r28-auditor；只记录不修复——`crates/` `scripts/` `docs/` 零改动（`git diff --stat v0.6.20 -- crates scripts docs` 为空）
- 新发现：**098、099、100、101、102、103（均 S5）** ⇒ **不收敛，未发收敛判词**

## 基线

`sh scripts/ci.sh > /tmp/r28-ci-baseline.log 2>&1; RC=$?` → **RC=0**，182 passed / 0 failed（r28-baseline/）。

## F-096 复核

| 核验点 | 结论 | 证据 |
|---|---|---|
| (a) fresh LAB init+setup→up1→stop→up2 | **通过**：init/setup/up1(329s)/stop1/up2(18s) 全 RC=0；up2 `-netdev user,...,restrict=on`；marker ok | r28-real-up/run.log |
| (a) egress-lock.service 实装 | 通过：active/enabled（up1、up2 两次 boot），无 drop-in 目录，ExecStartPost 恰 1 | evidence/facts-up*.log、rules-md5-up2.log |
| (a) rules.v4 == 渲染器逐字节 | 通过：guest `/etc/iptables/rules.v4` md5 `e13fe10a…` = `rules_v4_text(NAT_HOSTS_QEMU)` | rules-md5-up2.log |
| (a) stamp 经 ExecStartPost 落盘 | 通过：`/run/egress-armed` root 644，每次 boot mtime 刷新，内容为 live OUTPUT 段；guest 用户写入 Permission denied，direct tcp blocked | facts-up*.log |
| escape-test（restrict=on） | 11 PASS / 1 SKIP / proxy-path ESCAPE（lab 无代理节点，与 STATE-r20 同因），RC=1 非回归 | evidence/escape2.log |
| (b) 终止行计数 / 第二裸行 / 未引用 `<<EGRESSRULES` / `<<-` / body 内 EGRESSRULES 注释 / 无终止行 | 红（SSterm2/SSunq/SSdash/SScomment/SSnoterm） | r28-negative-controls/run.log |
| (b) 终止行缩进 `  EGRESSRULES`（及 tab、尾空格） | **绿 → F-098**；真实渲染 bootstrap 注入后 sh -e RC=127 `EGRESSRULES: not found` | run.log、r28-heredoc-ws/run.log |
| (b) 计数改 `>=1` / body 比对改 contains / 前缀（元变异 + 注入对应 bug） | 绿——每条断言是唯一防线（记入 F-098） | run.log |

## F-097 复核

- R27 15 例绿形状全部转红；R25/R26/F-087/F-093/F-095 回归全红（64 例回归中 62 红，NC-HDQ/NC-CMPskip 绿为既定语义等价边界）。
- 逐点（用户指定的绕过问）：

| 问 | 结论 |
|---|---|
| 递归遍历可被 src/ 下新目录绕过？ | 新目录本身被扫（MKsub 红）；但 `#[path]` 指向 src/ 外可绕（NC-PATHmod 绿，F-099） |
| `find("\n}")` 找错闭括号？ | **是**：单行 `#[cfg(test)] mod t {}` 后的产品 fn 被吞（NC-CUTnew/CUTnewQ 绿）；`#![cfg(test)]` 内属性不计入“每文件至多一个”（NC-CUTinner 绿）→ F-099 |
| `use up_gate_tests as x` 绕 tests:: 禁呼？ | 不构成：up_gate_tests 为 cfg(test)，产品构建不可达 |
| egress_probe_script 函数指针/别名绕钉？ | 别名调用红（NC-PROBEfnptr）；但丢弃结果/`.map` 改写可绕（NC-PROBEdisc/MAPout 绿，F-100） |
| let out 经宏/闭包遮蔽？ | `let (out, _)` 解构（NC-LETOUTpre）、局部 `mod escape` 遮蔽 verdict（NC-SHADOWmod）绿 → F-100；guard 内 `let out:` 形为编译错误不计 |
| `/.creance/` 形目录可被绕？ | `/.creance/` + `/state/qemu/` 双条件 gate 绿（NC-MPhome2，F-099）；symlink/相对路径对绝对产品路径无意义，未构成 |
| cfg! 变体 `#[cfg(test)]`/cfg_attr | `#[cfg(not(test))]` 属性（NC-MPattr）、vm.rs 层 `cfg!`（NC-VMcfg）绿 → F-099 |
| ExecStartPost 可经 drop-in/间接写？ | drop-in 红（NC-ESPdropin）；第二 unit 以 `cat >/etc/..`/`tee` 写入绿（NC-UNITns/UNITtee，F-101） |
| `-e '` 计数可被换引号/拼接绕？ | 替换条目（NC-ALLOWrep）、条目内嵌换行（NC-ALLOWnl）绿 → F-101 |
| WMslice（write_marker 前加 5 行注释） | 绿，非缺陷（窗口切片未误报） |

## F-096 教训

OPERATOR-PROMPT / docs / README 无“实机复验必须 fresh setup”条款 → F-103。本轮实机按 fresh LAB 执行（r28-real-up/run.sh，`LAB`/`CREANCE_BIN` 参数化）。

## F-088 类：CHANGELOG / commit 对账

v0.6.19..v0.6.20 仅 `d5d3853`；tag 内含 CHANGELOG `[0.6.20]`（F-096 S4、F-097 S5 条目），workspace 版本 0.6.20。条目宣称的 "checked STRUCTURALLY"、"excludes ONLY the trailing test module"、"forbids a `let out` shadow"、"exactly one unit file write"、"allowset is counted exactly" 分别被 F-098/099/100/101 证伪其守护强度。11 文件逐一审过：CHANGELOG、Cargo.toml/lock（版本）、provision.rs（F-098/101）、qemu/mod.rs（F-099）、escape.rs（F-101）、main.rs（F-099/100）、findings 096/097、INDEX、STATE-r27；qemu cloud-init 预算 600→1200s 与 up1 329s 相容。

## v0.6.19 watchdog（首切）

| 核验点 | 代码阅读 | 变异 |
|---|---|---|
| Open-only 计数 / Checking 豁免 | 正确（`core_up = !open \|\| connect`） | NC-WDany 绿 → F-102 |
| 3 次失败熔断 | 正确 | `>=8` 绿、`>=20` 红 → F-102 |
| 计数复位（成功 / 熔断后） | 正确 | 两处删复位均绿 → F-102 |
| 连接超时 250ms | 正确 | 改 30s 绿 → F-102 |
| closed 分支下一 tick 切 wire | 正确（stop + reap_orphans） | 删 stop 绿（reap 跳过自有 pid）→ F-102 |
| 熔断原因文案 | — | 改文案红 |

## 门禁矩阵 + 裁判双跑

- probe-inventory 门禁：POS RC=0；NC-A/NC-B/NC1/NC2/NC3/NC5/NC6v 全 RC=1；4 文件 md5 还原 OK（r28-gate-matrix/run.log）。
- 裁判：r14-convergence 双跑 RC=0 md5 `2ecbd0c1`、r15-064-recheck 双跑 RC=0 md5 `965e444c`，与参考一致；temp flag before/after 均 0（r28-judges/run.log）。
- 负控规程：家目录 worktree；cp 备份 → grep -c 注入前后（全部落地）→ cargo test → 还原 → md5sum -c 8 文件 OK（run.log / run-b.log 尾部）。判红以 test-RC≠0 且日志含 panicked 为准（`compile-err=` 列含 `error: test failed`）。

## 下一轮建议

1. 修 F-098..F-103 后复跑 r28-negative-controls 全集 + r28-heredoc-ws + fresh r28-real-up。
2. 守护文本计数已五轮被绕：marker 写入改类型级 verdict token；bootstrap 在 CI 中执行到临时根而非文本断言。
