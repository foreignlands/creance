# STATE — 2026-11-20T15:30:00+08:00（R11 收敛第三试 · 终稿，night-auditor）

## 判定：**有新洞（F-055），建议继续循环**（收敛判定推迟到 F-055 修复后的 R12）

## 已完成（R11 三面回归，night-12 HEAD c20332d / v0.5.6；ci.sh 真实 RC=0）

- **F-052 面 ✅ 代码在位+实机四 case**：三分支（main.rs:667-681）+实例存在检查（:686-694）真实落地（吸取 night-11 教训先 grep 后实机）。`harness/tools/r11-regression/f052-up-branches.sh` 4/4 PASS：无戳→rc1+戳缺失文案；漂移→rc1；戳对+实例缺失→rc1（模板陷阱关闭）；全对+假 limactl→rc0 且**恰一次** `start <instance>`。老 profile（0.5.5 前，无戳）升级路径=拒绝+明确中文指引（"请先 creance stop 再 creance setup"）——迁移语义可接受（fail-closed+可操作；stop 在已停实例上无害，setup 的 F-051 重建路径兜底）。
- **F-054 面 ⚠️ 拆分判定**：核心修复**实证有效**——APT_OPTS 拼接正确到达内层、curl -m 120/apt Timeout、300s 硬预算、`|| true` 吞 timeout 124、契约段（iptables/sudoers）可达（dash+stub 全流程实测）。但 arm64-URL 子声称**不成立**→ 新洞 **F-055**（S4）：`'"$ARCH"'` 在外层 dash 展开、ARCH 只在内层 sh -c 赋值→URL 架构段恒空（所有架构 404）→ nodejs.org 主下载死代码、恒走 apt 兜底（nodejs 18）。复现：`sh harness/tools/r11-regression/f054-provision-quotes.sh`（rc=1=洞在）。commit message "URL is even right on arm64" 与行为落差=F-052 同型（工程陷阱 #49）。无安全面：无 fail-open，containment 不受影响。
- **F-053 面 ✅ 全绿**：小写化在唯一收口点 `vmname::base_name`（to_ascii_lowercase）+ 仓内单测断言；消费点 grep 全部经两个 choke point（main.rs instance() / vm::instance_name→Limit::name）：serve.rs:259,314、escape.rs:103,531,827、diagnose.rs:146、gate_instance_dir、tunnel、running record。`r11-regression` cargo 探针 7/7 PASS（混合大小写折叠/非 ASCII 折叠/主路径小写恒等/恢复路径/两入口同名/fingerprint 锚/stamp 路径）。旧实例失配面记档：lima 2.3 create 本就小写化落盘 → 旧 profile 的磁盘目录已是小写 → 新代码的 expected 小写名直接命中 lima.yaml（无缝）；仅 pre-lima-2.3 大写落盘实例会 miss→up 拒（fail-closed）→内部用户重建。混合大小写 profile 实机 e2e 未做（探针矩阵+收口点分析已覆盖，性价比低）。

## 复跑记录

- `sh scripts/ci.sh`：**RC=0**（fmt+clippy -D warnings+test+release 全绿，真实退出码）。
- r10-regression @ v0.5.6：**全 PASS**（h1 21 case / h2 7 case / h3 4 case，R10_RC=0）。
- r9-regression @ v0.5.6：R9_RC=0；翻转语义符合预期——h1.1/h1.2 旧"洞"断言现在 FAIL（=F-048 修复生效）；h2.3/h2.4 的"洞成立"是 R9 陈旧注释：其 fixture 无假 limactl（virgin profile），NotEnforced 是修复后正确 virgin 语义，已被 r10 h2.2 精确矩阵（假 limactl Running→Escaped PASS）取代，**非回归**。

## 下一步（按序 3 条）

1. **R12**（night-12 fixer）：修 F-055（建议：URL 架构段留内层 `"$ARCH"`，或外层赋值+外层展开与 APT_OPTS 同式；补断言禁止 `'"$ARCH"'` 形态/URL 段必须含架构）+ 复跑 f054-provision-quotes.sh 应转 rc=0。
2. R12 收敛判定：若 F-055 修复后 r9/r10/r11 三探针全绿且无新洞 → STATE 写"审查收敛，建议停止循环"（最终停止信号）。
3. 停止后：0.6（Go 授权集 11 项+config 指纹三维 / multi-env）；剩余风险清单见下。

## 关键记忆（≤10）

1. F-055 根因模式：`sh -c '...'` 引号拼接块内"内层赋值、外层展开"错配——外层展开发生在参数组装期，内层赋值不存在。全脚本唯一错配点；APT_OPTS 是同作用域正确范例。
2. macOS /bin/sh 是 bash 3.2，对 `$(case ...)` 直接语法错误（bash≤3.2 解析限制）——guest 的 /bin/sh 是 dash 解析正常；VM 语义探针必须把 `sh` 指到 /bin/dash（本机 /bin/dash 存在）再跑，否则误报语法洞。
3. guest_fingerprint 锚：sha256(`["Etc/UTC","en_US.UTF-8","en-US"]`) = 5e2a08008a823a41…ad246a（r11 h2.1 库侧+shell 侧双验证）。
4. cmd_up 四分支顺序：check_running → stamp 三分支 → 实例存在检查 → vm::up；全在 limactl 之前，无需 VM 即可实机测试。
5. lima 2.3 create 小写化落盘 ⇒ F-053 修复对旧 profile 无缝（磁盘目录本就小写）；pre-lima-2.3 大写实例才需要重建。
6. f052-up-branches.sh 的 shell 陷阱：`$var` 后紧跟全角标点（如 `$c3（`）会让 bash 把多字节续接进变量名 → unbound variable；固定 ASCII 括号。
7. r9-regression 的 h2.3/h2.4 打印"洞成立"是 R9 陈旧标签（fixture virgin，无运行态假 limactl）——读者勿据标签误判回归；行为判定以 r10 h2.2 矩阵为准。
8. ci.sh 真实 RC 必须落到文件再 tail（管道吃 exit code）；本轮 RC=0。
9. 模板陷阱已闭：up 前查 `{lima_home}/{instance}/lima.yaml`；假 limactl 下 up 恰好一次 `start` 调用。
10. 探针工件：harness/tools/r11-regression/（cargo 探针 + f052-up-branches.sh + f054-provision-quotes.sh），全部可独立复跑。

## 会话统计

- R11：新发现 1（F-055 S4 待修复），三面回归完成，2 个 commit 未产生（审查轮不改代码）。
- 累计 55 findings：54 已修复闭环 + 1 待修复（F-055）。
- 基线：v0.5.6 / c20332d，ci.sh RC=0；r9/r10 复跑无回归。
