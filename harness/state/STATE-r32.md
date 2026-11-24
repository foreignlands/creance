# STATE-R32 — 自审终稿（R32 判词轮）

- 日期：2026-11-23
- HEAD 基线：v0.6.24 `d2a23f8`；产出：v0.6.25 `f01e34f`（main + tag 已推）
- 特殊情况：R32 审计子会话 caa7826c 在派发后即刻 out_of_quota 挂起（0 ACU）。经用户指示（"请你自己做测试"），本轮由主会话自审执行。
- 判词：**不收敛**（自审发现 5 项残余，已当场修复；需下一轮干净轮判收敛，待配额恢复派发 R33）

## 变异矩阵（全部 RED，prod-only 注入 + cp 还原）

| 变异 | 守护 | 结果 |
|---|---|---|
| `|i, p|` 参序对调 | verify_and_mark_shell_is_pinned | RED |
| 死闭包包 stop | 同上 | RED |
| vm.rs `mem::zeroed` 铸令牌 | 递归 walk unsafe/zeroed 计数钉 | RED |
| `pub(crate) const V: fn = egress_verdict` | verdict 名行规则 | RED |
| 未注册新文件含 `unsafe` | walk 覆盖目录而非 mod 树 | RED |
| `Result::Err(e) if` 守卫臂 | 前缀剥除+两臂钉 | RED |
| lib.rs `use … as idir` | use 行禁+`::instance_dir` 禁 | RED |
| 顶层裸 `false` | token 禁 | RED |
| 顶层 `mv` 覆写 rules.v4 | token 禁（新加） | RED |
| `export PATH=/tmp/evil` | 前缀禁（新加） | RED |
| ` EGRESSRULES` 缩进终止行 | `*x == tag` + 执行测试 | RED（双） |
| `exit 0` 早退 | token 禁 + 执行测试 | RED（双） |
| `/bin/systemctl disable egress-""lock.service` | 规范化白名单 | RED |
| `from_millis(500)+from_millis(300)` | verbatim tick 行 | RED |
| `let mut warm` 于 decl 之前 | prod 计数钉（新加） | RED |

## 自审发现并修复的残余（v0.6.25）

1. fuse 区逃逸：`warm` 旗标在 `let mut core_down_ticks` 之前声明落在区间外 → 可写状态助手改 prod 计数钉（let mut==18, = true;==2, = false;==2, mem::take/u32::from==0；区内保留 let mut==2 + bool 禁）。
2. ExecStartPost 从未被执行级验证（systemctl 是 stub）→ 测试抽取 unit 的 `sh -c '…'` 字面命令，iptables-save/grep stub 重放后断言 /run/egress-armed == OUTPUT 规则集。
3. 重写顺序腐蚀：链式 `.replace()` 会把 `{root}/usr/sbin/` 内的 `/sbin/`、`/bin/` 二次重写 → 改单遍从左到右最早前缀匹配。
4. 顶层动词缺口：mv/ln/chmod/chown/mkfifo/mktemp/unlink/rmdir 入 token 禁（合法用都在 inner 豁免块内）。
5. `export PATH`/`PATH=` 前缀重指向可劫持后续 systemctl → 入行首前缀禁。

## 诚实残余（记档）

- 字节数组+from_utf8 拼出的 marker 名/instance_dir 无字面量，文本扫描不可见——仅剩编译期封印与评审。
- inner `sh -c '…'` 工具链块内部不做动词禁（子 sh 无 -e，`exit`/`false` 良性；其外部 `|| true` 兜底）——块内 curl|bash 等高危形态由 sha256 钉+apt 兜底覆盖。
- 测试自身字面量被改（pin 的期望值同步更新）属"改测试"攻击，不在守护范围——协议前提是攻击者只动 prod。

## 复跑记录

- 变异还原事故：`git checkout` 还原曾两次冲掉未提交加固 → 改 cp 备份还原（教训已记入操作手册心智模型：变异 harness 禁 git checkout）。
- CI：`sh scripts/ci.sh` RC=0（v0.6.25）。
- 实机复验：沿用 v0.6.24 FRESH 腿（本批仅守护/测试面变更，无运行时行为变更）。
