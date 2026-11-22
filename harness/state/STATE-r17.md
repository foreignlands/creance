# STATE — R17 终稿（2026-11-22，night-auditor-v4，基线 a8dfea4 v0.6.8）

## 轮次定位

收敛判词轮第三次尝试（任务书 / STATE-r16 下一轮建议第 2 条）：增量复核
066 修复（055f11b，night-18：门禁 section 4 sock-$s 家族发射点文本守卫
+ QUICKSTART 枚举补 socket 类）+ attack-surfaces 邻接面穷举抽查（R16
记忆 #10 判词轮产出重心）。
`git log cc85289..HEAD` = 2 commits（055f11b 修复 + a8dfea4 release）。
基线 `sh scripts/ci.sh` **真实退出码 0**（CI_EXIT=0，14 个 test-result
块，日志 /tmp/r17-ci-baseline.log 已按卫生协议删除），工作树除本轮协议
产物（findings/067、INDEX 一行、attack-surfaces E5 注记、本文件）外干净。

## 066 修复面裁定：**修复成立（逐点核验 + 全负控矩阵）**

| 核验点 | 结果 | 证据 |
|---|---|---|
| 家族发射点守卫落地（066 方向①） | **成立** | scripts/check-probe-inventory.sh:80-88 section 4 在场；`grep -q 'echo "PROBE sock-\$s ESCAPE"'` 对源文本精确匹配；NC6 重放（perl 删 escape.rs:364-367 注释+for-loop 三行，grep 计数 0）→ **恰好 1 行 FAIL**（"FAIL: sock-$s family emission site missing…"）+ RC=1，验后 byte-identical 还原（md5 快照核对） |
| 正控不变 | **逐字一致** | "probe inventory: bidirectional diff empty (guest 12 code ids, host 6)" RC=0 |
| 门禁负控矩阵回归 | **全 fail-closed** | NC1 删 proxy-path（ROADMAP 块）→ 1 行 FAIL RC=1；NC2 塞 ghost-probe-r17（id 行尾）→ 1 行 FAIL RC=1；NC3 植入幽灵字面发射 → 1 行 FAIL RC=1；NC5 标记改名 guest-enforced-DRIFT → 11 行 FAIL RC=1（12 字面 id 中 sock-abstract 经 todo 块仍被追踪，方向正确）；全部验后还原（ROADMAP md5 5cae…、escape.rs md5 6b3d… 与快照一致，git status 干净） |
| QUICKSTART socket 类补齐（066 附带项） | **兑现** | docs/QUICKSTART.md:84-88 枚举现含"socket 暴露（sock-* 家族，参数化发射，门禁看守其发射点）"——四类补齐（065 修三类的遗留项闭账） |
| INDEX 状态 | **翻已修复** | INDEX 066 行 → 已修复（night-18 主会话…v0.6.8） |
| 无夹带 | **成立** | 055f11b 仅 3 文件（QUICKSTART/INDEX/check-probe-inventory.sh，逐行审过：section 1-3 未动、头注 allowlist 描述仍属实——豁免仍在但已被 section 4 补偿；相对路径在 cd 后有效；文件缺失形态 grep -q 失败→FAIL，fail-closed）；a8dfea4 仅 CHANGELOG+Cargo.lock+Cargo.toml，CHANGELOG 0.6.8 条目与实际改动一致，Cargo.toml=0.6.8 |
| 裁判双跑 | **双绿** | r14-convergence RC=0 七节 [A]-[G]（[A] 24 条含 sock-abstract；家族行仍不在 [A]——066 方向③裁判侧被有意降级，与 066 建议一致）；r15-064-recheck RC=0 六节 NC1/NC2/PF1/PF2/EQ1/EQ2；两工具 Cargo.lock 版本戳漂移已还原（固定动作） |

## 发现清单（1 项，067；INDEX 已登记）

| # | 严重度 | 一句话 | 证据等级 |
|---|---|---|---|
| 067 | S5 | README:70-76 验收节"Enforced since 0.3/0.4/0.5"现在时清单仍列已删除的 numeric proxy endpoint 探针（2026-11-21 E5 裁定删除）且无删除注记——三处探针声明面中唯一已漂移的一处（ROADMAP:53/QUICKSTART:90 均有历史注记、ROADMAP 块受门禁看守，README 零看守零注记）；本轮正控实测假宣称全程在树、门禁 RC=0；R14"残留引用仅三处"裁定按连字符 id grep 漏掉空格短语变体（本条修正该记录）、R16 复查焦点在 socket 类滑过——同病（声明面靠人肉同步、无自动看守）第五复发（058→063→065→066→067），首次落在第三声明面；附带记档：README:74-76 网络探针枚举漏 net-icmp-external/proxy-path（概述句先例随条记档）+ NC6c 文本在场证人边界 | 零操作静态事实（grep 逐行）+ 本轮正控门禁绿实测 + 三声明面逐行对照 + git -S 全历史追踪（短语 6612b7f 写入后从未被触碰，四轮修复绕行） |

定性说明：067 与 066 同族（声明面无自动看守的复发），但这次不是未来
风险而是**已兑现的活漂移**——一处"已强制"宣称指向不存在的探针。
S1-S4 面连续第五轮零新发现；066 修复本身六点核验全部成立。

## 收敛判词（R17，基于证据）

**"零新发现"判据未满足 → 收敛判词不发，循环进 night-19 微批。**
依据：066 修复面复核全绿（上表），但按 R16 记忆 #10 把产出重心放在
"修复未触碰的邻接面穷举"后，第一处抽查（三声明面看守强度差异清单的
第三项=README）即实测出 067 活漂移。不为收敛而放水：连续第三轮
"修复面完美成立仍因新立案不发判词"（R15→065，R16→066，R17→067）。
同病已五复发——判词前的穷举面还剩：README/QUICKSTART 其余段落声明、
harness/ 自身文档（ESCAPE-BRIEF/README/FIXER-PROMPT）声明面。

## 已攻击未破（证伪/排除/记档记录，不计 findings）

1. **门禁矩阵 7 场景**（正控/NC6 重放/NC1/NC2/NC3/NC5/NC6c）：除 NC6c
   外全红且单行定位；NC6c（死分支 `if false; then echo "PROBE sock-$s
   ESCAPE"; fi`，行为死/文本在）门禁绿——section 4 是文本在场证人，
   与 066 方向②同限，头注自洽（"textually present"），"deleting the
   probe has to fail HERE" 对行为性删除略有超额承诺；唯一行为证人=
   实机探针。记档入 067 未验证想法，不立案。
2. **探针自身假象 ×2（NC2 前两次）**：①幽灵 id 塞在关闭标记行 → 被
   块解析器 `grep -v '<!--'` 整行滤掉；②锚点 `^net-icmp-external…$`
   不匹配（全部 id 在同一行）注入 no-op——两次都因注入前 grep -c=0
   自察，未误判门禁（R16 记忆 #5"先怀疑探针"再兑现两次）。
3. **ci.sh 覆盖面自身**：5 步（fmt/clippy/probe-inventory/test/release），
   `set -eu` + 门禁无条件行传播成立（R16 已核）；"谁看守 ci.sh 含门禁
   步骤"——无层看守，元递归见底记档，不立案（先例 R16）。
4. **触碰面邻接**：workspace members=5 crate（tools 排除，工具腐烂不
   能破 --locked CI）；section 4 与 section 1-3 无共享状态干扰；RELEASES.md
   是版本计划非补丁清单（0.6.x 不列），CHANGELOG 0.6.8 如实。
5. **r15/r16 遗留本机可验项**：QMP powerdown 无读超时仍在（runner.rs:311，
   H4 记档维持不立案）；家族外延漂移（第 4 条 sock 路径 vs "三运行时"
   散文）仍不可自动检测——066 修复未宣称闭此项，记档维持；大写 id
   截断记档维持；U1-U5/H3 逗号路径/062 QEMU 形态非本机可验，挂账维持。
6. **findings 编号连续性**：001-066 文件齐全无 GAP（本轮 067 接续）；
   ROADMAP/QUICKSTART 版本声明（v0.6.x 当前）与 CHANGELOG 无漂移。

## 实验清理

/tmp/r17-ci-baseline.log、r17-ci-exit.txt、r17-md5-snapshot.txt、
r17-nc5.out、r17-judge1.out、r17-judge1.err、r17-judge2.out、
r17-judge2.err、r17-nums.txt 全部删除；负控临时改动全部还原（NC1/NC2/
NC5 → ROADMAP byte-identical；NC3/NC6/NC6c → escape.rs git checkout
还原，md5 快照逐一核对）；r14-convergence/r15-064-recheck 的 Cargo.lock
版本戳漂移 git checkout 还原。仓库本轮产物 = harness/findings/067-*.md
+ INDEX.md 一行 + attack-surfaces.md E5 行 R17 注记 + 本文件；新工具
目录 0（负控均为秒级 perl/shell 一次性操作，复现步骤全文在案
findings/067 与本表——未达建工具阈值）。

## 关键记忆（非显然事实，≤10）

1. 三声明面看守强度实测排序：ROADMAP（门禁双向）> QUICKSTART（无看守
   但已对齐+注记全）> README（无看守且已漂移=067）——066 修复只补了
   QUICKSTART，README 治本方向（门禁扩块）留 067 方向②。
2. 引用残留 sweep 必须含**短语拼写变体**：R14 按 id `proxy-numeric-
   endpoint` grep 裁定"仅三处残留"，README 的 "numeric proxy endpoint"
   （空格短语）漏网存活四轮——grep 面要覆盖连字符/空格/中文三种形态。
3. 066 修复（section 4 文本守卫）经 NC6 重放实证成立；NC6c 证明文本
   在场证人的边界：死分支保文本 → 门禁绿，行为证人只有实机。
4. NC 注入前先 grep -c 确认注入落地（本轮两次 no-op 注入自察）；块解析
   器 `grep -v '<!--'` 会滤掉含标记的整行——往块内塞东西只能塞 id 行。
5. 收敛判词判据仍是"零新发现"非"修复面全绿"——连续第三轮；本轮立案
   正是按 R16 #10 把重心放到邻接面清单第一项（三声明面）的产出。
6. 裁判双跑刷工具 Cargo.lock 版本戳——固定动作 git checkout 还原
   （R15 #6 / R16 #6 顺延，本轮照做）。
7. 负控 RC 必须无管道取值（R16 #5）；本轮全部 RC 直取，零管道污染。
8. 基线绿必须来自完整 ci.sh 真实退出码（本轮 CI_EXIT=0、14 块）。
9. /tmp/vmhome-501-* 历史符链维持不动（R14 #10 / R15 #10 / R16 #9 顺延；
   本轮零 VM 时长，未新增）。
10. 067 修复方向决定 R18 可验证性：方向①（删词）无自动看守，R18 复核
    只能静态 grep 三声明面对齐；方向②（README 块进门禁）才有负控可放
    ——建议主会话至少做到"删词+注记"，方向②入 backlog。

## 下一轮建议（按序）

1. **night-19 微批（≤3 行）**：修 067——README:72 删 "numeric proxy
   endpoint, " 一词 + 同段补删除注记（与 QUICKSTART:90 措辞对齐）；
   顺带 README:74-76 网络探针枚举补 icmp/正向控制；方向②（README 块
   进 check-probe-inventory.sh）入 backlog 不强求。
2. **R18 = 第四次收敛判词轮**：增量复核 067（静态三声明面对齐核对 +
   若方向②落地则补 README 块负控）+ 裁判双跑 + 邻接面续扫：README/
   QUICKSTART 其余段落声明（安装路径/命令/平台表）、harness/ 自身文档
   （ESCAPE-BRIEF/README/FIXER-PROMPT/OPERATOR-PROMPT）声明面、
   attack-surfaces 状态注记与 findings INDEX 交叉一致性。
3. **平台回填（不阻塞收敛，R14 起顺延）**：U1-U5 Ubuntu 实机 + H3
   逗号路径 qemu 实证 + 062 QEMU 传输形态——全部非本机可验，挂账维持。

## 会话统计

- R17（本轮）：1 新 finding（1×S5，待修复）；066 修复面七点核验全成立
  （含 QUICKSTART 附带项闭账）；门禁矩阵 7 场景（正控/NC6/NC1/NC2/NC3/
  NC5/NC6c）；裁判双跑双绿；探针自身假象 2 次自察；新工具 0
- 累计：67 findings；056-066 十一项修复复核闭环，067 待修
- 实机消耗：零 VM 时长（全部证据 = 静态核对 + 门禁/测试/裁判本地跑 +
  git -S 历史追踪），CI 一轮，零残留
