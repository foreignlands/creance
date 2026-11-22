# STATE — R16 终稿（2026-11-22，night-auditor-v4，基线 cc85289 v0.6.7）

## 轮次定位

收敛判词轮（任务书 / STATE-r15 下一轮建议第 2 条）：增量复核 065 修复
（89747e4，night-17：ROADMAP 清单标记块重构 + check-probe-inventory.sh
双向差集门禁进 ci.sh）+ v0.6.7 增量面攻击抽查。
`git log fb91d0f..HEAD` = 2 commits（89747e4 修复 + cc85289 release）。
基线 `sh scripts/ci.sh` **真实退出码 0**（fmt+clippy -D warnings+
probe inventory+test+release，14 个 test-result 块，日志
/tmp/r16-ci-baseline.log 已按卫生协议删除，终态 CI_EXIT=0 行在案），
工作树除本轮协议产物外干净。

## 065 修复面裁定：**修复成立（六层证据）**

| 核验点 | 结果 | 证据 |
|---|---|---|
| 裁判=ci.sh 门禁步骤本身 | **"每次必跑"成立** | ci.sh:18 无条件行 + 顶部 `set -eu` → 门禁失败即 CI 失败；CI 日志第 10 行 `== probe inventory ==` + 第 11 行差集空在场；门禁 `sh -n` POSIX 语法过 |
| 正控 | **与 commit 宣称逐字一致** | 实跑 `probe inventory: bidirectional diff empty (guest 12 code ids, host 6)`，RC=0；12 guest 字面 id 与 escape.rs:327-408 发射点独立枚举相等（sock-$s 参数化点按设计排除）；host 6 id 与 escape.rs `id: "` 六处逐一相等 |
| ROADMAP 侧双负控 | **各单行报错、方向正确** | NC1 删 proxy-path → 1 行 FAIL（代码→清单）RC=1；NC2 塞 ghost-probe-r16 → 1 行 FAIL（清单→代码）RC=1；验后 byte-identical 还原 |
| 代码侧负控 | **被抓** | NC3 escape.rs 植入幽灵字面发射 → 1 行 FAIL RC=1 |
| fail-closed 负控 | **块名漂移不静默** | NC5 标记改名 guest-enforced-DRIFT → RC=1、11 行 FAIL（sock-abstract 经 todo 块仍被追踪，方向正确）；块删空推演 18 行 FAIL（12 guest+6 host），标注为推演非实测 |
| findings/065 逐点 | **全兑现** | ①proxy-path 入 guest-enforced 块（ROADMAP.md:45）；②sock-abstract 入 guest-todo 块（:50）；③QUICKSTART:84-88 类别枚举对齐（fs/凭据三件/ssh 补齐，且提及门禁看守与 sock-abstract ⏭️）；④三块纯 id、注释全部在块外（commit 自述的 sed 多字节约束如实落地）；⑤host 6 id 与清单零漂移；INDEX 065 行状态翻已修复 |
| 无夹带 + 无回归 | **成立** | 89747e4 仅 5 文件（ROADMAP/QUICKSTART/INDEX/新门禁/ci.sh）逐一审过；cc85289 仅 CHANGELOG+Cargo.lock+Cargo.toml；裁判双跑 r14-convergence RC=0（七节，[A] 24 条含 sock-abstract/proxy-path）+ r15-064-recheck RC=0（六节 NC1-NC2-PF1-PF2-EQ1-EQ2），内容与 R15 基线一致；工具 Cargo.lock 版本戳漂移已还原 |

增量面范围核验：night-17 全部触碰面（文档×2、脚本×2、INDEX）均属
声明面，无 Rust 代码变更——行为面 delta 为零，与 commit 自述一致。

## 发现清单（1 项，066；INDEX 已登记）

| # | 严重度 | 一句话 | 证据等级 |
|---|---|---|---|
| 066 | S5 | 已强制的 sock-$s 家族探针（socket 暴露检测，escape.rs:364-367 三运行时路径）在全部五层自动化结构性不可见——门禁方向 2 对家族 token 无条件 allowlist 恒真豁免、escape.rs 测试只断言 sock-abstract、main.rs:385-386 提取器显式排除参数化点、两裁判同提取基准；NC6 实证删掉 sock for-loop 后门禁 RC=0（输出与正控逐字同）+ cargo test 探针断言 ok，ROADMAP/QUICKSTART/README 的"已强制"宣称可被静默证伪且零 CI 红；门禁头注如实声明豁免（未违反自身契约），但豁免后果未在任何文档陈述、无补偿层——同病（声明面无自动看守）第四复发向量，病灶活在为终结该病而买的门禁自身豁免条款里；附带记档 QUICKSTART:84-88 枚举仍略过 socket 类（四类修三类） | NC6 双实测（门禁绿 + 测试绿）+ 三层结构性证据（注释/裁判输出/测试断言逐行核对） |

定性说明：066 是**门禁覆盖边界缺口**（documented boundary 的未陈述
后果），非 065 修复引入的行为回归——门禁对其自身写下的契约完全成立，
Rust 代码零变更；S1-S4 面连续第四轮零新发现。

## 收敛判词（R16，基于证据）

**"零新发现"判据未满足 → 收敛判词不发，循环进 night-18 微批。**
依据：R15 判词模板"零新发现即按 R14/R15 判词模板给出收敛判词"——
065 修复本身六层证据全部成立（上表），但抽查在门禁方向 2 的家族
allowlist 处实测出 066（删除一个已强制安全探针，五层自动化全绿）。
不为收敛而放水：连续第二轮"修复面完美成立仍因新立案不发判词"
（R15→065，R16→066）。S1-S4 语义面自 R12 起持续零新发现；
056-065 十项修复全部复核闭环（066 待修）。

## 已攻击未破（证伪/排除记录，不计 findings）

1. **ROADMAP 侧三负控全被抓**（NC1 删 id / NC2 幽灵 id / NC5 标记名
   漂移）——门禁对声明面漂移 fail-closed 成立；块删空的 18-FAIL 推演
   未实测（同机制，标注为推演）。
2. **代码侧字面幽灵发射**（NC3）被抓——方向 1（代码→清单）对字面
   发射点成立。
3. **helper 形态（064 类）新探针**（NC4）：门禁绿——与 066 同根
   （非字面发射不可见），已并入 066"未验证想法"，不重复立案；已知
   探针 helper 化回归仍有三层网（方向 2 + cargo test:746-748 +
   裁判 [A]），064 防线实际比门禁宽。
4. **NC5 首测 RC 假象**：`gate | head` 管道吃掉退出码显 0——无管道
   重测 RC=1；探针自身假象，非仓库洞（R15 记忆 #8 同族：先怀疑探针）。
5. **QUICKSTART socket 类枚举缺失**：R15 已裁定"概述句非清单宣称，
   不单独立案"，night-17 顺带对齐修三类留一类——README:70-75 与
   ROADMAP 已强制块均完整，随 066 附带记档不另立案。
6. **cc85289 夹带**：release commit 仅 CHANGELOG+Cargo.lock+Cargo.toml，
   逐文件核过。
7. **QMP powerdown 无读超时**（H4 的 S3 候选）自 v0.6.1 未变——维持
   记档，不新增立案（R15 记忆 #7 顺延）。

## 实验清理

/tmp/r16-ci-baseline.log、r16-judge1.err、r16-judge2.err、r16-nc5.out、
r16-nc/ 全部删除；负控临时改动全部还原（NC1/NC2/NC5 → ROADMAP
byte-identical；NC3/NC4/NC6 → escape.rs git checkout 还原，sock-$s
发射点 grep 计数回 1）；r14-convergence/r15-064-recheck 的 Cargo.lock
版本戳漂移 git checkout 还原（R15 记忆 #6 固定动作）。仓库本轮产物 =
harness/findings/066-*.md + INDEX.md 一行 + attack-surfaces.md E5 行
R16 注记 + 本文件；新工具目录 0（负控均为秒级一次性 shell/perl 操作，
复现步骤全文在案 findings/066——未达建工具阈值）。

## 关键记忆（非显然事实，≤10）

1. 探针清单核对已从人肉流程变成 ci.sh 门禁（R15 建议 #1 兑现，双向
   差集 + 三块标记解析）；但方向 2 的家族 allowlist 是恒真豁免——
   "declared enforced must exist in code" 对 sock-$s 家族不成立（066）。
2. 参数化发射（sock-$s）是五层自动化（门禁/测试/缺行提取器/两裁判）
   的共同盲区：id 构造期不可枚举 → 唯一可行守卫形态是"发射点文本
   在场"（066 修复方向①门禁 grep 或②测试 assert contains）。
3. 已知探针 helper 化回归仍被三层网覆盖（方向 2 + cargo test:746-748 +
   裁判 [A] expected）——064 的实际防线比门禁宽，064 类回归风险低。
4. 门禁对 ROADMAP 侧全 fail-closed：块名漂移 → 11 行 FAIL 且
   sock-abstract 经 todo 块仍被追踪；fail-open 仅存在于 allowlist
   豁免一处（066）。
5. 负控 RC 必须无管道取值（NC5 首测 `gate | head` 显 0 假象）；与
   R15 #8（集合比较先 sort）同族：先怀疑探针再怀疑被测对象。
6. 裁判双跑固定动作（两工具 cargo run）会刷工具 Cargo.lock 版本戳
   ——收尾 git checkout 还原，git status 必查（R15 #6 顺延，本轮照做）。
7. QUICKSTART/README/ROADMAP 三处探针类目声明中只有 ROADMAP 受门禁
   看守；QUICKSTART 枚举 socket 类缺（066 附带）、README 完整——
   三处声明面的看守强度不等，引用声明时先看 ROADMAP 块。
8. 基线绿必须来自完整 ci.sh 真实退出码（本轮 CI_EXIT=0、14 块）；
   `cmd | tail/head` 吃 RC 的坑本轮在自家探针上再次踩到（NC5）。
9. /tmp/vmhome-501-* 历史符链持续新增（cargo test 临时 profile 副产品，
   2026-11-22 仍有新增），不动（R14 #10 / R15 #10 维持）。
10. 收敛判词判据是"零新发现"而非"修复面全绿"——R15/R16 连续两轮
    修复面完美成立仍不发判词；判词轮的产出重心应放在"对修复未触碰
    的邻接面穷举"，这才是两轮立案的来源（065=清单面、066=门禁 allowlist）。

## 下一轮建议（按序）

1. **night-18 微批（≤4 行）**：修 066——建议方向①门禁对家族 token
   显式守卫（`grep -q 'echo "PROBE sock-\$s ESCAPE"' crates/creance/
   src/escape.rs || FAIL`）或方向②escape.rs:758 附近补
   `assert!(script.contains("PROBE sock-$s ESCAPE"))`，二选一；
   顺带 QUICKSTART:84-88 枚举补 socket 类一词（闭 066 附带项）。
2. **R17 = 收敛判词轮（第三次预期达成）**：增量复核 066 修复（负控：
   删 sock for-loop → 必须红）+ 裁判双跑 + 门禁负控矩阵回归
   （NC1/NC2/NC3/NC5 + 新家族负控）；零新发现即发收敛判词，
   DRIVER 写 convergence 字段停轮。
3. **平台回填（不阻塞收敛，R14 起顺延）**：U1-U5 Ubuntu 实机 +
   Linux glibc `\]` 转义接受度 + H3 逗号路径 qemu 实证 + 062 的
   QEMU 传输形态同验——全部非本机可验，维持挂账。

## 会话统计

- R16（本轮）：1 新 finding（1×S5，待修复）；065 修复面六层复核全
  成立；7 方向证伪/排除存档；门禁负控矩阵 7 场景（正控/删 id/幽灵 id/
  幽灵字面发射/helper 逃逸/标记漂移/删 sock 探针）；新工具 0
- 累计：66 findings；056-065 十项修复复核闭环，066 待修
- 实机消耗：零 VM 时长（全部证据 = 静态核对 + 门禁/测试/裁判本地跑），
  CI 一轮，零残留
