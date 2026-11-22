# STATE — R15 终稿（2026-11-22，night-auditor-v3，基线 a05e602 v0.6.6）

## 轮次定位

收敛判词轮（DRIVER.md next_focus / STATE-r14 下一轮建议第 2 条）：增量复核
064 修复（d220e1b，night-16）+ v0.6.6 增量面攻击抽查。
`git log 7b51d45..HEAD` = 2 commits（d220e1b 修复 + a05e602 release）。
基线 `sh scripts/ci.sh` **真实退出码 0**（fmt+clippy -D warnings+test+
release，14 个 test-result 块，日志 /tmp/r15-ci-baseline.log 已按卫生协议
删除，终态复核 CI_EXIT=0 行在案），工作树除本轮产物外干净。

## 064 修复面裁定：**修复成立（四层证据）**

| 核验点 | 结果 | 证据 |
|---|---|---|
| r14-convergence 裁判（修复后断言） | **全绿 RC=0** | [A] expected 24 条含 fs-flag-readable（12 字面 id ×2 发射点，net-icmp ×3）+ 脚本无 `probe fs-flag-readable` 助手形态；[B] 独立枚举=12 字面 id 与提取器集合相等；[C] 健康零误报；[D] 空输出→24 全 missing；**[E] fs-flag 行被吞→missing 非空（fail-closed，翻转自 064 原观测）**；[F] 24 id × 74 行子串碰撞零误匹配；[G] up 守门真值表 10 行全过 |
| 裁判鉴别力（本轮新增负控） | **有齿** | 新工具 r15-064-recheck：把真 `guest_script()` 渲染产物回植成修复前形态（probe() 助手 + 参数化发射，文本逐字取自 d220e1b diff `-` 行）——[NC1] 提取器集合变回 22 条/11 id、无 fs-flag-readable（064 原观测复现），[NC2] 吞行场景 missing 为空 → 修复前形态必被裁判 [A]/[E] 判死。裁判不是恒 PASS |
| findings/064 逐点 | **全兑现** | ①提取网覆盖全部 12 探针 id（[B]+[PF1] 去重集合与清单逐一相等）；②main.rs:385-389 豁免注释如实化（只剩 sock-$s 参数化、注明 F-064）；③probe() 助手全仓删除（grep 实证：crates 内仅注释与测试名残留）；④escape.rs:746-747 测试断言同步更新（两字面形态） |
| 无新引入回归 | **成立** | [EQ1] 修复前/后 fs-flag 发射块真 /bin/sh 下 FLAG 存在/不存在两世界输出逐字节一致（PASS/ESCAPE）；[EQ2] 整份 guest_script `sh -n` 语法过；d220e1b 对 main.rs 仅注释变更（缺行判定逻辑零改动）；a05e602 = CHANGELOG + 版本戳（逐行核过） |

增量面范围核验：d220e1b 只触 escape.rs / main.rs / INDEX / r14-convergence
工具（--stat 实证）；a05e602 只触 CHANGELOG.md / Cargo.lock / Cargo.toml
版本戳。两 commit 均无夹带。

## 发现清单（1 项，065；INDEX 已登记）

| # | 严重度 | 一句话 | 证据等级 |
|---|---|---|---|
| 065 | S5 | ROADMAP.md:38 探针清单缺两个真实 guest 探针 id——proxy-path（被强制的正向控制，QUICKSTART:85 明文承认）已强制列表缺席、sock-abstract（诚实 SKIP 的未实现层）已强制与待做两节均零跟踪；host 侧 6 id 无漂移 | 双向差集实测：清单提及 id 在脚本中全存在（R14 单向核对没错），但脚本 12 字面 id 反查清单缺 2（`grep 'sock-abstract\|proxy-path' ROADMAP.md` 零命中 vs escape.rs:370/406/408 发射点在场）；该缺口自清单首版（6612b7f）就有，F-063 修复与 night-15 重写两轮未补；同时修正 STATE-r14 对 F-063 "逐一对上"的过宽裁定（只做了清单→脚本单向核对） |

定性说明：065 是**文档声明面缺口 + 上轮验证记录修正**，非 064 修复引入
的回归（缺口早于 d220e1b 两个版本轮存在）；S1-S4 面连续第三轮零新发现。

## 收敛判词（R15，基于证据）

**"零新发现"判据未满足 → 收敛判词不发，循环进 night-17 微批。**
依据：R14 判词模板明确"064 修复落地且裁判通过后，R15 按**预期零新发现**
给出收敛判词"——064 修复本身四层证据全部成立（上表），但攻击面抽查在
064 未触碰的邻接声明面（ROADMAP 清单）实测出 065。不为收敛而放水：
有洞就立案，哪怕 S5。S1-S4 语义面自 R12 起持续零新发现；056-064 九项
修复全部复核闭环。

## 已攻击未破（证伪/排除记录，不计 findings）

1. **提取器误报新形态**：注释行含 "PROBE" 字样会被 `echo "PROBE ` 匹配？
   证伪——[B] 独立枚举与提取器集合相等（12 id），脚本注释（含新 F-064
   注释）无 `echo "PROBE ` 形态。
2. **[F] 矩阵参数化行用短形（sock-docker）而非真实全路径 id
   （sock-/var/run/docker.sock）**——核对碰撞方向（expected id ⊂ 发射
   行）：12 个真实 id 无一是任一形态的子串，矩阵结论不受影响。
3. **expected 网重复 id（12×2=24 条）**：missing() 的 any() 语义幂等，
   R14 关键记忆 #4 在修复后依然成立（若未来加计数语义须先 dedup）。
4. **a05e602 夹带**：release commit 逐行核过，仅 CHANGELOG+版本戳；
   CHANGELOG "see git log…)" 行疑似截断——实为有意括注（0.6.2-0.6.5
   缺 entries 的如实承认），证伪。
5. **probe() 残留消费者**：全仓 grep `probe()`/`probe fs-flag`——crates
   内零调用点（仅注释/测试名），harness 内仅本轮工具与记录文件。
6. **host 侧清单漂移**：host_probes 6 id 与 ROADMAP 已强制列表逐一对上，
   065 的缺口仅在 guest 侧。

## 实验清理

/tmp/r15-ci-baseline.log 已删；/tmp/r15-064-recheck 由工具自清（终态
ls 无 r15 残留）。仓库本轮产物 = harness/tools/r15-064-recheck/（README +
Cargo.toml + src/main.rs，target/ 按全仓惯例 gitignore 保留）+
findings/065 + INDEX.md 一行 + 本文件。r14-convergence/Cargo.lock 被
cargo run 刷新（0.6.5→0.6.6 版本戳，release 机制等价）后已 git checkout
还原（R12 记忆 #8 的固定动作）。

## 关键记忆（非显然事实，≤10）

1. r14-convergence 裁判现已双证：修复后断言全绿 + r15-064-recheck
   NC1/NC2 证明修复前形态必 die——"裁判绿"从此有鉴别力背书，后续轮
   两个工具都要跑（`sh` 一键各一个 cargo run）。
2. 探针清单核对必须**双向差集**（清单→脚本 + 脚本→清单）：R14 单向
   核对放走了 065。058/063/065 同病三次（声明面人肉同步、无 grep 门禁）。
3. 064 修复的 main.rs 侧是纯注释变更；行为面唯一 delta 是 escape.rs 的
   fs-flag 发射块，EQ1 证明与修复前逐字节等价——该修复零行为风险。
4. guest_script 全文可在 macOS /bin/sh 下 `sh -n` 通过（EQ2）——便宜的
   POSIX 回归守卫，已固化进 r15 工具。
5. proxy-path 强制机制：guest 输出任何含 " ESCAPE" 的行 → exit 1
   （main.rs:407-411）；PASS 需真实订阅节点（QUICKSTART:85）——清单里
   不写它不改变其强制地位。
6. d220e1b 提交时 workspace 还是 0.6.5 → r14 工具的 Cargo.lock 钉 0.6.5，
   任何 cargo run 都会刷成 0.6.6（等价版本戳）；收尾前 git checkout
   还原，git status 必查。
7. QMP powerdown 无读超时（H4 记档的 S3 候选）自 v0.6.1 未变——维持
   记档，不新增立案。
8. 集合比较探针要先 sort 再比——r15 工具首跑 PF1 因 want 表未排序假
   FAIL（探针自身 bug，非仓库洞）；教训与 R14 假报告签名同族：先怀疑
   探针再怀疑被测对象。
9. ROADMAP 清单的 sock-docker·lima-guestagent 一条覆盖参数化 sock-$s
   三运行时 id；清单缺 sock-abstract/proxy-path 后，guest 侧"清单 id
   数（11）≠ 脚本字面 id 数（12）≠ 运行时 id 数（15）"三层不齐。
10. /tmp/vmhome-501-* 历史符链重启自清，不动（R14 记忆 #10 维持）。

## 下一轮建议（按序）

1. **night-17 微批（两行文档修）**：修 065——ROADMAP:38 已强制尾补
   `proxy-path（正向控制，需真实订阅节点）`、待做补
   `sock-abstract（现如实 SKIP）`；顺带对齐 QUICKSTART:84 类别枚举。
   强烈建议同时落地 063 就提过的 ci.sh 探针 id grep 门禁（双向差集）——
   同病三复发，门禁成本低于第四轮人肉复核。
2. **R16 = 收敛判词轮（预期达成）**：增量复核 065 修复（双向差集裁判，
   可复用 r15-064-recheck 扩一节）+ 裁判双跑，零新发现即按 R14/R15
   判词模板给出收敛判词，DRIVER 写 convergence 字段停轮。
3. **平台回填（不阻塞收敛，长期循环项，自 R14 顺延）**：U1-U5 Ubuntu
   实机 + Linux glibc `\]` 转义接受度 + H3 逗号路径 qemu 实证 + 062 的
   QEMU 传输形态同验——全部非本机可验，维持挂账。

## 会话统计

- R15（本轮）：1 新 finding（1×S5，待修复）；064 修复面四层复核全成立；
  6 方向证伪存档；新工具 r15-064-recheck（鉴别力负控 + 12 id 覆盖 +
  行为等价 + sh -n，六节）
- 累计：65 findings；056-064 九项修复全部复核闭环
- 实机消耗：零 VM 时长（裁判与负控均为真 crate 渲染 + /bin/sh 片段），
  CI 一轮，零残留
