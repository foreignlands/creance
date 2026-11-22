# STATE — R18 终稿（2026-11-22，night-auditor-v5，基线 1f307ef v0.6.9）

## 轮次定位

收敛判词轮第四次尝试（任务书 / STATE-r17 下一轮建议第 2 条）：增量复核
067 修复（289144d，night-19：README 删幽灵短语+删除注记，`readme-enforced`
标记块进 scripts/check-probe-inventory.sh 双向差集门禁）+ 邻接面续扫
（README/QUICKSTART 其余声明、harness/ 自身文档、attack-surfaces×INDEX）。
基线 `sh scripts/ci.sh > /tmp/r18-ci-baseline.log 2>&1; RC=$?` **真实
RC=0**（Linux/x86_64；fmt/clippy/probe-inventory/test/release 全过，14 个
test-result 块，零 FAILED/panicked；cfg-gated macOS 代码本机未编译——
本轮不宣称 macOS 绿）。

## 067 修复面裁定：**修复成立（全负控矩阵 + 正控 + 裁判双跑）**

| 核验点 | 结果 | 证据 |
|---|---|---|
| 正控 | **绿** | `probe inventory: bidirectional diff empty (guest 12 code ids, host 6)` RC=0 |
| NC-A README 块塞幽灵 id | **红，1 行 RC=1** | perl 在 README 块 `proxy-path` 后追加 ` / ghost-probe-r18`（grep -c=1 确认落地）→ "FAIL: README enforces probe 'ghost-probe-r18' but the code never emits it" |
| NC-B README 块删真实 id | **红，1 行 RC=1** | 删 ` / net-icmp-external`（grep -c 'net-icmp-external /'=0 确认）→ "FAIL: README enforcement block is missing 'net-icmp-external' (code emits it)" |
| NC1 ROADMAP 块删 proxy-path | **红，1 行 RC=1** | grep -c=0 确认 → "guest probe 'proxy-path' emitted by escape.rs but absent from ROADMAP inventory" |
| NC2 ROADMAP 块塞 ghost-probe-r18 | **红，1 行 RC=1** | grep -c=1 → "ROADMAP enforces guest probe 'ghost-probe-r18' but escape.rs never emits it" |
| NC3 escape.rs 植入幽灵字面发射 | **红，RC=1，2 行（预期变化）** | grep -c=1 → ROADMAP 方向 + README 方向各 1 行——R17 时为 1 行，第 2 行正是 289144d 新增 README 对账的兑现，非回归 |
| NC5 guest-enforced 标记改名 | **红，11 行 RC=1** | grep -c=2 → 11 行（与 R17 逐数一致；sock-abstract 经 todo 块仍被追踪） |
| NC6 删 sock-$s 发射点 | **红，1 行 RC=1** | perl 删 escape.rs 注释+for-loop 三行（grep -c=0）→ "FAIL: sock-$s family emission site missing from escape.rs…" |
| 还原 | **byte-identical** | 全部 `cp` 备份还原（零 `git checkout --`）；md5sum -c 快照：README 24ff933a…、ROADMAP 5cae246f…、escape.rs 6b3d03f2… 全 OK；git status 干净 |
| 裁判双跑 | **双绿** | r14-convergence RC=0 七节 [A]-[G]；r15-064-recheck RC=0 六节 NC1/NC2/PF1/PF2/EQ1/EQ2。**偏差如实记录**：`cargo run --offline` 两者 RC=101（本机 cargo 缓存无工具 lockfile 要求的 clap 4.6.9），改为联网 `cargo run` 后双绿；工具 Cargo.toml 的原作者 macOS 绝对路径以仓库外临时符链兼容（已删）；Cargo.lock 版本戳漂移已 `git checkout --` 还原 |
| 三声明面对齐 | **成立** | 三形态 grep（`proxy-numeric-endpoint` / `numeric proxy endpoint` / 数值端点·永久绿·空探针）全仓残留均为删除历史注记（README:76、QUICKSTART:90、ROADMAP:53、CHANGELOG:12、escape.rs:82、门禁头注、AUDIT 文档、attack-surfaces E5），零现在时宣称 |

## 发现清单（3 项，068-070；INDEX 已登记）

| # | 严重度 | 一句话 | 证据等级 |
|---|---|---|---|
| 068 | **S4** | fs-flag-readable 旗标 oracle 从未被放置：全仓仅 main.rs:360 推导路径、零写入（69bce85 首提交至今），默认流程该探针恒 PASS=空探针，而 README/QUICKSTART/ROADMAP 均称"已强制" | 新工具 r18-flag-oracle（真实 guest_script()+environment_dir()，宿主全盘可见下 S1 仍 PASS）+ grep/git -S 全历史 |
| 069 | S5 | ESCAPE-BRIEF:15-17 指示的手工旗标路径 `<workspace>/.creance.escape-flag` 与检查路径 `<environment_dir>.escape-flag` 名、位均不同且自相矛盾——照文档的活体演练裁判恒 PASS | 同工具 S2 + 逐行对照 |
| 070 | S5 | README:65 / harness/README:18 "20 项/20 个测试方向"（实 45 条）；attack-surfaces H 节标题"全部未覆盖"与 H1-H7 已覆盖矛盾；尾注重复 | 零操作 grep 计数 |

定性：068 打破了"S1-S4 连续五轮零新发现"——它不是声明面漂移，而是
探针本身说谎（F-011 sock-abstract 硬编码 PASS 同类定级 S4）；被 18 轮
漏掉的原因是五层自动化（门禁/缺行网/r14/r15/E2 复核）全部以"PASS 行
到达"为成立条件，没有一层问"oracle 前提是否成立"。

## 收敛判词（R18，基于证据）

**"零新发现"判据未满足 → 收敛判词不发。** 067 修复面十点核验全部成立，
但邻接面续扫（任务书焦点 B 第 2 项 harness/ESCAPE-BRIEF）沿旗标路径追到
产品代码，实测出 068（S4）——S1-S4 零发现连续计数归零，比前三轮的 S5
声明面漂移更重。连续第四轮"修复面成立仍因新立案不发判词"
（R15→065，R16→066，R17→067，R18→068-070）。

## 已攻击未破（证伪/排除/记档记录，不计 findings）

1. **README/QUICKSTART 安装路径与命令**：README Quick Start 只列
   `install.sh`，但明标"概览"并链 QUICKSTART（其 :9 先 fetch-proxy-core）；
   install.sh:30-34 缺核心时提示先 fetch——不立案。安装位 `~/.local/bin/creance`
   两文档一致；平台表（macOS14+ Lima vz / Ubuntu x86_64 QEMU）与 QUICKSTART 一致。
2. **README Status "v0.6.0 — Linux platform support"**：里程碑叙述而非当前
   版本宣称（CHANGELOG/Cargo.toml=0.6.9），不立案；其中"escape-test green on
   every enforced layer"在 fs-flag 层为空真，已并入 068 声明面。
3. **harness 文档引用路径存在性**：OPERATOR-PROMPT/FIXER-PROMPT/README/
   ESCAPE-BRIEF/tools/README 中反引号路径逐一 `-e` 核验，全部存在（相对
   路径解析后）；FIXER-PROMPT、tools/README 为带轮次时间语境的历史文档
   （R1-R12/night-03），不按现在时宣称立案。
4. **findings 编号与 INDEX**：001-067 文件连续无 GAP，INDEX 67 行与文件
   一一对应、067 状态如实翻"已修复（289144d）"；本轮 068-070 接续。
5. **旗标路径注入面**（F-011 未验证想法遗留）：flag 由 CLI 从
   environment_dir 推导，D3 已覆盖伪造面；本轮未见新路径——不立案。
6. **门禁新增 README 段自身**：block() 参数化后 ROADMAP 三块解析不变
   （NC1/NC2/NC5 行数与 R17 一致）；README 块缺失形态=空集→每个代码 id
   各报 missing，fail-closed（由 NC-B 同一代码路径推得，未单独变异）。

## 实验清理

/tmp/r18-ci-baseline.log、r18-ci-rc、r18-nc.sh、r18-bak、r18-nc.out、
r18-md5-snapshot.txt、r18-judge{1,2}.{out,err}、r18-oracle.{out,err} 全部
删除；r18-flag-oracle 运行时临时目录由工具自删；负控变异全部 `cp` 还原
并 md5 核对；两裁判 Cargo.lock 版本戳 `git checkout --` 还原；仓库外兼容
符链 /Users/shenyiyu/Documents/zcode/claude-cage-rs 已删（父目录空壳留存，
仓库外、非敏感）。仓库本轮产物 = findings/068-070 + INDEX 三行 +
attack-surfaces（E2 行注记、H 标题注记、尾部 R18 注）+ 新工具
harness/tools/r18-flag-oracle/（target/ 被 .gitignore 排除）+ 本文件。

## 关键记忆（非显然事实，≤10）

1. **"PASS 行到达"≠ 探针成立**：门禁/缺行网/裁判都只验 id 在场与有回答，
   不验 oracle 前提；068 存活 18 轮。复核探针要问"什么条件下它会报 ESCAPE，
   该条件在默认流程里能否成立"。
2. 文件系统旗标：检查路径 `format!("{}.escape-flag", environment_dir)`
   （workspace 兄弟路径），全仓无放置；ESCAPE-BRIEF 写的是另一个路径（069）。
3. 289144d 后 NC3 是 2 行 FAIL（ROADMAP+README 两方向），不是回归。
4. 裁判工具 `--offline` 在本 Linux VM 失败（缓存缺 clap 4.6.9）；工具
   Cargo.toml 用原作者 macOS 绝对路径，需仓库外符链；跑完删。
5. 三形态 grep（连字符/空格/中文）本轮全仓残留均为历史注记。
6. attack-surfaces 计数 45 条（A-H），"20"是初版遗留（070）。
7. 负控 RC 一律直取、注入前 grep -c、cp 还原 + md5——本轮零管道、零 git checkout 还原产品文件。
8. 收敛判据仍是"零新发现"；邻接面"文档→代码"顺藤摸瓜比纯文档对照更有产出。
9. /tmp/vmhome-501-* 历史符链维持不动（顺延）；本轮零 VM 时长。
10. 068 修复后的复核应有行为证人：r18-flag-oracle S1 预测需翻为"放置后 ESCAPE"。

## 下一轮建议（按序）

1. **night-20 修复批**：068（escape-test 运行前放置/运行后删除旗标，或未放置
   时降 ⏭️ SKIP 并改三声明面；加单测断言运行时旗标存在）→ 069（ESCAPE-BRIEF
   与之同步）→ 070（去写死"20"；attack-surfaces H 标题/尾注由审查员清理）。
2. **R19 = 第五次收敛判词轮**：复核 068 要有行为负控（删放置代码→某层必红）；
   用 r18-flag-oracle 更新预测重跑；继续"oracle 前提"视角扫其余 guest/host
   探针（net-* 判据靶点、proxy-path、guest-identity 期望用户来源）。
3. **平台回填**（不阻塞，顺延）：U1-U5 Ubuntu 实机、H3、062 QEMU 形态；068
   的真实 VM 内验证。

## 会话统计

- R18（本轮）：3 新 finding（1×S4、2×S5，均待修复）；067 修复面十点核验全
  成立；门禁矩阵 8 场景（正控/NC-A/NC-B/NC1/NC2/NC3/NC5/NC6）；裁判双跑双绿
  （联网偏差已记）；新工具 1（r18-flag-oracle）
- 累计：70 findings；067 修复复核闭环，068-070 待修
- 实机消耗：零 VM 时长，CI 一轮，零残留
