# STATE — 2026-11-20T22:30:00Z（R12 收敛第四试 · 终稿）

## 判定：审查收敛，建议停止循环

R12 纯回归收敛，零新发现（findings 维持 55/55 全闭环）。F-055 修复面三层验证
全绿，night-13 diff（单 commit 3413cc9）小扫无新洞。十一轮 + 四收敛试正式收官，
建议停止夜间循环；后续归 0.6（Go 授权集 11 项 + config 指纹三维 / multi-env）。

## 已覆盖（本轮验证面，全部通过）

1. **F-055 修复面·静态**：`crates/creance-vm/src/lima.rs:179-192` 引号层逐字符
   核对——`linux-$ARCH/bin/node`（:185）全程处于内层单引号文本（181 行
   `'"$APT_OPTS"'` 之后到 192 行闭合之间无任何 `'`），与 :182 的 ARCH 赋值同一
   内层 shell，归属正确。唯一跨引号形态是 `'"$APT_OPTS"'`（外层变量，合法）。
2. **F-055 修复面·单测断言自洽**：lima.rs:318-328——`contains("linux-$ARCH/bin/node")`
   + `!contains('\"$ARCH`（:326 的 format! 构造等价于该字面量）只封禁旧跨引号
   形态，不误伤 `'"$APT_OPTS"'`。
3. **F-055 修复面·动态（复刻探针）**：`harness/tools/r11-regression/f054-provision-quotes.sh`
   复跑 PASS rc=0；负控（/tmp 副本回填旧形态 `'"$ARCH"'`）rc=1、URL 架构段空——
   探针具鉴别力，非恒 PASS。
4. **F-055 修复面·动态（真实文本，本轮新增第三档）**：
   `harness/tools/r12-provision-real/`（path-dep 真实 `generate_lima_yaml`）——
   P1 真实文本 dash 实机执行 URL 含架构段；P2 真实文本负控复现空段；P3a
   可执行变体与原文差异仅 5 处 /etc 重写（8 diff 行，工具链段字节不动）；P3b
   工具链段与 r11 复刻探针逐字节等价（仅 F-034 两行注释差）；P4 假 uname=aarch64
   （真实 guest 语义）→ linux-arm64。整份生成脚本在 dash+stub 下从头跑到尾
   （real-exec rc=0）。TRUE_RC=0。
5. **night-13 diff 全量小扫**：r11-regression/src/main.rs（H1 五 case + H2 双锚
   HEAD 复跑全 PASS）、f052-up-branches.sh（4/4 PASS）、r9/r10 Cargo.lock 仅
   0.5.5→0.5.6 版本戳（release 机制，等价）、新增测试块断言自洽。
6. **CI 基线**：`sh scripts/ci.sh` 真实退出码 RC=0（日志 /tmp/r12-ci.log 内
   CI_RC=0；fmt+clippy -D warnings+test 全绿）。

## 进行中

无。

## 下一步

1. **停止夜间审查循环**（本判定为最终判定；除非 0.6 引入新攻击面后重启）。
2. 0.6 开发：Go 授权集 11 项 + config 指纹三维 / multi-env（用户节奏）。
3. 模型演练 + Devin（用户定时）；0.6 合入后可按需开一轮 R13 快速回归
   （r11/r12 探针均可复用，r12 探针 `sh run.sh` 一键）。

## 关键记忆（非显然事实）

1. F-055 修复语义三层等价：静态引号归属 = r11 复刻探针 = r12 真实文本探针，
   三者结论一致且 r11 复刻与生成文本工具链段逐字节等价（P3b）——复刻型探针
   无漂移。
2. 单测断言只钉 URL **形态**：若 ARCH 赋值行（lima.rs:182）被删，:321 断言仍绿；
   行为面由动态探针兜住（空展开 → r11 负控判据/r12 P2 判据命中 FAIL）。
   未来若动 provision 工具链段，动态探针必跑。
3. 整份生成 provision 脚本可在 macOS dash+stub 下跑通（real-exec rc=0），仅
   需 5 处 /etc 绝对路径重写（宿主 /etc 不可写 + set -e 极早中止）；重写清单
   见 r12 main.rs 头注。
4. macOS `uname -m` = `arm64`，Linux guest = `aarch64`——生成脚本的 case 分支
   在 macOS 直跑恒落 x64；两个分支已分别用 P1/P4 动态钉死。
5. 探针卫生教训：stub 建完必须 chmod +x，否则 PATH 静默跳过回退真命令
   （P4 首跑 FAIL 即此因，非仓库洞）。
6. r11-regression/src/main.rs 是自评式探针（打印 FAIL 但恒 rc=0）——工具卫生
   备注；f054-provision-quotes.sh 与 r12 run.sh 的 rc 是真判定。
7. scripts/ci.sh 不触及 harness/tools/——探针目录新增不影响 CI 基线有效性。
8. cargo run 探针会顺手刷新 tracked Cargo.lock（r11 的被刷新后已 git checkout
   还原）；收敛轮收尾务必 `git status` 核对不留意外痕迹。

## 会话统计

- R12（本轮）：0 新 findings（纯回归收敛，验证面 6 项全过）
- 累计：55 findings，十一轮全闭环；审查收敛，建议停止循环

## 剩余风险清单（停止时留档）

1. provision 在真实 guest（Ubuntu 24.04 arm64）上的实机全链未在本轮重验
   （r9 时代 setup→up→shell→stop 实测可用；本轮 diff 未触及该路径的运行语义）。
2. sudoers 剥夺行（lima.rs:212 sed `\#...#` 定界）在真实 guest 依赖 GNU sed；
   BSD/GNU 均支持该定界形式，风险极低，未单独实测。
3. guest 出网仍未收口（ROADMAP 已知项，非本轮新增）。
4. 未验证想法：无新增。
