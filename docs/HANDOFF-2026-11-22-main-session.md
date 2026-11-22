# HANDOFF — 2026-11-22 主会话（macOS 侧）交接文档

> 交接背景：用户于 13:3X 一键停止全部任务并归档会话（含夜审绑定会话与在飞的
> R18 审计）。本文档供**新开会话**的主会话（主刀模型）直接续任务使用。
> 配套记忆：`creance-night-loop-protocol`（v6）、`claude-cage-rs-project-state`、
> `creance-user-directives`。

## 1. 项目当前状态（一屏）

- **版本**：v0.6.9（`7901e42`，已推 main+tag；HEAD=`9ae0108` 补漏 commit）。工作树干净。
- **findings**：001-067 全闭环。最近四项（064-067，全 S5）由 night-16..19 四个
  修复批各自闭环：064=探针字面发射；065=ROADMAP 标记块+探针 id 双向差集门禁
  （`scripts/check-probe-inventory.sh`，已进 ci.sh）；066=门禁 sock-$s 家族发射点
  守卫；067=README 幽灵短语删除+**README 强制块进门禁**——三声明面
  （ROADMAP/QUICKSTART/README）看守强度已拉平。
- **审计态势**：S1-S4 安全语义面连续**五轮零新发现**；收敛判词连续三次未发
  （R15/R16/R17 各被一个 S5 声明面漂移立案挡下，见 STATE-r15/16/17.md）。
- **R18**（第四次收敛尝试）13:13:54 已派发但被用户一键停止，**无终稿、零残留**
  （harness/state/ 无 r18 产物，findings 无 068）。

## 2. 新测试协议（用户 2026-11-22 拍板，覆盖此前一切架构）

**主会话自己开 GLM-5.3-Flash 子代理做测试；不做任何跨会话。**

- 废弃清单（未经用户明确同意不得复活）：cron 自动化任务（已删
  automation-a9fc72a8）、绑定会话（已归档 sess_a135bbcf）、DRIVER.md 状态机
  （/Users/shenyiyu/Documents/zcode/creance-loop/DRIVER.md，已加退役横幅）、
  推送协议/哨兵/SendToSession 一切跨会话接力。
- **关键机制红利**：agent 定义 `~/.zcode/agents/night-auditor-v2.md` 已指向
  `account:bigmodel-start-plan/GLM-5.3-Flash`，而模型随**会话启动时快照**——
  **新开的会话快照即 start plan**，主会话直接
  `Agent(subagent_type="night-auditor-v2", run_in_background=true)` 就是
  免费套餐 Flash（旧会话快照 individual 的问题随新会话自然消失）。
- 子代理完成**自动通知主会话**（R10-R12 时代实证零轮询零丢失）——不再需要
  哨兵/推送/状态机，循环退化为主刀一个人的节拍：
  `spawn 审计子代理 → 通知到 → 读终稿 → 修 findings → 发版 → spawn 下一轮`。
- 审计任务书模板（自包含）：cd 仓库根；读 harness/OPERATOR-PROMPT.md 全文
  +最新前轮终稿（harness/state/ 下最新 STATE-r*.md）；按 harness/attack-surfaces.md
  与本轮重点执行；findings 接续 INDEX 编号；终稿写 STATE-r<N>.md；**只记录不修复**。

## 3. 新会话的第一步（按序）

1. **重跑 R18**（第四次收敛尝试，重点照抄 R17 终稿"下一轮建议"+被杀任务书）：
   增量复核 067 修复（裁判=README 块负控 NC-A/NC-B 必红+门禁矩阵
   NC6/NC1/NC2/NC3/NC5 回归+正控+裁判双跑）+ 邻接面续扫（README/QUICKSTART
   其余段落、harness/ 自身文档 ESCAPE-BRIEF/README/FIXER-PROMPT/OPERATOR-PROMPT
   声明面、attack-surfaces 注记与 INDEX 交叉一致性；grep 三形态：连字符/空格短语/中文）。
   findings 从 068 接续。零新发现 ⇒ 写收敛判词。
2. **收敛后**：开 0.6.x 最后两个功能版（ROADMAP v2）：
   **运行时熔断**（断代理→切断 guest 出口 ≤2s 零泄漏）→ **浏览器进 guest**
   （按需 OAuth 通道+四元组一致性探针）→ 防探测洗白收尾。
3. 长期尾项（每版发布后滚动，不阻塞主线）：U1-U5 Ubuntu 实机回填
   （harness/tools/r13-regression/SPEC.md）、GPG 镜像验签、ERE glibc 侧、
   H3 逗号路径。

## 4. 工程纪律（踩过的坑，新会话必读）

- 判绿必须存真实 RC（`sh scripts/ci.sh > log 2>&1; RC=$?`），**禁管道**。
- 时间戳落盘前先 `date` 实测（两次超前翻车记录在案）。
- 裁判双跑固定动作：r14-convergence + r15-064-recheck 各 `cargo run --offline`，
  跑完 `git checkout -- harness/tools/*/Cargo.lock`（版本戳漂移），`git status` 必查。
- 门禁负控：改 ROADMAP/README/escape.rs 做变异测试时**用 cp 备份**，禁
  `git checkout --`（会清掉未提交修复）；注入前 `grep -c` 确认落地。
- 负控矩阵现况：正控 12+6 差集空 / NC1 删 id / NC2 幽灵 id / NC3 幽灵发射 /
  NC5 标记漂移 / NC6 家族发射删除 / NC-A README 幽灵 / NC-B README 漏报——全单行红。
- 提交前 `git status` 核对 `??` 列表（9ae0108 教训：audit commit 漏加 finding 文件）。
- 版本 bump 后 `cargo update -w --offline` 刷 Cargo.lock 再 --locked CI。
- 声明面修改后跑 `sh scripts/check-probe-inventory.sh`（已进 ci.sh，本地先跑省时）。

## 5. 版本与角色（不变）

- 版本阶梯：ROADMAP v2（0.6.x 硬化收尾→0.7 用户安心功能批→0.8/0.9 其他 LLM
  审核→1.0.0 GA 付费投流）。注意 0.6.6-0.6.9 已被审计尾批消耗，**熔断=下一版**。
- 分工：主会话（强模型）=唯一主刀（代码/修复/CI/发版）；Flash 子代理=陪练
  （只测试只记录）。仓库 https://github.com/foreignlands/creance；
  记忆仅本地不推送；平台 macOS+Ubuntu（Linux 回填=长期尾项）。
