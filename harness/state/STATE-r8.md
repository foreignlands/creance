# STATE — 2026-11-20（R8 · night-09 修复面回归 + 收尾 · 审查收敛）

## 已覆盖（attack-surfaces 条目号 + 一句话结论）

- **F-041 面**（r8-regression H1，真实 Gate+GateClient 7/7 PASS）：修复后矩阵全 fail-closed。任务书问的"部分绑定落哪支"——落 branch 1：原样重写=Unchanged（Open 保持），填格仍欠=Err 需重启；等价锚（raw "us"）经 load 时 normalize 判 Unchanged，无误判；un-bind 被拒。`bind_missing` 无生产调用者，部分绑定只能来自手改 config。无新洞。
- **F-040 面**（H2 + 源码盘点）：host 侧变化探针保持绿 ✓ 修复意图成立；但 **FINDING-044 S4**——up 无条件刷戳把 stop→edit→up 的 guest 真实漂移洗绿（vm::up=裸 limactl start 不重供给；探针 h2.3 FAIL 实证）；**FINDING-045 S5**——browser_language 承诺无供给路径（Go 经 CAGE_LANGUAGE 注入，Rust CAGE_* env 链整条缺失）；dns_url 两版同形硬编码不进 guest 解析（F-040 排除正确）。
- **F-042 面**（H4 假核心在环）：**FINDING-046 S4**——check_running 对账集五字段+组选择不含 /rules，规则级翻转自述穿透（h4.1/h4.2）；负对照 mode=direct 被拒=修复对已记录攻击有效（h4.3）。TOCTOU（check→observe ≤25s）不独立成洞（被对账集盲区吸收）；同源限度=对账只信核心自述；SAFE_PATHS 同 uid 内不可收窄（设计地板）；unix 免鉴结案不动。
- **F-043 面**（H3 + 源码对照）：正向路径实证 ✓（在服 gate 即撤、死记录清理）；**FINDING-047 S5**——close 失败分支 `let _` 吞错 vs Go 事务性中止+回滚；窗口 ≤90s 有界（renew 零调用者→lease 必到期）且窗口内再 open 被 check_running selection 拒，无取证重复路径。
- **收尾**：attack-surfaces 全图无"未覆盖"，A1/F1 进行中收口；Go 漂移抽查（applyProxy 动作面）——route/链式无 Rust 缺口，validateProxyCore 前置=UX 漂移不立案，applyProxy 回滚语义差距=F-047。

## 进行中

无（本轮全部闭环）。

## 下一步（按序 3 条）

1. **night-10 修复面**（4 findings，全部 0.5 内可修）：F-044 删 refresh_fingerprint_stamp+up 拒绝 guest 指纹漂移+反转 up_refreshes_a_stale_stamp 测试；F-046 对账补 /rules 比对（生成侧单 MATCH 结构固定，一次 API 调用）；F-047 close_gates 挪 select 前+传播错误；F-045 补 CAGE_* env 注入或缩承诺（0.6 权衡）。
2. **R9 仅做修复面回归**（r8-regression 可直接复用/扩展）：若 night-10 后无新面，审查循环按收敛建议停止。
3. 0.6 主线：Go 授权集完整对齐（11 项+config 指纹三维，含 F-046 的二源交叉落点）或 multi-env/snapshots（按用户节奏）。

## 关键记忆（本轮学到的非显然事实，≤10 条）

1. `renew` 动作全仓库零调用者——Open gate 必然 ≤90s lease 到期关闭；所有"持续开 gate"窗口都由此有界。
2. `vm::up`=裸 `limactl start`，无 `--restart-provision`：Lima provision（timezone/locale-gen）只在 create 首启生效，存量 VM 不重供给——一切"改 config 后 up 就生效"的假设对供给面字段不成立。
3. F-040 后 `refresh_fingerprint_stamp` 的原始动机（revision 进戳）已消失——它现在只能把 guest 真实漂移洗绿（假阴性），是纯害处。
4. mihomo `PUT /configs` 重载可保 `mode: rule` + 保留 CAGE selector 组并预选回 store.selected——五字段自述全真而规则已换；`/rules` 是唯一能看见它的 API。
5. mihomo unix controller 免鉴=设计（文件权限即鉴权）；SAFE_PATHS=核心 config 所在目录，属主即同 uid，同 uid 边界内不可收窄。
6. `bind_missing` 无生产调用者（仅测试）——exit_policy 绑定只走手改 config 的路径。
7. `config::load` 就地 normalize exit_policy——sync 的等价锚比较天然无误判；`write_private_config` 只校验不归一。
8. core 的 DNS 段两版（Go store.go:303 / Rust runtime.rs:49-59）都硬编码 bootstrap+1.1.1.1，cfg.dns_url 是纯 host 侧（fetch/observe Egress）——guest 解析路径与它无关。
9. Go applyProxy 事务性：closeProxyGate 失败→中止+defer 回滚 store/config；Rust select 先落地后吞错——失败语义的结构性差异。
10. crates.io 不可达环境的探针离线构建：拷邻近探针的 Cargo.lock + `--offline`（缓存已含依赖）。

## 审查收敛建议（停止条件判定）

attack-surfaces 全部条目已标记"已覆盖/已穷尽 N 变体"，无未覆盖项；R8 四个新 findings 全部属于 night-09 修复面的残余/边界（0.5 内可修或 0.6 权衡面），非新攻击面。**建议：night-10 修复 044-047 后做一轮纯回归（R9，复用 r8-regression），无新洞即正式停止夜循环审查线。**

剩余风险清单（如实，停止后仍开放）：
- 同 uid 威胁边界整体（F-042/F-046 的地板：unix 控制器+SAFE_PATHS+核心自述对账）——0.6 降权运行/二源交叉才能实质性收窄；
- F-038 单目的地采样边界（洗地面已由 F-046 收窄一层：同 uid 可自装洗地路由；跨 uid 仍依赖订阅诚实性）；
- go-authz-alignment.md 三维绑定/24h 硬顶/Renew 重授权未落地（0.6 主面）；
- F-047 的 ≤90s 三方不一致窗口（修复前存在，有界自愈）。

## 会话统计

- R8：4 findings（044 S4 / 045 S5 / 046 S4 / 047 S5），累计 47。
- 探针 harness/tools/r8-regression：19/20 PASS，唯一 FAIL=F-044 实证；H1 矩阵 7/7 证 F-041 修复无回归。
- 仓库改动全部在 harness/（findings 044-047、INDEX、attack-surfaces、tools/r8-regression）；crates/ 零改动；/tmp 无残留；CI 未重跑（crates/ 无改动，985a5a2 基线 RC=0 由 night-09 会话保证）。
