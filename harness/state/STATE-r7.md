# STATE — 2026-11-20T02:00:00Z（R7 对抗性审查会话 · 终稿）

## 本轮定位

R7 = night-08 修复面回归 + R6 未尽项。基线 v0.5.2 `281899c`，完整 ci.sh **RC=0**（`/tmp/r7-baseline-ci.log`）。**产出 3 findings（041/042/043），全部待修复**；另有 3 条证伪记录与 1 条泄漏注记。

## 已覆盖（R7 全部方向，无遗留）

- **A1 token 内存化（F-037 回归）**：record token 外部改写→403 死锁：up 去重放行（r3）、stop 唯一自愈门（r5）——**证伪为非 finding**（被同 uid config 改写 fail-closed 自关支配，服务端 fail-dead 方向安全）；gate::open 铸造 TOCTOU（record 换手）：旧 gate 自洽通过绑定但 disowned watchdog 不动 wire → fail-closed，窗口 ≤500ms，证伪；启动窗口（record 先于 accept loop 发布，listener 先行）无洞。
- **A2 sync 先行（F-036 回归）→ F-041（S4）**：**night-08 幂等修复引入回归**——Unchanged 路径 strip_config 剥掉 exit_policy，锚点漂移+revision 不动 → 200 且 gate 保持 Open（m1 bound→bound 换 ip、m3 mode 迁移实证）；m2/m5 对照（revision 变化/timezone→拒），m4 幂等意图本身成立。探针 `harness/tools/r7-sync-matrix`（真实 crate，21/21 PASS RC=0）。
- **A3 grant 绑定（F-036 回归）**：可达时间矩阵 t1-t7 全拒（未来/过期/0/缺省/窗口+1/错 run）；**不可达 fail-open 附注**：时钟 ≤epoch → now=0 + created_at=0 通过，与 gate.rs:92 注释"0 = absent (refused)"矛盾（逻辑读，无时钟控制不可实测）；run_id 泄露面量化：绑定对同 uid 可读 record 域无增量价值（有 record 即有 token），价值在未来多调用方/record 不可读态。
- **A4 戳刷新（R6-H4/F-033 回归）**：eab85aa 语义全部验证——活记录+漂移 → check_running 拒且戳不动（漂移不被洗白）；死记录 → 合法 up 刷新；真实 host_probes 红绿矩阵 NotEnforced/Contained/Escaped ✓；**040（待修复）描述属实**：select 后不 up 探针恒红。探针 `harness/tools/r7-stamp-matrix`（10/10 PASS RC=0）。
- **A5 F-039 后生态**：r7 两探针即外部 path-dep 实证（creance/-gate/-proxy/-vm 四 crate 直连编译运行 ✓）；`cargo publish --dry-run`：creance-net RC=0，其余四 crate 拒（内部 path-dep 无 version 钉）——发布工程注记，非 finding。
- **B1 mihomo 控制器（R6 未验证想法）→ F-042（S4，实机实证）**：external-controller-unix **零 secret**（runtime.rs:90；Go store.go:304 同形=非漂移）；同 uid 无凭证：PATCH mode=direct（HTTP 204，磁盘 config.yaml 仍 rule=零痕迹）、SAFE_PATHS 内 yaml 重载 MATCH,DIRECT 成立、**出口证据预言机被劫持**（宿主 US 出口替代节点失败→任意证据）；check_running 查运行时但不查 mode 且无轮询。guest 不可达（0700 目录）。修复：secret+readiness 补 mode；二源交叉须绕核心。**实验全清理**（proxy-stop、launchd 无 cage 服务、全部 /tmp/cage-proxy-* 验死后删除）。
- **B2 Go 授权集对齐**：`harness/go-authz-alignment.md`——7 维 vs 4 维对照表（11 项 vs 5 项）、三条时间边界差（预铸下界/Renew 重授权/24h 硬顶）、三维绑定落点（gate 侧 check 时快照指纹）、与 F-041/042 交互与对齐顺序（状态层→续期层→铸造层）。
- **B3 attack-surfaces + Go 漂移 → F-043（S5）**：**Go applyProxy 每次 select/restart/route 同步 closeProxyGate（proxy.go:334），Rust select_and_apply 不触碰 gate**——select→proxy-start 窗口 Open+声明新节点+wire 旧节点；R4 在 C5 的预警（Unchanged 分支 exit_policy 静默忽略）0.5 输入面下兑现为 F-041；C2/C4/C5/F3/G3/G4 状态全部更新；C2 未覆盖→已覆盖（R5 已做未记）。

## 证伪记录（本轮尝试未立项，防重复）

1. record token 改写 403 死锁（041 文件"已排除"节，探针 r1-r5）。
2. gate::open TOCTOU（同上）。
3. start_managed 快速路径误判（service::running 经 mihomo API 实查 group selection，select 后正确绕开快速路径）——代码读证实，未立项。
4. **工程教训复验**：`cargo build | tail && run` 管道吃 exit code → 陈旧二进制跑了三轮才察觉（"判绿看真实 RC"再次自伤，探针脚本已改为 `grep -cE ^error` + `-ot` 新鲜度双保险）。

## 环境注记

- /tmp/cage-lima-501-* 短链接历史泄漏 450 个（lima_home 创建无清理者，历轮测试累积）：本轮验死删除 332 个，保留 118 个（目标仍存在的旧 profile 目录，非本轮产物未动）。**泄漏本身是 S5 候选**（lima_home 无清理路径；测试套件每 start 一次泄一个）。
- 本轮无仓库外残留（进程/launchd/socket 目录全清）；crates/scripts/docs 零改动。

## 下一步（按序 3 条）

1. **修复轮**：041（strip_config 保留 exit_policy 比较+回归测试）→ 043（select 后关 gate，复用 night-08 sync 机制）→ 042（controller secret+readiness 补 mode）→ 040（R6 遗留）。四件都是小修，一轮 night 可完。
2. **0.6 授权集对齐**（go-authz-alignment.md 为设计底稿）：三维绑定+Renew 重授权+24h 硬顶+预铸下界；若做二源交叉，源二必须不经核心（F-042 修复方向 3）。
3. 模型驱动逃逸演练 + Devin 介入（用户定时，不变）。

## 关键记忆（≤10 条）

1. **041 的机制**：strip_config 剥 url/revision 由 revision_changed 兜住，exit_policy 无兜底=唯一双盲字段；修复=Unchanged 分支显式比较 normalized exit_policy。
2. **042 的实质**：gate 平面（token 内存化 fail-closed）与 enforcement 平面（控制器零认证）同边界不同强度；证据预言机可被无痕重定向——"rests on subscription honesty"之下还有"rests on controller inaccessibility"。
3. **043 的对照**：Go select=apply（同步撤销 gate），Rust select=declare（等 proxy-start）——幂等保护（proxy-revision 命令）与 select 必关（动作语义）是两个入口，不冲突。
4. mihomo SAFE_PATHS 把 PUT /configs 限制在 managed proxy 目录——但该目录同 uid 可写，重载仍成立；secret 是唯一闭环。
5. R7 探针模式验证：真实 crate path-dep（F-039 后直连可用）+ Rig prepare/drop 模式 + gate-daemon argv 兜底防 spawn_daemon 重入。
6. cargo build 的 exit code 被管道吃掉时陈旧二进制静默运行——探针/CI 链一律存 RC 再判。
7. Go Renew 每次重跑 Authorizes(runID, Configuration, now)——Rust 对齐时 renew 层是 F-041 的续期侧补丁位。
8. lima_home 的 /tmp 短链接无任何清理路径（S5 候选）；批量清理先验死（connect/readlink 目标）再删。
9. baseline RC=0（v0.5.2 完整 ci.sh）；041/042/043 的复现材料：r7-sync-matrix（21 断言）、r7-stamp-matrix（10 断言）、F-042 实机 HTTP 序列（已在 finding 文件内逐步记录）。

## 会话统计

- R7：3 findings（S4×2+S5×1）、4 份文档产出（2 findings 文件已含证伪节、go-authz-alignment.md、attack-surfaces 六行更新）、2 探针工具、1 基线 CI RC=0、实机实验 1 场（全清理）
- 累计 43 findings（036-039 已修，040/041/042/043 待修复=4 个开放项，全部一轮 night 可修完）
