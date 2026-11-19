# STATE — 2026-11-19T16:00:00Z（R6 对抗审查会话 · 终稿）

## 已完成（R6 全部三大攻击面覆盖，5 新 findings，探针 27/27 RC=0）

基线 HEAD 7368663（v0.5.1）。探针 `harness/tools/r6-evidence-probe/`（真实 path-dep crate，经 /tmp 快照绕幽灵清单 F-039；run.sh 端到端可复现）。

- **F-036 S4**：exit-anchor 漂移链零绑定。grant 契约=5 键字符串表（gate.rs:99 注释 "mirroring Go" 不实——Go 是 11 项+RunID+Configuration 指纹+CreatedAt+24h 生命期+Renew 重授权，ref safety.go:54）；daemon 逐命令 applied() 对 co-updated revision 结构性失明；workbench `/api/proxy/start` 完全不 sync（90s 漂移窗口主洞）、CLI proxy-start 先重启后 sync 且 `let _` 吞错。探针 H3 实证：换节点后伪造五键静默再 Open。附带复查 attack-surfaces C5 预埋点：action 层对 Ok 也无条件关 gate（静默担忧不落地），但幂等 no-change sync 也关（注释矛盾，每次 proxy-start 强制重取证）。
- **F-037 S2（边界=同 uid）**：gate 认证 fail-open——record 不可读→`record_token()` 退化空串（每请求重读+unwrap_or_default），空 Bearer 过恒时比较；**无凭证+无证据→check→grant→Open 全链成立**（探针 H2 FULL CHAIN）。Go 用启动时内存 token 恒拒（gate_control.go:99）。guest 不可达（单 workspace 挂载+socket 在 VM 不可达域）；同 uid 进程本可读 token——破坏的是"控制面必须持凭证"不变量本身+close_and_remove 瞬态窗口可在 gate-close 后重开。
- **F-038 S4**：出口证据信任边界量化。**已封死（验证）**：MITM 伪造不可行（webpki 全量校验，egress.rs:616）、核心内差异化路由不可行（单 MATCH+单选组，runtime.rs:97）、parse_trace 畸形 15 项矩阵全 fail-closed（H1）。**开放路径**：出口节点自身对 1.1.1.1 差异化路由（TLS 只保证"终止于 Cloudflare"，不保证路径=其它流量）→ 大陆出口洗白不可检测；evidence.rs:4-12 注释低估一档（wire 信任≠锚定信任）。
- **F-039 S5**：幽灵 workspace 清单 crates/Cargo.toml（git tracked，ff286a6 残尸，0.2.0/your-org）阻断一切外部 path-dep（继承绑定旧版+crates/crates/ 双倍路径，实测 build error）。只读铁律未动，探针快照绕行。
- **F-040 S4**：F-033 回归——fingerprint() 覆盖全 config（含 proxy/revision/exit_policy），任何合法 select/重启使 escape-test 恒报 Escaped（H4 实证前提：select 轮换指纹而 guest 可见字段不变）；running record@up 吸收漂移、setup 戳永久报警——night-07 STATE "双源互补不冲突"结论不成立，实为冲突。

## 已检查未升级（诚实记录）

- **B-1 sources.json 豁免语义成立**：guest 仅 workspace 一个挂载（lima.rs:121，测试断言 mounts.len()==1）；profile 目录（sources.json 落点）不在挂载列表；CREANCE_SESSION_TOKEN 是 guestprofile 发放的唯一 credential_env（guestprofile.rs:111-117），宿主凭据不进 VM；树内无该 token 的宿主消费方（grep 仅 lima/guestprofile/escape 探针排除项）。秘密藏进订阅确实"不可见"，但找不到 guest 路径——豁免语义维持，不升级 S2。
- **B-2 spawn 等待拍收敛成立**：双 up 双 spawn → run_id 交接收敛（F-028 机制）；等待拍的 record+serving 判定在垂死守护场景（record 已删才死）观察不到残 record；残余 TOCTOU（serving 判定后 µs 级死亡→up 返回 Ok 但终态无 gate）窗口极小、下一次 gate 命令可见失败，不升级。
- **B-4 F-034 mv 分支固定正确**：残尸名 node.new 不遮蔽 /usr/bin/node（遮蔽需落在 /usr/local/bin/node）；唯一边角=mv 成功后 chmod 失败（`|| true`）留下 0644 node 且无兜底（同 fs rename 失败概率≈0），记档不升级。
- **serve 面**：无 gate open/grant 端点（只有 import/select/start/stop/check）；POST Origin 校验挡 CSRF；DNS rebinding 拿不到写操作（Origin 必带）。127.0.0.1 绑定不限同 uid（多用户机上他 uid 可调 /api/proxy/*）——单用户 macOS 边界，记档。

## 下一步（按序 3 条）

1. **R6 修复轮（night-08）**：按 036→037→040 优先（036 补 Go 三维绑定+workbench sync；037 token 入内存+fail-closed；040 指纹拆承诺面或降级 Drift 分类）；039 一行 git rm；038 改注释+审计标注。全部走 ci.sh 真实 RC。
2. 0.6 multi-env/snapshots（RELEASES 顺延主题）。
3. 模型驱动逃逸演练 + Devin 介入（用户定时）。

## 关键记忆（≤10）

1. Go SafetyReport.Authorizes 是三维绑定契约（RunID+Configuration+CreatedAt/24h）；Rust 5 键字符串表——"mirroring Go" 注释必须对照 ref 核实，不能信注释。
2. `sync_proxy_revision_with` 返回 Ok ≠ gate 保持状态：action 层对 Ok/Err 都 close——函数注释与包装层行为矛盾，读 gate.rs 要两层一起读。
3. 每请求重读安全材料（record_token）引入 fail-open 退化与 token 混淆两面；Go 的"启动时读入内存"是更稳的模式。
4. TLS 阻断的是内容伪造，不是路径分化：trace 单目的地采样泛化到全流量=未声明的节点同路假设。
5. 仓库只读铁律下，外部 path-dep 用 /tmp 快照副本（删幽灵清单）；快照基线必须写进探针头部。
6. 幽灵 crates/Cargo.toml 是 ff286a6 拆分残尸——外部消费者构建失败先查"最近的 [workspace] 清单"而非依赖本身。
7. 指纹承诺面要拆：guest 可见字段（timezone/locale）vs 宿主侧字段（proxy/revision）——全量哈希把良性操作变成永久逃逸误报。
8. cargo path-dep 的 workspace 继承解析：外部加载不做成员归属校验，直接绑最近祖先清单。
9. 探针跑真实 crate（path-dep）而非逻辑复刻——本轮三次"预期错误"全靠真实行为纠正（C5 静默、ENOTDIR、grant body 结构）。
10. 管道吃 RC：判绿必须 `cmd > file; RC=$?`（run.sh 沿用）。

## 会话统计

- R6：5 findings（036-040），探针 27 断言全绿 RC=0（run.sh 端到端复验）
- 覆盖：A1（trace 伪造量化）/A2（时序窗口）/A3（注入面）/A4（绕过面）/B1-B4 全部/C（Go 对比四处语义漂移+attack-surfaces C5 预埋点复查）
- 仓库零修改（只读铁律）；/tmp 快照与残留临时目录已清理
- 环境：无残留进程/目录；探针自身临时目录用后即删（run.sh 每次重建快照）

## 停止建议

R6 任务书 A/B/C 三面全覆盖：A 面四方向全部有实证结论（探针+Go 对照），B 面四方向全查（1 个升级为 finding，3 个豁免/记档），C 面 attack-surfaces 可加深点（C5 预埋）已复查。剩余风险清单：①多用户主机上 serve 无鉴权面（记档未升级）；②external-controller-unix 核心控制 socket 的同 uid 暴露面（F-038 未验证想法）；③真实出口节点的差异化路由无法本机复现（设计边界记录）；④F-036 修复若引入 renew 调用方必须同时补绑定字段（否则窗口无界）。建议停止 R6 审查、转入 night-08 修复轮。
