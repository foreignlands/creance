# F-041 — proxy-revision 幂等 Unchanged 路径对 exit_policy 锚点漂移失明：开放 gate 跨锚点变化存活，无重检查、无重启要求

- **严重度**：S4（S2 邻近——见"威胁模型"）
- **攻击面**：C3/C4（gate 控制面）· night-08 F-036 修复面回归（R7-A2）
- **状态**：待修复
- **基线**：v0.5.2 `281899c`；完整 ci.sh RC=0（R7 记录 `/tmp/r7-baseline-ci.log`）
- **复现**：`harness/tools/r7-sync-matrix/`（真实 crate path-dep；21/21 断言与预测一致，RC=0）

## 结论一句话

night-08 的 F-036 修复给 `proxy-revision` 增加了幂等 Unchanged 路径（`Ok(SyncOutcome::Unchanged)` 保持 gate 状态），但该路径的配置比较用 `strip_config`，**把 `exit_policy` 从比较中剥掉了**——于是"锚点变化但 revision 不动"的配置修改走 Unchanged 返回 200，gate 保持 Open。锚点（mode/scope/ip/国家等）是 exit_consistency 证据的判定基准；基准变了，已开 gate 的证据没有按新基准重判，也没有任何重启要求。修复前每次 sync 无条件 close（粗但 fail-closed），反而挡住此路——**这是 night-08 修复引入的回归**。

## 复现（探针 m1/m3，真实 Gate + GateClient）

前置：`Gate::start`（recorded 快照 = static/ip=203.0.113.7）→ 真实 grant 流开 gate（Open）→ 改 config.json 的 exit_policy（**revision 不动**，store/config 均不动 revision）→ `GateClient::sync_proxy_revision()`：

| 矩阵 | 变化 | revision | 期望（fail-closed） | 实测 |
|---|---|---|---|---|
| m1 | static/ip=203.0.113.7 → static/ip=198.51.100.9（bound→bound 换锚点） | 不动 | Err → close | **200 Unchanged，gate 保持 Open** |
| m2 | 同 m1 | 变化（store+config 成对） | Err → close | 409 Err → close ✓（only_completed 拦截） |
| m3 | dynamic/any → static/ip=203.0.113.7（mode 迁移） | 不动 | Err → close | **200 Unchanged，gate 保持 Open** |
| m4 | 无变化 | 不动 | 200 Unchanged，Open 保持 | ✓（修复意图本身成立） |
| m5 | timezone 变化 | 不动 | Err → close | 409 Err → close ✓（其余字段受 strip 比较） |

对照 m2/m5：同一锚点变化只要**伴随 revision 变化**就被 Adopted 路径的 `exit_policy_only_completed` 正确拒绝——洞被精确定位在 **Unchanged 路径的比较集合**，而非 Adopted 路径。

## 根因（文件:行号）

- `crates/creance-gate/src/gate.rs:675-680`：`!revision_changed && !binding_completed` → `strip_config(&old) == strip_config(&new)` 判 Unchanged。
- `crates/creance-gate/src/gate.rs:733-739`：`strip_config` 剥掉 `exit_policy`、`proxy_url`、`proxy_revision`。proxy_url/revision 的漂移由 `revision_changed`（gate.rs:668-669）单独兜住；**exit_policy 没有任何兜底**——它是唯一一个既不在 `revision_changed` 里、又被 `strip_config` 剥掉的字段。
- `binding_completed`（gate.rs:670-674）只覆盖"needs_binding → 绑定完成且 mode/scope 不变"一种形状；bound→bound 换 ip、mode 迁移、绑定擦除都落到 Unchanged。

## 威胁模型与残余窗口

- 触发面：任何对 config.json 的同 uid 写（合法工具流、workbench 未来加配置编辑、手工编辑）。写完后任意一次 `proxy-revision`（CLI/workbench `proxy-start` 的固定前置）即静默确认。**gate 自身对锚点漂移零感知**。
- 同 uid 攻击者本可杀进程/改 config（DoS 面），但"能摧毁"≠"能静默颠覆"：本洞让锚点变更**无证据重判、无错误、无日志**地生效——gate 的核心承诺（"配置变更即重新检查"）被绕过，且 escape-test 类探针（040）之外无任何观测点。
- 时间窗：90s OPEN_LEASE 到期 watchdog 会 close；但 `renew` 只验 report_id（gate.rs:604-620），配合 renew 可无限续期——**配合 renew 时无硬顶**（Go 在 renew 时重授权，036 已记为 0.6 对齐项）。
- m1 事实上的语义：gate 持旧证据（按旧锚点判定通过）继续放行 wire，而 config 声明新锚点——declared/verified 分叉。

## 修复方向（记录，不实现）

Unchanged 分支必须显式比较 exit_policy：`old.exit_policy.normalized() != new.exit_policy.normalized()` → `Err("出口地址或环境设置变化需要重启环境")`。即 `strip_config` 保持剥 url/revision（它们由 revision_changed 兜住），**但不再剥 exit_policy**；绑定完成形状仍由 Adopted 路径独占。回归测试：m1/m3 两形状 + m4/m5 对照。

## 附注（同区域逻辑读，探针不可达，未复现）

1. **created_at=0 + now=0 fail-open（时钟 ≤ epoch）**：`bound()`（gate.rs:573-577）为 `created_at <= now && now - created_at <= window`；`now` 由 `duration_since(UNIX_EPOCH).unwrap_or(0)`（gate.rs:568-571）——系统时钟 ≤ 1970-01-01 时 now=0，`created_at=0`（serde default，字段缺省）满足 `0<=0 && 0<=180` → 绑定判定**通过**。与 `SafetyReport.created_at` 的注释"0 = absent (refused by the grant check)"（gate.rs:92-93）直接矛盾——拒绝是涌现的（now 通常巨大）而非显式的。可达性：需时钟回拨到 epoch 且攻击者知道 run_id（无凭证进程拿不到 record）→ 当前不可达；建议显式 `created_at != 0` 检查以兑现注释承诺（0.6 授权集对齐顺带）。
2. 探针 t1-t7 已证可达侧全拒：未来+3600 / 过期-3600 / 0 / 字段缺省 / 窗口+1(-181) 拒，窗口内(-60) 收，run_id 错拒。

## 已排除（同日尝试，证伪记录）

- **record token 外部改写 403 死锁**（R7-A1b）：同 uid 改写 record 的 token 字段（run_id/socket 不变）→ 客户端持新 token 恒 403（探针 r1）；`up` 的 `spawn_daemon` 去重放行死锁守护（r3：record 存在且 serving → Ok，不重生）；唯一自愈门=`creance stop`（r5：close_and_remove 删 record → 守护退场）。**判非 finding**：同 uid 攻击者改 config.json 触发 `配置读取失败/代理节点未应用` 的 fail-closed 自关（更强 DoS），record 改写被其支配；且服务端 fail-dead（403）方向安全。残余=纯可用性，量化：stop 一次即愈。
- **gate::open 铸造 TOCTOU（check 与 grant 之间 record 被换）**：客户端持换手前 record 快照驱动的是**旧 gate 自己的 socket**，check_id/run_id 绑定都由旧 gate 自洽满足 → 旧（已 disowned）gate 可被开到 Open。但其 watchdog `still_owner()=false` 跳过 wire 操作，胜者 watchdog（Closed）主动 stop+reap → wire 保持 down，**fail-closed**；且旧 gate 在换手后 ≤500ms 内 shutdown 退场，窗口极窄。判非 finding（可用性噪声）。
