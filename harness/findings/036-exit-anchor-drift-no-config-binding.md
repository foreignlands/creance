# FINDING-036: exit-anchor 漂移全链无绑定——grant 契约比 Go 缺 RunID/Configuration/时间戳三维，换节点后伪造五键可静默再授权 Open

- **编号**: 036
- **严重度**: S4（语义洞；暴露被 90s 租期封顶，无 renew 调用方）
- **攻击面**: R6-A2/A3（0.5 证据链时序窗口 + grant_checks 注入面）
- **发现时间**: 2026-11-19T15:40:28Z
- **发现者会话**: R6
- **状态**: 待修复

## 复现（必须）

探针：`harness/tools/r6-evidence-probe/`（真实 path-dep crate，经 /tmp 快照绕过幽灵清单，见 F-039）。

```sh
export RUSTUP_HOME=$PWD/.toolchain/rustup CARGO_HOME=$PWD/.toolchain/cargo \
  PATH=$PWD/.toolchain/cargo/bin:$PATH CARGO_TARGET_DIR=/tmp/r6-target
cd harness/tools/r6-evidence-probe && cargo run
# H3 段全部 PASS，PROBE_RC=0：
#   grant → Open                          PASS
#   after node switch, mutating command still accepted (no drift detection)  PASS
#   re-grant after switch → Open (anchor never re-evidenced)                 PASS
#   explicit proxy-revision closes the gate（对照组）                       PASS
```

- **期望**: 换节点（select_and_apply 轮换 revision 并同步写 config.json）后，daemon 对任何 mutating 命令应察觉出口已变、关闭 gate 要求重新取证；重新 grant 必须绑定新的真实证据。
- **实际**: check/grant 照常放行，伪造五键（携带的还是旧 US 证据值）→ gate 再次 Open；只有显式 `proxy-revision` 动作（对照 recorded 快照）能察觉并关闭。端到端推论：workbench `POST /api/proxy/start`（serve.rs:169）调 start_managed 重启核心（新出口即时生效）后**完全不调 sync_proxy_revision**；CLI `cmd_proxy_start`（main.rs:370）先重启后 sync 且 `let _` 吞 sync 失败——两个入口都存在"Open gate + 新出口"窗口（≤90s，租期到期自动关）。

## 根因

1. `crates/creance-gate/src/gate.rs:99-104`：`authorizes()` 只查五个键 == "passed"。Go 的 `SafetyReport.Authorizes`（ref `internal/cage/safety.go:54`）要求报告绑定 `Policy 版本 + RunID + Configuration 指纹 + CheckID + CreatedAt`，逐检查要求 Critical+Passed+非空 Evidence+CheckedAt 时间窗，报告 24h 生命期封顶租期，Renew 每次重授权。**gate.rs:90 注释"mirroring the Go gate's authorization set"不实**：Rust 必需集 5 项 vs Go 11 项（缺 proxy_transport/dns_transport/guest_settings/browser_settings/filesystem_boundary/management_boundary），且零绑定字段。
2. `crates/creance-gate/src/gate.rs:503-527`：daemon 每条 mutating 命令重载 config + `applied()` 校验——但 select_and_apply/store.rs:378 把 store 与 config.json **同步**更新，`applied()` 永远一致，此校验对换节点结构性失明。
3. `crates/creance-gate/src/gate.rs:629-670`：唯一能察觉出口变化的是 recorded 快照，且只在显式 `proxy-revision` 动作时被查询；watchdog 循环不做任何重验。
4. `crates/creance/src/main.rs:370-380`：sync 在核心重启**之后**（顺序应反转：先关 gate 再换出口）；serve.rs:169-171 无任何通知。
5. 树内无 renew 调用方（全仓 grep 仅 gate.rs:579 定义）——Go workbench monitor（ref `internal/workbench/safety.go:1305`）每轮续期前重验配置指纹与出口，Rust 无对应物。这同时意味着：90s 租期是漂移暴露的唯一硬顶，**一旦未来补上 renew 调用方而不同时补绑定字段，窗口变无界**。

## 未验证想法

- grant 的内层 `report.report_id` 不与 `command.report_id` 校验（gate.rs:559 只查外层），renew 按 `inner.report.report_id` 匹配——绑定不对称，审计记录可携带错配 id（未单独复现，H2 的 409 只证了外层绑定）。
- 多余 checks 键（exit_ip 等）只存 daemon 内存（GateInner.report），不落盘、/status 不回显——审计污染面止于内存（未构造复现）。
- 0.5 前置路径：cmd_gate(true) 在 observe 前加载 config 一次，daemon grant 不校验 exit_policy——检测中改锚定不会被再评估（Go 的 Configuration 绑定会强制重启）。

## C5 预埋分支复查结论（attack-surfaces C5"0.5 须重审"）

探针 H3 末段实测（修正过一次预期——初判"静默保持 Open"错误）：锚定 JP→US（revision 不动）走 `!revision_changed && !binding_completed` + strip_config 相等 → `sync_proxy_revision_with` 返回 Ok，但 **action 层对 Ok/Err 都无条件 `inner.close`（gate.rs:607-619）**——gate Closed，安全方向成立，C5 担忧在 action 层不落地。两个真实残留：
1. gate.rs:644 注释 "Nothing to adopt: the gate keeps its state" 与 action 层行为矛盾——**幂等无变化 sync 也关 gate**：每次 `creance proxy-start`（无论是否 no-op）都强制 Open gate 重取证（可用性损耗，fail-closed 方向；探针实测 sync=Closed）。
2. 关 gate 依赖**有人调 sync**：workbench `/api/proxy/start` 不调（主洞），watchdog 不做周期重验——漂移暴露=整个 Open 租期。

## 建议修复方向（供第二天的人参考，非结论）

报告结构补齐 Go 三维绑定（run_id + config fingerprint + created_at，validate against recorded 快照）；serve 的 /api/proxy/start 与 CLI 的 start→sync 顺序反转；proxy-revision 的 Ok 幂等路径不关 gate（与注释对齐）或注明有意为之。
