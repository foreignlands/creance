# F-043 — select_and_apply 不撤销 gate：select→proxy-start 窗口内 Open gate + 声明新节点 + wire 旧节点共存（Go 在 select 即同步 closeProxyGate——语义漂移）

- **严重度**：S5（状态诚实性漂移；窗口内 wire 语义自洽——流量走的仍是已取证旧出口；与 F-041 组合后成为弱缝）
- **攻击面**：G4（Go 对照）· R7-A2 select 路径分析
- **状态**：待修复
- **基线**：v0.5.2 `281899c`
- **复现**：源码对照 + 推演（无需实机：行为由调用图唯一决定）

## 结论一句话

Go workbench 的每次 select/restart/route 都走 `applyProxy`，其中**无条件先 `closeProxyGate("代理节点切换中，旧连接及检测授权已关闭")`**（proxy.go:334-336，注释明言 "node-only switches … revoke the gate synchronously"）。Rust 的 `select_and_apply`（store.rs:378-408）只写 store+config.json——**不触碰任何 gate**；gate 的关闭要等到下一次 `proxy-start` 的 sync-first（Adopted → close）。于是 Rust 在 select 之后、proxy-start 之前存在一个 Go 不存在的窗口：**gate=Open、config.json 声明新节点（revision 已换）、运行核心与 wire 仍服务旧节点**。

## 窗口内的状态语义

- wire 仍按旧出口走——旧出口**有**当时的证据，流量语义自洽（非逃逸）；
- 但 gate=Open 的"应用配置仍然有效"承诺建立在对账盲区上：`applied()` 只对 config↔store 对（都是新值），对**运行中的核心**与 config 的脱节结构性失明（F-036 已记录该失明面，night-08 靠 sync-first 在 restart 前关 gate 补上——但 select 本身不触发任何 sync）；
- `up` 在窗口内被 check_running 拒（指纹漂移）——用户面有反馈；workbench /api/proxy/select 返回 `{"ok":true}` 无任何 gate 状态提示；
- 与 F-041 组合：若用户在窗口内又改 exit_policy 锚点（revision 不动），sync 的 Unchanged 路径连 Adopted 都不给——gate 在多重声明漂移下持续 Open。

## Go 证据

- `internal/workbench/proxy.go:150-152`（stop 动作：closeProxyGate → Stop）；:166-181（select/route/restart → `applyProxy`）；
- `applyProxy`（proxy.go:320-360）：**每个动作路径都先 closeProxyGate**，endpoint 变了才 stopEnvironment；随后 Stop 核心 → 铸新 revision → Save → startProxyCore——**select 即 apply，gate 同步撤销**，无窗口。

## Rust 证据

- `crates/creance-proxy/src/store.rs:378-408`：select_and_apply 无任何 gate 调用；
- `crates/creance/src/serve.rs:162-167`（workbench /api/proxy/select）与 `crates/creance/src/main.rs:568-573`（CLI proxy-select）都只调 select_and_apply；
- gate 关闭仅发生在：proxy-start 的 sync-first（main.rs:376-378 / serve.rs:174-178）、proxy-stop、stop。

## 修复方向（记录，不实现）

对齐 Go：select_and_apply 成功后对 profile 的全部实例 gate 发 `close`（"代理节点切换中，等待重新检测"）——或至少发 `proxy-revision` sync（revision 已换 → Adopted → close，复用 night-08 机制）。前者语义更强（Go 字符串即 close）。回归面：m4（干净幂等不关）与此处的"select 必关"是两个入口、两种语义，不冲突——幂等保护的是 **proxy-revision 命令**，本条对齐的是 **select 动作**。

## 关联

- F-036（applied 对运行核心失明；sync-first 补的是 restart 前的窗口）、F-041（Unchanged 路径锚点失明）、go-authz-alignment.md §3（指纹绑定=第三维兜底）。
