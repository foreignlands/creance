# F-047 — select 后 close_gates 失败被 `let _` 吞掉：Go 是事务性中止+回滚，Rust 是先落地后吞错（窗口有界 ≤90s，语义漂移）

- **严重度**：S5（状态诚实性/Go 漂移；失败窗口 ≤90s lease 有界自愈，窗口内再 open 被对账拒——无取证重复路径）
- **攻击面**：F-043 修复面回归（任务书 A4：close_gates Err 时 select 已生效；与 daemon_serving 组合）· G4
- **状态**：待修复（低优先；一行错误处理+顺序对齐）
- **基线**：v0.5.3 `985a5a2`
- **复现**：源码对照 + 窗口论证（失败注入需 daemon_serving-但-close-失败的楔入态，靠行为推演；正向路径已被 r8-regression h3.1/h3.2 实证）

## 结论一句话

F-043 修复（`ac0d2ef`）在两个 select 入口加了同步撤 gate，但错误用 `let _` 吞掉（`main.rs:588`、`serve.rs:167`）。Go 的 `applyProxy` 是**事务性**的：`closeProxyGate` 失败 → `return err` → defer 把 store 与 config **整体回滚**（proxy.go:329-336 + 339-344），select 等于没发生。Rust 的顺序是 select_and_apply **先落地**（store+config 已是新值），close 失败仅吞错——失败时产生"F-043 窗口的复活"：gate=Open（旧证据）+ config 声明新节点 + 核心仍服务旧节点，且两个入口都向用户报成功（CLI 打印 `applied {node}`、workbench 返回 `{"ok":true}`）。

## 窗口的有界性与不可利用性（如实论证）

1. **时间界**：`renew` 动作全仓库**零调用者**（grep 证实：gate.rs:604 的 handler 是唯一出现点）——Open gate 必然在 OPEN_LEASE=90s 内被看门狗关闭（gate.rs:324-328）并切断隧道。失败窗口 ≤90s，自愈。
2. **无重复取证路径**：窗口内 guest 重新 gate-open 会被 night-09 对账拒绝——`check_running` 比对运行核心的组选择（旧节点）与 store.selected（select 已写入新节点）→ `readiness: selection` 拒（service.rs:155-158）。`up` 亦被全量指纹锁拒（config revision 已换、活记录指纹旧）。即窗口内**无法**为旧节点再开 gate，只能等 lease 关闭。
3. **与 daemon_serving 的组合面**：close_gates 只在 `daemon_serving()==true` 时发 close 并把 Err 记为失败（gate.rs:1102-1107）；死记录路径（F-029）被就地清理（h3.2 实证 ✓）。失败楔入态=守护在服但 close 命令失败（socket 半死/守护僵死）——罕见且同 uid 自伤面。

## Go/Rust 失败语义对照

| | close 失败时 |
|---|---|
| Go applyProxy | return err → defer 回滚 store+config → **什么都没发生**（gate 可能仍开，但 config 未变=自洽） |
| Rust select 入口 | store+config 已落新值；`let _` 吞错 → 回 `ok`；Open gate 与新声明共存 ≤90s |

漂移点不在"有没有窗口"（Go 的 close 失败也可能留下开 gate），而在 **Go 不产生"新声明+旧 wire+旧证据"的三方不一致并报成功**。Rust 的窗口内三方声明互相矛盾——这正是 F-043 立案的状态诚实性标准，修复引入了它的失败分支版本。

## 修复方向（记录，不实现）

1. 对齐 Go：把 close_gates 挪到 select_and_apply **之前**并传播 Err（失败→select 不落地）。注意 Rust 侧 close_gates 在 select 前语义等价（关的是旧证据的 gate，Go 即此序：proxy.go:333 在任何落盘前 close）。
2. 或至少：失败时不吞——CLI 返回非零/打印警告，workbench 返回 207/带 gate 状态字段；并接受 ≤90s 有界窗口（记档）。
3. 回归面：h3 矩阵补"close 失败注入"变体（GateClient close 传坏 reason 长度或并发关闭以制造 Err——或以 trait 抽象注入失败）。

## 关联

- F-043（本条是其修复的失败分支）、F-041（窗口内若再叠锚点编辑，sync 的 Unchanged 拒绝会进一步延迟自愈到 lease 到期——仍 fail-closed）、go-authz-alignment.md §3。
