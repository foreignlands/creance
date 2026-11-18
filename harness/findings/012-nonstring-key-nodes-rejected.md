# FINDING-012: 含非字符串键的节点被整节点拒绝 — Go 版显式设计接受（map[any]any 分支）并逐字段检查

- **编号**: 012
- **严重度**: S5（与 Go 原版语义漂移：拒绝 Go 可导入的订阅；报错时 issue.name 也丢失）
- **攻击面**: G2（import.go vs import.rs 拒绝矩阵）
- **发现时间**: 2026-11-19T02:15:00Z
- **发现者会话**: s01
- **状态**: 待修复

## 复现（必须）

```sh
python3 -c "print('proxies:\n  - {name: IK, type: ss, server: 1.2.3.4, port: 1, cipher: aes-128-gcm, password: x, 123: junk-value}')" > /tmp/intkey.yaml
CREANCE_CONFIG=$(mktemp -d)/config.json \
  target/release/creance proxy-import --name ik --file /tmp/intkey.yaml
# 实际 rc=1："第 1 个节点 ""：节点字段使用了非字符串键"（注意 name 也是空的）
```

4 变体（数字键 `123:`、布尔键 `true:`、null 键 `~:`、序列键 `? [a,b]`）全部拒绝。

- **期望**: Go `internal/managedproxy/store.go:202-208` 的 `unsafeOption` 有显式 `map[any]any` 分支，注释写明 "YAML maps with a non-string key can still contain core option keys" —— 非字符串键的**值**仍参与 unsafe 检查，节点本身可导入（mihomo 侧自行处理）。
- **实际**: `crates/creance-proxy/src/import.rs:252-266`（`yaml_object`）在键非字符串时**直接拒绝整个节点**——比 Go 严；且拒绝发生在读取 name 之前，`NodeIssue.name` 为空，报错"第 1 个节点 ""：…"对用户不可定位。

## 根因猜测

Rust 的中间表示是 `serde_json::Map<String, Value>`——JSON 对象键必须字符串——所以 yaml_object 在入口把非字符串键上升为节点级错误。Go 的 `map[string]any` 由 yaml.v3 填充为 `map[any]any` 保留了原始键类型。这是**表示层差异**，非有意收紧。

**连带**：含数字键的节点在 Rust 全拒（连累正常字段），Go/下游 mihomo 可接受。真实场景：订阅生成器输出 YAML 数字键（少见但合法）。

## 未验证想法

- mihomo 对非字符串键的实际处理（忽略或报错）——决定下游风险等级。
- serde_yaml Mapping→JSON 的另一种移植方案（把非字符串键 stringify 保留值参与 unsafe 检查）是否能完全对齐 Go。

## 建议修复方向（供第二天的人参考，非结论）

`yaml_object`/`yaml_to_json` 遇非字符串键改为 `key.to_string()`（保留值），或仅对**顶层**节点键拒绝而嵌套键 stringify——对齐 Go 的"值仍受检查、节点可导入"。

## G2 矩阵其余结论（本次会话已逐条对照，无其他漂移）

- 拒绝矩阵的顺序/文案/条件（空名/超长名/重复名/不支持协议/server 空缺超长/dialer 三种错误/chain 依赖不可用）与 Go 逐行一致。
- `optionKey`（lowercase+`_`→`-`）Unicode 折叠行为一致（Kelvin 变体同判）。
- `sshPrivateKeyPath`/`withoutSSHPrivateKey`/`normalizeHysteria2`/`hysteria2Ports`（`case int` 分支差异已录 FINDING-003）/`hysteria2Pin`/`normalizeWebSocket`/`webSocketHeaders`（httpguts 语义等价）全部一致。
- `unsafeOption` 递归结构一致（Rust 的 JSON 表示使非字符串键分支不可达——即本 finding）。
