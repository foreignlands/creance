# FINDING-003: 数字类型 mport 在 Rust 版被拒、Go 版明确支持（case int 分支）— 数字表示在 yaml_to_json 丢失整数性

- **编号**: 003
- **严重度**: S4（拒绝 Go 版接受的合法输入；S5 与 Go 原版语义漂移）
- **攻击面**: A4（hysteria2 端口/pin 规范化）
- **发现时间**: 2026-11-18T15:43:46Z
- **发现者会话**: s01
- **状态**: 待修复

## 复现（必须）

```sh
python3 -c "print('proxies:\n  - {name: H, type: hysteria2, server: 1.2.3.4, port: 443, auth: pw, mport: 443}')" > /tmp/mport-num.yaml
CREANCE_CONFIG=$(mktemp -d)/config.json \
  target/release/creance proxy-import --name m --file /tmp/mport-num.yaml
# 实际 rc=1："Hysteria2 字段 mport 无效，未忽略该字段"
```

同族变体（均 Rust 拒绝、Go 源码推断接受）：
- `mport: 0x1F90` → Rust 拒（f64 8080.0 → "8080.0" 无法 parse）；Go yaml.v3 解析为 int 8080 → `strconv.Itoa` → "8080" 接受。
- `mport: 99999999999999999999` → Rust 拒**整份文档**（FINDING-002 同根）；Go 解析为 float64，`case int` 不匹配 → 仅拒该节点。

- **期望**: 数字 mport 是合法输入 —— Go 原版 `internal/managedproxy/import.go` 的 `hysteria2Ports` 有显式 `case int: ports = strconv.Itoa(v)` 分支（作者明确支持的输入形态）。
- **实际**: `harness/tools/a1-yaml-bomb` 黑盒矩阵确认 Rust 版对 `mport: 443` 报"Hysteria2 字段 mport 无效"。

## 根因猜测

`crates/creance-proxy/src/import.rs:272-275`（`yaml_to_json`）：**所有** YAML 数字统一 `n.as_f64()` → `serde_json::Number::from_f64` —— 整数性在进入 `Map` 时即丢失。`import.rs:540-545`（`hysteria2_ports`）的 `Value::Number(n) => n.to_string()` 对 f64 输出 `"443.0"`，随后 `parse::<i64>()` 失败。

对照：Go 版在 `map[string]any` 里保留 `int` 类型，`case int` 分支正确输出 `"443"`。

连带影响面（同一根因，未逐一复现）：
- 任何 mihomo 节点 config 里的**整数型协议参数**经 store 往返后都是 f64 表示，`runtime.rs:44` serde_yaml 序列化时可能输出 `443.0` 形态（未验证 mihomo 对 float 端口的容忍度——VM 全链曾实测可用，推测 mihomo 宽容或 serde_yaml 输出整数形态，待钉死）。
- `ports: 65536` 数字形态原样保留问题见 A4 归档（Go/Rust 共同缺陷：纯 ports 字段无校验）。

## 未验证想法

- Go 版对 `mport: 443` 的实际运行时行为（本机无 Go 工具链，未能实跑；证据 = import.go `case int` 分支 + import_test.go:20 的 `mport: 35000-39000` 字符串用例）。
- serde_yaml 对 f64 的序列化形态（`generate` 产出的 config.yaml 里 port 是否带 `.0`）——影响 mihomo 拒载概率。
- `udp`/`alterId` 等布尔/整数参数经 f64 往返的语义保持。

## 建议修复方向（供第二天的人参考，非结论）

`yaml_to_json` 区分 YAML 整数与浮点：serde_yaml::Number 有 `is_i64()/is_u64()`，整数走 `serde_json::Number::from_i64/from_u64`，仅浮点走 f64。这一处修复同时解决 FINDING-002 的一部分与 003。
