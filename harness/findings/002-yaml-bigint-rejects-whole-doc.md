# FINDING-002: 超 u64 范围的整数标量令整个订阅被拒（Go 版解析为 float64 接受）— 语义漂移 + 误导性报错

- **编号**: 002
- **严重度**: S4（拒绝合法输入；附带 S5 与 Go 原版语义漂移）
- **攻击面**: A1（订阅 YAML 炸弹 — 数字边界分支）
- **发现时间**: 2026-11-18T15:43:46Z
- **发现者会话**: s01
- **状态**: 待修复

## 复现（必须）

```sh
# 20 位整数（合法 YAML）：整个文档被拒
python3 -c "print('proxies:\n  - {name: U, type: ss, server: 1.2.3.4, port: 1, cipher: aes-128-gcm, password: 99999999999999999999}')" > /tmp/bigint.yaml
CREANCE_CONFIG=$(mktemp -d)/config.json \
  target/release/creance proxy-import --name big --file /tmp/bigint.yaml
# 实际 rc=1："无法读取 YAML，请导入 Clash/Mihomo 节点订阅或配置；暂不支持 Base64 列表或分享链接"
```

库层定位（`harness/tools/a1-yaml-bomb/src/bin/int-probe.rs`）：

```
ERR  "a: 99999999999999999999"          -> invalid type: integer … as u128, expected any YAML value
ERR  "a: 18446744073709551616" (u64MAX+1) -> 同上
OK   "a: 18446744073709551615" (u64MAX)  -> Number(u64)
ERR  "a: -99999999999999999999"         -> as i128 同上
OK   "a: 1e999"                          -> String("1e999")（浮点溢出回退为字符串，也是隐患）
```

- **期望**: 20 位整数是合法 YAML。对照 Go 原版（`internal/managedproxy/import.go:42` 用 `go.yaml.in/yaml/v3`，其 resolve 逻辑 i64→u64 失败后回退 ParseFloat），`99999999999999999999` 解析为 float64 1e20，导入继续（该节点随后会因端口字段校验被拒——但只是**该节点**被跳过，不是整个文档失败）。
- **实际**: serde_yaml 0.9.34 的 `Value` Deserialize 尝试 u128/i128 后 `serde_yaml::Value`（Number 仅 i64/u64/f64）无法容纳，`from_slice` **整体报错**，parse_nodes 把它当作"不是 YAML"拒绝整个订阅；错误文案还误导用户以为是格式问题。

## 根因猜测

`crates/creance-proxy/src/import.rs:40`（`serde_yaml::from_slice`）。serde_yaml 0.9 的 Value 反序列化路径对超 i64/u64 整数走 u128/i128 中间表示，最终 `invalid type` 硬失败，而唯一干净的失败路径（`.map_err(|_| "无法读取 YAML…")`）无法区分"真不是 YAML"与"合法 YAML 但含大整数"。

**攻击面价值**：一个订阅中只要**任何一个节点**的**任何一个字段**是 20 位以上整数（错误粘贴的数字、纳秒时间戳超界、uuid 数字化），整份订阅无法导入；同样的订阅在 Go 版 cage / mihomo 可正常导入（仅跳过坏节点）。这是 DoS-ish 可用性缺陷（S4）+ 与 Go 对照的语义漂移（S5）。

## 未验证想法

- `1e999` 被解析为**字符串**（serde_yaml 对 float overflow 的处理）——若该字符串进入 `server`/`port` 等字段的校验路径，报错信息会与数字输入时不同（低危文案不一致）。
- Go 版对同一 payload 的精确行为（未实际运行 Go 原版对照——仅从 yaml.v3 resolve 源码推断；可写 Go 测试钉死）。
- mihomo 对 `port: 1e20`（float64）的处理方式。

## 建议修复方向（供第二天的人参考，非结论）

两个方向任选：(a) parse_nodes 把 serde_yaml 解析失败的原因带出（区分 invalid type: integer 的情况，转为**跳过该节点**而非拒绝整份订阅，对齐 Go 节点级跳过语义）；(b) 预处理：解析前用正则把超 19 位数字的标量加引号。方案 (a) 更贴近 Go 语义。
