# FINDING-016: 011 修复残留两个探针缺陷 — ①结构错 YAML（根序列/标量/mounts 类型错）报 Contained 而非 NotEnforced（假 PASS）②YAML merge key `<<` 骗术：serde_yaml 不展开、lima(go-yaml) 展开，探针数 1 挂载实际 2

- **编号**: 016
- **严重度**: S4（escape 探针可被骗/假 PASS——night-03 修复 68d9721 引入的残留；FINDING-011 同类问题的子集残留）
- **攻击面**: R2 回归审查 → 011（68d9721）+ E1
- **发现时间**: 2026-11-19T01:44:47Z
- **发现者会话**: r2-s01
- **状态**: 待修复

## 复现（必须）

探针：`harness/tools/a1-yaml-bomb/src/bin/escape-yaml-probe.rs`（复刻 escape.rs mounts 判定逻辑逐行：`get("mounts")+as_sequence+unwrap_or(0)`，serde_yaml 0.9.34 同版本）。

```sh
cd harness/tools/a1-yaml-bomb && cargo run --release --bin escape-yaml-probe
# [root-sequence] -> Contained     ← YAML 根是序列：报"无逃逸"
# [root-scalar ] -> Contained     ← 根是标量
# [mounts-map  ] -> Contained     ← mounts 是映射不是序列
# [merge-key   ] -> Contained     ← ①见下：merge key 不被 serde_yaml 展开
# [merge-extra ] -> Contained
# [multi-doc   ] -> Escaped(parse-err)  ✓ fail-closed 正确
```

### 缺陷 ①：结构错 YAML 假 PASS（6 形态）

根为序列/标量/数字/null、或 `mounts` 为映射/字符串时，`get("mounts")` 返回 None / `as_sequence` 返回 None → `unwrap_or(0)` → **Contained**。这些文件不是合法 lima.yaml（lima 会拒载，VM 起不来）——此刻报 Contained 与事实无冲突，但违背 escape.rs:8-12 自己声明的 "reported separately so it can never silently pass" 哲学：应报 **NotEnforced**（无法判定）而非 Contained（检查通过）。

### 缺陷 ②：merge key 骗术（检测可被绕过）

lima.yaml（go-yaml v3 标准展开 merge key `<<`）：

```yaml
base: &b
  location: /secret
mounts:
  - <<: *b
```

- **lima 侧**：go-yaml v3 默认展开 merge key → mounts[0] 变成 `{location: /secret}` → 实际挂载 = workspace + /secret = **2 个**（挂载生效）。
- **探针侧**：serde_yaml 0.9 **不再支持 merge key**（0.9 弃用说明明确：`<<` 被当作普通键保留）→ `as_sequence().len() == 1` → **Contained**。
- 结果：多挂载逃逸存在而 escape-test 报 ✅ Contained——检测失效。

- **期望**（对照 ①②）：①结构不可判定的 YAML → NotEnforced；②merge key 形态 → Escaped（或至少 NotEnforced）。
- **实际**：全部 Contained。

## 根因猜测

`crates/creance/src/escape.rs`（mounts-workspace-only 分支，68d9721 引入）。`unwrap_or(0)` 把"无法判定挂载数"折叠为"零挂载"。修复用 serde_yaml 是对的（修掉了行前缀骗术），但 merge key 是 serde_yaml 与 go-yaml 的**解析器能力差**——探针的解析器必须与被检测系统（lima/go-yaml）能力对齐，否则任何"一方展开另一方不展开"的 YAML 特性都是骗术窗口（下一个候选：YAML 1.1 的 `?` 显式键、多流文档 lima 端取舍）。

**lima 端到端未验证**（本机无 VM/无 go 工具链）；go-yaml v3 展开 merge key 是库文档明载的默认行为，置信度高。写入者威胁模型：宿主侧进程（本来就可信）——探针的价值在于自动化发现，被骗 = 检测层失效，故 S4 不升级。

## 未验证想法

- lima 对 mounts 数组项里未知键（如 `<<` 展开后的字段集）的 Unmarshal 行为（strict 与否）——若 lima 拒载该形态则骗术降级为"探针漏报一个 lima 也起不来的配置"（危害减半）。
- `mounts` 用 alias 直接复用大序列（探针能数对 ✓ 已验证）、双锚点交叉 merge、`??` 复杂键等更多 YAML 特性差窗口。
- duplicate keys：serde_yaml 0.9 会 Err → Escaped（fail-closed ✓）；go-yaml 对 duplicate 的处理（取后者/报错）决定真实行为漂移方向。

## 建议修复方向（供第二天的人参考，非结论）

1. `unwrap_or(0)` 三处折叠改为区分"mounts 键缺失（0 挂载，lima 默认挂 workspace 或无）"与"结构不可判定"——后者 NotEnforced。
2. merge key/解析器能力差：探针里遇到任何含 `<<` 键或锚点定义的文件直接 NotEnforced（"解析器能力不足以判定"），或预扫描拒绝 `<<`。根治需与 lima 同解析器（不现实），NotEnforced 是务实解。
