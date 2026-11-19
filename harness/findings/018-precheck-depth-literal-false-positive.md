# FINDING-018: F-001 修复的 precheck_depth 把 YAML 字符串字面量里的 `[`/`{` 计入嵌套深度——合法订阅（密码含 129 个 `[`）被误拒；Go 版接受

- **编号**: 018
- **严重度**: S5（合法输入误拒；无受害者方向的 DoS——攻击者只能让**自己的**订阅失败；F-001 修复 f364ab0 引入的边角）
- **攻击面**: R2 回归审查 → 001（f364ab0 precheck）+ A1
- **发现时间**: 2026-11-19T01:44:47Z
- **发现者会话**: r2-s01
- **状态**: 待修复

## 复现（必须）

```sh
python3 -c "
pw = '[' * 129
print(f'proxies:\n  - name: BracketPW\n    type: ss\n    server: 1.2.3.4\n    port: 1\n    cipher: aes-128-gcm\n    password: \"{pw}\"')" > /tmp/pw.yaml
CREANCE_CONFIG=$(mktemp -d)/config.json \
  target/release/creance proxy-import --name pwtest --file /tmp/pw.yaml
# 实际 rc=1："订阅嵌套过深（>128 层），已拒绝"
# 对照：128 个 '[' → rc=0 导入成功
```

- **期望**: `password: "[[[…×129…]]]"` 是完全合法的 YAML（`[` 在双引号标量里无语法含义）；Go 版（无预扫描，yaml.v3 直接解析）接受该订阅。R1 的 FINDING-001 修复加入线性预扫描时假设 `[`/`{` 只出现在结构位置。
- **实际**: `precheck_depth`（import.rs:39-61）对**原始字节**计数，不区分字符串字面量/block scalar（`|`、`>` 多行文本）/注释里的括号。129 个字面量 `[` → depth=129 > 128 → 拒。**同样可触发**：节点描述/备注（base64 密钥、UUID 数组、含括号的多行 block scalar）。

## 根因猜测

`crates/creance-proxy/src/import.rs:42-52`：逐字节计数无 YAML 语义。修复预扫描的目的是把 F-001 的 O(n²) 从小时级压到毫秒级——这个目标不受影响，误杀面可以通过**提高阈值**或**允许不平衡回落**缓解：真实嵌套炸弹需要 >128 层**同时到达** serde_yaml 的 recursion limit；把阈值提到如 512 仍能拦截炸弹（libyaml 扫描成本在深层才平方爆炸，128→512 的合法配置空间极大拓宽），或对字面量引号状态做简单的 in-string 跳过（处理 `"…"`/`'…'` 与 `#` 注释，不处理 block scalar——阈值放宽后 block scalar 误杀也被 512 阈值容纳）。

**附带观察**：`depth` 跨行不重置是正确行为（配对平衡后回落），单行 >1MiB 检查同理含字面量（base64 二进制节点行超 1MiB 会误拒——8MiB 订阅的单节点大字段场景，见 R1 A1 的 8MiB password 实验：那次 0.06s 通过是因为有换行，若写成单行即触发）。

## 未验证想法

- libyaml O(n²) 的实际平方起始深度（128 层时 20KB 输入 0.2s——阈值 512 会让 20KB 恶意输入回到 ~3s，8MiB 恶意输入的拒绝时间会变长多少需要重新钉曲线；阈值与误杀的权衡需要实测数据）。
- serde_yaml 的 recursion limit 是 128——阈值提到 512 后预扫描放行的 129~512 层文档仍会被 serde_yaml 拒绝（recursion limit），只是拒绝前要付 libyaml 的部分扫描成本——这正是 F-001 想省的成本，权衡需量化。

## 建议修复方向（供第二天的人参考，非结论）

最小修复：阈值 128→512 并对 `"…"`/`'…'` 做 in-string 跳过（状态机 3 状态：normal/in-double/in-single，注释 `#` 仅在 normal 态且前导空白时进入）。或者：接受误杀为已知限制，文档标注"密码不得含连续 >128 个括号"（不推荐——对用户不可见）。
