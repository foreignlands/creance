# FINDING-032: 订阅内容的 48-hex 字符串可伪造 escape-test 的 credentials 探针误报

- **编号**: 032
- **严重度**: S4
- **攻击面**: E（逃逸与探针本身）/ R5 revision 期望集回归
- **发现时间**: 2026-11-19T09:40:00Z
- **发现者会话**: R5
- **状态**: 待修复

## 复现（必须）

宿主侧即可，无需 VM（探针仅以 guest-profile.json 存在为门）：

```sh
P=/tmp/r5-f032; mkdir -p $P
# config.json（合法默认形状）+ guest-profile.json（合法 schema）照常
cat > $P/sub.yaml <<'EOF'
proxies:
  - name: exit
    type: ss
    server: 192.0.2.1
    port: 8388
    cipher: aes-128-gcm
    password: deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef   # 恰 48 个小写 hex
EOF
CREANCE_CONFIG=$P/config.json ./target/release/creance proxy-import --name poison --file $P/sub.yaml --select exit
CREANCE_CONFIG=$P/config.json ./target/release/creance escape-test; echo "EXIT=$?"
```

- **期望**: credentials-are-session-only 判 Contained（"deadbeef"×6 是订阅方控制的口令字符串，不是任何已发凭据；探针不该被远程内容操纵）
- **实际**:
  ```
  ❌ credentials-are-session-only [credentials] — token-shaped secret outside the issued set:
     proxy/sources.json:deadbeef…, sub.yaml:deadbeef…
  1 escape(s) … EXIT=1
  ```
  订阅口令经 import 落入 `proxy/sources.json`，scan_unknown_tokens 把它当"已发集之外的 token 形状秘密"→ 探针 Escaped、exit 1。
- **对照**（同会话实测）：
  - 干净订阅（password: hunter2cypher）→ 全绿 contained，exit 0 ✓
  - 64-hex 口令（常见 32 字节 hex 密钥形状）→ **不触发**（hex48_runs 要求恰 48 + 两侧非 hex 边界）✓

## 根因猜测

`crates/creance/src/escape.rs:239-301` `scan_unknown_tokens`：expected 集只含**自己生成**的凭据（session token、store.auth、store.revision、gate token）；扫描域是**整个 profile 目录**（含 `proxy/sources.json` —— 远程订阅内容的落点）。任何恰 48 小写 hex、边界非 hex 的**攻击者可选**字符串（订阅 name/password/auth 任意字段）都会被判 unknown。night-06 附带修复只把合法的 store.revision 加进 expected，未处理"扫描域内含远程攻击者内容"这一更大的形状面。

影响：订阅提供方可远程把信任预言机打成"不 contained"——狼来了效应（真实泄漏被淹没）+ 对正常 hex 口令订阅的持续误报。无真实泄密方向（sources.json 不进 guest），纯预言机操纵。

## 未验证想法

- guest 侧若有 48-hex 工件（如 hex 编码的会话材料）落在挂载进 guest 的 environment_dir 内、且该目录在 profile 扫描域内 → 同误报（未实测挂载布局）。
- 预期集漂移时窗：scan 读取 store/gate record 与 guest-profile 之间发生 import/select → 合法 token 短暂成 unknown（单次运行内不一致，未构造实测）。

## 建议修复方向（供第二天的人参考，非结论）

扫描域应聚焦"guest 可见工件 + 凭据落点"，或把 `proxy/sources.json`（远程内容）从扫描域剔除/对其做内容级白名单；也可改为"只对已发集 token 做正查（泄漏检测）+ unknown 形状仅报 SKIP 级噪声"。
