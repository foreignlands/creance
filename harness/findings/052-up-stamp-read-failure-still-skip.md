# F-052 — F-049 修复只落地了三claim中的两个：`cmd_up` 的 stamp 读失败仍 `if let Ok` 跳过（缺失 stamp → up rc=0），commit message 与 STATE 声称的"up 拒绝"不存在于代码

- **编号**: 052
- **严重度**: S4（与 F-049/F-044 同类：纪律绕过/验收假绿；实测可让 `creance up` 在无戳且无实例时启动一台**未供给的原版 Lima VM**）
- **攻击面**: night-11 F-049 修复面回归（任务书 F-049 面：up 三分支 + 老 profile 放行路径确认）
- **发现时间**: 2026-11-20T06:30:00Z
- **发现者会话**: R10 (night-auditor)
- **状态**: 待修复

## 复现（必须）

```sh
BIN=target/release/creance
T=$(mktemp -d /tmp/r10-e2e-XXXX)
CREANCE_CONFIG="$T/config.json" $BIN init
mkdir -p "$T/state"
# CASE A（对照）：stamp 在但值不匹配 → 拒绝
echo wrong > "$T/state/fingerprint.txt"
CREANCE_CONFIG="$T/config.json" $BIN up; echo $?        # rc=1，"guest 环境…已变更"
# CASE B：stamp 缺失 → 跳过检查
rm "$T/state/fingerprint.txt"
CREANCE_CONFIG="$T/config.json" $BIN up; echo $?        # rc=0 ← 洞
```

- **期望**: stamp 读失败（缺失/不可读/目录）一律拒绝，提示 re-setup（F-049 commit message 原文 "any stamp read failure refuses `up` with re-setup guidance"）。
- **实际**: CASE B rc=0——检查被跳过，`vm::up` 继续；实例不存在时 `limactl start` **从 template:default 自动创建**（lima 2.3.0 实测），一台未供给的原版 Ubuntu VM 在 `creance up` 下启动成功（stderr 可见 "Creating an instance … from template:default (Not from template:…)"）。该 VM 无 provision（无拓扑锁定/无身份/无会话令牌），escape-test guest 探针全 ESCAPE（net-direct-egress / net-dns-external / proxy-path / guest-identity），但 `up` 本身成功退出。

## 根因猜测

`crates/creance/src/main.rs:666`：

```rust
if let Ok(pinned) = std::fs::read_to_string(&stamp) {
```

仍是 F-044 时代的跳过式写法。night-11 修复 commit `6b1aab5` 的实际 diff 只有 escape.rs（探针 Escaped 分支）和 main.rs:613（setup 写戳改 fatal）两处——commit message 声称的 "any stamp read failure refuses `up`" 与 `harness/state/STATE.md`（night-11 终稿）中 "stamp 读失败（缺失/不可读/目录）= up 拒绝" 在代码中**不存在**。finding-049 修复方向 1（`match … Err(_) 拒绝`）未被实现。

## 未验证想法

- `limactl start` 对不存在实例的 template:default 自动创建是 lima 2.3.0 行为（v0.5.5 假设不变）；若未来 lima 改为报错，up 会在别处失败，但 stamp 跳过仍让"旧 VM+新配置"洗白路径成立。
- CASE B 启动的原版 VM 的 gate daemon/tunnel 是否真的建立并 Open 未逐项核验（up rc=0 且无 warning；若 tunnel fallback 成立则 wire 可用）。
- 062 洞（054）的供给失败态与本洞叠加：洗白路径 + 供给失败-open 双重存在时，攻击者（同 uid 删一个文件）可让 cage 全程无拓扑运行而 `up`/`stop` 全绿。

## 建议修复方向（供第二天的人参考，非结论）

`main.rs:666` 改 `match std::fs::read_to_string(&stamp)`：`Ok` 比对、`Err` 一律 `fail("指纹戳缺失/不可读…请 creance setup")`。 virgin profile（无实例）也 fail-closed 语义正确——无实例时 up 本就该被指引去 setup，而非 lima 的 template:default 自动创建。补一条 E2E 回归（本文件 CASE B 形态，断言拒绝文案而非仅 rc）。
