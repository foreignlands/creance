# FINDING-037: gate 控制面认证 fail-open——record 不可读时 token 退化为空串，无凭证进程可完成 check→grant→Open 全链

- **编号**: 037
- **严重度**: S2（授权语义破坏；**可利用边界 = 同 uid 本地进程**，跨 uid/guest 不可达，见边界分析）
- **攻击面**: R6-A4（绕过面）+ R6-A3
- **发现时间**: 2026-11-19T15:40:28Z
- **发现者会话**: R6
- **状态**: 待修复

## 复现（必须）

探针：`harness/tools/r6-evidence-probe/` H2 段（真实 `Gate::start` + 原始 unix socket HTTP）。

```sh
cd harness/tools/r6-evidence-probe && cargo run   # （工具链 env 见 F-036）
# H2 段全部 PASS，PROBE_RC=0：
#   wrong token → 403                                        PASS（基线）
#   empty bearer check accepted                              PASS
#   no-token grant with forged window id → refused           PASS（check_id 绑定层独立成立）
#   FULL CHAIN: no token + no evidence → Open                PASS
#   GET /status empty bearer → 200 (leaks status)            PASS
```

- **期望**: 认证 fail-closed——凭证缺失/校验材料不可得时一律 403（Go 语义）。
- **实际**: `chmod 000 cage-gate.json` 后（daemon 主循环对 unreadable 按 transient 处理继续存活，gate.rs:885-889 `Err(_) => continue`），空 Bearer 通过 `constant_time_eq("", "")`；`POST /control {"action":"check"}` 返回 200 并签发 check_id，随后带五键伪造 checks + 该 check_id 的 grant → **Open**。零凭证、零证据。

## 根因

1. `crates/creance-gate/src/gate.rs:485-491`：`record_token()` **每请求重读 record 文件**，`unwrap_or_default()` 使读失败退化为空串；而 `handle()`（gate.rs:449-457）以 `constant_time_eq(bearer, self.record_token())` 判定，空对空通过。
2. Go 对照（ref `internal/cage/gate_control.go:99`）：`subtle.ConstantTimeCompare(Authorization, "Bearer "+record.Token)` 用**启动时内存中的 record**，token 永非空、缺失头恒拒——Rust 是语义漂移 + fail-open 退化。
3. 连带语义：重读当前文件意味着 F-028 交接窗口内，被覆盖的败者守护接受**胜者的** token（token 混淆，同信任域）。

## 可利用边界（诚实量化）

- **chmod 000 路径**：需文件属主（同 uid）。同 uid 进程本可直读 0600 token——此路径在同 uid 域内**无新增特权**，破坏的是"控制面必须持凭证"的不变量本身。
- **免 chmod 的瞬态窗口**：`close_and_remove`（gate.rs:935）先删 record 再等守护 ≤500ms 退场；该窗口内 socket 仍在服务，同 uid 无凭证进程可重新 check→grant **在 gate-close 之后重开 gate**。
- **跨 uid**：record 0600、instance_dir 非他人可写，另一 uid 无法触发退化；**guest（VM）无宿主 FS 路径**（lima.rs:121 单 workspace 挂载；gate socket 在 $TMPDIR 下 0700 目录，VM 内核不可达）。
- check_id 绑定层独立成立（伪造 id → 409），但 check 响应自带新 check_id，绑定对"无凭证+无证据"链无效。

## 未验证想法

- macOS seatbelt 沙箱进程若被禁 file-read* 但允许 file-write*/chmod——可在同 uid 下构造"能 chmod 却不能读 token"的进程，此时 fail-open 提供真实提权（未构造沙箱 profile 复现）。

## 建议修复方向（供第二天的人参考，非结论）

token 改为启动时读入内存（Go 语义），record 读失败时 fail-closed（拒所有请求）；或最少：`record_token()` 返回 `Option<String>`，None → 403。
