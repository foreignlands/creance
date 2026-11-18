# FINDING-008: gate 状态机与 Go 版四处漂移 — grant 无 Checking 前置（Go 要求 CheckID/时间戳绑定）、close reason 200B 上限对多字节失效、token 非常量时间比较、exit_policy 任意变化不触发重开

- **编号**: 008
- **严重度**: S4（正确性/与 Go 语义漂移；本地 unix socket + 可信客户端架构下无 guest 可达路径）
- **攻击面**: C3 + C4（gate 状态机 / 鉴权）
- **发现时间**: 2026-11-19T00:40:00Z
- **发现者会话**: s01
- **状态**: 待修复

## 复现（必须）

### 1. close reason 200B 上限失效（黑盒可复现，纯函数）

`truncate_utf8`（gate.rs:138-147）用**字符数**而非字节数对齐上限：

```sh
rustc harness/tools/trunc/t.rs -o /tmp/trunc_test && /tmp/trunc_test
# ascii300 -> 199B          ✓
# cjk150(450B) -> 447B      ✗ 只截掉 1 个 char，上限 200 形同虚设
# cjk300(900B) -> 597B      ✗
# emoji100(400B) -> 396B    ✗
```

`POST /control {"action":"close","reason":"好×150"}` → status 的 reason 字段 447 字节（契约 ≤200）。`chars ≤ max` 的多字节串几乎不截（fallback 分支只截 1 char）。

### 2. grant 无状态前置（源码对照 Go）

- Rust `gate.rs:456-469`：`"grant" => match command.report { Some(report) if report.authorizes() => 直接 Open }` —— **Closed 状态 + 5 个必需项 "passed" 即开闸**，report 与 check 会话无绑定。
- Go `internal/cage/gate.go:256`：`if g.state.Mode != GateChecking || … || report.CheckID != g.state.CheckID || report.CreatedAt.Before(g.state.CheckStartedAt)` —— grant 只在 Checking 态有效，report 必须携带本次 check 生成的 CheckID 与不早于检查开始的时间戳。
- Rust `SafetyReport` 只有 `report_id`/`checks` 两个字段，无 CheckID/时间戳概念；`renew` 只比对 report_id 字符串。

### 3. token 非常量时间比较

- Rust `gate.rs:360`：`bearer != self.record_token()`（逐字节短路）。
- Go `gate_proxy.go:64`：`subtle.ConstantTimeCompare(...) != 1`。

### 4. exit_policy 任意变化不触发 gate 重开（已确认与 Go 漂移，证据补强）

`sync_proxy_revision_with`（gate.rs:533-538）：revision/proxy_url 未变时走 `strip_config(old) == strip_config(new)` —— 而 `strip_config`（gate.rs:553-558）**把 exit_policy 整体抹掉** → 用户/宿主进程改 config.json 的 `exit_policy.country_code`（region/city 同理，只要 old 已绑定）→ `proxy-revision` 返回 Ok 且 **gate 保持当前状态（含 Open）**，不强制重新检查。

**Go 对照（gate.go:109-121 SyncProxyRevision）**：initialBinding 要求**逐字段单调填充**（`oldPolicy.IP == "" || oldPolicy.IP == newPolicy.IP`，CountryCode/Region/City 同款四连）+ NeedsBinding 变化；任何其他 exit_policy 变化 → `before != after` → Err "出口地址或环境设置变化需要重启环境" 且 `transitionLocked(GateClosed)` **强制关闸**。Rust 两者皆缺：变化被静默采纳、gate 保持 Open。兜底评估：mainland deny list 对 country_code→CN 仍会 Failed（check_exit_country 强制），但 region/city 层无此兜底。

**附带缺失**：Go 的 proxy-revision 分支（gate_control.go:128-134）在 sync 成功后调 `cfg.RecordRunningAt(instanceDir)` 刷新环境记录的 fingerprint；Rust `control()` 的 "proxy-revision" 分支（gate.rs:498-510）无对应调用 → running 记录指纹过期，下次 `check_running` 报 "configuration changed; run cage stop" 的残留不一致。

## 根因猜测

1. `truncate_utf8` 的算法把"截到 max 字节"实现成"截掉 (chars−max) 个字符"——两个度量根本不同；且 `nth_back(0)` 时只截一个字符。
2. grant/renew 的会话绑定（CheckID/时间戳）在移植时被简化为 report_id 字符串比对。
3. `!=` 未引入恒时比较。
4. `strip_config` 的豁免范围过宽。

**安全影响评估（诚实分级）**：gate 控制面在宿主私有 unix socket 上，token 在受保护 record 文件里——唯一可触达方是同 uid 宿主进程（本已可信/等同完全控制）。1 是正确的资源/契约缺陷；2/3/4 是与 Go 的防御深度/语义漂移，无 guest 逃逸路径。

## 未验证想法

- 4 与 running 记录 fingerprint（C6/C7）的组合：若环境生命周期用 fingerprint 检测配置变化并要求重启，则 gate 保持 Open 被上层兜住；若不检测，则 exit_policy 变化完全静默（需读 creance-vm/src/running.rs 与 vm.rs 联合判定）。
- 双 Content-Length 时 `gate.rs:347-348` 最后一行覆盖前者（`body_len = v.parse().unwrap_or(0)` 无重复检测）——自家 GateClient 恒单 CL，无走私面（S5 记录）。
- `/tmp/cage-gate-{8hex}` 目录预占（D2 类）：ensure_private_dir 的属主校验未逐行核对。

## 建议修复方向（供第二天的人参考，非结论）

1. `truncate_utf8` 改按字节 + char boundary：`while s.len() > max { s = &s[..floor_char_boundary-ish] }` 或直接 `s.char_indices().take_while(|(i,c)| i+c.len_utf8() <= max).last()`。
2. grant/renew 补 CheckID + CreatedAt 绑定（对齐 Go gate.go:256 的四连判定）。
3. `ConstantTimeCompare` 等价物（逐字节 XOR 累积）。
4. `strip_config` 只豁免 proxy_url/proxy_revision/exit_policy.binding 字段，mode/scope/country_code 变化应要求重启。
