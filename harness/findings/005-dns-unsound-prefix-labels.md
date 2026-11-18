# FINDING-005: DNS unpack 接受 RFC 保留前缀标签（0x40/0x80，长度可 >63）— 与 miekg/dns 严格性漂移；pack 端 rdlen `as u16` 截断地雷

- **编号**: 005
- **严重度**: S5（解析宽容度与 Go 原版（miekg/dns）漂移；无直接安全破坏）
- **攻击面**: A6（DNS wire）
- **发现时间**: 2026-11-18T16:35:00Z
- **发现者会话**: s01
- **状态**: 待修复

## 复现（必须）

探针：`harness/tools/a6-dns-probe/`（`src/dnsmsg_copy.rs` 是生产 `crates/creance-net/src/dnsmsg.rs` 的逐字节拷贝，2026-11-18 快照）。

```sh
cd harness/tools/a6-dns-probe && cargo run --release
# [UNPACK-OK] prefix-0x80-label-128 qnames=["AAAA…×128"]   ← 预期拒绝
# [UNPACK-OK] prefix-0x40-label-64  qnames=["AAAA…×64"]    ← 预期拒绝
# [PACK] data=65536 -> rdlen_field=30720                     ← as u16 截断
```

- **期望**: 首字节 0x40/0x80 前缀是 RFC 1035/2673 保留类型（0x80 = EDNS bitstring label），miekg/dns（Go 原版 `internal/cage/egress.go:19` 用的库）对其报错拒绝整个消息 → egress 返回 "invalid DNS upstream response"。
- **实际**: `skip_or_take_name`（dnsmsg.rs:220 `n =>` 兜底分支）把 0x40/0x80 前缀字节当普通标签长度，且不检查 `n > 63`（最长可 191 字节标签），解析出畸形 name 后消息被接受。

## 根因猜测

`crates/creance-net/src/dnsmsg.rs:220-228`：`n =>` 分支缺少两类检查——(a) `n & 0xc0 == 0x40 || 0x80` 应拒绝（保留类型）；(b) `n > 63` 应拒绝。

**安全影响评估（为何 S5 而非更高）**：unpack 的输入是经代理的 DoH 上游响应；egress 层另行校验 `r.Response && r.Id == q.Id`，answers 的 rdata（A 记录字节）不因 name 宽容而受影响。恶意 DoH 上游利用此宽容最多让畸形 name 进入日志/显示层。

**附带地雷（pack 端）**：`dnsmsg.rs:106` `(a.data.len() as u16)` 对 >65535 的 rdata 静默截断（实测 65536 → 30720），产出损坏 wire。当前唯一调用方（egress 合成 NXDOMAIN/AAAA 拒答）data 恒 ≤4 字节——不可达，但属未来回归地雷。

## 未验证想法

- 非 UTF8 标签字节被 `from_utf8_lossy` 替换为 U+FFFD（实测接受）——miekg 保留原始字节；对 name 的下游字符串匹配（如日志去重）可能有微弱影响。
- `jumps > 128` 边界（恰好 128 跳合法、129 拒绝）未逐跳实测；指针环/越界/自指已全部正确拒绝。

## 建议修复方向（供第二天的人参考，非结论）

`skip_or_take_name` 的 `n =>` 分支加两个拒绝条件：`n & 0xc0 != 0`（保留前缀）与 `n > 63`；pack 端对 `data.len() > 65535` 返回 Err（对齐 64 KiB DNS 上限的既有语义）。
