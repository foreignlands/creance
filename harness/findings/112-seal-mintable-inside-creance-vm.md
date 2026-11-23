# FINDING-112: F-105 封印在 creance-vm 内部仍可铸：`pub(super)`/`pub(crate) fn egress_verdict` 不被拦、vm.rs 内 `unsafe transmute` 铸令牌（unsafe 禁只扫 gateprobe.rs），且 marker 可在 verdict 之前武装

- **编号**: 112
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: F-105 修复面（gateprobe.rs:114,247-262；vm.rs）
- **发现者会话**: r30-auditor
- **状态**: 已修复（main-session，实机复验）：`pub` 任意拼写禁（行级）；crate 全域 `_sealed`/`transmute` 禁（vm.rs/qemu 三文件 prod）；verdict→mark 位置序钉死

## 机理

可见性钉只是 `!prod.contains("pub fn egress_verdict")`，`pub(super) fn`/`pub(crate) fn` 不含该子串；gateprobe 是 crate 根子模块，`pub(super)` 即全 crate 可见。`unsafe`/`transmute` 禁只扫 gateprobe.rs prod，vm.rs/qemu/* 不扫；而 crate-wide 计数（qemu/mod.rs:620 测试）只数 `mark_provisioned`/`write_marker`，不数令牌铸造。`mark_provisioned(`==1 不钉位置序：调用挪到 `match egress_verdict(&out)` 之前、Ok 臂改返回预先算好的 bool，计数不变。

## 复现

```sh
CREANCE_REPO=$HOME/r30-wt ONLY="NC-VISmint NC-VISmint2 NC-XMUTE3" python3 harness/tools/r30-negative-controls/run.py   # worktree 放 $HOME（git worktree add --detach $HOME/r30-wt v0.6.22）；用例见 harness/tools/r30-negative-controls/cases.py
```

期望：每个用例至少一项测试或 clippy 红。实际：

| 用例 | 注入 | 测试（fmt+cargo test --workspace+clippy -D warnings；裁判双跑） | 后果 |
|---|---|---|---|
| NC-VISmint | `fn egress_verdict` → `pub(super) fn`；vm.rs 加 `pub(crate) fn proof()` 用 concat! 通过串调 verdict；verify_and_mark_with 在 verdict 前 `let armed = vm::mark_provisioned(profile, instance, &vm::proof());`，Ok 臂 `Ok(_verified) => Ok(armed)` | 绿×2 | 任何探针输出（含 tcp-open）都先武装 marker 再拒绝——行为测试的伪造 open 用例只断言 Err+stop，不断言 marker 未落盘 |
| NC-VISmint2 | 同上，`pub(crate) fn egress_verdict` | 绿×2 | 同上 |
| NC-XMUTE3 | vm.rs 加 `#[allow(unsafe_code)] pub(crate) fn proof()` 内 `transmute::<(), EgressVerified>(())`；同上前置武装 | 绿×2 | 零检测铸令牌 |

## 已尝试未通的路（对照红）

已拒：derive Default/Clone、`Self { _sealed`、他 crate transmute（NC-XMUTE/XMUTE2 编译失败：`mark_provisioned` 已 pub(crate)）、`&Result` 签名降级（NC-SIGres 红）。`use … as`/type 别名：`_proof: &crate::gateprobe::EgressVerified` 字面钉 + rustc 类型检查使别名只能指向同一类型，无新通道。

## 建议

可见性钉改为 `fn egress_verdict(` 前缀必须是行首 `fn `；unsafe/transmute 禁扩到整个 creance-vm prod（或 `#![forbid(unsafe_code)]`）；伪造 open/runner Err 行为测试断言 `provisioned` 不存在；钉 `mark_provisioned(` 偏移 > `egress_verdict(&out)` 偏移。
