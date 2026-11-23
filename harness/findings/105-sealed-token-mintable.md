# FINDING-105: `EgressVerified` 封印可绕：`derive(Default)`、`Self { _sealed }` 第二构造点、他 crate 以 pub `egress_verdict(字面量)` 铸令牌、签名降级 `&Result<…>` 先武装后判全绿

- **编号**: 105
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: F-099/F-100 修复面（gateprobe.rs `EgressVerified`/`egress_verdict`；vm.rs/qemu `mark_provisioned` 签名）
- **发现者会话**: r29-auditor
- **状态**: 已修复（main-session，实机复验）：egress_verdict 私有化+mark_provisioned pub(crate)，签名字面钉+第二构造点/Default/Clone/unsafe 全禁；unsafe_code 维持 deny（libc 合法，transmute 路径由钉覆盖）

## 机理

CHANGELOG [0.6.21] 称令牌 "unforgeable … arming the restrict=on marker without a real passing verdict is a compile error"。实测：(1) 构造点钉 `prod.matches("EgressVerified { _sealed").count()==1` 只认一种拼写；(2) `egress_verdict` 为 `pub` 且吃任意 `&str`，creance-vm 之外的 crate（creance-gate 未被任何 walk 扫描）可用字面量合法铸令牌并调 pub `vm::mark_provisioned`；(3) 签名钉不存在——`_proof` 改 `&Result<EgressVerified,_>` 后 marker 在 match 之前写入。transmute 路径被 workspace `unsafe_code = "deny"` 拦（NC-XMUTE 红），但见 NC-XMUTE2（`#[allow(unsafe_code)]`，结果见下表）。

## 复现

```sh
CREANCE_REPO=$HOME/r29-wt ONLY="NC-GPdefault NC-GPself NC-XGATE NC-SIGres NC-XMUTE2" python3 harness/tools/r29-negative-controls/run.py   # worktree 放 $HOME；用例定义见 harness/tools/r29-negative-controls/cases.py
```

| 用例 | 注入 | 测试（cargo test --workspace + clippy -D warnings；裁判双跑） | 后果 |
|---|---|---|---|
| NC-GPdefault | `#[derive(Debug, Default)]` + `egress_verdict(&out).or_else(\|_\| Ok(EgressVerified::default()))` | 绿×2 | verdict Err 被吞，恒铸令牌 |
| NC-GPself | `impl EgressVerified { pub fn mint() -> Self { Self { _sealed: () } } }` + `.or_else(\|_\| Ok(EgressVerified::mint()))` | 绿×2 | 第二构造点，计数钉仍 1 |
| NC-XGATE | creance-gate/src/lib.rs 新增 `pub fn arm_relay` = `vm::mark_provisioned(p,i,&gateprobe::egress_verdict("tcp-blocked…fw-armed\n").unwrap())`；main.rs up-gate `Err(e)` 臂先调 `creance_gate::arm_relay` 再 fail | 绿×2 | 零 unsafe、跨 crate：verify 失败照样武装 marker |
| NC-SIGres | qemu+vm.rs `_proof: &Result<EgressVerified, &'static str>`；verify_and_mark 先 `let armed = vm::mark_provisioned(.., &verdict)` 再 `match verdict` | 绿×2 | verdict 失败也已写 marker |
| NC-XMUTE2 | 同 XGATE，令牌由 `#[allow(unsafe_code)] … transmute::<(), EgressVerified>(())` 得 | 绿×2 | workspace lint 是 deny 非 forbid |

对照（红）：NC-SEALcnt（字面第二个 `EgressVerified { _sealed: () }`，计数 2 红）、NC-XMUTE（无 allow 的 transmute 被 `-D unsafe-code` 拦）。

## 建议

`egress_verdict` 降为私有（令牌只能经 `verify_and_mark` 出 crate）、`vm::mark_provisioned` 降 `pub(crate)`；构造点钉改为“全 workspace 任意 `_sealed` 出现次数==1 且禁 `Default`/`Clone` derive 与 `impl EgressVerified`”；`unsafe_code = "forbid"`；签名钉断言 `_proof: &crate::gateprobe::EgressVerified,` 字面。
