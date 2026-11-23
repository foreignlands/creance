# FINDING-104: `verify_and_mark` 单缝内输入仍可伪造：verdict 判字面量、guest 跑 canned echo、guest_script 失败喂通过串、`.map` 改写、`let out` 遮蔽全绿

- **编号**: 104
- **严重度**: S5（质量：守护/测试强度不足，需代码变更才可触发；无运行时可达路径）
- **攻击面**: F-100 修复面（crates/creance-vm/src/gateprobe.rs `verify_and_mark`）
- **发现者会话**: r29-auditor
- **状态**: 待修复

## 机理

CHANGELOG [0.6.21] 称 "main.rs holds no `out` to forge"——确实，但伪造面只是搬进了 `verify_and_mark`：sealed 令牌只证明“某个 &str 通过了 egress_verdict”，不证明该串来自本实例 guest 内真实探针。gateprobe 测试对 `verify_and_mark` 只有源码计数（`egress_verdict(`==2、`verify_and_mark(`==1），无任何行为测试（guest_script 不可注入）。

## 复现

```sh
CREANCE_REPO=$HOME/r29-wt ONLY="NC-GPforge NC-GPcanned NC-GPerr NC-GPmap NC-GPshadow2" python3 harness/tools/r29-negative-controls/run.py   # worktree 放 $HOME；用例定义见 harness/tools/r29-negative-controls/cases.py
```

| 用例 | 注入 | 测试（cargo test --workspace + clippy -D warnings；裁判双跑） | 后果 |
|---|---|---|---|
| NC-GPforge | `match egress_verdict(&out)` → `match egress_verdict("tcp-blocked\nicmp-blocked\nfw-armed\n")` | 绿×2（test+clippy -D warnings） | 任何 guest 输出都铸令牌→marker 武装 |
| NC-GPcanned | 探针脚本参数 `&egress_probe_script(vm::nat_allow_hosts())` → `"echo tcp-blocked; echo icmp-blocked; echo fw-armed"` | 绿×2 | guest 内不再探测，恒通过 |
| NC-GPerr | guest_script 的 `Err(e) => { stop_vm; return Err }` 臂 → `Err(_) => "tcp-blocked…fw-armed\n".to_owned()` | 绿×2 | 无法验证防火墙时反而判通过（fail-open） |
| NC-GPmap | guest_script 结果后接 `.map(\|_\| String::from("tcp-blocked…"))` | 绿×2 | 真实输出被丢弃 |
| NC-GPshadow2 | verdict 前插 `let out = if out.is_empty() { out } else { String::from("tcp-blocked…") };` | 绿×2 | 遮蔽（R28 F-100 同类，形状换成 if 表达式） |

对照（红）：NC-GPshadow（无引用的 `let out = String::from(..)` 遮蔽被 rustc unused_variables + clippy -D warnings 拦下，非测试之功）。

## 建议

让 `verify_and_mark` 以注入的 runner（trait/fn 参数）取得 guest 输出，行为测试喂“tcp-open/fw 缺失/guest 失败”断言 marker 不落盘且 VM 被 stop；或把探针输出与 verdict 合并为同一私有函数、令牌只能由“运行探针并解析”的单函数铸造。
