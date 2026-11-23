# FINDING-100: up-gate verdict 输入仍可伪造——探针单调用钉与 `let out ` 缺席断言可被丢弃结果/`.map`/元组解构/局部 `mod escape` 绕过

- **编号**: 100
- **严重度**: S5（质量：CHANGELOG [0.6.20] "pins the `egress_probe_script` producer call and forbids a `let out` shadow" 不被 CI 守住）
- **攻击面**: F-097 修复面（crates/creance/src/main.rs cmd_up :751-756 / `up_gate_tests`）
- **发现者会话**: r28-auditor
- **状态**: 待修复

## 复现

```sh
CARGO_TARGET_DIR=$HOME/r28-wt-target CREANCE_REPO=$HOME/r28-wt ONLY="NC-PROBEdisc NC-MAPout NC-LETOUTpre NC-SHADOWmod" sh harness/tools/r28-negative-controls/run.sh
```

全部 test-RC=0（creance 20p/0f，无编译错误）；每例 verdict 恒 Ok → 未验证即 `mark_provisioned`。

| 用例 | 注入 | 绕过点 |
|---|---|---|
| NC-PROBEdisc | `guest_script(.., &{ let _ = escape::egress_probe_script(..); "echo tcp-blocked; echo icmp-blocked; echo fw-armed".to_owned() })` | 单调用钉只数 `egress_probe_script(` 出现次数，不钉其返回值流入 guest_script |
| NC-MAPout | `guest_script(..)` 后链 `.map(\|_\| String::from("tcp-blocked\nicmp-blocked\nfw-armed\n"))` | 钉的是调用文本，不是 `out` 的数据来源 |
| NC-LETOUTpre | 外层 `let (out, _) = (String::from(".."), ());`，臂改 `Ok(_real) => match escape::egress_verdict(&out)` | `let out ` 缺席断言只认该字面；解构绑定 `let (out` 不匹配 |
| NC-SHADOWmod | cmd_up 体内 `mod escape { pub use creance::escape::egress_probe_script; pub fn egress_verdict(_: &str) -> Result<(), String> { Ok(()) } }` | 块内 item 遮蔽 crate 级 `escape`；`match escape::egress_verdict(&out) {` 字面钉仍命中但解析到伪函数 |

NC-LETOUTty（`Ok(out) if { let out: &str = .. }`）为编译错误（E0004），无效用例，不计（logs/NC-LETOUTty.log）。

## 建议

同 F-099：verdict 应返回只能由真实探针输出构造的类型，marker 写入以之为参数。
