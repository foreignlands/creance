# FINDING-099: v0.6.20 marker 守护（递归扫描/尾部 mod 排除/write_marker 目录与 cfg! 禁体）仍有 7 例变异全绿

- **编号**: 099
- **严重度**: S5（质量：同 F-087/091/093/095/097 类——CHANGELOG [0.6.20] F-097 宣称的守护语义不被 CI 守住）
- **攻击面**: F-097 修复面（crates/creance/src/main.rs `up_gate_tests`、crates/creance-vm/src/qemu/mod.rs 守护）
- **发现者会话**: r28-auditor
- **状态**: 已修复（main-session，实机复验）

## 复现

```sh
CARGO_TARGET_DIR=$HOME/r28-wt-target CREANCE_REPO=$HOME/r28-wt ONLY="NC-CUTnew NC-CUTinner NC-CUTnewQ NC-PATHmod NC-MPhome2 NC-MPattr NC-VMcfg" sh harness/tools/r28-negative-controls/run.sh
```

全部 grep-c before=0 after=1、test-RC=0、日志无 `error[E`（creance 20p/0f、creance-vm 65p/0f），md5sum -c 全 OK。

| 用例 | 注入 | 落空的宣称 |
|---|---|---|
| NC-CUTnew | 新文件 `src/escape/relay.rs`：`#[cfg(test)]\nmod t {}\npub fn arm(..){ mark_provisioned(..) }`；main.rs `Err(reason)` 臂调 `escape::relay::arm` | “只排除尾部测试 mod”：`rfind("\n#[cfg(test)]")` 后 `find("\n}")` 找到的是 **其后产品 fn 的闭括号**（单行 `mod t {}` 没有 `\n}`）——产品 fn 整段被当测试区排除。verdict 失败仍写 marker |
| NC-CUTinner | escape.rs 原 `#[cfg(test)] mod tests` 改内属性 `mod tests { #![cfg(test)]`，另加 `#[cfg(test)] mod t {}` + `arm_after` 产品 fn | 同上；“每文件至多一个 `#[cfg(test)]`”只数外属性文本，内属性 `#![cfg(test)]` 不计 |
| NC-CUTnewQ | qemu/arm.rs 同形，`mount-ok` 臂调 `arm::mark`→`write_marker` | creance-vm 侧同一截断逻辑；全局计数 (3,2) 不变 |
| NC-PATHmod | lib.rs `#[path = "../relay/arm.rs"] pub mod relay;`（文件在 `src/` 之外） | 递归遍历只走 `src/`；`#[path]` 把模块源放到扫描树外 |
| NC-MPhome2 | write_marker 首行 `if dir.contains("/.creance/") && dir.contains("/state/qemu/") { return true; }` | 第五目录 `…/.creance/prof` 不含产品真实层级 `/state/qemu/`——产品形路径 gate 仍可写 |
| NC-MPattr | write_marker 内 `#[cfg(not(test))] let marker = format!("{marker}.d");` | “fn 体禁含 `cfg!`”只禁宏；`#[cfg(..)]` 属性同样把测试/产品行为分叉（产品写到 `provisioned.d`，探测不到） |
| NC-VMcfg | vm.rs `mark_provisioned` 首行 `if !cfg!(test) { return true; }` | cfg! 禁体只覆盖 qemu::write_marker；vm.rs 分发层无此约束 |

对照（红）：R27 的 15 例绿形状（MKtail/MKtailE/MKsub/MKxcrate/VERDin/WMsub/WMtail/VMtail/MPhome/MPcfg/ESPsp/ESPsp2/STAMPq/UNITsep/SETtcp）全部转红；R25/R26 回归全红；NC-ESPdropin（drop-in 目录写 ExecStartPost）红；NC-PROBEfnptr（函数指针别名调用探针）红。`use up_gate_tests as x` 形未立案：`up_gate_tests` 为 `#[cfg(test)]`，非测试构建中不存在，产品二进制不可达。

## 建议

文本计数已连续五轮被绕；宜改结构性约束（marker 写入需 verdict 成功才能构造的 token 类型参数），使绕过在类型层面不可编译。
