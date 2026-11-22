# FINDING-095: v0.6.17 守护加固 11 例变异仍全绿——跨文件/`#[cfg(test)]` 注释截断绕开 marker 计数、verdict 可被 `.or_else` 中和、vm.rs/qemu 侧 `use … as`/`(write_marker)(…)` 直写 marker、产品路径形 gate、unit 内追加 ExecStartPost、`/run/./egress-armed` 伪盖章、结构行允许集混入 ACCEPT

- **编号**: 095
- **严重度**: S5（质量：同 F-076/078/079/084/087/091/093 类——CHANGELOG 0.6.17 F-093 宣称的守护语义不被 CI 守住）
- **攻击面**: H1 / F-093 修复面
- **发现时间**: 2026-11-22T16:25Z
- **发现者会话**: r26-auditor（R26 第十一次收敛判词轮）
- **状态**: 已修复（main-session，实机复验）

## 复现（必须）

```sh
CREANCE_REPO=$PWD sh harness/tools/r26-negative-controls/run.sh          # run.log；每例 cargo 输出 logs/<case>.log
# 隔离复跑（git worktree，不碰主 checkout）：
git worktree add --detach /tmp/r26-wt HEAD
CARGO_TARGET_DIR=/tmp/r26-wt-target CREANCE_REPO=/tmp/r26-wt NC_LOGS=/tmp/r26-wt-nclogs \
  ONLY="NC-MKmod NC-MKcfg NC-VERD NC-VMuse NC-WMparen NC-WMuse NC-MP4 NC-UNIT1 NC-UNIT2 NC-STAMPdot NC-SETMIX NC-MKuse" \
  sh harness/tools/r26-negative-controls/run.sh                               # run-worktree.log：同 11 绿 + NC-MKuse 红
```

规程：cp 备份 → perl 注入 → grep -c 前后计数证明落地（全部 before=0 after≥1）→ `cargo test --locked -q -p <crate>` → cp 还原 → md5sum -c（6 文件全 OK）。全绿用例均编译通过、测试 0 failed（非编译错误伪绿）。

变红（守护有效，43 例中 32 例）：R25 F-093 九例回归全红（NC-MKuse/MKparen/MKswap/MKarrow/MK6/WM/MP3/MP2/STAMPf2/STAMPf3/RST5，另 NC-STAMPc 注释塞路径、NC-STAMPvar `/var/run/…`、NC-RST4）；F-092 整文件校验变异全红（NC-B92SEL/B92SEL2 还原选行、NC-NFILT/NCOMMIT/NOUT 摘计数、NC-BLANKmis `^#` 过滤错位、NC-BLANK0、NC-LIVESTRUCT、NC-NOX/NOX2 摘 `-x`）；F-087 回归全红（NC-MK4m、NC-MK3、NC-WMtrue、NC-ESPor `|| true`、NC-RSTc `#` restart、NC-NOCKb、NC-CTNEW 放行 NEW、NC-NAT1）。

**全绿（无守护，11 例）**：

| 用例 | 注入 | 落空的宣称 / 后果 |
|---|---|---|
| NC-MKmod | escape.rs 加 `pub fn arm_after(p,i)->bool{creance_vm::vm::mark_provisioned(p,i)}`，main.rs `Err(reason)` 臂调 `escape::arm_after(&profile,&instance)` | "全文件唯一调用点"——计数只扫 main.rs；同 crate 其它模块转一手，verdict 失败时写 marker |
| NC-MKcfg | main.rs 在 `fn cmd_shell(` 前插注释 `// #[cfg(test)] marker-free helper` + 调 marker 的 helper，Err(reason) 臂调 helper | pre-test 区由 `find("#[cfg(test)]")` 截取——注释里的字面量把截断点提前，helper 中第二个 `mark_provisioned` 落在"测试区"不计 |
| NC-VERD | `match escape::egress_verdict(&out).or_else(\|_\| Ok::<(), &str>(())) {` | 位置守护只看 marker 在 Ok(()) 臂内，不守 verdict 真被消费；fw-down/tcp-open 全被吞成 Ok，marker 照写、up 照绿（F-081 宣称的 up 门禁失效） |
| NC-VMuse | vm.rs `up`：`use crate::qemu::mark_provisioned as arm_now; let rc = crate::qemu::up(..); if rc == 0 { let _ = arm_now(..); } rc` | vm.rs 计数针是 `mark_provisioned(`（`use … as` 不含 `(`），位置钉用 `rfind("mark_provisioned(")` 仍落在 dispatch 体内；marker 回到"verdict 前写"（main.rs 已修的别名形在 vm.rs 未修） |
| NC-WMparen | qemu/mod.rs `up` mount-ok 臂 `let _ = (write_marker)(&dir);` | "counts `write_marker(` too"——`write_marker)(` 不含针；直写 marker，跳过整套调用点守护 |
| NC-WMuse | 同处 `use self::write_marker as wm; let _ = wm(&dir);` | 同上：别名调用不计 |
| NC-MP4 | `write_marker` 开头 `if dir.contains("/state/qemu/") { return true; }` | "a path-prefix gate that declines to write now fails"——第三目录只是 `cwd/target-mk-*`；按产品 instance_dir 形（`…/state/qemu/<inst>`）gate，恒 true 不写盘 |
| NC-UNIT1 | unit 里真 ExecStartPost 后加 `ExecStartPost=/usr/sbin/iptables -P OUTPUT ACCEPT` | 尾部逐字节断言只覆盖 `systemctl restart` 之后；unit 体只有 `contains(真行)`，第二条 ExecStartPost 在盖章后把策略改 ACCEPT——stamp 仍 DROP，live 全开 |
| NC-UNIT2 | 同处加 `ExecStartPost=-/usr/sbin/nft flush ruleset` | 同上（"nft flush … fails" 的宣称只对 apply 尾部成立） |
| NC-STAMPdot | 同处加 `ExecStartPost=/bin/sh -c 'echo ":OUTPUT DROP [0:0]" > /run/./egress-armed'` | "counts every `/run/egress-armed` occurrence (any spelling)"——`/run/./egress-armed` 是同一路径的另一拼写，计数仍 1；伪盖章覆盖真盖章 |
| NC-SETMIX | escape.rs body 允许集追加 `-e '-A OUTPUT -j ACCEPT'` | 任务书点名"canonical 行与结构行允许集混淆"变异应红；真值表无"live canonical + rules.v4 含裸 ACCEPT"行，rules.v4 侧放行裸 ACCEPT 不被抓 |

## 根因

- `crates/creance/src/main.rs:800-826`（`provisioned_marker_only_after_verdict`）：只扫 main.rs；pre-test 区用首个 `#[cfg(test)]` 字面量截断；只钉 marker 位置不钉 verdict 结果被原样 match。
- `crates/creance-vm/src/qemu/mod.rs:577-616`（`mark_provisioned_is_called_only_from_the_cli_crate`）：针 `mark_provisioned(` / `write_marker(` 带括号，`use … as` 与括号路径逃逸——F-093 对 main.rs 修成裸名计数，creance-vm 侧未同步。
- `crates/creance-vm/src/qemu/mod.rs:543-575`（`write_marker_writes_once_then_refuses`）：三目录无一为产品 instance_dir 形。
- `crates/creance-vm/src/provision.rs:323-362`：unit 体只 `contains` 真 ExecStartPost 行，不钉 unit 全文；路径计数是字面子串。
- `crates/creance/src/escape.rs` 测试段：真值表缺"rules.v4 被篡改而 live 仍 canonical"的裸 ACCEPT 行。

## 修复建议（仅建议，审查员不修）

同 F-093 建议，源码字面守护已连续三轮被同构绕过（F-091→F-093→F-095），宜转行为：marker 写入要求只能由 `egress_verdict` 的 Ok 构造的 `Verified` 令牌（类型系统保证，无需计数）；`write_marker` 在 `instance_dir(profile, instance)` 真实形路径下测；egress-lock unit 断言为整段逐字节相等；stamp 路径改由单一 Rust 常量渲染并断言脚本内只有该常量一次出现；真值表补 rules.v4 单侧篡改行。
