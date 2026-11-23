# FINDING-097: v0.6.18 F-095 守护补齐仍有 15 例变异全绿——`rfind` 截断把测试模块之后的产品代码整段丢弃、read_dir 不递归/子模块文件不在清单、跨 crate 中转、verdict 输入可伪造、产品家目录形路径 gate、`ExecStartPost =` 空格拼写（systemd 实测执行）、`egress-"armed"` 引号拆词、第二个 unit 翻策略、允许集混入非裸 ACCEPT

- **编号**: 097
- **严重度**: S5（质量：同 F-087/091/093/095 类——CHANGELOG [0.6.18] F-095 宣称的守护语义不被 CI 守住）
- **攻击面**: F-095 修复面
- **发现时间**: 2026-11-23T10:40Z
- **发现者会话**: r27-auditor（R27 第十二次收敛判词轮）
- **状态**: 未修复（只立案）

## 复现（必须）

```sh
git worktree add --detach $HOME/r27-wt HEAD     # 勿放 /tmp：见下 NC-MP3 说明
CARGO_TARGET_DIR=$HOME/r27-wt-target CREANCE_REPO=$HOME/r27-wt sh harness/tools/r27-negative-controls/run.sh
sh harness/tools/r27-systemd-spacing/run.sh       # systemd 249 实测 `ExecStartPost =` / tab 形均执行
```

规程：cp 备份 → perl 注入 → grep -c 前后计数（全部 before=0 after=1）→ `cargo test --locked -q -p <crate>` → cp 还原 → md5sum -c（6 文件全 OK）。全绿用例日志均无 `error[E`/`could not compile`，且为 N passed / 0 failed（creance 20、creance-vm 65、双 crate 85）。注：run.log 的 `compile-err=` 列把 `error: test failed` 也计入，判红/绿以 test-RC 为准、编译错误另行 grep 为 0。

变红（守护有效）：R25/R26 回归 33 例全红（NC-MP3 以家目录 worktree 复跑计；含 F-095 11 例 NC-MKmod/MKcfg/VERD/VMuse/WMparen/WMuse/MP4/UNIT1/UNIT2/STAMPdot/STAMPvar，F-093 NC-MKuse/MKparen/MKswap/MKarrow/MK6/WM/MP2/MP3/STAMPf2/f3/c/RST4/RST5/NOX，F-087 NC-MK4m/MK3/WMtrue/ESPor/RSTc/NOCKb/CTNEW/NAT1）；新增 NC-STAMPdd `/run/../run/egress-armed`、NC-STAMPsym symlink、NC-SETregx `--regexp=`、NC-LIVESTRUCT 红。

**全绿（无守护，15 例）**：

| 用例 | 注入 | 落空的宣称 / 后果 |
|---|---|---|
| NC-MKtail | main.rs 末尾（`mod tests` 之后）追加 `fn arm_unverified(p,i){ mark_provisioned(p,i) }`，`Err(reason)` 臂调用 | `rfind("\n#[cfg(test)]")` 截断丢弃**最后一个测试属性之后的全部文本**——测试模块之后的产品 fn 不计数；verdict 失败仍写 marker |
| NC-MKtailE | 同上，helper 追加在 escape.rs 末尾 | 同上（全 crate 扫描每个文件都按 rfind 截断） |
| NC-MKsub | 新文件 `src/escape/relay.rs` + `pub mod relay;`，Err 臂调 `escape::relay::arm` | `read_dir(src)` 不递归，子目录模块文件不扫 |
| NC-MKxcrate | creance-vm `lima.rs` 加 `pub fn arm_relay`→`crate::vm::mark_provisioned`，main.rs Err 臂调 `creance_vm::lima::arm_relay` | 计数只看 cli crate 的裸名；vm crate 的 qemu/mod.rs 守护清单不含 lima.rs |
| NC-VERDin | `guest_script(…, "echo tcp-blocked; echo icmp-blocked; echo fw-armed")` 替换真实探针 | 字面钉只钉 `match escape::egress_verdict(&out) {`，不钉 `out` 来自 `egress_probe_script(...)`——verdict 恒 Ok，未验证即 arm |
| NC-WMsub | 新文件 `qemu/arm.rs`（`super::write_marker(d)`）+ `mod arm;`，`up` 的 mount-ok 臂调用 | qemu 守护用固定 4 文件清单（mod/runner/provision/vm），新文件不在内 |
| NC-WMtail | qemu/mod.rs 末尾追加 `fn wm_relay(d){write_marker(d)}`，mount-ok 臂调用 | rfind 截断，同 NC-MKtail |
| NC-VMtail | vm.rs 末尾 `fn arm_now`→`crate::qemu::mark_provisioned`，Linux `up` 成功即调 | rfind 截断；位置断言 `rfind("mark_provisioned(")` 也在截断后区域内找 |
| NC-MPhome | `write_marker` 首行 `if dir.contains("/.creance/") { return true; }` | 产品默认 profile 在 `~/.creance/`（main.rs:98）——生产路径永不写 marker 而报 true；4 个测试目录无一含 `/.creance/` |
| NC-MPcfg | `if !cfg!(test) { return true; }` | 行为测试天然看不到；无源码文本守护 |
| NC-ESPsp | unit 内追加 `ExecStartPost = /usr/sbin/iptables -P OUTPUT ACCEPT` | `matches("ExecStartPost=")` 只认无空格拼写；systemd 接受 `=` 两侧空白（r27-systemd-spacing：`'ExecStartPost=' substring: 0`，`ran: spaced-post-ran tab-post-ran`，systemd 249）——盖章后策略被翻 ACCEPT |
| NC-ESPsp2 | `ExecStartPost = -/usr/sbin/nft flush ruleset` | 同上 |
| NC-STAMPq | `ExecStartPost = /bin/sh -c 'echo ":OUTPUT DROP [0:0]" > /run/egress-"armed"'` | `egress-armed` 计数被 shell 引号拆词绕开，且与空格形叠加；伪盖章覆盖真章 |
| NC-UNITsep | bootstrap 另写 `net-tune.service`（`After=egress-lock.service`，`ExecStart=/usr/sbin/iptables -P OUTPUT ACCEPT`）并 enable | 唯一性计数只针对 egress-lock 的 ExecStartPost/stamp；尾部字节钉从 apply 腿开始，unit 定义区不受钉 |
| NC-SETtcp | 允许集加 `"-A OUTPUT -p tcp -j ACCEPT"` | 缺席断言只认字面 `-e '-A OUTPUT -j ACCEPT'`；全部 TCP 出站进白名单 |

另记（非缺陷、语义等价，作为边界存档）：NC-HDQ（`<<CREANCE_RULESET_EOF` 不加引号——期望文本无 `$`/`` ` ``/`\`，展开后字节不变）、NC-CMPskip（`cmp -s "$WANT" - 0 0` 跳 0 字节）绿。NC-MP3 在 `/tmp` 下的 worktree 里为绿系环境假象（`outside` 目录=cwd 也在 temp_dir 下），家目录 worktree 复跑为红（run-home.log），不计。

## 根因假设

源码文本守护的三个结构性盲区：(1) `crates/creance/src/main.rs:812-819`、`crates/creance-vm/src/qemu/mod.rs:603-627` 用 `rfind("\n#[cfg(test)]")` 截取"产品区"，假设测试模块总在文件末尾；(2) 文件集合是 `read_dir` 单层（main.rs:812）或硬编码清单（qemu/mod.rs:603-606），且只覆盖单 crate；(3) provision.rs:355-361、escape.rs:1039 的计数/缺席断言是固定拼写子串匹配，而 systemd/shell 对同义拼写宽容。verdict 字面钉（main.rs:826-833）不约束其输入来源。

## 影响

守护可被无编译错误、测试全绿的改动绕开，F-095 修复宣称的"任何拼写/中转都计数"不成立；产品当前代码未发现利用（v0.6.18 产品源码本身各计数为 1），故 S5。
