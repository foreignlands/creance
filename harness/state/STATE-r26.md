# STATE-r26 — 第十一次收敛判词轮（独立对抗性审查员）

- 基线：HEAD = main = v0.6.17 `6d314f6`；`sh scripts/ci.sh > /tmp/r26-ci-baseline.log 2>&1; RC=$?` → **RC=0**（181 passed / 0 failed，release build OK）
- 二进制：`target/release/creance` → `creance 0.6.17`（md5 8811ad60）
- 判词：**不收敛**——新立 F-094（S4）、F-095（S5）。收敛判词未发。
- 产品文件零改动（`crates/`、`scripts/`、`docs/`）：所有变异 cp 备份 → 还原 → md5sum -c 全 OK；隔离复跑用 git worktree（已移除）。

## 复核矩阵

| 核验点 | 结论 | 证据 |
|---|---|---|
| F-092 (a) 实机 up（v0.6.17 release） | 通过：init/setup/up1 RC=0（79s）/stop/up2 RC=0（18s）`-netdev user,…,restrict=on`；marker `ok`；盖章与 rules.v4 root 644、unit active+enabled、guest 用户写两文件 Permission denied、直连 tcp blocked、sudo 需密码 | r26-real-up/evidence |
| F-092 restrict=on 下 fw-armed 真判 | 通过：up2 出厂 probe 读真盖章 + 真 rules.v4 判 armed；guest 内 replay P01 armed；escape-test 网络族全 PASS（escape2 RC=1 仅因 proxy-path ESCAPE = lab 无代理节点，同 R20–R25） | r26-real-up/evidence/{up2,escape2,guest-replay}.log |
| F-092 (b) 整文件白名单变异 | 通过：还原选行（NC-B92SEL/SEL2）、摘 nfilter/ncommit/nout 计数、`^#`/空行过滤错位（NC-BLANKmis/BLANK0）、live 侧混结构行（NC-LIVESTRUCT）、摘 `-x`（NC-NOX/NOX2）全 RC=101；**例外**：结构允许集混入 `-A OUTPUT -j ACCEPT`（NC-SETMIX）全绿 → F-095 | r26-negative-controls/run.log |
| F-092 (c) 产品真实渲染文件 byte-level | 通过：r26-fw-exact 渲染 rules.v4 md5 e13fe10a = 真 guest `/etc/iptables/rules.v4`；P01（产品文件）A/B 均 armed + DROP；save 形（K03）、空行（K05）不误杀；注释行（K04）、CRLF（K06）、nat 表（S11）、`-F OUTPUT`（S10）被保守拒（fail-closed，产品文件不含这些形，非缺陷）；IPv6 走独立 net-ipv6 探针不在 rules.v4 | r26-fw-exact/netns*.log |
| F-092 (c') 白名单自身绕过面 | **不通过 → F-094**：S01–S09（R25 形）全 fw-down；但 `#\0` NUL 行使 GNU grep binary 模式吞行（Z01/Z02 `-I`/`-A OUTPUT -j ACCEPT` 判 armed），结构行只计数不定序（O01–O04 判 armed，restore 拒载）；qemu/C、C.UTF-8、lima 三口径一致；真 guest replay 复现；实机下一次开机 Z1/O1 up RC=1 fail-closed | netns*.log, r26-real-up/evidence/guest-replay.log, r26-stamp-drift/{Z1,O1}.log |
| F-092 (d) 盖章侧 live 检查独立失效面 | 通过：live 裸 ACCEPT（N01）、NEW（N03）、注释伪造（B01）判 fw-down；重复 canonical（C04）armed 无害；rules.v4 单侧坏而 live 好的形由 F-094 覆盖 | netns.log |
| F-093 点名变异 | 通过：R25 九例（use-as/括号/臂重排/vm.rs `up` 直调/`write_marker(` 直调/temp 前缀 gate/`>/run`/`\| tee`/`nft flush`）+ Ok 臂内插第二 `=>`（NC-MKarrow）+ 注释塞 `/run/egress-armed`（NC-STAMPc）+ `/var/run/…`（NC-STAMPvar）+ 摘 `-x` 全 RC=101 | r26-negative-controls/run.log |
| F-093 守护绕过面 | **不通过 → F-095**：跨模块转调（NC-MKmod）、`#[cfg(test)]` 注释截断（NC-MKcfg）、verdict `.or_else` 中和（NC-VERD）、vm.rs `use … as`（NC-VMuse）、`(write_marker)(`/`use … as wm`（NC-WMparen/WMuse）、instance_dir 形 gate（NC-MP4）、unit 内追加 ExecStartPost（NC-UNIT1/UNIT2）、`/run/./egress-armed`（NC-STAMPdot）、允许集混 ACCEPT（NC-SETMIX）共 11 例全绿；worktree 隔离复跑一致 | run.log, run-worktree.log |
| F-087 复核 | 通过：marker 移出 Ok 臂（NC-MK4m）、拆两处（NC-MK3）、`write_marker` 恒 true（NC-WMtrue）、ExecStartPost `\|\| true`（NC-ESPor）、restart 腿 `#`（NC-RSTc）、node sha 条件（NC-NOCKb）、conntrack 放行 NEW（NC-CTNEW）、NAT 表多项（NC-NAT1）全红；真 sh 真值表 = netns 矩阵 + guest replay | run.log |
| F-088 CHANGELOG 按 tag 区间 | 通过：`git log vA..vB` 0.6.10–0.6.14 逐 commit 对账同 R25 结论（无漏项/夸大）；v0.6.16..v0.6.17 仅 `6d314f6`，0.6.17 条目在 tag 内（`git show v0.6.16:CHANGELOG.md` 无 0.6.17，`v0.6.17` 有），条目 29 行全部对应 diff 中的 escape.rs/main.rs/qemu/mod.rs/provision.rs 变化，旧条目未改动 | git log / git show vX:CHANGELOG.md |
| F-089 r14/r15 裁判 | 通过：r14 RC=0×2 md5=2ecbd0c1、r15 RC=0×2 md5=965e444c（= R25 武装世界参考：27 个 expected id 含 fs-flag-readable）；flag 前后计数 0/0；r15 NC1/NC2 段仍证红 | r26-judges |
| 门禁矩阵 + 正控 | 通过：POS RC=0；NC-A/B/1/2/3/5/6v 全 RC=1；md5 四文件 OK | r26-gate-matrix |
| v0.6.16..v0.6.17 全量 diff | 已逐文件过：CHANGELOG/Cargo.{toml,lock}（仅版本号）/provision.rs（stamp 计数+尾部断言，测试代码）/qemu/mod.rs（write_marker 第三目录+计数，测试代码）/escape.rs（fw_probe_fragment 整文件校验 → F-094；真值表 → F-095 SETMIX）/main.rs（marker 守护 → F-095）/findings 092–093 + INDEX | git diff v0.6.16..v0.6.17 |

## 新 findings

| # | 严重度 | 一句话 |
|---|---|---|
| 094 | S4 | rules.v4 整文件白名单 NUL/定序盲：NUL 让 GNU grep binary 模式吞行、结构行只计数不定序——本次开机判 armed、rules.v4 下次开机不能重新武装（失败关闭，restrict=on 仍在） |
| 095 | S5 | v0.6.17 守护加固 11 例变异全绿（跨模块转调/cfg 注释截断/verdict 中和/vm.rs 别名/`(write_marker)(`/instance_dir gate/unit 追加 ExecStartPost/`/run/./` 伪盖章/允许集混 ACCEPT） |

## 工具（均 `CREANCE_REPO`/`CREANCE_BIN`/`LAB`/`PROBE` 参数化）

- `r26-fw-exact/`：出厂 probe/rules 渲染 dump + netns 两阶段（A 本次开机 / B 下次开机）矩阵，`BACKEND=lima`、`PLANG=C.UTF-8`
- `r26-real-up/`：真 QEMU init/setup/up/stop/up + facts；`guest-replay.sh` 真 guest 内跑出厂片段
- `r26-stamp-drift/`：qemu-nbd 离线改 rules.v4 → restrict=on up + CONTROL up（新增 O1/Z1）
- `r26-negative-controls/`：43 例源码变异（`ONLY=` 子集，`NC_LOGS=` 日志目录）
- `r26-judges/`、`r26-gate-matrix/`：裁判双跑、probe-inventory 门禁矩阵

## 下一轮建议

F-094 修复后复跑 `r26-fw-exact` Z/O 段与 `r26-stamp-drift Z1|O1`；F-095 修复后复跑 `r26-negative-controls`（期望 43/43 红）。源码字面守护已连续三轮（F-091→093→095）被同构绕过，建议修复方向转向类型/行为守护（见 F-095 修复建议）。
