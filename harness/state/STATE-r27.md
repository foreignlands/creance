# STATE-r27 — creance 第十二次收敛判词轮（终稿）

- 对象：main = v0.6.18 tag `e831956`（单 commit v0.6.17..v0.6.18）；release 二进制 `creance 0.6.18`
- 审查员：r27-auditor；只记录不修复——`crates/` `scripts/` `docs/` 零改动（`git diff --stat v0.6.18 -- crates scripts docs` 为空）
- 新发现：**096（S4）、097（S5）** ⇒ **不收敛，未发收敛判词**

## 基线

`sh scripts/ci.sh > /tmp/r27-ci-baseline.log 2>&1; RC=$?` → **RC=0**，181 passed / 0 failed（harness/tools/r27-baseline/）。

## F-094 复核（rules.v4 cmp 化 + 单源渲染）

| 核验点 | 结论 | 证据 |
|---|---|---|
| (a) 实机 up 真通过 / restrict=on fw-armed | **不通过**：fresh setup 后 up1/up2 均 RC=1（probe `tcp-open icmp-open fw-down`）→ F-096 | r27-real-up/evidence/ |
| (b) 实机 rules.v4 == 渲染器字节 | 通过：guest 盘 rules.v4 md5 `e13fe10a` = `rules_v4_text(NAT_HOSTS_QEMU)` | evidence/offline-facts.log |
| (c) 探针侧变异验红 | 通过：CMPtrue/CMPnoS/CMPn/CMPswap/TRUNC/PDRIFT/AND/LIVEor 8 例全红；HDQ（heredoc 去引号）、CMPskip（`0 0`）绿但语义等价，非缺陷 | r27-negative-controls/run.log |
| (d) 盖章侧 live 独立失效面 | 通过：N01/N03/B01/C04 live 注入全 fw-down；NOX/SETregx/LIVESTRUCT 红 | r27-fw-exact/netns*.log |
| (e) 单源破坏守护 | **不通过**：bootstrap heredoc 结构/体漂移 5 例（SSfix/SSterm3/SSnoterm/SSdrift/SSdrop）全绿——CI 不执行/不比对 heredoc（F-096）；探针侧漂移 PDRIFT 红 | run.log |
| netns 真值表（qemu C / qemu C.UTF-8 / lima） | 通过：各 34 例 63 次判定，仅 P00/P01 产品形 fw-armed，余 60 次 fw-down（含 NUL Z01-03、乱序 O01-04、X01-04 尾空行/无尾换行/尾 NUL/BOM） | r27-fw-exact/ |

## F-095 复核（11 例绕过补齐）

- R26 的 11 例绿全部转红（NC-MKmod/MKcfg/VERD/VMuse/WMparen/WMuse/MP4/UNIT1/UNIT2/STAMPdot/STAMPvar）——修复对原形状有效。
- 新形状 15 例仍绿 → **F-097**：rfind 截断丢测试模块之后的代码（MKtail/MKtailE/WMtail/VMtail）、子模块文件不扫（MKsub/WMsub）、跨 crate 中转（MKxcrate）、verdict 输入伪造（VERDin）、`/.creance/` 路径 gate（MPhome）、`!cfg!(test)`（MPcfg）、`ExecStartPost =` 空格（ESPsp/ESPsp2，systemd 249 实测执行，r27-systemd-spacing）、引号拆词盖章（STAMPq）、第二 unit（UNITsep）、`-p tcp` 允许集（SETtcp）。
- 红：`/run/../run/egress-armed`（STAMPdd）、symlink（STAMPsym）、`--regexp=` 允许集（SETregx）。
- NC-MP3 在 /tmp worktree 中为绿系环境假象，家目录 worktree 复跑为红（run-home.log）。

## F-092 回归

netns 真值表 R01/R02/S01-S11 在 qemu/lima 两后端全 fw-down（boot B 中 iptables-restore 实际放行的 S01-S09 等均被拒）——cmp 化后无回退。

## F-088 类：CHANGELOG / commit 对账

v0.6.17..v0.6.18 仅 `e831956` 一个 commit；tag 内含 CHANGELOG `[0.6.18]`（F-094/F-095 条目），版本号 workspace 0.6.18。条目宣称 "verified on a live restrict=on guest" 与 fresh setup 实测相悖（记入 F-096）。

## 门禁矩阵 + 裁判双跑

- probe-inventory 门禁：POS RC=0；NC-A/NC-B/NC1/NC2/NC3/NC5/NC6v 全 RC=1；4 文件 md5 还原 OK（r27-gate-matrix/run.log）。
- 裁判：r14-convergence 双跑 RC=0 md5 `2ecbd0c1`、r15-064-recheck 双跑 RC=0 md5 `965e444c`，与参考一致；temp flag before/after 均 0（r27-judges/run.log）。
- 负控规程：cp 备份 → grep -c 注入前后计数（全部落地）→ cargo test → 还原 → md5sum -c 6 文件 OK（run.log / run-home.log 尾部）。

## v0.6.17..v0.6.18 全量 diff

10 文件：CHANGELOG、Cargo.toml/lock（版本）、provision.rs（rules_v4_text 提取 → F-096 根因 :92-94）、qemu/mod.rs（守护 → F-097）、escape.rs（cmp heredoc 探针 + 真值表；通过）、main.rs（守护 → F-097）、findings 094/095/INDEX。

## 未完成 / 受阻

- R26 r*-stamp-drift（已供给 guest 上 rules.v4 离线篡改实机回放）未跑：前提是一台 restrict=on 已供给实例，F-096 使 v0.6.18 无法供给。
- restrict=on 下 escape-test 实机判定同因未获得（escape2 RC=0 仅在 up2 失败后运行，不作证据）。

## 下一轮建议

1. 修 F-096 后实机 fresh setup → up1 → stop → up2（restrict=on）→ facts/escape-test 全链复跑，并补一个执行 bootstrap（或至少提取 heredoc 体 == rules_v4_text、`^EGRESSRULES$` 恰 1 行）的 CI 用例。
2. F-097 各形复跑；守护宜从文本计数转向结构性约束（如 marker 写入 API 需 verdict token 类型）。
3. stamp-drift 实机回放补跑。
