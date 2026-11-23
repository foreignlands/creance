# FINDING-096: v0.6.18 bootstrap 的 rules.v4 heredoc 多出一行 `EGRESSRULES`——`set -e` 下 bootstrap 在写完 rules.v4 后立即中止（`EGRESSRULES: not found`, RC=127），egress-lock.service 不落地，每次 fresh `setup` 之后 `up` 都 fail-closed 变砖；CI 无任何用例执行或结构校验该 heredoc

- **编号**: 096
- **严重度**: S4（正确性：fail-closed——up 门禁拒绝并停 VM，未出现直连回退成功的 up；但 v0.6.18 Linux/QEMU fresh setup 100% 不可用，Lima 同一 bootstrap 同病）
- **攻击面**: F-094 修复面（`rules_v4_text` 单源提取的波及面）
- **发现时间**: 2026-11-23T10:00Z
- **发现者会话**: r27-auditor（R27 第十二次收敛判词轮）
- **状态**: 未修复（只立案）

## 复现（必须）

```sh
# 1) 渲染真实 bootstrap（产品函数 provision::guest_bootstrap / rules_v4_text，独立 crate 调用）
cargo run -q --manifest-path harness/tools/r27-render/Cargo.toml bootstrap qemu > /tmp/boot.sh
grep -n -B1 -A1 '^EGRESSRULES$' /tmp/boot.sh          # COMMIT / EGRESSRULES / EGRESSRULES
# 2) 逐字节：heredoc 体 == rules_v4_text（单源本身成立）
cargo run -q --manifest-path harness/tools/r27-render/Cargo.toml rules qemu | md5sum   # e13fe10a…
# 3) 实机（v0.6.18 release，Linux QEMU/KVM）
LAB=$HOME/r27-lab CREANCE_BIN=$PWD/target/release/creance sh harness/tools/r27-real-up/run.sh
LAB=$HOME/r27-lab sh harness/tools/r27-real-up/offline-facts.sh        # VM 停止后 qemu-nbd 只读挂盘
# 4) 变异：CI 对 heredoc 结构零感知
CREANCE_REPO=<repo-outside-/tmp> ONLY="NC-SSfix NC-SSterm3 NC-SSnoterm NC-SSdrift NC-SSdrop" \
  sh harness/tools/r27-negative-controls/run.sh
```

## 期望

bootstrap heredoc 恰一个终止行；脚本执行到底（写 egress-lock.service、enable、`systemctl restart egress-lock.service` 盖章 `/run/egress-armed`）；up#1 探针 fw-armed → 写 marker → up#2 restrict=on。CHANGELOG [0.6.18] F-094 条目宣称 "verified on a live restrict=on guest"。

## 实际

- 渲染输出第 53 行起：`COMMIT` / `EGRESSRULES`（结束 heredoc）/ `EGRESSRULES`（被当成命令）。`sh /tmp/boot.sh` 等价回放：dash/bash 均 `EGRESSRULES: not found`，RC=127，`set -e` 中止。
- 实机 evidence（harness/tools/r27-real-up/evidence/）：init RC=0、setup RC=0（25s）、**up1 RC=1（78s）**、stop1 RC=0、**up2 RC=1**，up2 原文：`guest 防火墙未生效（直连可达），VM 已停止；…探针原始输出："tcp-open\nicmp-open\nfw-down\n"`。
- 离线挂盘（offline-facts.log）：`/var/log/cloud-init-output.log:84: sh: 53: EGRESSRULES: not found`，`cc_scripts_user … Failed to run module scripts_user`；`/etc/iptables/rules.v4` md5 = `e13fe10a…` = 渲染器输出（文件已写，F-094(b) 字节一致成立）；`/etc/systemd/system/egress-lock.service` **不存在**、multi-user.target.wants 无 egress-lock；toolchain 日志不存在（其后所有供给步骤均未执行）。→ 无 unit、无盖章、netfilter OUTPUT 默认 ACCEPT，探针正确判 fw-down，门禁拒绝并停 VM。
- 变异：NC-SSfix（删掉多余那行=正确修复）、NC-SSterm3（再加一行）、NC-SSnoterm（终止符拼错→heredoc 吞掉余下整个脚本）、NC-SSdrift（heredoc 体前加注释行→文件 ≠ 渲染器→每次 up 必砖）、NC-SSdrop（heredoc 侧丢一条规则）——**5 例全绿**（65 passed），CI 无法区分正确与损坏的 bootstrap。

## 根因假设

`crates/creance-vm/src/provision.rs:92-94`：e831956 把旧的 `-{nat_rules}COMMIT` 行替换为 `+{rules_v4}EGRESSRULES`（`rules_v4` 已以 `COMMIT\n` 结尾，终止符被并到同一行），但保留了原有的 `EGRESSRULES` 终止行，于是出现两行终止符。provision.rs 测试只做 `contains`/计数/apply 之后尾部字节钉（`:340-365`），从不执行 bootstrap（`sh -n` 也查不出——是运行期 command-not-found），也不提取 heredoc 体与 `rules_v4_text` 比对、不计 `^EGRESSRULES$` 行数；F-094 的"单源"仅在 Rust 层成立，shell 层的嵌入结构无守护。CHANGELOG 的实机验证宣称与 fresh setup 实测相悖（推测验证于旧版 setup 过、rules.v4/unit 已存在的 guest 上——推断，未证）。

## 影响

v0.6.18 任何 fresh `creance setup` 后 `creance up` 恒失败；用户被提示"stop 后 setup 重建"，重建同样失败（无自救路径）。安全方向 fail-closed（marker 不写、restrict 不开、VM 被停），故定 S4 而非 S2。
