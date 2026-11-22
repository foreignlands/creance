# FINDING-086: v0.6.14 的 fw-armed 判据只拒一个字面形态、且是 apply 时快照——带任意限定词的 ACCEPT（`-o e+`）或盖章后的规则漂移下，restrict=on 的 `up` 依旧全绿；F-081/F-083 的遮蔽在实机复现

- **编号**: 086
- **严重度**: S4（正确性：与 F-081/F-083 同级——隔离仍由 slirp restrict=on 守住，直连 1.1.1.1:443 实测仍 blocked；但第一道防线失效依旧不可观测）
- **攻击面**: H1 / F-082+F-083 修复面（escape.rs:312、provision.rs:102）
- **发现时间**: 2026-11-22T13:00Z
- **发现者会话**: r23-auditor（R23 第九次收敛判词轮）
- **状态**: 待修复

## 复现（必须）

宿主 netns 逐字回放（ExecStartPost 与探针 fw 行从源码抽取，只把 /run 换成临时目录）：

```sh
sh harness/tools/r23-stamp-netns/netns.sh      # 证据 harness/tools/r23-stamp-netns/netns.log
```

实机（v0.6.14 release 二进制，Linux QEMU，已 setup+up#1，marker 在 ⇒ restrict=on）：

```sh
LAB=<lab> sh harness/tools/r23-stamp-drift/run.sh D1   # rules.v4 追加 -A OUTPUT -o e+ -j ACCEPT
LAB=<lab> sh harness/tools/r23-stamp-drift/run.sh D2   # 盖章后另一 root unit: -P OUTPUT ACCEPT; -F OUTPUT
# 证据 harness/tools/r23-stamp-drift/evidence/{D1,D2}.log
```

| 用例 | 生效 OUTPUT | stamp 内容 | probe | up（restrict=on） | 对照 up（无 marker） |
|---|---|---|---|---|---|
| netns V02 裸 `-A OUTPUT -j ACCEPT` | 全放行 | 含该行 | fw-down | — | — |
| netns V03/V04/V05/V07/V08/V09 `-o d0`/`-o d+`/`-p tcp`+`-p udp`/带 comment/跳自定义链/`ctstate NEW` ACCEPT | 全放行（UDP 外发实测成功） | 含该行 | **fw-armed** | — | — |
| netns V10/V11/V12 盖章后插入裸 ACCEPT / 改策略 ACCEPT / flush | 全放行 | 旧快照 | **fw-armed** | — | — |
| 实机 D1 `-A OUTPUT -o e+ -j ACCEPT` | 全放行 | 含 `-A OUTPUT -o e+ -j ACCEPT` | **fw-armed** | **RC=0 绿** | RC=1，探针原始输出 `tcp-open icmp-open fw-armed` |
| 实机 D2 盖章后 `-P OUTPUT ACCEPT; -F OUTPUT` | 空链、策略 ACCEPT | 旧快照（`:OUTPUT DROP` + 7 行） | **fw-armed** | **RC=0 绿** | RC=1，探针原始输出 `tcp-open icmp-open fw-armed` |

- **期望**: "第一道防线在武装状态"的正向证据覆盖生效规则集——即 F-083 建议方向：生效 OUTPUT 段与宿主渲染的期望（provision.rs rules.v4 + nat_allows）一致，任何偏离即 fw-down；并且反映探针时刻的状态，而非 apply 时刻。
- **实际**: (1) 探针只做 denylist：`grep -q '^:OUTPUT DROP'` 且 `! grep -qxF -- '-A OUTPUT -j ACCEPT'`。iptables-save 对任何带匹配条件的放行规则都不会输出成这一字面行，所以 `-o e+`/`-p tcp`/`-m comment`/`-j LEAK`/`ctstate NEW` 等写法都判 armed。(2) stamp 只在 egress-lock.service 的 ExecStartPost 时写一次；之后对 netfilter 的任何修改（别的 unit、包的 postinst、dhcp/网络钩子、人工）都不会更新它，探针读到的是旧快照。两个对照 up 证明这些规则确实让第一道防线失效（无 restrict 时 tcp/icmp 直连可达），而 restrict=on 时 tcp/icmp 探针被 slirp 拦下，fw 判据又被骗过——这就是 F-081 原形态，up 全绿、"供给完成"语义成立、escape-test 网络四项全 PASS。

## 根因猜测

- crates/creance/src/escape.rs:312：fw 判据是"策略行 + 一个字面拒绝项"，不是期望规则集比对。
- crates/creance-vm/src/provision.rs:102：`ExecStartPost=... iptables-save ... > /run/egress-armed` 是 apply 时快照，没有绑定探针时刻的生效状态（无特权 guest 读不了 netfilter，这是 F-082 的约束；可选方向是由 root 侧在探针时刻重写，或由 root 定时/按需比对后写结论）。
- 测试 escape.rs:926 `egress_probe_reads_only_unprivileged_evidence` 只断言字符串存在，没有执行探针去覆盖限定 ACCEPT（见 F-087）。

## 未验证想法

- Lima（arm64，macOS）未在本 VM 实测；共用 guest_bootstrap，同一 unit 与同一探针，判据缺陷与后端无关（静态推断）。
- 威胁模型：guest uid1000 无 sudo（实测 `sudo: a password is required`），不能自行改 netfilter；本条是 F-081 已接受的"规则漂移/被篡改/供给中途打断"类可观测性缺口，不是 uid1000 可利用的越狱。

## 建议修复方向（供第二天的人参考，非结论）

stamp 由 root 写"与期望摘要一致与否"的结论（期望摘要在宿主渲染、随 cloud-init 落盘），并在 up 守门前由 root 侧重新生成（例如 egress-lock 改为可重入的 check unit，由 guest_script 之前一次 `systemctl start` 的 root 路径触发，或 timer），探针只读结论 + 时间戳与本次 boot_id。
