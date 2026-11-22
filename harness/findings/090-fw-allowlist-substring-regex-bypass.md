# FINDING-090: v0.6.15 fw-armed 白名单是逐行子串正则——注释伪造令牌、`NEW,ESTABLISHED`、`! -d`/`! --dport`、端口区间、tcp+注释"-p icmp" 等真实放行规则全判 fw-armed（实机 restrict=on 下 up RC=0）

- **编号**: 090
- **严重度**: S4（正确性：与 F-081/F-083/F-086 同级——第一道防线失效依旧不可观测；restrict=on 第二道防线仍在，实机直连 1.1.1.1:443 仍 blocked）
- **攻击面**: H1 / F-086 修复面（escape.rs `fw_probe_fragment`）
- **发现时间**: 2026-11-22T13:50Z
- **发现者会话**: r24-auditor（R24 第十次收敛判词轮）
- **状态**: 已修复（main-session，实机复验）

## 复现（必须）

```sh
# netns 回放：真 iptables-restore → provision.rs 逐字 ExecStartPost 盖章 → 出厂 probe 片段（uid 65534, STAMP/RULES env 覆盖）
#            → OUTPUT policy 计数差判每个目的地是否真被放行
CREANCE_REPO=$PWD sh harness/tools/r24-fw-allowlist/netns.sh        # 证据 netns.log
# 实机（v0.6.15 二进制, QEMU, 已供给实例；离线 qemu-nbd 往 rules.v4 追加一行 → up(restrict=on) → 盖章+出厂 probe）
LAB=<lab> PROBE=harness/tools/r24-fw-allowlist/probe-qemu.dump.sh sh harness/tools/r24-stamp-drift/run.sh D3   # 证据 evidence-D3.log
LAB=<lab> PROBE=... sh harness/tools/r24-stamp-drift/run.sh D4                                                   # 证据 evidence-D4.log
```

## 期望

CHANGELOG 0.6.15 F-086 原文："every `-A OUTPUT` line … must be `lo`, an ESTABLISHED conntrack catch-all, or an ACCEPT to a sanctioned /32 NAT host over udp/67 or icmp. A qualified ACCEPT (`-o e+`, `-p tcp`, a comment match), a chain jump, or a rules.v4 drift now reads fw-down." —— 任何让非白名单流量出 OUTPUT 的规则都应判 fw-down。

## 实际（netns.log，盖章为 iptables-save 真输出，流量为 live netfilter 真判）

| 用例 | 追加到产品形态的规则 | probe | 真实放行 |
|---|---|---|---|
| B01 | `-A OUTPUT -m comment --comment "-d 10.0.2.2/32 -p icmp" -j ACCEPT` | **fw-armed** | 全放行（udp/53、tcp/443、icmp 外网） |
| B02 | `-A OUTPUT -m comment --comment "conntrack --ctstate ESTABLISHED" -j ACCEPT` | **fw-armed** | 全放行 |
| B03 | `-A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT` | **fw-armed** | 全放行 |
| B04 | `-A OUTPUT ! -d 10.0.2.2/32 -p udp -m udp ! --dport 67 -j ACCEPT` | **fw-armed** | 外网任意 udp（8.8.8.8:53/5353） |
| B05 | `-A OUTPUT ! -d 10.0.2.2/32 -p icmp -j ACCEPT` | **fw-armed** | 外网 icmp |
| B06 | `-A OUTPUT ! -d 10.0.2.3/32 -p udp -m udp --dport 67:65535 -j ACCEPT` | **fw-armed** | 外网 udp/5353 |
| B07 | `-A OUTPUT -d 10.0.2.2/32 -p tcp -m comment --comment "-p icmp" -j ACCEPT` | **fw-armed** | 宿主 NAT tcp/22（F-073 关掉的面） |
| B08 | `-A OUTPUT -p tcp -m comment --comment "-d 10.0.2.3/32 -p icmp" -j ACCEPT` | **fw-armed** | 外网任意 tcp |
| R01 | 仅 rules.v4 加 B01 行（live 干净） | **fw-armed** | 下次开机落地的全放行 |
| 对照 N01/N02/N03/R02 | 裸 ACCEPT / `-o e+` / `--ctstate NEW` / rules.v4 `-o e+` | fw-down | — |

实机 D3（evidence-D3.log）：rules.v4 追加 B01 行 → `up`（marker 在，`-netdev user,…,restrict=on`）**RC=0**；guest 内出厂 probe 输出 `tcp-blocked / icmp-blocked / fw-armed`，盖章末行即 `-A OUTPUT -m comment --comment "-d 10.0.2.2/32 -p icmp" -j ACCEPT`；escape-test 的 net-* 四项全 PASS。即：guest iptables 已全放行，up 守门与 escape-test 都给出"第一道防线武装"的正向证据——F-081/F-086 要消灭的不可观测态复现。D4（`--ctstate NEW,ESTABLISHED`）同理，见 evidence-D4.log。CONTROL 段（移走 marker、无 restrict）同一 guest：`up` RC=1，探针原始输出 **`tcp-open\nicmp-open\nfw-armed`**——直连真实可达的同时 probe 仍报 fw-armed，坐实假阳性。

CHANGELOG 0.6.15 "a comment match … now reads fw-down" 因此与实测不符（只有不含伪造令牌的注释行才判 down）。

## 根因假设

`crates/creance/src/escape.rs` `fw_probe_fragment`（约 :330-:345）：
- 每阶段都是**行内任意位置子串**匹配 `grep -E`：`'^-A OUTPUT .*conntrack --ctstate .*ESTABLISHED.*-j ACCEPT$'`、`'-d ((hosts)/32|…) '`、`'-p udp.*--dport 67|--dport 67.*-p udp|-p icmp'`——令牌可以来自 `--comment "…"` 的引号内文本；
- 没有拒绝 `!` 取反、`--ctstate` 值不是"仅 ESTABLISHED[,RELATED]"、`--dport` 不是精确 `67`（区间 `67:65535`）、`-p tcp` 与 `-p icmp` 并存（取最后/注释）；
- 三阶段是独立的"每行命中任一形"，而不是"整行等于白名单中的某一规范行"（例如对 iptables-save 规范化输出做 `grep -vxF -f <允许行集合>` 的全行精确比对）。

## 守护缺口

`escape::tests::fw_probe_fragment_real_shell_truth_table` 的真值表无注释伪造、取反、多状态、端口区间行；r24-negative-controls 中 NC-NEG（显式允许 `! -d`）亦全绿。
