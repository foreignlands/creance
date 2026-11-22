# FINDING-083: fw-armed 只看 OUTPUT 链的默认策略行——`:OUTPUT DROP` + 一条 `-A OUTPUT -j ACCEPT` 照样判"armed"；即使 F-082 修好，F-081 的遮蔽在"策略在、规则漂"形态下依旧

- **编号**: 083
- **严重度**: S4（正确性：与 F-081 同级——restrict=on 武装后第一道防线失效仍不可观测）
- **攻击面**: H1 / F-081 修复面（main.rs:754）
- **发现时间**: 2026-11-22T07:20Z
- **发现者会话**: r22-auditor（R22 第八次收敛判词轮）
- **状态**: 已修复（main-session，实机复验）

## 复现（必须）

```sh
sh harness/tools/r22-fw-armed/netns.sh    # 证据 harness/tools/r22-fw-armed/netns.log
```

探针行逐字回放（root、完整 PATH，排除 F-082 的两个缺陷）：

```
P1 产品形态（-P OUTPUT DROP + lo/ESTABLISHED）    → fw-armed
P2 -P OUTPUT DROP + -A OUTPUT -j ACCEPT（全放行）  → fw-armed   ← 第一道防线实际已死
P3 -P OUTPUT ACCEPT                                 → fw-down
```

- **期望**: "第一道防线在武装状态"的正向证据应覆盖规则内容——至少是加载的 OUTPUT 规则集与宿主渲染的 rules.v4（provision.rs:75-86 + nat_allows）一致，而非仅默认策略。
- **实际**: `iptables -L OUTPUT -n | head -1 | grep -q 'policy DROP'` 只读 "Chain OUTPUT (policy DROP)" 首行。规则漂移/被篡改为前置 ACCEPT（F-081 列举的"规则漂移/被篡改/供给中途打断"同类）时，策略仍是 DROP，检查通过；restrict=on 下 tcp/icmp 探针亦 blocked，up 全绿——F-081 原形态复现。iptables-legacy 与 iptables-nft 的 `-L` 首行格式一致（"Chain OUTPUT (policy DROP)"），后端兼容性本身无误报。

## 根因猜测

crates/creance/src/main.rs:754：判据取的是链默认策略而不是生效规则集。ip6 面由 sysctl 禁 IPv6（provision.rs:66-67）兜，探针也未检查（未立案，仅记录）。

## 未验证想法

- 在真实 guest 内造 P2 形态需先修 F-082（当前探针无法在 guest 内产出 fw-armed）；本项用宿主 netns 逐字回放同一行，判定逻辑与 guest 内一致（同为 iptables-nft 1.8.x）。

## 建议修复方向（供第二天的人参考，非结论）

与 F-082 一并：比对加载后 OUTPUT 段（`iptables-save -t filter` 中 `:OUTPUT` 与 `-A OUTPUT` 行）与宿主渲染期望值的摘要，任何偏离即 fw-down。
