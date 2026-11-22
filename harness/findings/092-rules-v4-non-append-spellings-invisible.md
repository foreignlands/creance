# FINDING-092: fw-armed 的 rules.v4 半边只看 `^-A OUTPUT` 行——`-I`/`--append`/`-R`/前导空白/tab/双空格/`:OUTPUT ACCEPT` 重声明/第二个 `*filter` 块全被 iptables-restore 应用但探针看不见，up#1 判 fw-armed 并写 marker

- **编号**: 092
- **严重度**: S4（正确性：F-086/F-090 宣称的"rules.v4 漂移判 fw-down"对这些拼写不成立；下一 boot 的盖章仍兜住，up 失败关闭，不构成直连逃逸）
- **攻击面**: H1 / F-090 修复面（fw_probe_fragment 选行语义）
- **发现时间**: 2026-11-22T14:40Z
- **发现者会话**: r25-auditor（R25 第十次收敛判词轮）
- **状态**: 已修复（main-session，实机复验）

## 复现（必须）

```sh
CREANCE_REPO=$PWD sh harness/tools/r25-fw-exact/netns.sh               # 证据 netns.log（qemu 表）
BACKEND=lima CREANCE_REPO=$PWD sh harness/tools/r25-fw-exact/netns.sh  # 证据 netns-lima.log
```

工具从产品函数现取 probe（`egress_probe_script(NAT_HOSTS_*)`）与 rules.v4（`guest_bootstrap` 的 `EGRESSRULES` heredoc），在 netns 里：
A = 当前 boot（live 由干净 rules 加载、盖章由 unit 同款 `iptables-save -t filter | grep -E "^:OUTPUT|^-A OUTPUT"` 生成；rules.v4 = 产品文件 + 注入行）；
B = 下一 boot（`iptables-restore rules.v4` → 重新盖章）。

## 期望行为

`/etc/iptables/rules.v4` 中任何会被 `iptables-restore` 应用、放行非白名单流量的内容，都令 A 判 `fw-down`（CHANGELOG 0.6.15 F-086："a rules.v4 drift now reads fw-down"；0.6.16 F-090："每条 OUTPUT 规则必须命中 canonical 行"）。

## 实际行为（qemu 与 lima 两表结果一致）

| 用例 | rules.v4 注入 | A probe | B probe | B 外部 udp53/tcp443/icmp |
|---|---|---|---|---|
| S01 | `-I OUTPUT -j ACCEPT` | **fw-armed** | fw-down | PASS |
| S02 | `-I OUTPUT 1 -j ACCEPT` | **fw-armed** | fw-down | PASS |
| S03 | `--append OUTPUT -j ACCEPT` | **fw-armed** | fw-down | PASS |
| S04 | `-A  OUTPUT -j ACCEPT`（双空格） | **fw-armed** | fw-down | PASS |
| S05 | ` -A OUTPUT -j ACCEPT`（前导空格） | **fw-armed** | fw-down | PASS |
| S06 | `-A<TAB>OUTPUT -j ACCEPT` | **fw-armed** | fw-down | PASS |
| S07 | `-R OUTPUT 1 -j ACCEPT` | **fw-armed** | fw-down | PASS |
| S08 | `COMMIT` + `*filter` + `:OUTPUT ACCEPT [0:0]` | **fw-armed** | fw-down | PASS |
| S09 | `:OUTPUT ACCEPT [0:0]`（策略重声明） | **fw-armed** | fw-down | PASS |
| 对照 R01/R02 | rules-only `-A OUTPUT` 伪造/限定行 | fw-down | fw-down | — |

A 阶段 cmd_up 的 verdict 为 Ok → `mark_provisioned` 写 marker → 交付；此后首次重启 rules.v4 被 restore，live OUTPUT 实为全放行。
实机（`harness/tools/r25-stamp-drift`，E1=`-I OUTPUT -j ACCEPT`、E2=`:OUTPUT ACCEPT [0:0]` 离线写入 rules.v4）：下一次 `up` 盖章已含放行 → fw-down、VM 停止、RC=1——第二道判据兜住，故不定 S2。
（实机无法复现 A 阶段：guest 用户无 root，不能在 boot 内改 rules.v4；A 阶段证据为 netns 对同一 probe/同一文件的重放。）

## 根因

`crates/creance/src/escape.rs:360-361`（`fw_probe_fragment`）：
- `grep -q '^:OUTPUT DROP' "$WANT"` 只证"存在一行" DROP 声明，不证它是唯一/最后一条 OUTPUT 策略声明（S08/S09）；
- `grep -hE '^-A OUTPUT'` 是选行而非否定：白名单 `grep -vxF` 只作用在被选中的行上，凡不以字面 `-A OUTPUT` 开头的规则命令（`-I`/`-R`/`--append`/空白变体）直接被跳过（S01–S07）。
对 iptables-save 产物（盖章）这一选择安全（save 输出规范化为 `-A`），但 rules.v4 是 iptables-restore 的**输入**，语法远宽于 save 形；白名单需要在 rules.v4 上是"除允许行外全部拒绝"（例如：rules.v4 去注释/空行后的整文件必须逐行等于 canonical 文件），而非"在 `-A OUTPUT` 子集里白名单"。

## 修复建议（仅建议，审查员不修）

rules.v4 侧改为整文件精确比对（产品自己渲染的 rules.v4 全文 = 期望全文，`cmp`/`grep -vxF` 作用于全部非空非注释行），或至少：拒绝任何 `OUTPUT` 字样但不在 canonical 集里的行、拒绝多于一个 `:OUTPUT` 声明/多于一个 `*filter`。真值表补 S01–S09 九形。
