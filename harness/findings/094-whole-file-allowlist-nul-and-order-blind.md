# FINDING-094: v0.6.17 rules.v4 整文件白名单仍可被绕过——NUL 字节让 GNU grep 进入 binary 模式吞掉所有行（`-I OUTPUT -j ACCEPT` 过检），结构行只计数不定序（COMMIT 提前、*filter 放尾）iptables-restore 下次开机拒载

- **编号**: 094
- **严重度**: S4（正确性：同 F-090/F-092 类——up 当前开机判 fw-armed，而 rules.v4 已不能在下次开机重新武装；下次开机 fail-closed，restrict=on 仍在）
- **攻击面**: H1 / F-092 修复面（`crates/creance/src/escape.rs::fw_probe_fragment` rules.v4 侧）
- **发现时间**: 2026-11-22T16:20Z
- **发现者会话**: r26-auditor（R26 第十一次收敛判词轮）
- **状态**: 已修复（main-session，实机复验）

## 复现（必须）

```sh
CREANCE_REPO=$PWD sh harness/tools/r26-fw-exact/netns.sh                    # C locale  -> netns.log
PLANG=C.UTF-8 CREANCE_REPO=$PWD sh harness/tools/r26-fw-exact/netns.sh      # UTF-8     -> netns-utf8.log
BACKEND=lima CREANCE_REPO=$PWD sh harness/tools/r26-fw-exact/netns.sh       # lima 表   -> netns-lima.log
# 真 guest（v0.6.17 release 二进制已 up，restrict=on）：出厂探针片段 + 真 /run/egress-armed + CREANCE_RULES 指向 fixture
LAB=<lab> PROBE=<r26-fw-exact probe qemu 输出> sh harness/tools/r26-real-up/guest-replay.sh   # evidence/guest-replay.log
# 真 guest 下一次开机（qemu-nbd 离线改 rules.v4 → up）
LAB=<lab> PROBE=<…> sh harness/tools/r26-stamp-drift/run.sh Z1 ; … run.sh O1             # Z1.log / O1.log
```

netns 规程（每例两阶段）：A = 产品 canonical rules.v4 已 iptables-restore + 产品 ExecStartPost 原样盖章，再把 rules.v4 换成 fixture，跑出厂探针（"本次开机判词"）；B = 对 fixture 做 iptables-restore（模拟下次开机 egress-lock.service），失败则不盖章，再跑出厂探针 + 真实出站探测。三种口径（C / C.UTF-8 / lima 表）结果一致：

| 用例 | rules.v4 fixture（由产品真实渲染文件派生） | A 判词 | B iptables-restore | B 判词 | B 出站 |
|---|---|---|---|---|---|
| P01 | 产品真实渲染文件（md5 e13fe10a，与真 guest 一致） | fw-armed | ok | fw-armed | DROP |
| **Z01** | 产品文件 + `#\0` 注释行 + `-I OUTPUT -j ACCEPT`（COMMIT 前） | **fw-armed** | ok，live 首条 `-A OUTPUT -j ACCEPT` | fw-down | **全开** |
| **Z02** | 同上，插入 `-A OUTPUT -j ACCEPT` | **fw-armed** | ok | fw-down | **全开** |
| **O01** | COMMIT 移到 `:OUTPUT DROP` 之前（每行都在允许集，计数 1/1/1） | **fw-armed** | `line 5 failed` → 无规则、无盖章 | fw-down | **全开** |
| **O02** | COMMIT 紧跟 `*filter` | **fw-armed** | `line 3 failed` | fw-down | **全开** |
| **O03** | `*filter` 放到文件尾 | **fw-armed** | `line 1 failed` | fw-down | **全开** |
| O04 | canonical 规则行放在 COMMIT 之后 | **fw-armed** | `line 6 failed` | fw-down | DROP（策略未改） |
| Z03 | 非法 UTF-8 注释 + `-I OUTPUT` | fw-down（正确拒） | ok | fw-down | 全开 |

真 guest 复核（`guest-replay.log`，Ubuntu guest，grep 3.11，LANG=en_US.UTF-8 经 SendEnv 转发）：P01/Z01/O01/O03 本次开机均判 **fw-armed**，Z03 判 fw-down；Z01 在 guest 里 `grep -v '^[[:space:]]*$'` 输出 0 行，仅 stderr 打 `binary file matches`（探针不看 stderr、不看退出码）。真 guest 下一次开机（Z1/O1，见 stamp-drift 证据）：rules.v4 md5 与 netns fixture 逐字节相同（Z1=1be757fb），up 判 fw-down 失败关闭。

## 根因

- `escape.rs::fw_probe_fragment` 的 `body=$(grep -v '^[[:space:]]*$' "$WANT" | grep -vxF …)`：GNU grep ≥3.5 遇 NUL 视文件为 binary，匹配行不输出，只在 stderr 打 `binary file matches`；`body` 为空即视为"无白名单外行"。`-a`/`LC_ALL=C` 均未用，退出码也未检查。`grep -c`（nfilter/ncommit/nout）在 binary 模式下仍计数，三个计数照样为 1。
- 结构校验只计 `*filter`/`COMMIT`/`:OUTPUT ` 各出现 1 次，不校验顺序（`*filter` 首行、`:… [0:0]` 声明在规则前、`COMMIT` 末行）。iptables-restore 对顺序敏感，乱序文件逐行都在允许集却整体不可加载。
- CHANGELOG 0.6.17 宣称 "Every non-blank line must literally equal a canonical OUTPUT rule or one of the five structural lines"——Z01/Z02 中 `-I OUTPUT -j ACCEPT`/`-A OUTPUT -j ACCEPT` 是非空行且不在允许集，判 armed，宣称不成立。
- 单元测试真值表无 NUL 行、无乱序行（`escape.rs` 测试段）。

## 影响

与 F-092 同：需要 guest root 才能改 rules.v4（产品已收回 sudo），且下次开机 up 失败关闭（stamp 缺失或含裸 ACCEPT → fw-down → stop）、slirp restrict=on 仍在。缺陷在于 F-092 修复声称的"rules.v4 判过 ⇒ 下次开机可重新武装"不变量可被构造反例打破：本次 up 报 armed，持久化武装实际已失效。

## 修复建议（仅建议，审查员不修）

整文件比较改为逐字节相等（`cmp` 期望渲染文件，或在 Rust 侧渲染期望文本、guest 侧 `sha256sum` 对比），从根本上消除"允许集+计数"带来的顺序/编码面；若保留 grep，至少 `LC_ALL=C grep -a`、检查 `tr -d '\000' | cmp` 无 NUL、并钉顺序（首行 `*filter`、末行 `COMMIT`、`:OUTPUT` 先于首条 `-A`）。真值表补 NUL 行与三种乱序行。
