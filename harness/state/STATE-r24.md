# STATE-r24 — 第十次收敛判词轮（独立对抗性审查员）

- 基线：HEAD = main = v0.6.15 `6406ece`；`sh scripts/ci.sh > /tmp/r24-ci-baseline.log 2>&1; RC=$?` → **RC=0**（180 passed / 0 failed，release build OK）
- 二进制：`target/release/creance` → `creance 0.6.15`（md5 92572b94）
- 判词：**不收敛**——新立 F-090（S4）、F-091（S5）。收敛判词未发。

## 复核矩阵

| 核验点 | 结论 | 证据 |
|---|---|---|
| F-086 (a) 实机 up#1/up#2 | 通过：up1 RC=0（369s，首供给提示），up2 RC=0（24s）`-netdev user,…,restrict=on`；guest 盖章 root 644、rules.v4 root 644、unit active+enabled、guest 用户写两文件均 Permission denied、直连 tcp blocked、sudo 需密码 | r24-real-up/evidence |
| F-086 restrict=on 下 fw-armed 真判 | 通过（干净 guest）：出厂 probe 在 restrict=on 下读盖章+rules.v4 判 fw-armed；但见 F-090——伪造行同样判 armed | r24-real-up, r24-stamp-drift |
| F-086 (b) 变异：hosts_re 不转义/漏 icmp/去 /32/放行 NEW | 变红（NC-HRE/ICMP/D32/CTN）；`-j LEAK` 与 hosts 拼接断点（join）全绿 → F-091 | r24-negative-controls |
| F-086 (c) 白名单自身绕过面 | **不通过 → F-090**：注释伪造令牌、`--ctstate NEW,ESTABLISHED`、`! -d`/`! --dport`、`--dport 67:65535`、`-p tcp`+注释"-p icmp" 全判 fw-armed 而 live netfilter 真放行；实机 D3/D4 restrict=on up RC=0，CONTROL（无 restrict）探针输出 `tcp-open icmp-open fw-armed` | r24-fw-allowlist/netns.log, r24-stamp-drift |
| F-086 (d) rules.v4 / stamp 任一改坏 | 通过（规范形）：stamp-only `-o e+`(N02)、rules-only `-o e+`(R02) 各判 fw-down；NC-RULES/NC-CAT 变红；但 rules-only 注释伪造(R01) 判 armed（F-090） | 同上 |
| F-086 (e) rules.v4 合法等价形误杀 | 记录不立案：rules.v4 写 `-d 10.0.2.2`（无 /32，K01）或 `-m state --state`（K02）判 fw-down——fail-closed，产品渲染不产生这两形 | netns.log |
| F-086 NAT hosts 单源 | 通过（结构）：仅 vm.rs 定义，lima.rs/qemu/provision.rs/escape 调用方经常量/nat_allow_hosts()；常量值无精确钉（NC-NAT1 全绿 → F-091） | grep, NC-NAT1 |
| F-087 probe 真 sh 真值表 + env 覆盖 | 通过：出厂片段经 STAMP/RULES env 在真 sh、uid 65534 下跑出与 netns 实测一致的判词；真值表缺 F-090 各形 | netns.log |
| F-087 marker 在 Ok 臂 + 唯一调用点 | **不通过 → F-091**：Err(reason) 第二调用点变红，但移入 `Err(e)` 臂、`&*profile` 别名、qemu/mod.rs 无 `&` 调用、vm.rs 调用全绿 | NC-MK3/MK4m/MKalias/MK2/MK5 |
| F-087 write_marker 写一次 | 通过（行为）：已存在不覆写、恒 true 变红（NC-MP）；仅测 temp 目录形（NC-MP2 绿，F-091） | NC-MP/MP2 |
| F-087 provision 精确行 | 部分：ExecStartPost `\|\| true`/`=-`、restart `#`/`; true`、`if false`、二次下载变红；伪造第二条 ExecStartPost、restart 后 `iptables -P OUTPUT ACCEPT`、sha 条件尾加 `&& false` 全绿 → F-091 | NC-STAMP*/RST*/NOCK* |
| F-088 CHANGELOG 对账 | 通过：v0.6.9..v0.6.15 每区间非 harness commit 逐条落在对应版本条目（1f307ef 为纯 docs handoff 无条目，合理）；0.6.15 条目在 tag 内（6406ece 自带）；0.6.14 条目 129782d 落在 tag 后已在 0.6.14 条目自述。夸大项：0.6.15 F-086 "a comment match now reads fw-down"、F-087 "guard rejects call sites inside creance-vm" 与实测不符（并入 F-090/F-091） | git log, CHANGELOG |
| F-089 裁判可写 flag | 通过：main 原工具 r14 RC=0×2 md5=2ecbd0c1、r15 RC=0×2 md5=965e444c（= R22/R23 武装世界参考，非 SKIP 世界）；flag 前后计数 0/0（清理完成）；r15 NC1/NC2 段仍证红 | r24-judges |
| 门禁矩阵 + 正控 | 通过：POS RC=0；NC-A/B/1/2/3/5/6v 全 RC=1；md5 四文件 OK | r24-gate-matrix |
| 源码复原 | 每个变异/门禁工具 md5sum -c 全 OK；`git status` 只含 harness 新增 | 各 evidence.log |

## 新发现

| # | 严重度 | 一句话 |
|---|---|---|
| 090 | S4 | fw-armed 白名单是逐行子串正则：注释伪造令牌/NEW,ESTABLISHED/取反/端口区间等真实放行规则全判 armed（实机复现） |
| 091 | S5 | v0.6.15 修复面 12 例变异全绿：marker 字面针守护、provision 在场式断言、hosts_re 拼接与 NAT 常量无行为守护 |

## 邻接面备注（记录不立案）

- escape-test 的 proxy-path ESCAPE：lab 无代理节点（同 R20 结论），与本轮判定无关。
- r24-negative-controls NC-PRB5/NC-NOCK4 首版注入未编译（harness 错误），以 PRB5b/NOCK4b 重注，均变红。
