# STATE-r25 — 第十次收敛判词轮（独立对抗性审查员）

- 基线：HEAD = main = v0.6.16 `60f5b32`；`sh scripts/ci.sh > /tmp/r25-ci-baseline.log 2>&1; RC=$?` → **RC=0**（181 passed / 0 failed，release build OK）
- 二进制：`target/release/creance` → `creance 0.6.16`（md5 e5634006）
- 判词：**不收敛**——新立 F-092（S4）、F-093（S5）。收敛判词未发。

## 复核矩阵

| 核验点 | 结论 | 证据 |
|---|---|---|
| F-090 (a) 实机 up#1/up#2 | 通过：init/setup/up1 RC=0（58s，首供给提示）/stop/up2 RC=0（18s）`-netdev user,…,restrict=on`；marker `ok`；盖章与 rules.v4 均 root 644、unit active+enabled、guest 用户写两文件 Permission denied、直连 tcp blocked、sudo 需密码 | r25-real-up/evidence |
| F-090 restrict=on 下 fw-armed 真判 | 通过：up2 在 restrict=on 下由出厂 probe 读 save 形盖章 + written 形 rules.v4 判 armed；escape-test 网络族全 PASS（proxy-path ESCAPE = lab 无代理节点，同 R20–R24） | r25-real-up/evidence |
| F-090 (b) canonical 集变异验红 | 通过：漏 save 形 icmp / 去单引号 / save 形去 /32 / 选行收窄 / `-vxF`→`-vF` / 不读 rules.v4 / 白名单加 NEW 共 7 例全 RC=101 | r25-negative-controls/run.log |
| F-090 (c) 白名单自身绕过面 | 通过：R24 的 B01–B08 伪造形（注释令牌/取反/端口区间/NEW,ESTABLISHED/tcp+注释）全判 fw-down（qemu+lima）；重复 `-d` 与大写 target 被 iptables-restore 拒绝；`-j ACCEPT` 中夹 `-m`、OUTPUT 子链链顶均 fw-down；重复 canonical 行 armed 且流量 DROP（无害） | r25-fw-exact/netns.log, netns-lima.log |
| F-090 实机回归（D3 注释伪造写入 rules.v4） | 通过：restrict=on up RC=1 fw-down 且 VM 停止；CONTROL up RC=1 | r25-stamp-drift/evidence-D3.log |
| F-090 (d) stamp / rules.v4 任一改坏 | **部分不通过 → F-092**：`-A OUTPUT` 形的改坏两文件各判 fw-down（R01/R02、N01–N03）；但 rules.v4 中 `-I`/`--append`/`-R`/空白变体/`:OUTPUT ACCEPT` 重声明/第二 `*filter` 块（S01–S09）当前 boot 判 fw-armed，下一 boot 全放行；实机 E1/E2 下一次 up 由盖章兜住（fw-down，RC=1） | r25-fw-exact/netns*.log, r25-stamp-drift/evidence-E1/E2.log |
| F-090 (e) rules.v4 多出合法形是否误杀 | 通过：rules.v4 写 save 形（K03）、加注释行（K04）、末尾 `-F OUTPUT`（S10，下一 boot 仍 DROP+armed）均不误杀；`-p icmp` 不带 /32、`-m state` 形判 fw-down（非产品写形，保守拒绝，可接受） | r25-fw-exact/netns.log |
| NAT hosts 单源（QEMU/Lima） | 通过：两表 probe 均 P00 armed + 外部全 DROP；NC-NAT1/NAT2 红 | netns*.log, run.log |
| F-091 任务书点名变异 | 通过：`&*profile` 别名、Err(reason) 第二调用、marker 移入 `Err(e)`、qemu mount-ok 调用、vm.rs `up` 第三调用、`creance-mk-` 前缀 gate、第二条 `> /run/egress-armed`、restart 后 `iptables -P OUTPUT ACCEPT`、NAT 表多一项 全红 | r25-negative-controls/run.log |
| F-091 守护绕过面 | **不通过 → F-093**：`use … as` 改名调用、括号路径调用、Ok/Err(reason) 臂互换、vm.rs dispatch 改到 `up` 内直调、`write_marker` 直调、temp_dir 前缀 gate、`>/run/egress-armed`、`\| tee`、restart 后 `nft flush ruleset` 共 9 例全绿 | r25-negative-controls/run.log |
| F-087 复核（marker 移出 Ok 臂/拆两处/ExecStartPost/restart/node sha/NEW） | 通过（R24 已红形全部仍红）；拆两处的改名形见 F-093 | run.log |
| F-088 CHANGELOG 按 tag 区间 | 通过：`git log vA..vB` 0.6.10–0.6.16 逐 commit 对账，每个产品 commit 落在自身版本条目（0.6.11 restrict/idempotent-up/quality/probe-semantics/platform-shrink；0.6.12 wire/supply-chain；0.6.13 F-078–081；0.6.14 F-082–085，且条目自述 129782d 补录于 tag 后），无漏项/夸大；0.6.15、0.6.16 条目首次出现在打 tag 的同一 commit（tag 内、不早于 tag）；0.6.10–0.6.14 tag 内无自身条目（历史事实，F-085 已立案过） | git log / git show vX:CHANGELOG.md |
| F-089 r14/r15 裁判 | 通过：r14 RC=0×2 md5=2ecbd0c1、r15 RC=0×2 md5=965e444c（= 武装世界参考）；flag 前后计数 0/0；r15 NC1/NC2 段仍证红 | r25-judges |
| 门禁矩阵 + 正控 | 通过：POS RC=0；NC-A/B/1/2/3/5/6v 全 RC=1；md5 四文件 OK | r25-gate-matrix |

## 新 findings

| # | 严重度 | 一句话 |
|---|---|---|
| 092 | S4 | rules.v4 半边只看 `^-A OUTPUT` 行：iptables-restore 会应用的 `-I`/`--append`/`-R`/空白变体/策略重声明/第二 `*filter` 块不可见，up#1 判 armed 并写 marker（下一 boot 盖章兜住，失败关闭） |
| 093 | S5 | v0.6.16 守护加固 9 例变异全绿（改名/括号调用、臂重排、vm.rs 位置、write_marker 直调、temp_dir 前缀 gate、`>/run`/`tee` 伪盖章、`nft flush`） |

## 环境备注

- netns.sh 首版把注入内容当 printf 格式串（`-A`/`-F` 开头被当选项），已改 `printf --` 后全量重跑；作废输出未入库。
- NC-MK4m 首版锚到 main.rs 更早的 `Err(e) =>`（编译错误），重锚到探针 `Err(e)` 臂后 `ONLY=NC-MK4m` 重跑为红。
