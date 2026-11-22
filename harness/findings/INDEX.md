# Findings Index

| # | 严重度 | 标题 | 攻击面 | 状态 |
|---|---|---|---|---|
<!-- NNN | S? | 一句话 | A? | 待修复/已修复(commit)/误报 -->
| 094 | S4 | rules.v4 整文件白名单 NUL/定序盲：`#\0` 让 GNU grep binary 模式吞行（`-I OUTPUT -j ACCEPT` 判 armed）、COMMIT 提前/`*filter` 置尾逐行合法但 restore 拒载——本次 armed、下次开机失效 | H1 / F-092 修复面 | 待修复 |
| 095 | S5 | v0.6.17 守护加固 11 例变异全绿：跨模块转调/`#[cfg(test)]` 注释截断/verdict `.or_else` 中和/vm.rs use-as/`(write_marker)(`/instance_dir 形 gate/unit 追加 ExecStartPost/`/run/./egress-armed`/允许集混入 ACCEPT | H1 / F-093 修复面 | 待修复 |
| 092 | S4 | rules.v4 半边只筛 `^-A OUTPUT` 行：`-I`/`--append`/`-R`/空白变体/`:OUTPUT ACCEPT` 重声明/第二 `*filter` 块被 restore 应用但探针不可见 | H1 / F-090 修复面 | 已修复（main-session，实机复验 up RC=0 + S01-S09 真值表全 fw-down） |
| 093 | S5 | v0.6.16 守护加固 9 例变异全绿：use-as/括号调用/臂重排/vm.rs 位置/write_marker 直调/前缀 gate/stamp 拼写/nft | H1 / F-091 修复面 | 已修复（main-session，27 例 NC 复跑全红） |
| 090 | S4 | fw-armed 白名单是逐行子串正则：注释伪造令牌/`NEW,ESTABLISHED`/`!` 取反/端口区间/tcp+注释全判 armed | H1 / F-086 修复面 | 已修复（main-session，实机复验：armed 实例 up RC=0 + 15 例伪造真值表） |
| 091 | S5 | v0.6.15 修复面守护缺口：marker 守护漏别名/Err 臂/vm.rs，stamp 唯一写点/apply 后净面/NAT 表/探针参数面无钉 | H1 / F-087 同类 | 已修复（main-session，CI 全绿） |
| 086 | S4 | fw-armed 判据是黑名单+apply 时快照：限定 ACCEPT/跳链/rules.v4 漂移全判 armed | H1 / F-083 修复面 | 已修复（main-session，实机复验） |
| 087 | S5 | v0.6.14 修复面 13 例变异全绿：probe 语义未执行、marker 守护只比首次出现、写盘/stamp 内容/restart 腿/校验门无行为守护 | H1 / F-076 同类 | 已修复（main-session，实机复验） |
| 088 | S5 | CHANGELOG 0.6.10–0.6.14 与 tag 不对账：条目错位一个版本、两批 audit-batch 无条目、tag 内无自身条目 | 发版规程 | 已修复（main-session） |
| 089 | S5 | r14/r15 裁判用不可写 flag 路径渲染 SKIP 世界：r15 panic RC=101、r14 绿但判错形态 | H1 / F-084 修复面 | 已修复（main-session，双裁判复跑 RC=0） |
| 082 | S4 | fw-armed 探针无特权运行 iptables -L：PATH 无 /usr/sbin + Permission denied，v0.6.13 每次 up 恒失败停机、provisioned 永不写入 | H1 / F-081 修复面 | 已修复（main-session，实机复验） |
| 083 | S4 | fw-armed 只看默认策略：DROP 策略 + 裸 -A OUTPUT -j ACCEPT 仍判 armed | H1 / F-081 修复面 | 已修复（main-session，实机复验） |
| 084 | S5 | v0.6.13 修复面 10 例变异仍全绿：F-078 调用点、F-079 TE/node 校验/Lima digest 键、F-081 五例 | H1 / F-076 同类 | 已修复（main-session，实机复验） |
| 085 | S5 | CHANGELOG 停在 0.6.9，0.6.10–0.6.13 无条目 | 发版规程 | 已修复（main-session） |
| 078 | S5 | F-076 修复残留：flag_placed 仍内联于 cmd_up 且其与 oracle_ready 的接线零守护 | H1 / F-074+076 修复面 | 已修复（main-session，实机复验） |
| 079 | S5 | v0.6.12 新面零行为守护：strict_content_length 拒绝矩阵、gate 重复 CL→400、node sha256 钉值、Lima digest 钉值均无测试 | H1 / F-076 同类 | 已修复（main-session，实机复验） |
| 080 | S4 | Lima digest 钉在滚动 release/ URL：下次 Ubuntu 刷新 digest 必失配，全部 setup 失败关闭 | H1 / a7ac0e3 修复面 | 已修复（main-session，实机复验） |
| 081 | S4 | restrict=on 遮蔽第一道防线：guest iptables 失效时 up 守门与 escape 探针全绿；且 provisioned 标记在校验前写入 | H1 / 1ca32c8+F-077 修复面 | 已修复（main-session，实机复验） |
| 077 | S5 | restrict=on 声明面漂移：qemu/mod.rs 称无条件生效、ROADMAP 列待办、runner 注释过时；供给会话无第二道防线且零提示 | H1 / 1ca32c8 | 已修复（main-session，实机复验） |
| 076 | S5 | v0.6.11 修复面零行为守护：五例注入（删 restrict、/32 表互换、双判词回退等）cargo test 全绿 | H1 / F-073+F-074 修复面 | 已修复（main-session，实机复验） |
| 075 | S4 | F-072 中断收敛只收敛防火墙：QEMU 首启 runcmd 被打断后 9p 挂载腿永不执行，up 全绿但 workspace 不共享 | H1 / F-072 修复面 | 已修复（main-session，实机复验） |
| 074 | S5 | F-068 修复残留：旗标不可落盘时 guest 空真 PASS 与 SKIP 双判词；oracle_ready 参数化后只发 SKIP | E2 / F-068 修复面 | 已修复（main-session，实机复验） |
| 073 | S2 | rules.v4 含两后端网段：QEMU/slirp 上 192.168.5.0/24 可路由——UDP/67+ICMP 实测经宿主 ens5 离开；按后端 /32 渲染（QEMU 10.0.2.2/.3，Lima 192.168.5.2/.3） | H1 / F-060+F-072 修复面 | 已修复（main-session，实机复验） |
| 072 | S2 | 首启 runcmd 被打断 → status: done 永久撒谎 + guest 永久裸奔且每次 up 必拒；修复=持久层（rules.v4/noipv6/egress-lock.service enable）前置到工具链之前 + rules.v4 单源（iptables-save/LIMADNS 捕获路径一并移除） | H1 | 已修复（main-session，实机复验） |
| 071 | S2 | QEMU 后端 up 只等 sshd 不等 cloud-init：F-059 探针在供给窗口内开火、健康首启必杀；wait_cloud_init 首版又把 status.json 未建立的非零退出误读为"无 cloud-init" 早放（serial.log 实证 modules-final 启动 1s 内被杀） | H1+H2 | 已修复（main-session，实机复验） |
| 070 | S5 | harness 声明面计数/状态陈旧：README:65 与 harness/README:18 称攻击面地图"20 项/20 个测试方向"（实 45 条 A-H），attack-surfaces:78 H 节标题仍写"全部未覆盖"（H1-H7 全已覆盖），文件尾状态注记重复 | harness 文档 | 已修复（main-session） |
| 069 | S5 | ESCAPE-BRIEF:15-17 指示 `touch <workspace>/.creance.escape-flag`，与探针实际检查的 `<environment_dir>.escape-flag`（main.rs:360，workspace 兄弟路径）文件名、位置均不同，且自相矛盾（"墙内"旗标 vs "挂载之外"判据）——照文档准备的活体演练 fs-flag 裁判恒 PASS（r18-flag-oracle S2） | E2 邻接 | 已修复（main-session） |
| 068 | S4 | fs-flag-readable 旗标 oracle 从未被放置：全仓只有 main.rs:360 推导路径、无任何写入（69bce85 起），默认流程该探针恒 PASS（r18-flag-oracle S1：宿主全盘可见仍 PASS）=空探针，而 README:71-72/QUICKSTART:84-87/ROADMAP:43 均列为"已强制" | E2 | 已修复（main-session） |
| 067 | S5 | README:70-76 验收节 "Enforced since 0.3/0.4/0.5" 现在时清单仍列已删除的 numeric proxy endpoint 探针（2026-11-21 E5 裁定删除：空探针两臂恒 Contained）且无删除注记——三处探针声明面（ROADMAP/QUICKSTART/README）中唯一已漂移的一处：ROADMAP:53 与 QUICKSTART:90 均有历史注记、ROADMAP 块受门禁看守，README 零看守零注记；本轮正控实测假宣称全程在树门禁 RC=0；R14 "残留引用仅三处"裁定按连字符 id grep 漏掉空格短语变体（本条修正该记录），R16 复查焦点在 socket 类滑过——同病（声明面靠人肉同步、无自动看守）第五复发（058→063→065→066→067），首次落在第三声明面；附带记档：README:74-76 网络探针枚举漏 net-icmp-external/proxy-path（概述句先例不单独立案）+ NC6c 实证新家族守卫为文本在场证人（死分支保持文本门禁仍绿） | E5 邻接（探针声明面第三处：README） | 已修复（night-19 主会话：README:72 删幽灵短语+补删除注记+网络枚举补 icmp/proxy-path+sock-abstract/ssh 材料如实归类；**README 强制块进门禁**（readme-enforced 标记块，双向差集=代码已强制集（减 todo 跟踪项））——NC-A 幽灵 id/NC-B 删 id 各单行红；三声明面看守强度拉平；ci.sh RC=0（macOS），v0.6.9） |
| 066 | S5 | 已强制的 sock-$s 家族探针（socket 暴露检测，guest 摸 docker/lima-guestagent unix socket 即报 ESCAPE）在全部五层自动化结构性不可见：门禁方向2对家族 token 无条件 allowlist 豁免（恒真、不对任何代码工件核验）、escape.rs 探针断言只测 sock-abstract 不测 sock-$s、main.rs:385-386 缺行提取器显式排除参数化点、r14裁判[A] expected 24 条无家族行、r15-recheck 同提取基准——NC6 实证：删掉 escape.rs:364-367 的 sock for-loop 后门禁 RC=0（输出与正控逐字同）+ cargo test 探针断言 ok，ROADMAP/QUICKSTART/README 的"已强制"宣称可被静默证伪且零 CI 红。门禁头注如实声明了豁免（未违反自身契约），但豁免后果未在任何文档中陈述、无补偿层——同病（声明面无自动看守）第四复发向量，病灶活在为终结该病而买的门禁自身豁免条款里；附带跟踪：QUICKSTART:84-88 类别枚举仍略过 socket 类（065 未验证想法四类修三类，R15 裁定不立案，随本条记档） | E5 邻接（探针清单声明面）+ night-17 门禁 allowlist 面 | 已修复（night-18 主会话：门禁方向④ sock-$s 家族发射点文本守卫——NC6 重放（删发射行）单行报错、正控不变；QUICKSTART 枚举补 socket 类；ci.sh RC=0（macOS），v0.6.8） |
| 065 | S5 | ROADMAP.md:38 探针清单缺两个真实 guest 探针 id：proxy-path（被强制的正向控制探针，QUICKSTART:85 明文承认其存在）已强制列表缺席、sock-abstract（诚实 SKIP 的未实现层）已强制与待做两节均零跟踪——host 侧 6 id 无漂移；R14 对 F-063 "逐一对上"的裁定只做了单向核对（清单→脚本），本条同时修正该验证记录。病根同 063（声明面靠人肉同步、063 建议的 grep 门禁未落地），同病第三次复发（058→063→065） | E5 邻接（探针清单声明面） | 已修复（night-17 主会话：ROADMAP 清单改标记块重构（host-enforced/guest-enforced/guest-todo 三块纯 id）；已强制补 proxy-path、待做补 sock-abstract；QUICKSTART 类别枚举对齐；新增 scripts/check-probe-inventory.sh 双向差集门禁进 ci.sh——双负控实证（删 id/塞幽灵 id 各单行报错）；裁判 r14-convergence+r15-064-recheck 双跑绿 + ci.sh RC=0（macOS），v0.6.7） |
| 064 | S5 | F-062 缺行网漏掉 probe() 助手路由的 fs-flag-readable：提取器只枚举字面 `echo "PROBE <id>` 发射点并把 `$` 参数化发射连同该探针一起放弃（escape.rs:332 调用点的 id 本可静态枚举，main.rs:379-382 豁免注释"not statically knowable"名不符实）——该探针行可被单独致盲而 transport ESCAPE 不触发；其余 11 探针缺行网、子串碰撞矩阵、up 守门真值表经 r14-convergence 全实证 fail-closed | R14（F-062 修复面回归） | 已修复（night-16 主会话：escape.rs 删 probe() 助手改字面 if/else 发射，main.rs 豁免注释如实化；r14-convergence [A]/[E] 翻修复后断言全绿 + ci.sh RC=0（macOS），v0.6.6） |
| 062 | S4 | guest_script 传输层 stdout 全权受 guest 控制（Ubuntu bash 非交互 source ~/.bashrc，实机实证）：PATH 影子/全盲 exec-redirect/整份 PROBE 伪造三形态——up 守门 `Ok(_)=>{}` 与 escape-test 缺行不计失败双消费点 fail-open，假绿（吞 tcp-open）与假红（echo tcp-open 杀健康 VM，实机验证）皆可；containment 内核侧未破，破坏的是守门/验收监控语义 | R13.5（F-059/F-011 修复面回归） | 已修复（night-15：守门改正向证据（tcp-blocked 必须在场，缺失=拒交+停机）；escape-test 探针行计数缺行=transport ESCAPE；探针脚本 PATH 硬重置+绝对路径；README 边界段如实降格"guest 探针=遥测，安全控制在宿主侧"。双向实机：致盲 .bashrc 下 up rc=1 拒交、escape 报 transport ESCAPE；健康路径零假报） |
| 063 | S5 | ROADMAP.md:16 探针清单未随 E5 同步：仍列已删的 proxy-numeric-endpoint、缺新增的 net-icmp-external（E5 执行清单三处同步漏第三处）——与 F-058 同病（改名/删改后无 grep 门禁） | E5 执行面 | 已修复（night-15：随 ROADMAP v2 落地同步——探针清单去 proxy-numeric-endpoint、补 net-icmp-external） |
| 061 | S4 | 基础镜像信任根弱于 fetch-proxy-core：SHA256SUMS 与镜像同通道取回、SHA256SUMS.gpg 不拉不验，注释自称 "signed-by-construction" 名不符实——MITM 同时给 img+量身 sums 即通过；对照钉版哈希有仓库 git 第二通道 | H7 | 已修复（night-14：谎言注释改为如实信任模型声明——同通道 TLS 防损坏不防双文件 MITM；GPG 验签留 Ubuntu 侧跟进，STATE-r13 F-061 记录；R13.5 复核裁定：注释-only=文档诚实化+接受风险记档，非代码修复，裁定见 STATE-r135） |
| 060 | S2 | lockdown 的 `-p udp --dport 67` 与 `-p icmp` 两条 ALLOW 无目的限定：非特权 guest 可经 slirp NAT 向任意外部主机外传数据（UDP/67 同发 DNS 成本、ping cap_net_raw 载荷信道）——"唯一出口=托管核心"契约直接违反，且 net-direct-egress/net-dns-external 探针只测 TCP 80/443 与 53，探针网对此不设防 | H1 | 已修复（night-14：UDP67/ICMP 限定 NAT 网段（10.0.2.0/24、192.168.5.0/24、DHCP 广播），新增 net-icmp-external 探针实机 PASS；U2 Linux 侧待回填） |
| 059 | S2 | guest 重启后 containment 静默蒸发：iptables 规则只存内核 RAM，rules.v4 的两个潜在恢复机制（netfilter-persistent/ifupdown）都不在 24.04 cloud image 或工具链 leg 里；cloud-init runcmd 是 per-instance 且 instance-id 冻结、up 不重建 seed——qemu 崩溃 + up 恢复后 OUTPUT policy 回到 ACCEPT，up 无任何防火墙验证照常绿灯 | H1 | 已修复（night-14：egress-lock.service boot 重放（Before=network-pre）+ 规则幂等 -C||-A + up 行为级守门（TCP/ICMP 直连即拒交）；macOS 实机重启循环四探针全 PASS；Linux/U1 侧待 Ubuntu 实机回填） |
| 058 | S5 | 去集群化改名隐藏消费者：r7-sync-matrix 手拼 `Host: cage` 对现 gate（host != "gate" 即 403）全数判死——实跑首个请求即 panic；r8-regression 编译死（refresh_fingerprint_stamp 已删）+ 同病；r9-regression 编译死（SetupOptions 私有化）+ 同目录 f052 夹具钉旧 /tmp/cage-lima-*；c3/r6 同病；harness/tools 在 ci.sh 之外腐烂无警报 | 8c3fa14 波及面 | 已修复（night-14：r7/c3/r6 Host 字面量→gate、f052 夹具路径→/tmp/vmhome-；r8/r9/r12 按 README 裁定退休——主体/API 有意删除） |
| 057 | S4 | 孤儿收割 ppid==1 判定在 systemd user session（PR_SET_CHILD_SUBREAPER）下恒假：relay 死后核心 re-parent 到 systemd --user（pid≠1）→ 收割网 no-op，audit #2 修复在 Linux 主场景失效；macOS 不受影响（launchd 即 pid 1）；stop_local 5s 预算后还删 socket 文件自毁判据，无自愈路径 | H6 | 已修复（night-14：relay 自写 core.pid（双平台，spawn 即写）+ 判定改"ppid==活 pidfile relay 即健康，否则收"——platform-neutral，subreaper 形态覆盖；U3 Linux 实机回填仍待） |
| 056 | S4 | reap_orphan_cores 把 profile 目录未转义拼进 pgrep ERE：实机四场景——`+` 目录漏杀自己孤儿且 stop 谎报 RC=0（下次 start 楔死"端口被占"）、`a+b` 的 ERE 误杀 `aab` profile 的孤儿（跨目录误杀）、`(` 未闭合 regcomp 失败被 output() 静默吞掉；对照 tunnel.rs 同功能签名用安全字母表 instance 名有正确先例 | H6 | 已修复（night-14：ERE 全元字符转义 + pgrep exit 2 响亮化；r13-orphan-probe 四场景复跑全中：跨目录不误杀 a+b/aab、元字符与括号目录自身孤儿被收） |
| 055 | S4 | F-054 修复的 arm64-URL 子声称不成立：工具链段 `'"$ARCH"'` 在外层 dash 展开、ARCH 只在内层 sh -c 赋值 → URL 架构段恒空（所有架构 404）→ nodejs.org 主下载死代码、恒走 apt 兜底（nodejs 18）；F-054 其余子修复（APT_OPTS 拼接/300s 预算/124 吞/契约可达）实证有效；commit message "URL is even right on arm64" 与行为落差与 F-052 同型（night-11 工程陷阱 #49 再现） | R11（F-054 修复面回归） | 已修复（night-13：内层展开+探针同步复验 PASS） |
| 052 | S4 | F-049 修复只落地 2/3：cmd_up 的 stamp 读失败仍 `if let Ok` 跳过（commit message 与 STATE 声称的 "any stamp read failure refuses up" 不存在于代码）——实机：删 stamp → up rc=0，且无实例时 limactl start 从 template:default 自动创建未供给原版 VM（无拓扑/无身份/无令牌）在 creance up 下启动成功 | R10-A1（F-049 修复面回归） | 已修复（night-12：三分支真落地+up 前实例存在检查；实机双 case 拒绝） |
| 053 | S4 | lima 2.3.0 create 小写化实例名 vs creance vmname 大小写保留 → instance_running 名字恒等式永假：F-049 探针守卫（stamp missing on running VM）与 gate-record 探针在 setup 产物上永不触发（实机：Running VM+删 stamp → 两探针 NotEnforced、escape-test 报 contained）；macOS APFS 大小写不敏感掩盖路径级后果，case-sensitive 卷上 F-051 重建检测必 miss→死胡同回归；limactl start 自动创建反而保留大写（lima 自不一致） | R10-E1/F-051 面 | 已修复（night-12：实例名生成统一小写对齐 lima） |
| 054 | S4 | 首启供给截断 fail-open：无 --max-time 的 nodejs curl 在供给期（无 tunnel）挂死被超时击杀，拓扑锁定+特权回收（脚本自称 containment contract）整段未执行——实测 VM 交付 OUTPUT ACCEPT+免密 sudo+ipv6 开（up rc=0）；手工重跑脚本可全程走完=纯次序+超时缺陷；次生：[[ bashism 在 dash 下恒 x64 退化 | R10-E1/D（F-031/F-034 残留） | 已修复（night-12：网络步骤全有界+工具链段 300s 硬预算+POSIX case） |
| 051 | S5 | F-044 拒绝后的法定恢复路径不可达：全仓库无实例删除命令，setup→裸 limactl create 对存量实例必然失败不重写戳——漂移用户被"creance setup 重建"指引引进死胡同，唯一出路是删整个 profile 目录（含 workspace）；先于 night-10 存在但 F-044 使其成为法定路径 | R9-A1/A2（F-044/F-045 闭环） | 已修复（night-11：setup 检测存量实例 delete -f 重建） |
| 050 | S4 | gate-open 对账对 store load 失败 fail-open：cmd_gate 两处 `if let Ok(load)`——同 uid 写坏 sources.json 一个文件即把 night-09+night-10 对账（含采样后二次对账）整体致盲，PUT 重载 evil yaml 免检出；缺文件形态反而 fail-closed（默认 store 空 selected 被 selection 拒）——只防住缺失没防住损坏 | R9-A3（F-042/F-046 修复链） | 已修复（night-11：store 读失败 fatal 两处对账） |
| 049 | S4 | F-044 修复对 stamp 异常态 fail-open：up 的 `if let Ok(read_to_string)` 读失败即跳过漂移检查放行，探针同态报 NotEnforced（exit 0 不计失败）——stop→rm fingerprint.txt→改时区→up 完整复活洗绿路径；空/尾随空白形态反而 fail-closed（不对称）；setup 写戳失败仅警告返回 0 也造成合法序列的静默缺失 | R9-A1（F-044 面） | 已修复（night-11：stamp 读失败 fail-closed 三处） |
| 048 | S4 | night-10 /rules 对账按裸数组断言响应体，真实 mihomo 返回 `{"rules":[…]}` 包装对象（实机冒烟捕获）→ check_running 对诚实核心恒 Err("readiness: rules")→gate-open 全灭+proxy-start no-op 判定永不命中；type=="Match"/proxy==GROUP 猜对、外壳猜错；修复 diff 零测试行、假核心不答 /rules、无真实冒烟（任务书明写"别猜"）——CI 全绿=该路径零覆盖。fail-closed 方向，核心功能 100% 不可用 | R9-A3（F-046 修复面回归） | 已修复（night-11：真实包装形状+实机固化夹具；gate-open 复活实机验证） |
| 047 | S5 | F-043 修复的失败分支：select 先落地后 `let _` 吞 close_gates 错误——Go applyProxy 是事务性（close 失败→中止+defer 回滚 store/config），Rust 失败时"Open gate+新声明+旧 wire"三方不一致共存且报成功；窗口 ≤90s（renew 零调用者→lease 必到期）且再 open 被 check_running selection 拒，无取证重复路径 | R8-A4（F-043 面） | 已修复（night-10：select 事务性——close 前置传播 Err） |
| 046 | S4 | night-09 check_running 对账集不含 /rules：保 mode=rule+同端口/同 interface/unified-delay+伪装 CAGE 组预选回 selected 的规则级重载自述穿透对账（假核心在环实证；负对照 mode=direct 仍拒=修复对已记录攻击有效）；对账=对核心自述的对账（同源限度）；TOCTOU 不独立成洞（被本面吸收）；SAFE_PATHS 同 uid 内不可收窄（设计地板）；F-038 假设再收窄：洗地路由可由同 uid 自装、无需不诚实订阅 | R8-A3（F-042 面） | 已修复（night-10：对账补 /rules+采样后二次对账） |
| 045 | S5 | browser_language 被 guest_fingerprint 承诺为 guest 可感知但全仓库零供给路径（改它→探针红→强制 re-setup→依然无人消费）；Go 经 CAGE_LANGUAGE 注入（guest.go:315）且 CAGE_TZ/CAGE_LOCALE env 链整条缺失；dns_url 两版同形硬编码不进 guest（F-040 排除正确，承诺面盘点收口） | R8-A2（F-040 面） | 已修复（night-10：provision 写 /etc/profile.d/cage-env.sh 三字段） |
| 044 | S4 | up 无条件刷新 fingerprint stamp：F-040 后刷戳唯一能改变结果场景=guest 三字段真实漂移，而 vm::up=裸 limactl start 不重供给——stop→edit→up 把诚实红洗绿（探针 h2.3 FAIL 实证），guest 实际仍旧时区；刷戳注释理由"proxy_revision is part of it"已被 F-040 自删；up_refreshes_a_stale_stamp 测试把假绿奉为规范须反转 | R8-A1（F-041 邻面/F-040 修复引入） | 已修复（night-10：删刷新，漂移 up 拒绝+re-setup 提示） |
| 043 | S5 | select_and_apply 不撤销 gate（Go applyProxy 每次 select/restart/route 同步 closeProxyGate——proxy.go:334）：select→proxy-start 窗口内 Open gate+声明新节点+wire 旧节点共存；applied() 对运行核心失明（F-036），与 F-041 组合成弱缝 | R7-B3/G4 | 已修复（night-09：select 即撤 gate 两入口） |
| 042 | S4 | mihomo external-controller-unix 零认证（Go 同形非漂移）：同 uid 无凭证 PATCH mode=direct / SAFE_PATHS 内 yaml 重载 MATCH,DIRECT 全部 HTTP 204 成立，出口证据预言机随核心运行时被劫持（宿主出口替代节点失败），config.yaml/sources.json 零痕迹；guest 不可达（0700 目录） | R7-B1 | 已修复（night-09：secret+readiness 对账+gate-open 前核心对账；unix 免鉴为 mihomo 设计） |
| 041 | S4 | night-08 回归：proxy-revision 幂等 Unchanged 路径的 strip_config 剥掉 exit_policy——锚点漂移（换 ip/mode 迁移）+revision 不动 → 200 且 gate 保持 Open，无重检查无重启要求；renew 可无限续期无硬顶（探针 m1-m5 实证；附 created_at=0+时钟≤epoch fail-open 逻辑读） | R7-A2/A3 | 已修复（night-09：Unchanged 含锚点比对） |
| 040 | S4 | F-033 回归：setup 指纹戳覆盖全 config（含 proxy/revision/exit_policy），任何合法 select/重启使 escape-test 恒报 Escaped（探针 H4 实证前提）；record 源吸收漂移、戳源永久报警，双源冲突 | R6-B3 | 已修复（night-09：戳改 guest 承诺面指纹） |
| 039 | S5 | 幽灵 workspace 清单 crates/Cargo.toml（git tracked，ff286a6 残尸，0.2.0/your-org）阻断外部 path-dep：继承绑定旧版+crates/crates/ 双倍路径（实测 build error） | R6-C 工具链 | 已修复（night-08：幽灵清单删除，path-dep 实证通过） |
| 038 | S4 | 出口证据=单目的地采样被泛化为全流量锚定：出口节点差异化路由可洗白大陆出口（TLS 防 MITM/核心单 MATCH/parse_trace 15 项矩阵均已验证封死，唯一开放路径在节点以外） | R6-A1 | 已修复（night-08：单目的地边界如实声明+审计 exit_sample 标注） |
| 037 | S2 | gate 认证 fail-open：record 不可读→token 退化空串，空 Bearer 过恒时比较；无凭证进程 check→grant→Open 全链成立（探针实证）；Go 用启动时内存 token 恒拒——语义漂移。边界=同 uid+close 瞬态窗口，guest 不可达 | R6-A4/A3 | 已修复（night-08：token 内存化 fail-closed，r6 探针实证全拒） |
| 036 | S4 | exit-anchor 漂移链零绑定：grant 契约 5 键字符串表 vs Go 11 项+RunID+Configuration+CreatedAt+24h+Renew 重授权；daemon 逐命令 applied() 对 co-updated revision 结构性失明；workbench start 不 sync、CLI start 先重启后 sync 且吞错——换节点后伪造五键静默再 Open（探针 H3 实证），90s 租期为唯一硬顶。C5 预埋分支复查：action 对 Ok 也无条件关 gate（静默担忧不落地），但幂等 sync 也关（注释矛盾，proxy-start 强制重取证） | R6-A2/A3 + attack-surfaces C5 | 已修复（night-08：start 先 sync+幂等不关+grant 绑 run/时间） |
| 035 | S4 | spawn_daemon 的 pidfile-alive 去重命中垂死守护（确定性探针复现）：up 返回 Ok 而终态无守护无 record；对称风险=stop 的 close_and_remove 可刺杀并发 up 的年轻 record | R5-1 F-028 修复面回归 | 已修复（night-07：等待一拍分离在途/垂死） |
| 034 | S4 | provision curl -o 失败残留半截 /usr/local/bin/node 遮蔽 apt 兜底的 /usr/bin/node（PATH 先序）→ 兜底链被尸体击败；containment 不受影响 | R5-4 F-031 修复面回归 | 已修复（night-07：tmp+mv 原子下载） |
| 033 | S5 | fingerprint-consistent 探针死代码：fingerprint.txt 全仓库无写入者，恒 NotEnforced（"layer not implemented yet"）；漂移检测实际由 running.rs 承担 | R5-6 C7 | 已修复（night-07：setup 写戳，探针激活） |
| 032 | S4 | 订阅内容恰 48-hex 字符串（password 等）经 sources.json 被 scan_unknown_tokens 判 unknown → escape-test 误报 Escaped exit 1（实测；64-hex/干净订阅对照不触发）——远程内容可操纵信任预言机 | R5-5 期望集回归 | 已修复（night-07，实机重放） |
| 031 | S4 | provision 的 set -e 使安装失败=部署 fail-open：apt/curl 失败中断脚本，拓扑锁定与特权摘除全部不执行 | R4 F-020 回归残留（night-06 核实） | 已修复（night-06） |
| 030 | S5 | Egress::dial 目标含 CRLF（尾冒号数字端口形状）可向 HTTP 代理 CONNECT 请求注入任意头部（实测成立）；生产不可达（fetch 走 WHATWG 规范化）——API 加固 | B1/B2 | 已修复（night-06） |
| 029 | S4 | retire_stale_record `!is_ok()` 把 5s 读超时当守护已死：冻结/慢守护即被 `creance up` 删活 record+切隧道+更替守护+gate 静默跌落 Closed（实机复现）；与 close_gates 的 "unreachable" 字符串判定双标 | night-05 修复面回归（C3） | 已修复（night-06，实机复验冻结 no-op） |
| 028 | S2 | 双守护战争：spawn 竞态/直接双抛 → 败者凭 record 路径存在永生，Closed rogue 每 500ms 杀隧道 → record=closed 期间 wire 间歇可用（guest 实测 UP/死交替），rogue gate 不可达不可管理，状态永不自愈 | night-05 修复面回归（C3） | 已修复（night-06，实机复验双抛收敛+wire 稳定；含 disown 补丁——败者 drop 曾删胜者 record 致全灭） |
| 027 | S4 | 未收割 ssh 僵尸被 pidfile 判活（kill(pid,0)+start token 双双被僵尸骗过）→ ensure 永久短路，gate Open 但 wire 死（机制探针+实机端到端双验证）；另记 ensure/reap 竞态窗口 | night-05 修复面回归 | 已修复（night-06，实机复验 kill -9 后 1s 重生） |
| 026 | S4 | 孤儿 ssh -R 超出 pid 文件管辖即无人能切（closed=wire down 依赖单文件存活；F-025 现场实测遗留） | night-05 实机验证 | 已修复（night-05，实机复验） |
| 025 | S4 | 处女 profile 的 up 误报失败：proxy/ 目录缺失使 gate.pid/log 写入 ENOENT（守护已 spawn 但 CLI 走回退且回退同败） | night-05 实机验证 | 已修复（night-05） |
| 024 | S3 | v0.4.0 终稿未过 CI：fmt 11 处红 + lima 测试断言引用已删除的 hostname 字段恒失败（R3"基线绿"不实） | night-05 基线核验 | 已修复（night-05） |
| 023 | S5 | 深路径 profile setup 撞 UNIX_PATH_MAX：limactl fatal 原样抛出，creance 无预检 | R3→0.3+D1 | 已修复（night-05） |
| 022 | S4 | 0.4 身份声明差距：username 未接线（宿主用户名镜像进 guest）/load_or_create 读失败重置身份/credentials 探针假 PASS | R3→0.4+E1 | 已修复（night-05，①实机复验） |
| 021 | S4 | tunnel stop() 盲杀 pid 文件进程：pid 复用窗口误杀同 uid 任意进程（实测 sleep 被杀） | R3→0.3+C6 | 已修复（night-05） |
| 020 | S2 | guest 内一条无密码 sudo 撤销 0.3 拓扑强制：OUTPUT ACCEPT 后直连 1.1.1.1 得 301（实测逃逸） | R3→0.3+D/E | 已修复（night-05，实机复验） |
| 019 | S4 | gate-daemon SIGKILL 后 record 残留：up 全部短路+孤儿隧道 wire 无法关（fail-open）+escape 探针假 PASS（实测全链） | R3→0.4+C3 | 已修复（night-05，实机复验） |
| 018 | S5 | precheck_depth 把字符串字面量括号计入深度：密码含 129 个 [ 的合法订阅被拒（Go 接受） | R2→001+A1 | 已修复（night-04） |
| 017 | S4 | 204/304 无 body 挂满 deadline（refresh+304 场景 60s 失败）；Go 按状态码立即完成 | R2→night-02/B2 | 已修复（night-04） |
| 016 | S4 | 011 残留：结构错 YAML 假 PASS + merge key 骗术（serde_yaml 不展开 lima 展开，探针被骗） | R2→011+E1 | 已修复（night-04） |
| 015 | S5 | 004 尾斜杠启发式被尾随空白/反斜杠绕过（4 变体误放行） | R2→004 | 已修复（night-04） |
| 014 | S4 | 并发 import 丢失更新（双成功单存活）+ select_and_apply 非原子残留不一致 | C1 | 已修复（night-03） |
| 013 | S4 | SOCKS5 凭据 as u8 截断（ULEN=44 实测），target 有校验凭据没有 | B1 | 已修复（night-03） |
| 012 | S5 | 非字符串键节点整拒（Go map[any]any 显式接受），issue.name 丢失 | G2 | 已修复（night-03） |
| 011 | S4 | 探针质量：mounts 计数 3 种 YAML 骗术/sock-abstract 硬编码 PASS/env-credentials 恒误报 | E1+E2 | 已修复（night-03；误报项即 grep 模式对齐 STRIPPED 未动，属共同窄设计） |
| 010 | S2 | limactl() 自删 LIMA_HOME→全部 VM 操作落全局 ~/.lima，profile 隔离失效+探针脱节 | D2+E1 | 已修复（见 FIX-NIGHT-01 提交） |
| 009 | S2 | fetch.rs 缺 https 策略：明文订阅/userinfo/5 跳全被接受（Go 全拒）→订阅凭据对出口明文 | B4 | 已修复（见 FIX-NIGHT-01 提交） |
| 008 | S4 | gate 四处漂移：grant 无 Checking 前置/reason 200B 上限对 CJK 失效/token 非恒时比较/exit_policy 变化不重开 | C3+C4 | 已修复（FIX-NIGHT-02） |
| 007 | S2 | SSRF 守卫漏 IPv4-mapped IPv6：::ffff:127.0.0.1 绕过检查，真实 mihomo 规范化后拨号本机 | B4 | 已修复（见 FIX-NIGHT-01 提交） |
| 006 | S4 | egress 五类宽容接受：chunked EOF/CRLF 重同步/双 CL/垃圾 CL/半截头均当成功（Go 严格拒绝） | A7+A8+B2+B3 | 已修复（FIX-NIGHT-02） |
| 005 | S5 | DNS unpack 接受 0x40/0x80 保留前缀标签（>63），miekg 拒绝；pack rdlen 截断地雷 | A6 | 已修复（night-03） |
| 004 | S5 | config 校验三处 Go 漂移：时区目录名/IPv6 括号/尾斜杠 | A5 | 已修复（night-03） |
| 003 | S4 | 数字 mport 被拒、Go case int 明确支持（yaml_to_json 丢整数性） | A4 | 已修复（FIX-NIGHT-02） |
| 001 | S3 | 订阅 YAML 深嵌套 O(n²) CPU：1MiB 烧 406s，8MiB 外推约 7 小时 | A1 | 已修复（见 FIX-NIGHT-01 提交） |
| 002 | S4 | 超 u64 整数标量拒绝整份订阅（Go 版回退 float64 接受） | A1 | 已修复（FIX-NIGHT-02） |

