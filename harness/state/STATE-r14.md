# STATE — R14 终稿（2026-11-21，night-auditor-v2，基线 6155c1f v0.6.5）

## 轮次定位

收敛判词轮（DRIVER.md 定义）：对 v0.6.x 全部修复（findings 056-063，
night-14 = 54f6169 / night-15 = 6155c1f 两批）做全增量对抗复核——修复是否
落地、有无回归、邻接代码有无同类残留——外加攻击面收尾扫描。
`git log 469e37c..HEAD` = 3 commits（54f6169 / afe9ec6 / 6155c1f）。
基线 `sh scripts/ci.sh` **真实退出码 0**（fmt+clippy -D warnings+test+
release，`/tmp/r14-ci-baseline.log` 尾行 CI_EXIT=0），工作树干净。

## 八修复面裁定（056-063）

| 面 | 裁定 | 证据 |
|---|---|---|
| F-056 ERE 转义 | **修复成立（扩展实证）** | R13.5 四场景维持；本轮新做全 14 元字符矩阵（真二进制 `creance proxy-stop`，4 批 × 5 目录含 `\` `.` `[` `]` `{` `}` `(` `)` `*` `+` `?` `^` `$` `|` + plain/dz/d- 对照 + `d.`/`d*`/`d?` vs `dx` 交叉守卫）：**4/4 批全过**——自身孤儿全收、零 CROSSKILL、零 MISS；转义表覆盖 POSIX ERE 全集（14 元字符逐一核对），BSD regex 引擎对全部转义形态接受。Linux glibc 对 `\]` 等的接受度留 Ubuntu 回填（U 系列随行） |
| F-057 relay pidfile | **修复成立** | 静态复核：log_relay_proxy 在信号处置安装前自钉 core.pid（双平台）、launch_supervised 双写同 pid 同 token；判活 filter 三条件（token 非空 + starttime 匹配 + kill(0) 活）齐备；kill 块 SIGTERM→2s 预算→SIGKILL 升级；pidfile 写失败→下轮 stop 把该 profile 全部匹配核心当孤儿收=方向正确（sweep 只在 stop() 调用）。R13.5 的 zombie 推演（内核 re-parenting 语义）维持证伪 |
| F-058 探针复活 | **修复成立** | r7-sync-matrix/c3-gate-hammer/r6-evidence-probe 的 `Host: cage` 全部改 `Host: gate`（grep 实证 6 处）；f052 夹具 `/tmp/vmhome-`；r8/r9/r12 退休裁定在 tools/README |
| F-059 boot 重放+守门 | **修复成立（守门本轮强化后复验）** | provision.rs: egress-lock.service（Before=network-pre + DefaultDependencies=no + enable）+ rules.v4 + 幂等 -C\|\|-A 三层齐；up 守门经 night-15 强化后真值表 10 行全 fail-closed（[G] 节：正向证据缺失/畸形/伪造+诚实泄漏共存全拒）。R13.5 macOS 实机重启循环维持 |
| F-060 网段限定 | **修复成立** | provision.rs:114-118 三条 UDP67 + 两条 ICMP 全部 -d 网段限定（10.0.2.0/24、192.168.5.0/24、DHCP 广播）；测试断言裸 ALLOW 不得存在；conntrack RELATED 兜底 PMTU 论证维持。R13.5 usernet 实机维持 |
| F-061 注释-only | **维持 R13.5 裁定** | image.rs:50-56 注释如实（同通道 TLS、防损坏不防双文件 MITM、GPG 留 Ubuntu）；R13.5 已裁定文档诚实化+风险显式化，非代码修复 |
| F-062 正向证据 | **修复成立，带一处覆盖缺口 → 新 064（S5）** | up 守门 `Ok(_)=>{}` 已删，正向证据（tcp-blocked 必须在场）fail-closed；escape-test 缺行计数 fail-closed（[D] 节：空输出 → 22 项全 missing）；PATH 硬重置+绝对路径落地。**缺口**：缺行网只覆盖 11/12 探针——fs-flag-readable 经 probe() 助手参数化发射被提取器放弃，可被单独致盲而 transport ESCAPE 不触发（[A-OBS]/[E-OBS] 实证）。影响有界：宿主侧 mounts 探针不经 guest 传输兜底同一属性；完全伪造本在 F-062 如实边界内。详见 findings/064 |
| F-063 文档同步 | **修复成立** | ROADMAP 探针清单（宿主 6 + guest 11 含 net-icmp-external、numeric-endpoint 删除注明）与 escape.rs 实际 id 全集逐一对上；QUICKSTART:84-86、README:128-132 同步；全仓残留 proxy-numeric-endpoint 引用仅三处且均为有意历史记录（escape.rs:82 删除注释、docs/AUDIT-2026-11-21.md:53、attack-surfaces E5 裁定行） |

## 发现清单（1 项，064；INDEX 已登记）

| # | 严重度 | 一句话 | 证据等级 |
|---|---|---|---|
| 064 | S5 | F-062 缺行网漏掉 probe() 助手路由的 fs-flag-readable（提取器只枚举字面 `echo "PROBE` 发射点并把 `$` 参数化发射连同该探针一起放弃；调用点 escape.rs:332 的 id 本可静态枚举，main.rs:379-382 豁免注释 "not statically knowable" 名不符实）——该探针行可被单独致盲而 transport ESCAPE 不触发 | 真输入实证：r14-convergence 探针以真 `guest_script()` 渲染 + main.rs 逐字符镜像提取器，[A] 集合无 fs-flag-readable、[E] 整行缺失时 missing 为空；对照组 [C]/[D]/[F]/[G] 全过证明缺口仅此一项 |

## 收敛判词（R14，基于证据）

**"零新发现"判据未满足 → 收敛判词不发，循环进 night-16 微批。**
依据：v0.6.5 的 v0.6.x 安全修复面（056-061 + 059/060 行为守门）经全增量
对抗复核**全部成立**——无回归（PATH 重置、守门强化、文档同步均复验）、
无邻接残留（pgrep 三处调用点、pidfile 判活全仓盘点、裸插值 ERE 唯一
豁免者 tunnel.rs 经 vmname 字母表核验安全）；本轮唯一新发现 064 属
F-062 修复自身的遥测覆盖缺口（11/12 探针），不触及安全语义（S1-S4 面
零新发现）。**064 修复落地且 r14-convergence 裁判通过后，R15 按预期
零新发现给出收敛判词**——届时无需重跑本轮已闭环的八个面，只需增量
复核 064 修复 + 攻击面抽查。

剩余风险清单（不阻塞收敛，随行记录）：①平台回填——Linux glibc 对
`\]` 等 ERE 转义的接受度、U1-U5 Ubuntu 实机、QEMU 传输形态的 062 同验；
②H3 未验证想法——workspace 含 `,` 击穿 qemu fsdev 选项串（本机无 qemu
不可实证，setup 校验只拒单引号）；③F-061 GPG 验签、首 boot 供给开窗、
slirp restrict=on——产品路线图议题，维持不立案；④QMP powerdown 无读
超时（attack-surfaces H4 已记档的自伤面 S3 候选）。

## 已攻击未破（证伪记录，不计 findings）

1. **PATH 重置破坏 net-ipv6 探针**：night-15 给脚本加 `export
   PATH=/usr/bin:/bin`，而 net-ipv6 用裸 `ip`——若 ip 仅在 /usr/sbin 则
   command-not-found → 恒假 PASS（回归形态）。下载 noble iproute2
   6.1.0 deb 定案：`ip` 是 **/bin/ip 实体文件**（usrmerge 下即
   /usr/bin/ip）→ 探针语义完好。getent/curl/timeout/ping 均在
   /usr/bin。证伪。
2. **提取器子串碰撞**：某 expected id 是其它探针可发射行的子串 → 缺行
   网假答。68 行矩阵（11 id × 3 verdict + 2 参数化行）全查无误匹配。
3. **up 守门"伪造+诚实泄漏共存"**：输出同时含 tcp-blocked 与 tcp-open
   → 真值表拒绝（fail-closed）。
4. **tunnel.rs 裸插值 ERE 同型残留**（F-056 邻接面）：`HostKeyAlias=
   {alias}.*-R {port}` 中 alias 直插——host_key_alias(instance) 的
   instance 经 vmname 折叠为 `[a-z0-9-]`+hex（F-053 小写化），`-` 括号
   外为字面量，无元字符可注入。安全，先例成立。
5. **probe() 助手多消费者**：全仓盘点 `echo "PROBE` 25 个发射点 + 调用
   点——probe() 唯一消费者是 fs-flag-readable（已立案 064）。
6. **ERE 矩阵 CROSSKILL 风暴**：矩阵首跑报成片 CROSSKILL（每个 stop 误杀
   同批全部后发邻居）——定位为**探针自身机制假报告**：bash `( cmd & )`
   快速连发存在位置依赖 fork/exec 竞态，后发进程整段不执行（进程在、
   env 对、但二进制首条 fprintf 不出现）→ pid 文件假缺失 → alive() 误判
   死亡。改自守护化 fakecore（main 内 fork 即退 + setsid + 子写 pid）后
   4/4 批干净。被测对象（转义表）无罪；教训入库（关键记忆 #1/#8）。

## 实验清理

/tmp/r14-ere*（矩阵+7 个 manual 现场）、/tmp/r14-iproute2-check、
/tmp/fakecore-{diag,daemon}.c、/tmp/r14-ci-baseline.log 全删；全部假核心
验死（首跑 manual 残留 5 进程已 pkill，终态 pgrep 0）。仓库仅
harness/tools/r14-convergence/（新工具：README + ere-matrix.sh +
fakecore.c + Cargo.toml + src/main.rs）+ findings/064 + INDEX + 本文件
为本轮产物。tracked Cargo.lock 未动（探针独立 [workspace]，git status
仅 ?? 新目录）。

## 关键记忆（非显然事实，≤10）

1. bash `( cmd & )` 快速连发有位置依赖 fork/exec 竞态：后发进程可整段
   不执行（进程活着、env 正确、但二进制代码不跑、pid 文件假缺失）——
   C 内自守护化（fork 即退 + setsid + 子写 pid + 调用方去掉 `&`）根治；
   一切连发孤儿探针该用这个形态（fakecore.c R14 版即模板）。
2. F-056 转义表在 macOS/BSD regex 对全 14 元字符实证成立（4/4 批真二进
   制）；Linux glibc 侧待回填。
3. Ubuntu 24.04 (noble) iproute2 的 `ip` 是 /bin/ip 实体文件（usrmerge
   下即 /usr/bin/ip）——`export PATH=/usr/bin:/bin` 不破坏任何 escape
   脚本裸命令。
4. F-062 提取器输出含重复 id（每个字面 id ×2，escape+PASS 两发射点）——
   判定幂等无害；若未来加计数语义须先 dedup。
5. cmd_up 守门失败路径在 spawn_daemon 之后（night-14 既有顺序）：guard
   fail → stop_vm 但 gate daemon 已拉起——90s 租期硬顶 + VM 停止即 wire
   down + stop 清理，无安全语义，非本轮回归。
6. crates/creance 有 lib.rs 导出 escape::guest_script——探针可用真输入
   （r14-convergence 形态）；但 cmd_up/cmd_escape_test 消费逻辑内联在
   bin crate 不可导入，只能逐字符镜像（F-033"复刻无效"教训的边界：真
   crate 渲染输入 + 镜像逻辑 + 头部注明基线）。
7. creance_proxy::service::stop 的 reap kill 块 = SIGTERM → 2s 预算轮询
   → SIGKILL 升级；pidfile 写失败降级 = 下轮 stop 全收，方向保守。
8. 探针假报告的特征签名：pid 文件"前缀成功后缀缺失"+ 进程 pgrep 可见 +
   env 正确——先查 spawn 机制再怀疑被测对象。
9. noble 的 getent/curl/timeout/ping 全在 /usr/bin；`[ -x /usr/bin/ping ]`
   守门与 net-icmp-external 的 SKIP 分支是仅有的两处二进制缺席防御。
10. /tmp/vmhome-501-* 历史符链约 200 个（悬空居多）重启自清，不动。

## 下一轮建议（按序）

1. **night-16 微批（单文件小修）**：修 064——提取器补 `probe <id>` 调用
   点枚举（或最简：fs-flag-readable 在脚本里改字面 if/else 发射，与其
   余 11 探针同构），顺带修 main.rs:379-382 豁免注释措辞。修后以
   r14-convergence [A]/[E] 节作裁判（expected 集合应含 fs-flag-readable、
   整行缺失场景应报 missing）+ sh scripts/ci.sh 判绿（不用管道吃码）。
2. **R15 = 收敛判词轮（预期达成）**：增量复核 064 修复 + 攻击面抽查，
   零新发现即按本轮判词模板给出收敛判词，DRIVER 写 convergence 字段
   停轮。
3. **平台回填（不阻塞收敛，长期循环项）**：U1-U5 Ubuntu 实机 + Linux
   glibc `\]` 等转义接受度 + H3 逗号路径 qemu 实证 + 062 的 QEMU 传输
   形态同验。

## 会话统计

- R14：1 新 finding（1×S5，待修复）；6 方向证伪存档；8 修复面全裁定
  （7 成立 + 062 成立带缺口）；ERE 全元字符矩阵 20 目录 4 批实机全过
- 累计：64 findings；056-063 八项修复全部复核闭环（062 遗留 064 微缺口）
- 实机消耗：真二进制 proxy-stop × 20 目录 × 4 批 + 假核心 ≤5 并发/批，
  零 VM 时长、零残留
