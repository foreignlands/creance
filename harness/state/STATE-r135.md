# STATE — R13.5 终稿（2026-11-21，night-auditor-v2，基线 afe9ec6 v0.6.4）

## 轮次定位

纯回归轮：对 night-14（54f6169）六项修复 + afe9ec6 README 边界段做对抗复验，
`git diff b62823c..afe9ec6`（28 files, +909/-59）。基线 ci.sh 全绿
（fmt+clippy -D warnings+test+release），工作树干净。

## 六修复面裁定（5 过 1 裁定）

| 面 | 裁定 | 证据 |
|---|---|---|
| F-056 ERE 转义 | **修复成立** | r13-orphan-probe 四场景复跑全翻转：A 正控死（鉴别力在）、B `+` 目录修复（漏杀→收割）、C 跨杀修复（a+b 的 stop 不再杀 aab，aab 存活）、D `(` 目录修复（静默→收割）。字符表对照 POSIX ERE 全集（\\ . [ ] { } ( ) * + ? ^ $ \|），`-` 括号外为普通字符、换行不特殊；exit 2/3 响亮化，spawn Err 静默可接受（pgrep 已入 require_tools） |
| F-057 relay pidfile | **修复成立** | pidfile::write 自取 started token（pidfile.rs:149-152），relay 自写路径闭合；launch_supervised 双写同 pid 同 token 一致；"写失败→全收退化"评估为良性（sweep 只在 stop() 里调用，stop 本意即杀）；**zombie 缺口推演后被内核语义证伪**（见下） |
| F-058 探针复活 | **修复成立**（带分级） | r7-sync-matrix 实机全 PASS 无 panic，可作回归裁判；r6 复活可编译可运行但 7 处断言是修复前形态（status 泄漏期望 200 实得 403=洞已闭），**不能作裁判**——已写入 tools/README 裁判分级 |
| F-059 boot 重放+守门 | **修复成立**（守门被 062 击穿） | 实机 stop→up 循环：reboot 后 egress-lock `active/exited/Result=success`（13:27:29 执行），unit enabled、rules.v4 正确（OUTPUT DROP+定向 allows）、/usr/sbin/iptables-restore 在（alternatives 符链）、Lima 二次 boot 脚本重放幂等成立；守门红路径实机验证（伪造 tcp-open→stop_vm+正确报错）。**但守门/escape 的证据通道可被 guest 单方面致盲——新 062** |
| F-060 网段限定 | **修复成立** | **usernet 192.168.5.0/24 实证**（guest eth0=192.168.5.15/24，网关+DHCP=192.168.5.2，非猜测）；广播 255.255.255.255 困于虚拟链路（usernet 是用户态 NAT，vmType=vz 无桥接）；ICMP 限定后 PMTU 由 conntrack RELATED 兜底（碎片需 ICMP 只对已建立连接），tunnel 是宿主发起的 inbound ssh -R（guest 无出站 TCP 需求）；net-icmp-external 实机首跑 PASS；ping 缺席→SKIP 如实（iputils-ping 在 24.04 cloud image 常驻）。**首供给 boot 早期开窗实证**：21:23:52 NTP 数据报到达 usernet（lockdown 21:23:56-58 才跑完）——供给期开窗与工具链 leg 同一设计边界（provision.rs 头注释），非回归 |
| F-061 注释-only | **裁定：记档，非修复** | image.rs 只改注释（谎言声明→如实信任模型）。信任根实质（同通道 sums、无 GPG）不变。裁定=文档诚实化+接受风险显式化，非代码修复；INDEX 061 行措辞已如实（"GPG 留 Ubuntu 侧跟进"），night-14 的 commit message "all six fixed" 严格说 5 fix + 1 doc-rewrite。维持 S4 记档状态，GPG 验签仍是后续工作 |
| E5 删除执行 | **成立，漏一处** | escape.rs 删净+守卫注释在位；QUICKSTART 6 项+四类 guest 探针一致；escape-test 实机 6 宿主探针 ✅ 无 numeric-endpoint 残留。**ROADMAP.md:16 漏同步——新 063** |

## 发现清单（2 项，062-063；INDEX 已登记）

| # | 严重度 | 一句话 | 证据等级 |
|---|---|---|---|
| 062 | S4 | guest_script 传输层 stdout 全权受 guest 控制（~/.bashrc 非交互被 source，实机实证），up 守门 `Ok(_)=>{}` 与 escape-test 缺行不计失败双 fail-open——假绿（吞 tcp-open）假红（echo tcp-open 杀健康 VM）皆可；containment 内核侧未破 | **实机全链**：PATH 影子 marker 实证 + exec-redirect 零输出实证 + up 红路径实机触发 |
| 063 | S5 | ROADMAP.md:16 探针清单未随 E5 同步：仍列已删 probe、缺新增 net-icmp-external（E5 三处同步清单漏第三处） | grep 双向实证 |

## 已攻击未破（证伪记录，不计 findings）

1. **F-057 zombie relay 缺口**：reap_orphan_cores 的 relay 判活 filter
   （service.rs:244-248）无 entry_alive 的 reaped_zombie 探针，zombie relay
   会通过 kill(0)+token 判定——但内核在父进程退出瞬间即将存活子女
   re-parent 到最近的 subreaper，**zombie 不可能持有任何存活子女的 ppid**，
   `ppid != relay` 恒成立→核心照样收割。唯一形态缺口=serve 长存父进程持
   zombie 且另一进程跑 stop（serve.rs:167 的 select→start 使 serve 成为
   relay 父进程）——后果为零。filter 未用 entry_alive 属外观瑕疵，不立案。
2. **F-060 网段怀疑**：曾怀疑 lima 2.x 改网段（hostagent 日志出现
   192.168.50.182）——实机证明那是宿主 Mac 自身 LAN 地址（usernet 代理
   UDP 的源绑定），guest 实际在 192.168.5.0/24，修复注释正确。
3. **守门 stop_vm 副作用**：Err/tcp-open → stop_vm 路径实机触发，行为与
   消息正确；up 等待期 2:44（首供给）→5:16（重放），守门本身 +8s
   （tcp 5s DROP 等待 + icmp 3s），可接受。
4. **LIMADNS 混入 rules.v4**：iptables-save 捕获 lima guestagent 的 nat
   跳转（空链）；restore 重放这些跳转无副作用，lima 自身 nft 表在另一
   namespace 不受 restore 影响。
5. **ERE 旁路**：路径含换行（ERE 普通字符）、`-`（括号外普通）、跨 profile
   前缀碰撞（`/mihomo -d ` 字面锚+双 dir 拼接使 `foo` 不会匹配 `foobar`）
   均推演不可达；跨 profile 误杀的残余面要求目录名含字面 `mihomo -d `
   结构（用户自伤面，S5 不值立案）。

## 实验清理

r13-orphan-probe 四场景现场已 clean（/tmp/r13-ere 已删、假核心全验死）；
VM 实例 creance-r135-downloads-9f569e72 已 limactl delete -f、
/tmp/creance-r135* 已删、本 profile vmhome 符链已删；guest 家目录改动
（~/bin、.bashrc、shadow-proof）已还原为 skel 原样；tracked Cargo.lock 已
git checkout 还原；仓库仅 harness/tools/README.md + findings/{062,063,INDEX}
+ state/STATE-r135.md 为本轮产物。**遗留观察**：/tmp/vmhome-501-* 约 200 个
历史轮次符链残留（多数悬空）——重启自清，不动（协议：不删非本轮产物）。

## 关键记忆（非显然事实，≤10）

1. Ubuntu bash（Debian 补丁 SSH_SOURCE_BASHRC）对非交互+SSH_CLIENT 会 source
   ~/.bashrc——`limactl shell inst sh -s` 与 `ssh … sh -s` 通道均先过用户
   rc 文件再跑命令；FINDING-011 的绝对路径加固护探针体，护不住传输层。
2. 内核 re-parenting 时机：父进程退出瞬间（非被 reap 时）子女即改挂最近
   subreaper——**zombie 不能有存活子女**，一切"ppid==死进程"判定天然只对
   活父成立。
3. lima 2.3.0 vmType=vz 默认 usernet=192.168.5.0/24（guest DHCP 到 .15、
   网关/宿主=.2）；hostagent 日志里的 192.168.50.x 是宿主自身 LAN 地址
   （UDP 代理源绑定），不是 guest 网段。
4. 首供给 boot 存在固有开窗：lockdown leg 在工具链 leg 之后（设计如此），
   其间的 NTP/DHCP/工具链下载走 NAT 出网——egress-lock unit 只保护
   重 boot，首 boot 开窗与 README"工具链 best-effort"同边界。
5. lima guestagent 的 DNS 重定向在 nft 侧（iptables-save 只捕到空 LIMADNS
   链+跳转）——iptables-restore 与 lima 自身 nft 规则互不覆盖。
6. `creance stop` 对已 Stopped 实例会透传 limactl 的 fatal
   （"expected status Running, got Stopped"）——噪声级，stop 梯队其余部分
   照常执行；产品无 delete 子命令（F-051 setup 内部走 vm::delete）。
7. cargo run 对 harness/tools 仍会刷 tracked Cargo.lock（r6/r7）——收尾
   git checkout；本机沙箱仍须 --offline。
8. escape-test 的 exit code 只由含 " ESCAPE" 的行驱动：guest 探针行缺失
   （传输被致盲）不产生失败——与 up 守门同 fail-open 病根（062）。
9. r6-evidence-probe 复活后 7 处断言是修复前形态（status 泄漏期望 200/
   grant 期望直 Open）——历史探针"能跑"≠"能当裁判"，见 tools/README 分级。
10. /tmp/vmhome-501-* 历史符链约 200 个（各轮 lima_home 派生），悬空居多，
    重启自清；新轮建 profile 前不必清理。

## 下一轮建议（按序）

1. **小修复批（night-15，预计极小）**：062 守门/escape-test 消费点改正向
   证据（须见 tcp-blocked、PROBE 行数核对，缺失=fail-closed）+ 探针脚本顶
   PATH 重置（写明防不了 exec-redirect）；063 一行文档修复。若把 escape-test
   定位为安全控制而非遥测，062 需要结构方案（宿主侧独立证据源）再议。
2. **Ubuntu 实机回填 U1-U5**（r13-regression/SPEC.md）：057/059/060 的
   Linux 侧证据 + 062 的 QEMU 传输形态同验（`ssh … sh -s` 是否同 source
   .bashrc）。
3. **收敛路径**：062/063 修复后，R13.5 遗留攻击面已穷尽（六修复面全复验、
   5 方向证伪），建议下一轮为收敛判词轮（零新发现停轮条件预期达成）；
   F-061 GPG 验签与首 boot 开窗收窄属产品路线图议题，不再立案。

## 会话统计

- R13.5：2 新 findings（1×S4 / 1×S5）；5 方向证伪存档；2 项裁定落地
  （F-061 记档化、E5 执行清单核验）
- 累计：63 findings；056-061 六项修复全部复验闭环（5 代码修复成立+1 裁定
  记档），062/063 待 night-15 小批
- 实机消耗：1 个临时 profile 全生命周期（setup→up→stop→up→escape-test→
  红路径→delete），~13 分钟 VM 时长，零残留
