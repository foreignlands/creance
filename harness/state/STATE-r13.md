# STATE — R13 终稿（2026-11-21，night-auditor-v2，基线 b62823c v0.6.3）

## 轮次定位

R12 收敛后三波未审增量（v0.6.0 Linux 移植 / v0.6.1 Ubuntu 审计 / v0.6.2-0.6.3
macOS 硬化）的第一轮对抗审查，范围 `git diff 9ab42fb..b62823c`（48 files,
+3401/-1203）。按 P1（最新代码）→ P2（H 节）→ P3（v0.6.0/0.6.1 复验）推进完毕。

## 发现清单（6 项，056-061；INDEX 已登记）

| # | 严重度 | 一句话 | 证据等级 |
|---|---|---|---|
| 056 | S4 | reap_orphan_cores pgrep ERE 元字符：漏杀自己/跨目录误杀/regcomp 静默吞 | **macOS 全链实机四场景**（真 binary，tools/r13-orphan-probe） |
| 057 | S4 | ppid==1 判定在 systemd user session（child subreaper）恒假，收割网 Linux 主战场失效 | 静态证实 + systemd 行为引证；U3 待实机 |
| 058 | S5 | 去集群化隐藏消费者：r7/r8/r9/c3/f052 五探针判死（403/编译死/夹具旧路径） | **实机**（r7 运行即 panic）+ 双 cargo check 证据 |
| 059 | S2 | guest reboot 后 containment 蒸发：iptables 无恢复机制 + up 无验证绿灯 | 静态证实（cloud-init per-instance + 无 restore 消费者）；U1 待实机 |
| 060 | S2 | ICMP/UDP67 两条 ALLOW 无目的限定 = 后 lockdown 常驻出网通道，探针网不设防 | 静态证实（规则文本+slirp 行为）；U2 待实机 |
| 061 | S4 | 基础镜像 SHA256SUMS 同通道取回、不验 GPG，注释自称 signed-by-construction | 静态证实 + 同仓 fetch-proxy-core 对照 |

S2 两项共用同一主题：**Linux 后端的 containment 是"第一次 boot 的事件"而非
"实例的属性"**——U1/U2 实机回填是 0.6.x 修复前的必跑前置。

## 已攻击未破（证伪记录，不计 findings）

1. **PROXY 组名撞名**（H6/8c3fa14）：GROUP 改成真实订阅最常见组名后，同名节点
   会与托管组撞 mihomo 命名空间——但生成层节点名=store 节点 **ID（哈希）**
   （runtime.rs:45 + store 映射），显示名根本不进 config。真 mihomo -t 复现了
   撞名拒绝形态（dup name），全链 import/select/start 实测绿。设计规避成立。
2. **fetch-proxy-core.sh 四项攻击面**全清：`set -eu` + if 条件豁免=return 1
   路径行为正确（else 分支响亮跳过）；钉版哈希盖全文件 → .gz 尾部附加数据
   两头不可同时骗（提取=哈希字节纯函数）；**BSD gunzip 尾部垃圾 RC=2 实测**
   → override 路径也 fail-closed（GNU 行为待 U4）；tmp→verify→gunzip→new→mv
   + trap 断面无工作核心遮蔽。
3. **daemon_serving 有界轮询**（8c3fa14 flake 修复）：活方向两断言即时
   （gate.rs:1381/1394），死方向 2s 硬 deadline 持续假活必 FAIL——轮询只容忍
   有界瞬态，不洗真回归。
4. **launchd 双 label 回退**：bootout 按路径、legacy label 探测只作用于同 uid
   gui 域；旧 plist 残留在 bootout 后留盘、下次 start 覆盖写——无越权面。
5. **H2/H5**：hostfwd 端口预占→spawn 即死→秒级报错；/proc starttime 空 token
   走 legacy pid-only、升级杀要求 token 匹配 → hidepid 形态恒拒（fail-closed）。

## E5 空探针裁定（只裁定，未实现）

**删除** `proxy-numeric-endpoint`（escape.rs:81-97）。三段理由见
attack-surfaces.md E5 行——核心：名义命题与安全契约无因果，真校验已被
config validate + store applied() 承担，宿主侧同文件循环验证无增量证据。
对照 F-033 不适用（那个有 guest 可感知的真实承诺）。

## v0.6.1 九修复对抗复验（全过，无翻案）

1 stop 梯队进程探针 ✓（zombie 假活边缘=极低可达性记档）/ 2 wait_ssh 早退+TOCTOU
残窗 ✓ / 3 up 失败主动 stop ✓ / 4 四个 limactl 点位 strip-then-set 全数核对 ✓ /
5 doctor qemu_binary ✓ / 6 pgrep 入 require_tools ✓ / 7 workspace 单引号拒绝
先行于下载 ✓ / 8 流式哈希 ✓ / 9 gate-daemon：config_path 走 **argv**，
gate.rs 无 CONFIG_ENV 环境回读——strip_env 与寻址兼容 ✓。

## 下一轮建议（按序）

1. **0.6.x 修复批**（主线）：F-059/F-060 同批修（bootcmd 重放规则 + ALLOW 收窄
   + up 防火墙验证），F-056/F-057 同批修（签名换安全字母表 + ppid 判定去
   平台化）；F-058 探针修复 + tools 最小编译门；F-061 加 GPG 验签；E5 执行删除。
2. Ubuntu 实机跑 harness/tools/r13-regression/SPEC.md U1-U5，回填 057/059/060
   的实机证据栏（059/060 若实机复现即维持 S2，复现不了按事实降级）。
3. 修复后开 R13.5 回归轮：r13-orphan-probe 四场景复跑 + U 系列 + 既有 r11/r12
   探针（注意 F-058：旧探针修好前不可作回归裁判）。

## 关键记忆（非显然事实，≤10）

1. pgrep -f 是 ERE 且全 argv 子串搜索：`+` 量化符使含字面 `+` 的路径必 miss、
   相邻字符串路径必 hit；未闭合 `(` regcomp RC=2——`output()` 只取 stdout 时
   静默成 no-op。tunnel.rs 已示范正确形态（安全字母表 instance 名）。
2. systemd 系统+user manager 均设 PR_SET_CHILD_SUBREAPER：用户会话孤儿
   re-parent 到 user manager pid（≠1）；ppid==1 只是 launchd 平台的特例。
3. cloud-init runcmd 是 per-instance（instance-id 冻结于 instance.json），
   `up` 不重建 seed——供给语义=每 setup 一次，reboot 不重放；iptables 规则
   只存内核 RAM，24.04 无 netfilter-persistent/ifupdown 消费 rules.v4。
4. mihomo config 节点/组共用一个命名空间，撞名 → "proxy group X: the
   duplicate name" 整份拒绝；creance 生成层用节点 ID 命名天然规避。
5. BSD gunzip 尾部垃圾：警告 + RC=2 + 输出干净前缀——`set -e` + `&&` 链下
   连 override 路径也 fail-closed。
6. `expected=$(cmd)` 放 if 条件可豁免 errexit——set -eu 下 case 函数
   return 1 的正确消费形态。
7. cargo run 对 harness/tools 探针会刷四个 tracked Cargo.lock（r6/r7/r8/r9），
   收尾 git checkout；且本机沙箱阻断 crates.io → 必须 `--offline`。
8. escape 探针网实测覆盖：TCP 80/443（net-direct-egress）、53（dns）、IPv6；
   ICMP 与非常规 UDP 端口无覆盖——探针绿灯≠通道关闭。
9. r8-regression 依赖的 `creance::escape::refresh_fingerprint_stamp` 与
   `creance_vm::lima::SetupOptions` pub 面（r9）已在 0.6.x 收缩——tools 的
   path-dep 编译是 API 面回归的免费探测器。
10. v0.6.3 生成的 mihomo config：节点名=store 节点 ID（哈希）、组=PROXY、
    SOCKS 用户=session、socket=/tmp/managed-core-{uid}-{4hex}/control.sock。

## 会话统计

- R13：6 新 findings（2×S2 / 3×S4 / 1×S5）；5 方向证伪存档；1 项裁定落地（E5）
- 累计：61 findings；R1-R12 的 55 项全闭环，056-061 待修复批
- 实验清理：r13-ere 假核心全部验死删除、/tmp 三处临时树已删、无 mihomo 残留、
  tracked Cargo.lock 已还原、仓库仅余 harness/tools/{r13-orphan-probe,r13-regression} 两个新工具目录
