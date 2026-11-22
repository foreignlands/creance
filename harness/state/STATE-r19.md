# STATE — R19 终稿（2026-11-22，night-auditor-v6，基线 a601c6a v0.6.10）

## 轮次定位

第五次收敛判词轮：增量复核 068–072 修复（a601c6a）+ v0.6.9..v0.6.10 全量 diff
邻接面续扫 + QUICKSTART/ROADMAP/install.sh 声明面。基线
`sh scripts/ci.sh > /tmp/r19-ci-baseline.log 2>&1; RC=$?` **真实 RC=0**
（Linux/x86_64；fmt/clippy/probe-inventory/test/release 全过，14 个 test-result
块，零 FAILED/panicked；macOS cfg 代码未编译——不宣称 macOS 绿）。
本轮首次动用实机：本 VM 有 /dev/kvm，装 qemu 后起 3 个一次性 Ubuntu 24.04
lab guest（非 creance 全链，形态逐字取自 provision.rs / runner.rs）。

## 068–072 修复复核

| 核验点 | 结论 | 证据 |
|---|---|---|
| F-068 放置→运行→删除顺序 | **成立（可放置路径）** | r19-flag-skip A：真实 release 二进制 + 伪 ssh（宿主执行探针=最大逃逸）→ `PROBE fs-flag-readable ESCAPE`，跑后旗标已删；oracle 位于 `<environment_dir>.escape-flag`（挂载外兄弟路径），QEMU 9p 挂载点 = 宿主同路径（qemu/provision.rs mount_script）——guest 侧探针从此有牙 |
| F-068 SKIP 分支 | **不成立 → F-074** | B：不可落盘时先回显 guest 的空真 PASS、再追加 SKIP（双判词） |
| F-068 行为负控（删放置→某层必红） | **无层变红 → F-074** | main.rs:364 write 换 `true`（grep 确认落地）→ `cargo test -p creance` RC=0；cp 还原 + md5 OK |
| F-069 ESCAPE-BRIEF | 成立 | 新文 "由 creance escape-test 自行放置在 `<environment_dir>.escape-flag`（宿主侧、挂载之外），跑完即删" 与 main.rs:358-426 一致 |
| F-070 计数/H 标题/尾注 | 成立 | README:65、harness/README:18 = 45（`grep -c '^| [A-H][0-9]'`=45）；H 标题改为 "R13 静态已全覆盖"；重复尾注已去；INDEX 068-072 登记齐 |
| F-071 终态表 | 成立（读表无早放路径） | done/degraded→Ok、error/disabled→Err、其余（含 ssh 失败空输出、`|| echo 'status: pending'`）继续轮询；exit 2（degraded）时输出兼含 done+pending→Ok 合理；lab：cloud-init 26.2 runcmd 失败 → `status: error`（Err 分支真会触发），中断 → `running` 后 `done`。残余：①单次 guest_script 无时限（vm.rs:373 wait_with_output、无 ServerAlive），600s "预算"仅在两次调用之间检查（F-062 同类传输面，后续启动 guest rc 可挂起/伪造 "status: error"——自伤 DoS，不立案）；②预算耗尽分支 runner::stop 自产中断态 → 并入 F-075 |
| F-072 (a) 0.3a→0.3b 窗口 | 成立 | restore 的唯一输入 /etc/iptables/rules.v4 root 属主；窗口内跑的只有 root 工具链腿（供应链信任与 v0.6.9 同），guest 用户首启无进程；Lima 每启 `cat >` 重写 |
| F-072 (b) rules.v4 内容 | **不成立 → F-073（S2）** | lab：192.168.5.0/24 ALLOW 在 slirp 上是可路由目的，UDP/67 + 带载荷 ICMP 从宿主 ens5 离开；10.0.2.0/24 本后端对照安全；1.1.1.1 TCP/UDP67 对照被拦；IPv6 全接口 disable_ipv6=1、无 inet6 |
| F-072 (c) Before=network-pre.target | 成立（netplan/networkd 实测） | lab2 重启 journal：egress-lock Finished @2.32s → network-pre @3.91s → systemd-networkd @3.92s → DHCPv4 @3.99s；agent TCP 1.1.1.1:443 blocked；本机 unit 文件：networkd After=network-pre.target，cloud-init-local Before=network-pre（与 egress-lock 并行，无用户进程） |
| F-072 (d) Lima replay | 成立（静态） | restore 整表替换，幂等；不碰 nat 表（LIMADNS 不再被捕获；filter DROP 仍拦 DNAT 后到网关的 DNS） |
| F-072 中断收敛声明 | **不完整 → F-075（S4）** | lab3：杀于 runcmd[0] → 二启 runcmd 零执行，9p 挂载腿/fstab 永缺，result.json errors=[]；up 无挂载校验 |
| 门禁矩阵 | **全绿（fail-closed）** | POS RC=0（guest 12 / host 6）；NC-A 1 行 RC=1；NC-B 1 行；NC1 1 行；NC2 1 行；NC3 2 行（ROADMAP+README 两方向，同 R18）；NC5 11 行；NC6（R18 体例删 3 行）1 行；NC6 变体（改发射文本）3 行。全部 cp 备份、注入前 grep -c 确认、md5sum -c 四文件 OK |
| 裁判双跑 | 双绿 | r14-convergence RC=0（[A]-[G]）；r15-064-recheck RC=0（NC1/NC2/PF1/PF2/EQ1/EQ2）；联网 cargo run（相对路径后不再需要仓库外符链）；两 Cargo.lock 漂移 `git checkout --` 还原 |

## 发现清单（3 项，073-075；INDEX 已登记）

| # | 严重度 | 一句话 |
|---|---|---|
| 073 | **S2** | rules.v4 单源含两后端网段：QEMU 上 192.168.5.0/24 是活外发通道（UDP/67 + ICMP 载荷实测离开宿主网卡）；Lima 上 10.0.2.0/24 对称推论 |
| 074 | S5 | F-068 修复残留：不可落盘时 PASS+SKIP 双判词；删放置代码 CI 全绿；被打断遗留 oracle |
| 075 | S4 | 中断首启后 9p 挂载腿永不执行，cloud-init done/errors=[]，up 全绿但 workspace 不共享 |

## 收敛判词（R19）

**"零新发现"判据未满足 → 收敛判词不发。** 068–072 的主修复面多数成立（F-069/F-070/F-071 终态表、
F-072 a/c/d、门禁矩阵、裁判双跑），但：073 是 S2（契约直接违反，由 F-060+F-072 修复面组合产生），
074/075 是两个修复面的不完整处。连续第五轮"修复面基本成立仍因新立案不发判词"。
值得记下：本轮 3 项里 2 项来自首次实机 lab——纯静态对照已近饱和，实机才是产出面。

## 已攻击未破（不计 findings）

1. wait_cloud_init 子串匹配：`extended_status: degraded done` 不含 "status: done"；`status: disabled` 早期不可能出现（ds-identify 在 sshd 前）；无 cloud-init 镜像 → 600s 后 Err（fail-closed）。
2. guest rc 伪造 "status: done"：只在后续启动有效，此时 egress-lock 已先于网络 restore，F-059 探针仍裁决——无早放。
3. slirp 本网段：10.0.2.77 UDP/ICMP 零出包（无 ARP 应答）；10.0.2.3:67 被 libslirp sotranslate_out4 拒（非 53）。
4. IPv6：lab 全接口 disable_ipv6=1；systemd-networkd 遵守 all.disable_ipv6（socket_ipv6_is_enabled）。
5. 工具脚本参数化（CREANCE_REPO/CREANCE_BIN）：仅运维者环境变量，变量均加引号，无 guest 可控输入——无注入面。
6. QUICKSTART/ROADMAP/install.sh：安装三步、~/.local/bin、核心布局（../proxy-core）、平台表、24.04 镜像（image.rs server-cloudimg）、探针枚举与门禁块一致；ROADMAP v0.6.x 定位无版本号宣称。CHANGELOG 无 0.6.10 条目（0.6.2–0.6.5 亦缺，先例在前）——记档不立案。
7. 记档（不在 v0.6.10 diff、留下轮）：escape-test 在实例存在但 VM 未运行时，guest 段走 Err 分支只打 stderr，退出码只由宿主探针决定（可 0）；Lima 每启重跑工具链腿时 egress 已 DROP，可能每启空耗至多 300s（macOS 未测）。

## 实验清理

/tmp/r19-ci-baseline.log（交付后删除）、r19-ci-rc、r19-nc.sh/.out/-case.out、r19-nc6b.out、r19-md5-snapshot.txt、
r19-bak/、r19-judge{1,2}.{out,err,rc}、r19-f068nc.log、r19-flagskip.out、libslirp 源码片段两份——全部删除。
~/r19-lab（cloud image、3 个 overlay、seed、pcap、ssh key）整目录删除；3 个 qemu 进程全部终止；
nbd0 已 disconnect、/mnt/r19 已删。r19-flag-skip 运行期临时目录由 trap 自删；其 target/ 被 .gitignore 排除。
apt 装了 qemu-system-x86/qemu-utils/genisoimage/tcpdump（本 VM 环境，仓库外，保留）。
负控全部 cp 还原 + md5 核对；零 `git checkout --` 还原产品文件（仅还原裁判 Cargo.lock）。
仓库本轮产物：findings/073-075 + INDEX 三行 + attack-surfaces 尾注 + tools/r19-flag-skip/ +
tools/r19-slirp-subnet-egress/ + 本文件。

## 关键记忆（≤10）

1. 本 Linux VM 有 /dev/kvm，`sudo -n apt install qemu-system-x86 qemu-utils genisoimage tcpdump` 可用——实机 lab 便宜（minimal cloud image 250MB、启动 ~25s）。
2. minimal cloud image 不带 iptables（产品用 server-cloudimg，带）；lab 需 runcmd 里 apt 装。
3. 杀 qemu 别用 `pkill -f <含命令行片段>`——会把执行该命令的 shell 一起杀掉；用 pidfile 或 `pgrep -f 'ov[2]…'`。
4. slirp 只对本网段地址做特殊处理；其它 RFC1918 目的照常从宿主 socket 发出——"子网限定"必须按后端算。
5. cloud-init 中断：semaphore 先写，二启 runcmd 零执行，result.json errors=[] → done。
6. 069/070 文档面与代码一致；NC3 仍是 2 行（非回归）。
7. 裁判工具相对路径后无需仓库外符链；联网 cargo run 双绿。
8. "PASS 行到达≠探针成立"之后的下一层："修复后探针成立≠所有分支只有一个判词"。

## 下一轮建议（按序）

1. **night-21 修复批**：073（按后端渲染子网或收窄到网关 /32，删 ICMP；补跨网段外发探针）→ 075（挂载腿前移/mount 单元 + up 正向挂载证据）→ 074（单判词 + 放置函数可测 + RAII 删除）。
2. **R20 = 第六次收敛判词轮**：用 r19-slirp-subnet-egress 做 073 行为负控（修复后宿主零包）、r19-flag-skip B 预测翻为单 SKIP；在完整 creance setup→up 链上实机复演 075（本轮为等价形态 lab）。
3. 记档第 7 条两项择一深挖；macOS/Lima 侧 073 对称面待实机。

## 会话统计

- R19：3 新 finding（1×S2、1×S4、1×S5，均待修复）；068–072 复核 13 点（10 成立、3 转立案）；门禁 9 场景全 fail-closed；裁判双绿；新工具 2；lab guest 3 个（零 creance VM 时长）
- 累计：75 findings
