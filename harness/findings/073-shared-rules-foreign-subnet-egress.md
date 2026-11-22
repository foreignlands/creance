# FINDING-073: rules.v4 单源化把两个后端的 NAT 网段放进同一份规则——QEMU/slirp 上 192.168.5.0/24（Lima usernet 网段）不是本地 NAT，而是可路由目的：非特权 guest 用户的 UDP/67 与带载荷 ICMP 实测离开宿主网卡

- **编号**: 073
- **严重度**: S2（对"唯一出口=托管核心"契约的直接违反，F-060 同类同级：guest 不经核心向宿主网络外发任意载荷；目的受限于 192.168.5.0/24 但包确实离开宿主——实验中经宿主默认路由出 ens5）
- **攻击面**: H1（slirp 可达面）+ F-060 修复面（ALLOW 目的限定）+ F-072 修复面（rules.v4 单源）
- **发现时间**: 2026-11-22T06:07:08Z
- **发现者会话**: night-auditor-v6（R19 第五次收敛判词轮）
- **状态**: 待修复

## 复现（必须）

```sh
# 真实 QEMU guest（Ubuntu 24.04 cloud image，netdev 形态与 runner.rs:150-152 相同：
# user,hostfwd=tcp:127.0.0.1:P-:22，无 restrict），逐字套用 provision.rs 的 rules.v4，
# 以非特权用户（uid 1000，无 sudo）发标记包，宿主 tcpdump 抓包：
R19_IMG=<ubuntu-24.04 cloud image> sh harness/tools/r19-slirp-subnet-egress/run.sh
# 注：run.sh 是本轮 lab 手工步骤的脚本化（sh -n 通过）；下方实测数据来自同等手工步骤，run.sh 本身未整体复跑
```

- **期望**: F-060 修复注释（provision.rs 0.3a 段）的契约："Scoped to the NAT subnets — slirp's 10.0.2.0/24, Lima usernet's 192.168.5.0/24, plus DHCP broadcast — so neither can carry traffic to a real destination."——lockdown 后 guest 的 UDP/67 与 ICMP 只能到达虚拟网关，不得离开宿主。
- **实际**（R19 实测，lab guest + 宿主 `tcpdump -ni any`）:
  ```
  guest: T1 tcp 1.1.1.1:443 blocked              （对照：TCP 出网已封）
  guest: UDP 1.1.1.1 67 FAILED [Errno 1] EPERM    （对照：外部 UDP/67 被 OUTPUT 拦）
  guest: UDP 192.168.5.77 67 kernel-accepted
  guest: ping 192.168.5.77 (-p 5231392d4943) 已发出
  host : 05:58:21 ens5 Out IP 172.16.255.2.37199 > 192.168.5.77.67: ... R19-EXFIL-UDP67-192
  host : 05:58:23 ens5 Out IP 172.16.255.2 > 192.168.5.77: ICMP echo request ... R19-ICR19-ICR19-...
  ```
  两条带攻击者载荷的包经 slirp NAT 从宿主物理网卡（ens5，默认路由）离开。对照组 10.0.2.77（slirp 自己的网段）：内核接受但宿主零包——slirp 不应答该地址的 ARP，包从未离开 guest。即：**本后端的网段安全，另一后端的网段是活通道**。

## 根因猜测

- `crates/creance-vm/src/provision.rs`（0.3a，rules.v4 heredoc）：`-A OUTPUT -p udp --dport 67 -d 192.168.5.0/24 -j ACCEPT` 与 `-A OUTPUT -p icmp -d 192.168.5.0/24 -j ACCEPT`。脚本被两个后端共享（Lima provision / QEMU runcmd），而 slirp 的虚拟网段只有 10.0.2.0/24；对 QEMU guest 而言 192.168.5.0/24 是普通的 off-link 目的，走网关 10.0.2.2 → slirp 以宿主 socket 转发（libslirp `sotranslate_out4` 对非特殊地址不改写目的）。
- 对称推论（未实测，macOS/Lima）：Lima usernet 上 10.0.2.0/24 同样是外来网段，那两条 10.0.2.0/24 ALLOW 在 Lima guest 上是同型通道。
- F-072 把规则收敛为单一静态文件，使"每后端一份正确子网"更难表达；F-060 的 U2 实机回填（SPEC.md U2"实测"段）只测了外部 IP（8.8.8.8/93.184.216.34）与 10.0.2.2，没测另一后端的网段。
- 探针网同样失明：escape.rs 的 net-icmp-external 只 ping 1.1.1.1，无 UDP/67 探针。

## 未验证想法

- 宿主处于 192.168.5.0/24 局域网（家用路由器常见网段之一）或经 VPN 路由该网段时，此通道直达真实主机（含路由器本身的 UDP/67 DHCP 服务——横向面）。
- DHCP 广播 255.255.255.255:67 与 slirp `forward_broadcast` 选项的交互未测（QEMU 默认关）。

## 建议修复方向（供第二天的人参考，非结论）

按后端渲染子网（QEMU 只放 10.0.2.2/32 + 广播，Lima 只放 192.168.5.2/32 + 广播），或干脆收窄到网关 /32；ICMP 若无诊断刚需直接删除。补一支 guest 探针向另一后端网段发标记包、宿主侧断言不可见（r19-slirp-subnet-egress 可作行为负控）。
