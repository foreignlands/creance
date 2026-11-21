# FINDING-059: guest 重启后 containment 静默蒸发——iptables 规则无恢复机制，up 对开放 VM 照样绿灯

- **编号**: 059
- **严重度**: S2（containment 语义在一次常规恢复动作后静默丢失；guest→宿主回环
  10.0.2.2 与外网直连全部复活）
- **攻击面**: H1
- **发现时间**: 2026-11-21T13:05:00Z
- **发现者会话**: r13
- **状态**: 待修复（静态证实；Linux 实机探针 U1 见 harness/tools/r13-regression/SPEC.md）

## 复现（必须）

静态链（每步可独立核对）：

1. lockdown 是 cloud-init `runcmd`（qemu/provision.rs:47-48）——cloud-init 的
   per-instance 语义：instance-id 不变则后续 boot 不再执行。
2. instance-id 冻结在 instance.json（qemu/mod.rs:57"rotates per setup"），`up`
   只 load_instance + start（mod.rs:140-169），**不重建 seed、不重供给**；
   源码注释"later boots answer in seconds"确认后续 boot 是预期路径。
3. 规则持久化只有一行（provision.rs:115）：
   `iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > /etc/iptables.up.rules`
   ——rules.v4 的消费者是 netfilter-persistent（工具链只装 nodejs/npm/git/xz，
   不装 iptables-persistent；ubuntu 24.04 cloud image 默认无）；up.rules 的
   消费者是 ifupdown（24.04 用 netplan，不装）。**没有任何 boot 期恢复机制。**
4. qemu 进程死亡（OOM/宿主重启/崩溃）→ 用户 `creance up` → guest 从盘启动 →
   OUTPUT policy = 内核默认 **ACCEPT** → guest→internet、guest→10.0.2.2
   （= slirp 宿主回环别名，可摸宿主全部 loopback 服务）全开。
5. 宿主侧无检测：up 只等 ssh + 本地 stamp（main.rs:589 stamp 是宿主写的）；
   escape 探针里唯一能撞见的是 net-direct-egress，但它只在手动 `creance
   escape-test` 时跑，gate-open 流程不强制。

- **期望**: containment 是"实例的属性"而非"第一次 boot 的事件"——任何 boot
  之后 OUTPUT DROP 必须在位，或 up 拒绝启动无防火墙的实例。
- **实际**: 一次 qemu 崩溃恢复后，VM 带着全开 NAT 继续服务，且所有宿主侧
  绿灯照常。

## 根因猜测

provision.rs:100-115 的 lockdown 设计假设"cloud-init 首次供给 = 唯一供给时机"，
把持久化寄存在两个不在 guest 镜像里的机制（netfilter-persistent/ifupdown）上。

## 未验证想法

- sudoers 剥夺行与 passwd -l 是文件/数据库态，重启后存活；唯独防火墙是
  内核 RAM 态——即"丢失 containment"的精确形状是**防火墙单腿**（账号仍无
  sudo，但出网不再受限，root 类逃逸的收益全靠这一条）。
- U1 实机回填时顺带测 `cloud-init status` 在恢复 boot 后是否仍报 green
  （若 green，宿主侧想加验证也只能另起判据）。

## 建议修复方向（供第二天的人参考，非结论）

三层择一或叠加：① lockdown 落 `bootcmd`（cloud-init 每 boot 重放，改五个
iptables 行的挂载位置即可）；② 工具链 leg 加装 iptables-persistent 并
`netfilter-persistent reload`；③ up() 在 wait_ssh 后 guest 侧验
`iptables -S OUTPUT` 含 Policy DROP，缺则 fail loud（最贴近现有 escape 探针
纪律）。slirp `restrict=on`（ROADMAP 已挂）是拓扑级根治。
