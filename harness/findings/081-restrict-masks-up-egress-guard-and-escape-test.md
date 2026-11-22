# FINDING-081: restrict=on 武装后遮蔽第一道防线——guest 内防火墙整段失效时 up 的 F-059 出口守门与 escape-test 网络探针全绿；且 provisioned 标记写在出口校验之前，防火墙校验失败的那次 up 也会把标记补写回去

- **编号**: 081
- **严重度**: S4（正确性：隔离本身仍由 slirp restrict=on 守住——直连 1.1.1.1:443 实测仍被拦；但"两道防线"在用户与守门侧都退化为不可观测的一道，第一道失效永远不再报警）
- **攻击面**: H1 / 1ca32c8 restrict=on + 23b0da2（F-077 修复面）× F-059 up 守门
- **发现时间**: 2026-11-22T08:20Z
- **发现者会话**: r21-auditor（R21 第七次收敛判词轮）
- **状态**: 待修复

## 复现（必须）

```sh
# 实机：Ubuntu 24.04 cloud image，QEMU+KVM，真实 setup → up#1（RC=0，写 provisioned）
LAB=~/r21-lab sh harness/tools/r21-restrict-mask/run.sh     # 证据 harness/tools/r21-restrict-mask/evidence/
# 步骤：stop → qemu-nbd 离线把 guest /etc/iptables/rules.v4 改成 OUTPUT ACCEPT 全放行（模拟第一道防线失效：
#       规则漂移 / 被篡改 / 供给中途被打断）→ up#2（标记在 → restrict=on）→ guest 内取证 + escape-test
#       → stop → 移走标记 → up#3（对照：无 restrict）→ 还原 rules.v4 与标记
```

实测（v0.6.12 / daece7f）：

```
up#2 (marker present, firewall dead) RC=0  netdev: -netdev user,id=net0,restrict=on,hostfwd=…
    Environment is up. The guest's only route out is the managed core (`creance escape-test` proves it).
up#2 in-guest:  /etc/iptables/rules.v4 = *filter :INPUT ACCEPT :FORWARD ACCEPT :OUTPUT ACCEPT COMMIT
                egress-lock.service active（加载的就是全放行表）；tcp 1.1.1.1:443 blocked（slirp 拦）
escape-test:    net-direct-egress / net-dns-external / net-ipv6 / net-icmp-external 全 PASS
                （proxy-path ESCAPE 是 lab 无代理节点，与 R20 相同，与本项无关）
up#3 CONTROL (marker absent, same dead firewall) RC=1
    供给完成——下次 creance stop && creance up 起 slirp restrict=on 第二道防线生效
    guest 防火墙未生效（直连可达），VM 已停止；请 creance stop 后 creance setup 重建环境。探针原始输出："tcp-open\nicmp-open\n"
```

- **期望**:
  1. F-059 守门（main.rs:745-770）判的是"guest 防火墙是否生效"，其报错文案也这么写；第一道防线失效时应当报警（或至少区分"防火墙在位"与"仅靠 slirp 拦住"）。
  2. escape-test 作为"proves it"的证据，应当能看出第一道防线缺失。
  3. provisioned 标记只在整条供给（含出口锁定）验证通过后写，且"供给完成"不应与"防火墙未生效"出现在同一次 up 输出里。
- **实际**:
  1. 标记在位后，up 的探针（`bash -c '</dev/tcp/1.1.1.1/443'` + `ping 1.1.1.1`）测到的是 slirp restrict，不是 guest 防火墙；防火墙全放行时 up#2 照样 RC=0 并打印 "The guest's only route out is the managed core"。
  2. escape-test 四个 net-* 探针同样只测外部可达性，restrict 下恒 PASS；escape.rs 没有任何读取 guest 规则表的探针。
  3. qemu/mod.rs:286-297 在 vm::up 内、挂载校验通过即写标记并打印"供给完成"；main.rs 的出口守门在其后才跑。对照组 up#3 在标记缺失时先打印"供给完成"、紧接着报"guest 防火墙未生效……VM 已停止"——同一次 up 两句矛盾，而且此时标记已经补写；用户再执行一次 `creance up`（不按提示 setup 重建）就会进入 up#2 的形态：全绿、第一道防线缺失、无任何信号。

## 根因猜测

- crates/creance-vm/src/qemu/mod.rs:286-297：标记的写入条件只有 mount-ok（F-075 的挂载校验），而它触发的是网络层面的加固；出口锁定的正向证据在上层 main.rs:745-770，晚于写标记。
- crates/creance/src/main.rs:745-770 与 escape.rs 的 net-* 探针都是"从 guest 往外打"的行为探针，restrict=on 之后它们无法区分第一道与第二道防线；1ca32c8 引入 restrict 时没有同步调整守门语义。

## 未验证想法

- 未测"供给中途在防火墙持久层写入之前被打断（F-072 窗口）→ 挂载腿已完成 → 标记写入"的自然路径；本项用离线改 rules.v4 代替，触发的是同一段判定逻辑。
- restrict=on 自身是否有可被 guest 利用的缺口（guestfwd、slirp 内建服务）R20 已测过主要面，本轮未重测。

## 建议修复方向（供第二天的人参考，非结论）

把标记写入挪到 main.rs 出口守门通过之后（vm::up 只返回"可标记"，由上层在守门通过后落盘），"供给完成"提示随之后移；守门与 escape-test 各补一条直接观测第一道防线本身的检查（例如核对 guest 已加载的 OUTPUT 策略/规则摘要与宿主渲染值一致），使 restrict=on 下第一道防线失效仍可报警。
