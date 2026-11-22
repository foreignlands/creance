# FINDING-077: restrict=on 声明面漂移——qemu/mod.rs 模块文档称 restrict 无条件生效、ROADMAP:11 仍列为待办、runner.rs 单测注释过时；且完成供给的那次会话全程无第二道防线，用户侧零提示

- **编号**: 077
- **严重度**: S5（文档/参考语义漂移；隔离本身仍由 guest 内防火墙 + 无 sudo 保证，未发现直接旁路）
- **攻击面**: H1 / 1ca32c8 restrict=on
- **发现时间**: 2026-11-22T06:45Z
- **发现者会话**: r20-auditor（R20 第六次收敛判词轮）
- **状态**: 待修复

## 复现（必须）

```sh
sed -n 3,7p crates/creance-vm/src/qemu/mod.rs      # "slirp user networking whose ONLY opening is the hostfwd'd ssh port (`restrict=on`: ...)" ——无条件陈述
sed -n 11p ROADMAP.md                              # "存量：slirp restrict=on 按启停状态、..." ——已交付仍列待办
grep -n 'no restrict until provisioning' crates/creance-vm/src/qemu/runner.rs   # :372 单测注释仍指 ROADMAP 待办
# 实机（~/r20-lab，真实 setup→up，见 STATE-r20 §实机链）：
#   up#1 RC=0，06:22 写出 prof/state/qemu/<inst>/provisioned；同一 qemu pid 21813 的 -netdev 仍为
#   "user,id=net0,hostfwd=tcp:127.0.0.1:46015-:22"（无 restrict），直到 stop；
#   stop → up#2：-netdev user,id=net0,restrict=on,hostfwd=...
#   两次 up 输出同一句 "Environment is up. The guest's only route out is the managed core"（main.rs:776）
R20_IMG=<cloud img> R20_RESTRICT=0 sh harness/tools/r20-slirp-restrict/run.sh   # 量化缺口
R20_IMG=<cloud img> R20_RESTRICT=1 sh harness/tools/r20-slirp-restrict/run.sh
```

- **期望**: 文档如实描述"restrict 自供给完成后的下一次启动起生效"；ROADMAP 更新；供给会话结束时提示需重启才能武装第二道防线（或经 QMP netdev 热替换立即武装）。
- **实际**:
  - mod.rs:4-7 把 restrict=on 写成每个实例的常态；实际首启（及首启后不重启的整段工作会话）没有。只有 runner.rs:145-146 的代码注释承认"applies from the next boot"。
  - lab 量化（同 ruleset、root 冲掉 iptables 模拟"guest 击穿防火墙"）：RESTRICT=0 → `P2 tcp 1.1.1.1:443 OPEN`，宿主 tcpdump 抓到发往 1.1.1.1 / 1.0.0.1 / 192.168.5.77 的包；RESTRICT=1 → P2 全部 blocked，抓包 0 条。即供给会话内，第二道防线承诺的那部分保护不存在。
  - 用户若 setup 后一直不 stop（常见），实例永远不进入 restrict 态，且无任何信号。

## 根因猜测

1ca32c8 只改了 runner.rs/mod.rs 的代码与紧邻注释（mod.rs:284-287 写标记），未同步模块级文档、ROADMAP:11 与 runner.rs 单测注释；restrict 依赖下次启动由 `build_args` 读标记，设计上不覆盖当前会话，但这一点没有进入任何用户可见面。

## 未验证想法

- 用 QMP `netdev_add user,restrict=on,...` + 设备换绑做热武装是否可行、是否影响已建立的 hostfwd ssh 会话，未测。

## 建议修复方向（供第二天的人参考，非结论）

改 mod.rs:4-7 与 ROADMAP:11 为条件描述；供给成功写标记后在 up 输出中提示"重启后启用 restrict=on"，或在 up 内对首次供给完成的实例自动 stop→start 一次；runner.rs:372 注释同步。
