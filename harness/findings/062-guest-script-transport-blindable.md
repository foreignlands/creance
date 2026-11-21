# FINDING-062: guest_script 传输层 stdout 全权受 guest 控制——up 守门与 escape-test 两个消费点对"无输出"一律 fail-open

- **编号**: 062
- **严重度**: S4（containment 内核侧不受影响；被破坏的是"守门/验收"监控语义，见"定级说明"）
- **攻击面**: R13.5 对 F-059 修复面的复验发现（attack-surfaces.md E 节/D 节相邻；F-059/011 修复面回归）
- **发现时间**: 2026-11-21 21:38 (+08:00)
- **发现者会话**: R13.5（night-auditor-v2，回归轮）
- **状态**: 待修复

## 复现（必须）

全部实机复现于 macOS 14 / Lima 2.3.0 / Ubuntu 24.04 guest（v0.6.4，afe9ec6）。
实例：`/tmp/creance-r135`（已清理）。

**前提事实——通道会 source ~/.bashrc**：guest 用户（dev*, shell=/bin/bash）重写
`~/.bashrc` 后，经 `vm::guest_script` 同形态通道（`limactl shell <inst> sh -s`）
送达的脚本可见其效果：

```sh
# 1) PATH 影子：guest 重写 .bashrc 并前置 PATH
creance shell sh -c 'mkdir -p ~/bin && printf "#!/bin/sh\nexit 1\n" > ~/bin/timeout \
  && printf "export PATH=\$HOME/bin:\$PATH\n" > ~/.bashrc'
# 2) 送与 main.rs:688 一字不差的守门探针
printf 'timeout 5 bash -c "</dev/tcp/1.1.1.1/443" 2>/dev/null && echo tcp-open || echo tcp-blocked\n' \
  | LIMA_HOME=<profile vmhome> limactl shell <inst> sh -s
#   → 输出 tcp-blocked，且假 timeout 内的标记（echo SHADOW_RAN … >> ~/shadow-proof）
#     实际写入（timestamp 1795268058）——守门判词出自假二进制，网络从未被探测。
# 3) 全盲形态：.bashrc 用守卫写法只对非交互会话 exec 1>/dev/null
printf 'case $- in *i*) ;; *) exec 1>/dev/null 2>/dev/null;; esac\n' > ~/.bashrc
printf 'echo tcp-open\n' | limactl shell <inst> sh -s   # → 空输出，RC=0
# 4) 假红形态（guest 杀自己 VM）：.bashrc 里 echo tcp-open → creance up
#   → "guest 防火墙未生效（直连可达），VM 已停止" + VM 真被停止（实机验证）
```

- **期望**: F-059 守门注释声称 "fails `up` loudly instead of shipping an open
  VM"；escape-test 是验收面（README: "escape-test green on every enforced
  layer"）。二者应只把**正向证据**当通过。
- **实际**: 两个消费点都把 guest 无输出当通过：
  - up 守门（main.rs:690-703）：`Ok(_) => {}`——`out` 为空、缺 `tcp-blocked`
    字样、甚至缺整行，全部落 `Ok(_)` 绿灯放行；
  - escape-test（main.rs:369-376）：只对含 " ESCAPE" 的行置 exit 1，guest 探针
    行缺失不产生任何失败，exit code 仍是 host 探针的 0。
  - 三种伪造形态全部或结构成立：① PATH 影子（**实证**，假 timeout 执行）；②
    stdout exec-redirect 全盲（**实证**，echo tcp-open 零输出）；③ 整份 PROBE
    行伪造（结构成立：外层 bash 按被污染 PATH 解析 `sh` 本体——FINDING-011 的
    绝对路径加固护住探针体，护不住传输层与解析器选择）。

## 根因猜测

- `crates/creance-vm/src/vm.rs:341`（guest_script）：传输 = `limactl shell …
  sh -s`（macOS）/ `ssh … sh -s`（Linux），外层是 guest 用户的 login shell
  （`/bin/bash -c "sh -s"`）。Ubuntu bash 对非交互 + SSH_CLIENT 会 source
  `~/.bashrc`（Debian SSH_SOURCE_BASHRC；机制归因未单独验证，但 PATH 前置
  生效已实证），而 `~/.bashrc` 由 guest 用户全权可写，且随 stop→up 的持久盘
  存活——**植入一次，此后每次 up 守门与 escape-test 永久受控**。
- `crates/creance/src/main.rs:698`：`Ok(_) => {}` 把"无证据"当"无逃逸"——
  fail-open 监控。
- `crates/creance/src/main.rs:369-376`：escape-test 按行消费、缺行不计数。

## 定级说明（为什么是 S4 不是 S2/S3）

containment 本体（iptables OUTPUT DROP、sudo 退役）内核侧强制，guest 无 root
不可触碰——本次实机四通道（TCP443/TCP53/ICMP/HTTP）reboot 后全 blocked 未破。
被破坏的是**检测/验收面**：守门的"红"可以被 guest 吞掉（基础设施故障开墙时
静默继续），escape-test 的"绿"可以被 guest 制造（伪造验收）。S2 定义清单
（直连回退/凭据泄漏/SSRF/路径逃逸/授权绕过）不含此形态，S3 是资源类。**但
若团队把 escape-test 当安全控制而非遥测，应自行上调**——这是"被监控方可以
致盲监控"的经典弱点。

## 未验证想法

- `sh` 本体替换（~/bin/sh 吃 stdin 并打印全套 PROBE PASS 行）未单独实机验证，
  但与已实证的 PATH 前置同机制。
- QEMU 后端的 `ssh … sh -s`（vm.rs Linux 分支）同传输形态，理论同病；本机无
  Ubuntu 实机，U 系列回填时可一并验证。
- guest 能否进一步伪造**宿主侧**消费（gate 出口证据走代理实测，不经
  guest_script——README"单目的地边界"已记）不受影响。

## 建议修复方向（供第二天的人参考，非结论）

1. 消费点改**正向证据**：守门必须看到 `tcp-blocked` 字样（且可选：`icmp-*`
   行存在），否则按"无法验证"fail-closed；escape-test 对 PROBE 行计数，
   缺行=失败。
2. 探针脚本顶部硬重置 `PATH=/usr/bin:/bin` 并用绝对路径调 `timeout/bash/ping`
   ——挡住形态①，挡不住②③（要在 finding 里写明）。
3. 结构性出路：守门证据走宿主侧独立通道（gate 的 proxy-path 实测先例），
   guest 内探针降级为 UX 而非安全控制，并写进 README"诚实边界"。
