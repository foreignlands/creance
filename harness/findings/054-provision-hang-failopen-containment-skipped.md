# F-054 — 首启供给截断 fail-open：无超时的 nodejs curl 挂死被杀，拓扑锁定与特权回收（脚本自己的"containment contract"）在 `up` rc=0 下整段未执行——实测 VM 带裸网络+免密 sudo 交付

- **编号**: 054
- **严重度**: S4（供给 fail-open 族，与 F-031 同级定标；端态与 F-020 的 S2 端态相同：guest 裸出网+免密 sudo）
- **攻击面**: night-11 F-051 面延伸实机测试中发现（E1/D 谱系；F-031/F-034 修复面残留）
- **发现时间**: 2026-11-20T07:10:00Z
- **发现者会话**: R10 (night-auditor)
- **状态**: 待修复

## 复现（必须）

网络环境：apt/claude.ai 可达或不可达均可复现挂死路径；本复现机 nodejs.org 长时间无响应（TCP 黑洞）。

```sh
T=$(mktemp -d /tmp/r10-e2e-XXXX)
CREANCE_CONFIG="$T/config.json" target/release/creance init
CREANCE_CONFIG="$T/config.json" target/release/creance setup
CREANCE_CONFIG="$T/config.json" target/release/creance up          # rc=0（实测 9 分钟后"成功"）
export LIMA_HOME="$T/state/lima"; IN=$(limactl list --json | …实例名)
limactl shell "$IN" -- bash -c 'sudo iptables -L OUTPUT -n; sudo -n true; \
  cat /proc/sys/net/ipv6/conf/all/disable_ipv6; ls /usr/local/bin/node'
```

- **期望**: 供给完成后 OUTPUT 链有 4 规则且 policy DROP、免密 sudo 被剥、ipv6 栈关闭（脚本自己的注释称其为 "the containment contract"，lima.rs:171-173）。
- **实际**（guest 内实检）：`Chain OUTPUT (policy ACCEPT)` 零规则；`sudo -n true` 静默成功（免密 sudo 在）；`disable_ipv6=0`；node/claude 缺失。而 `creance up` 退出码 0。guest 探针（escape-test）如实报 ESCAPE（net-direct-egress/net-dns-external/proxy-path/guest-privilege）——检测在，执行层 fail-open。

## 根因猜测

journal（guest 内）证据链：

```
05:48:55 Executing /mnt/lima-cidata/provision.system/00000000
05:49:15 /mnt/lima-cidata/provision.system/00000000: 29: [[: not found
（此后供给再无任何输出——脚本在 line 29 的 nodejs curl 上挂死后被终止）
```

`crates/creance-vm/src/lima.rs:180`：`curl -fsSL https://nodejs.org/…` **无 `--max-time`**，供给期无 tunnel、网络可长期黑洞；`set -e`（:153）+ 脚本被超时机制（lima 供给超时，未验证具体参数）截断 → :191-198（拓扑锁定）与 :205-209（特权回收）**从未执行**。F-031 的修复守住了"安装失败不 *abort*"（|| true），但没守住"安装 *挂死*"——挂死被外部击杀时同样跳过 contract 段；且 contract 段被排在 best-effort 网络步骤**之后**是结构性的次序脆弱。
次生缺陷：`[[ $(uname -m) = aarch64 ]]` 是 bashism 而 shebang `#!/bin/sh`（Ubuntu=dash）——journal 实证 "[[: not found"，arm64/x64 选择退化为恒 x64（URL 错但非致命，复现 dash 最小用例不 abort）。
手工重跑同脚本（network 状态不同、curl 快速失败）全段走完、containment 全部落地——证明脚本体可完成，纯粹是"无界网络步骤在 contract 之前"的次序+超时缺陷。

## 未验证想法

- 截断的执行者：lima 2.3.0 供给超时 vs `creance up` 的 START_BUDGET vs hostagent——未逐层定位；journal 无 kill 记录。
- lima 对失败/截断的 system provision 是否重试（本次实例后续 stop/start 未再验证）；若"once"标记在脚本启动时即写，则截断=**永久** fail-open（更严重）。
- apt 不可达 + nodejs 黑洞的具体网络成因（本机该时段网络状态）不影响结论：代码层面无 --max-time 是事实。
- setup on RUNNING instance 实测：`creance setup` 对运行中实例直接 `limactl delete -f` 成功摧毁（rc=0、无确认、无 "run creance stop" 提示——lima 2.3.0 的 -f 可删运行中实例）；工作负载无提示丢失。S5 观察记录在案，未单开条目。

## 建议修复方向（供第二天的人参考，非结论）

1. 次序翻转：containment 段（sysctl/iptables/sudo 剥离）放在一切网络步骤**之前**——contract 先落地，工具链后装。
2. 所有供给期 curl 加 `--max-time 60 --connect-timeout 10`；apt 加 `timeout 120`。
3. 供给结束自检：`iptables -P OUTPUT DROP` 后 grep 断言四条规则+policy，失败则 `exit 1` 并让 lima 把 provision 标记为失败（同时确认截断/失败的供给在下次 start 会重试或 `creance up` 拒绝）。
4. `[[` 改 POSIX `case`/`[ ]`（或脚本改 `#!/bin/bash`），消除 dash 退化。

## 关联

- F-031（同族 fail-open，其修复注释自称 contract 不可跳过——本条即其未覆盖的挂死形态）、F-034（[[ bashism 所在行的 tmp+mv 重写）、F-020（端态相同的历史 S2）、F-052/F-053（同轮叠加洞）。
