# FINDING-072: 首启 runcmd 被打断 → cloud-init `status: done` 永久撒谎，guest 永久裸奔且每次 `up` 必拒（fail-closed 变砖）；静态持久层前置 + rules.v4 单源消灭"杀掉=裸奔"路径

- **编号**: 072
- **严重度**: S2（"cloud-init 报 done 但 egress 全开"的不可恢复状态；用户唯一出路是整实例重建，且不知情时日志里全是 `done`）
- **攻击面**: H1（供给窗口/锁定的持久性）
- **发现时间**: 2026-11-22T05:4xZ（U1-U5 Ubuntu 实机回填）
- **发现者会话**: main-session（live guest 检查：semaphore、toolchain log、/etc/iptables、fstab、TCP-OPEN 逐项实证）
- **状态**: 已修复（main-session，实机复验）

## 复现（必须）

```sh
# 在首启 runcmd 执行期内 SIGTERM guest（等价于 F-059 探针误杀/断电）：
# 之后任何一次 `creance up`：
creance up   # → "guest 防火墙未生效（直连可达），VM 已停止"
ssh guest -- 'cloud-init status'   # → status: done
ssh guest -- 'ls /etc/iptables /etc/systemd/system/egress-lock.service'   # → 不存在
```

- **期望**: 供给被中断后，下一次启动应收敛到"受控"或"明确失败可重建"，绝不能"done + 裸奔"。
- **实际**: cloud-init 的 `config_scripts_user` semaphore 写在模块开始时刻；被打断后 scripts-user 永不重跑 → rules.v4、egress-lock.service、fstab 9p 挂载均未落盘 → status `done` 是谎言，guest 输出全开（TCP-OPEN 实锤）。

## 根因

- `provision.rs` 原结构：持久化（rules.v4、egress-lock.service、`iptables-save`）在**尾部**、300s 工具链预算之后——中断在工具链内 ⇒ 持久层从未存在过。
- `iptables-save` 本身另有一坑：Lima 上把 guestagent 的 NAT 重定向（LIMADNS）一并捕获进 rules.v4。

## 修复（已落）

- 脚本重排为 0.3a LOCKDOWN PERSISTENCE（写 `/etc/iptables/rules.v4` 静态规则、`sysctl.d` 禁 IPv6、`egress-lock.service` 并 `systemctl enable`）**先于**网络工具链 leg；
- 尾部仅剩 `/usr/sbin/iptables-restore < /etc/iptables/rules.v4`——同一文件既是被 enable 的 boot replay 也是 runtime apply，applied 集合与 persisted 集合不可能漂移；
- `iptables-save` 及第二份 LOCKUNIT 彻底移除（LIMADNS 捕获路径一并消失）；
- 中断语义：工具链内被杀 → 下次启动由 egress-lock.service 在 network-pre 前 restore → 收敛为"受控但缺工具"，永远不再是"open brick"。

## 未验证想法

- workspace 含 `,`/`=` 击穿 fsdev 选项串（H3 已记档）；被中断后再 setup 的幂等细节留待后续轮次复查。
