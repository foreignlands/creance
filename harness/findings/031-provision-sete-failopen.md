# FINDING-031: provision 的 `set -e` 使安装失败=部署 fail-open——apt/curl 任一步失败即中断脚本，拓扑锁定与特权摘除全部不执行（guest = 直连网络 + passwordless sudo 的裸奔态）

- **编号**: 031
- **严重度**: S4（部署失败窗口：触发需首次 boot 时网络/mirror 故障；一旦触发则 0.3/0.4 的全部强制层缺席，且用户只能从 VM 内行为异常发现）
- **攻击面**: R4 在 F-020 回归审查中的"未验证想法"（night-05 核实成立并修复）
- **发现时间**: 2026-11-19T07:30:00Z
- **发现者会话**: night-06（主线修复会话）
- **状态**: 已修复（night-06）

## 复现（逻辑级，无需 VM）

读 `crates/creance-vm/src/lima.rs` 的 provision_script：

```sh
set -e
...
apt-get update -qq                       # ← mirror 故障/断网：非零退出
apt-get install -y -qq curl git ...      # ← 同上
curl -fsSL https://nodejs.org/... || apt-get install -y -qq nodejs npm >/dev/null
                                         # ← 双 fallback 都失败：非零退出 → set -e 终止
# 以下全部不执行：
sysctl ... disable_ipv6
iptables ... -P OUTPUT DROP
sed -i ... /etc/sudoers.d/90-cloud-init-users   # 特权摘除
passwd -l ...
```

- **期望**: 工具链安装可以失败（claude 没装=功能缺失，可接受），**containment 契约（拓扑锁定+特权摘除）必须无条件到达**。
- **实际**: 云镜像首次 boot 恰好发生在网络初始化不稳/mirror 不可达时（真实场景：弱网、mirror 抽风、DNS 未就绪——provision 里 apt 在锁网前，用的是 VM NAT），脚本在 iptables 前死亡，guest 以"有直连+有 sudo"状态完成部署。escape-test 会如实翻红（net-direct-egress/guest-privilege ESCAPE），但用户不跑就不知道。

## 修复

安装步骤全部 `|| true`（apt update/install、node 双 fallback、claude install 原本已容错），脚本注释写明契约顺序：工具链尽力而为，锁定与摘除必达。locale/hostname 步骤原本已容错。

## 附带

- 该缺陷自 0.3 引入（iptables 进 provision 时就带着 set -e）；0.4 的摘除步骤放大了赌注。
- R4 已实测"stop→up 重放后摘除存活"（boot_id 已换）——本修复不改变该结论，只是把"安装失败"从契约杀手降级为功能缺失。
