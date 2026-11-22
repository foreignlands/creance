# FINDING-075: F-072 的"中断收敛"只收敛了防火墙——QEMU 首启 runcmd 被打断后 9p 工作区挂载腿（第二条 runcmd）永不执行，cloud-init 报 done 且 errors=[]，`up` 无挂载校验而全绿：用户拿到一个看似正常、实则不共享 workspace 的 VM

- **编号**: 075
- **严重度**: S4（正确性：不破坏隔离——防火墙经 egress-lock.service 已收敛；但 guest 内的工作成果落在 guest 本地盘、宿主 workspace 看不到，stop→setup 重建即丢失；无任何诊断信号）
- **攻击面**: H1（供给窗口持久性）/ F-072 修复面（中断语义）
- **发现时间**: 2026-11-22T06:07:08Z
- **发现者会话**: night-auditor-v6（R19 第五次收敛判词轮）
- **状态**: 已修复（main-session，实机复验）

## 复现（必须）

```sh
# R19 实测（lab，真实 cloud-init 26.2 / Ubuntu 24.04，形态同 qemu/provision.rs:46-55 的两条 runcmd）：
# runcmd[0] = 长任务（代表 bootstrap 的 300s 工具链腿），runcmd[1] = 9p mount + fstab。
# 首启在 runcmd[0] 执行中 SIGKILL qemu（等价 wait_cloud_init 预算耗尽后 runner::stop、断电、F-059 误杀）；再启动后离线检查盘：
#   首启被杀时：  cloud-init status → running；sem/config_scripts_user 已写
#   二启 serial： "modules:final ... Up 7.00s" → "finished ... Up 7.08s"（runcmd 零执行）
#   离线盘：      /var/log/r19-leg1 = "leg1-start"（无 end）；leg2 标记不存在；fstab 无 9p 行；
#                 /var/lib/cloud/data/result.json errors=[] → status: done
grep -rn 'mountpoint\|/proc/mounts' crates --include=*.rs   # 零命中：up/shell/escape-test 均不校验 guest 内挂载
```

- **期望**: F-072 修复声明"中断语义：工具链内被杀 → 下次启动 … 收敛为'受控但缺工具'"——若还缺别的（工作区挂载），`up` 应如实失败或告警。
- **实际**: 中断后 `wait_cloud_init` 读到 `status: done` → 放行；F-059 探针因 egress-lock.service 已 restore 而通过；`up` 打印 "Environment is up"。缺的不止工具：qemu/provision.rs 的 mount_script（mkdir/mount -t 9p/chown/fstab）是独立的第二条 runcmd，与第一条同属一次 scripts_user 运行、共用同一 semaphore，永不重跑；fstab 行也从未写入，任何后续启动都不会挂载。宿主侧 mounts-workspace-only 只读 instance.json 记录（qemu/mod.rs:366-370 declared_mounts），看不见 guest 实况。

## 根因猜测

- `crates/creance-vm/src/qemu/provision.rs:46-55`：挂载腿放在 runcmd[1]，排在 300s 工具链腿之后——F-072 把防火墙持久层前移，挂载腿留在原位。
- `crates/creance-vm/src/qemu/mod.rs` `up()` / `wait_cloud_init`：只认 cloud-init 终态，`status: done` 不代表 runcmd 跑完（F-072 已证 semaphore 先写）。
- 600s 预算耗尽分支本身调用 `runner::stop`（qemu/mod.rs:190-195）——慢网/慢盘下自产这一中断态。

## 未验证想法

- 未在完整 creance setup→up 链上复演（lab 用最小镜像 + 等价 runcmd 形态）；`creance shell` 落地目录是否会因挂载点不存在而报错未测（mount_script 的 mkdir 同样未执行）。

## 建议修复方向（供第二天的人参考，非结论）

挂载腿前移到工具链之前（或写成 boot 期 systemd mount 单元，与 egress-lock.service 同为实例属性）；`up` 在 F-059 探针旁加 guest 内 `mountpoint -q <workspace>` 正向证据，缺失即拒绝交付。
