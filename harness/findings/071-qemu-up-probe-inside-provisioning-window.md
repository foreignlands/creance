# FINDING-071: QEMU 后端 `up` 只等 sshd 不等 cloud-init——F-059 行为探针在供给窗口内开火，健康首启必杀；`status` 提前态被误读为"无 cloud-init"是第一版修复的二次踩坑

- **编号**: 071
- **严重度**: S2（功能性隔离失效：Linux 上每次干净 `setup`+`up` 都失败——健康 VM 被自己人误杀；杀法还是 fail-closed 的方向，但产品完全不可用等于"隔离承诺"零交付）
- **攻击面**: H1（slirp/供给窗口）+ H2（wait_ssh 早退）
- **发现时间**: 2026-11-22T05:39Z（U1-U5 Ubuntu 实机回填时）
- **发现者会话**: main-session（U1-U5 实机回填，serial.log + 手工 qemu 复现）
- **状态**: 已修复（main-session，实机复验）

## 复现（必须）

```sh
# Linux 上全新实例：
creance setup && creance up
```

- **期望**: `up` 等首启供给（runcmd：工具链 ≤300s + egress 锁定）结束后才做 F-059 行为探针；供给完成 → 探针绿 → VM 存活。
- **实际**: `up` 在 sshd 应答后约 1s 即跑 tcp/icmp 直连探针 → "guest 防火墙未生效（直连可达），VM 已停止" —— 探针打进的是供给窗口（runcmd 甚至还没开始：serial.log 显示 modules:final 于 15.46s 启动、16.29s 收到 SIGTERM）。
- **二次踩坑**: 第一版修复加了 `wait_cloud_init`，但把 `cloud-init status` 的非零退出回显读成 'status: absent' 并视为终态放行——sshd 应答时 status.json 尚未建立、命令返回非零 → 探针照旧在 modules-final 启动 1 秒内开火。实测 serial.log 逐行可证。

## 根因

- `crates/creance-vm/src/qemu/mod.rs` `up()`：`wait_ssh` 成功即返回 0，`main.rs:733` 的 F-059 探针立刻执行；Lima 的 `limactl start` 原生等 cloud-init 完成，QEMU 后端没有对等物 → 平台行为不对称，Linux 独占的坑。
- `wait_cloud_init` 初版把 "命令尚未可执行"（status.json 未建立 → rc≠0 → 回显 absent）当成 "guest 无 cloud-init" 的终态。

## 修复（已落）

- `up()` 在 `wait_ssh` 之后调用 `wait_cloud_init`（600s 预算，pidfile 活守卫）：`status: done|degraded` → Ok 交探针裁决；`status: error|disabled` → Err；其余一律继续轮询。
- `provision.rs` 同时把持久层提前（见 F-072）：即便将来再有提前探针类缺陷，规则已在盘上。

## 未验证想法

- `cloud-init status --wait` 可作单命令替代轮询，但 ssh 无内生 deadline，放弃。
