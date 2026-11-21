# FINDING-057: 孤儿判定 ppid==1 在 systemd user session（child subreaper）下恒假——收割网在 Linux 主战场静默失效

- **编号**: 057
- **严重度**: S4（audit #2 修复在 Linux 的主场景不生效；start 楔死回归）
- **攻击面**: H6
- **发现时间**: 2026-11-21T12:15:00Z
- **发现者会话**: r13
- **状态**: 待修复（静态证实；Linux 实机探针 U3 见 harness/tools/r13-regression/SPEC.md）

## 复现（必须）

静态链（每步可独立核对）：

1. `crates/creance-proxy/src/service.rs:230`：孤儿判定 `if ppid == 1`。
2. Linux 上 relay 由 CLI `spawn`（`launch_supervised`，service.rs:431-461，
   `process_group(0)` + `mem::forget`，不 daemonize）；relay 死（SIGKILL/OOM，
   正是 audit #2 修的形态）后核心 re-parent 到**最近的 child-subreaper 祖先**。
3. systemd（系统与 user manager 同）在 `manager_setup()` 里
   `prctl(PR_SET_CHILD_SUBREAPER, 1)`（src/core/manager.c）——Ubuntu 桌面/开发机
   的用户会话进程的孤儿全部收养给 `systemd --user`（典型 pid 为三位数，≠1）。
4. 故 Linux 常规形态下核心孤儿的 ppid == systemd-user-pid ≠ 1 → 不进 orphans
   → 收割网 no-op → stop 返回 Ok 而核心仍占端口。

macOS 不受影响（launchd 即 pid 1）。对照：同一次 stop 里 `stop_local` 只等
5s socket 活性（relay 死时 socket 恒活，预算耗尽后升级杀又只认 entry.pid=已死
relay 的 token），随后 `remove_file(socket)` 把 socket 文件删了——连"控制 socket
不说谎"的判据也被删掉，此后无任何自愈路径，只剩这个失效的收割网。

- **期望**: relay 死后核心在 stop 时被收走，下次 start 正常。
- **实际**: （Linux 推演；待 U3 实机回填）核心存活占端口，下次 start 报
  "creance 代理端口已被占用，请更换独立端口"。

## 根因猜测

service.rs:202-207 的注释把"orphan = ppid 1"当成平台不变量——这是 launchd
（macOS pid 1）的特例，不是 POSIX 的一般规则（`prctl(PR_SET_CHILD_SUBREAPER)`）。

## 未验证想法

- 若发行版把 user manager 关掉（ssh-only 无 lingering 会话），孤儿落 init ——
  ppid==1 恰好成立；即本洞的暴露面随 session 形态摆动，探针 U3 应同时测
  desktop-session 与 ssh-session 两形态。

## 建议修复方向（供第二天的人参考，非结论）

判定从"ppid==1"改为"ppid 不是活 relay 也不是本 creance 进程"或直接比对
`/proc/<pid>/stat` 的 ppid ∉ {relay 树}；更稳的是以控制 socket 存活+无 token
绑定作为收割判据（该函数本来就是兜底，socket 判据比进程谱系抗摆动）。
