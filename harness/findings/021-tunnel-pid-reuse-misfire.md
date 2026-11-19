# FINDING-021: tunnel stop() 按 pid 文件盲杀 — pid 复用窗口内 `creance stop` 杀死同 uid 任意无关进程（实测 victim sleep 进程被 SIGTERM）；running.rs 对同类问题有 start-time 校验而 tunnel.rs 没有——0.3 新代码重现旧缺陷模式

- **编号**: 021
- **严重度**: S4（误杀同 uid 任意进程；ensure 的 alive 误判使隧道不重建=guest 断网 fail-closed；非安全绕过但破坏进程完整性）
- **攻击面**: R3 → 0.3 tunnel.rs（4ab3c19）+ C6 同族
- **发现时间**: 2026-11-19T06:55:00Z
- **发现者会话**: r3-s01
- **状态**: 待修复

## 复现（必须）

```sh
# 伪造 tunnel.pid 指向任意同 uid 进程（模拟 pid 复用后的文件内容）
sleep 3000 & VICTIM=$!
mkdir -p /tmp/p1/proxy && echo $VICTIM > /tmp/p1/proxy/tunnel.pid
ps -p $VICTIM > /dev/null && echo alive

export CREANCE_CONFIG=/tmp/p1/config.json
creance stop            # tunnel::stop 读 pid → kill(0) 判活 → SIGTERM
sleep 1.5
ps -p $VICTIM > /dev/null 2>&1 || echo "VICTIM KILLED"
# 实测：victim sleep 进程被 SIGTERM 杀死；pid 文件被 stop 删除
```

- **期望**: 0.1 的 running.rs（cage-running.json）对同一问题（"A PID alone is not proof of life"）实现了 kinfo_proc 启动时间校验（macOS sysctl KERN_PROC_PID 的 p_starttime union 重叠，R1 C6 已验证布局正确）。tunnel.rs 的 stop()/ensure()/alive() 处理同样的 pid 文件却**只有 kill(pid, 0)**。
- **实际**: pid 复用窗口内（宿主重启后、长时运行），`creance stop` SIGTERM 杀死复用该 pid 的任意同 uid 进程（编辑器/终端/用户服务）；`ensure()` 的 alive 误判则跳过重建 → 隧道缺失 → guest 全断（fail-closed 方向，无危害但可用性损）。

## 根因猜测

`crates/creance-vm/src/tunnel.rs:87-98`（stop）、`110-115`（alive）。`#![allow(unsafe_code)]` 注释自述 "pid from our own pid file"——但 pid 文件不是防篡改对象（同 uid 可写），复用才是主威胁。gate.rs 的 gate.pid 同样模式（gate-daemon 的 alive 检查无 start-time；spawn_daemon:685-690）——同修。

## 未验证想法

- gate.pid 复用 → spawn_daemon 误判 alive → gate 永不启动（fail-closed）——与 F-019 叠加（record 残留先短路，pid 检查通常到不了）。
- SIGTERM 对复用进程的伤害面（多数进程默认终止；对 sshd 等关键服务是 DoS 向量——同 uid 才能写 pid 文件，攻击者同 uid 本可 kill 任意进程，**增量危害=非恶意触发路径**）。

## 建议修复方向（供第二天的人参考，非结论）

把 running.rs 的 `process_start_token(pid)` 提升为 creance-vm 公共助手，tunnel.rs/gate.rs 的 alive() 一律加 start-time 比对：写入 pid 文件时同时记录 `{pid, started}`（JSON 两字段），校验时两者匹配才算活。
