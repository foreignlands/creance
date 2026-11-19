# FINDING-026: 孤儿 ssh -R 不受 pid 文件管辖时无人能切——`closed = wire down` 契约依赖单个文件的存活（F-025 场景实测遗留：pid 写入失败的隧道进程永远活着）

- **编号**: 026
- **严重度**: S4（wire 无法关闭的残余路径；触发需 pid 文件丢失/写入失败——F-025 修复后写入路径已健在，删除文件或历史遗留实例仍可触发）
- **攻击面**: night-05 实机验证（/tmp/creance-n5 第一次 up 的 ENOENT 隧道孤儿实测：ssh 96351 以正确身份运行、无 pid 文件，新 daemon 的 Closed→stop 对其永远 no-op）
- **发现时间**: 2026-11-19T05:35:00Z
- **发现者会话**: night-05（主线修复会话）
- **状态**: 已修复（night-05，实机复验）

## 复现（必须）

```sh
# F-025 场景的现场：第一次 up 的 fallback ensure spawn 了 ssh 但 pid 写失败
ps -eww -o pid,command | grep '[s]sh.*HostKeyAlias=lima-<inst>'   # 孤儿在跑
ls <profile>/proxy/tunnel.pid                                    # 不存在
# 新 daemon（gate Closed）watchdog 每 500ms 调 tunnel::stop →
#   pidfile::stop：load 失败 → 什么都不做 → 孤儿永生
```

- **期望**: Closed gate ⇒ guest 无线。切断不该以"pid 文件恰好存活"为前提。
- **实际**: stop 的全部切断力都来自 pid 文件；文件缺失 = 无人能关 wire。

## 修复

`tunnel::reap_orphans(profile, instance, port)`：pgrep 特征匹配 `HostKeyAlias=lima-<instance>.*-R <port>:127.0.0.1:<port>`，杀掉 pid 文件未拥有的进程，pid 文件拥有的豁免（与 F-021 的所有权判定不冲突）。接线四处：watchdog 的 Closed 分支、spawn_daemon 的 stale 清扫、close_and_remove、run_daemon 退场。

**特征必须同时含 HostKeyAlias 与 `-R <port>:127.0.0.1:<port>` 两段**——第一版只匹配 HostKeyAlias，实机立即暴露误杀：`limactl shell` 的每次 ssh 客户端命令行同样携带 `HostKeyAlias=lima-<instance>`（lima 约定），watchdog 每 500ms 的清扫把执行中的 shell 会话掐死（短命令幸存、>500ms 的命令 rc=255）。反向转发段 `-R <port>:127.0.0.1:<port>` 只有我们的隧道有（vz 下 lima 自身不设 -R）。回归测试三进程：孤儿死、owned 活、shell 形态客户端（仅 alias 无 -R）永不被收割。

## 边界（如实记录）

- 特征匹配杀的是"命令行携带该实例 HostKeyAlias 的进程"——同 uid 攻击者可主动构造该字符串令我们误杀自己的进程，但那属于"同 uid 已可 kill 任意进程"的既有面（与 F-021 的增量危害论证相同）。
