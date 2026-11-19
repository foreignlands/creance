# FINDING-025: 处女 profile 的 `creance up` 误报失败——proxy/ 目录不存在时 gate-daemon/隧道 的 pid 与 log 写入 ENOENT（守护进程实际已 spawn，CLI 却走回退路径且回退同样失败）

- **编号**: 025
- **严重度**: S4（首次开箱体验破坏 + 状态分叉：守护活着但无 pid 文件、隧道未建；fail-closed 方向无逃逸面）
- **攻击面**: night-05 实机验证（/tmp/creance-n5 全新 profile，`init→setup→up` 直接复现）
- **发现时间**: 2026-11-19T05:20:00Z
- **发现者会话**: night-05（主线修复会话）
- **状态**: 已修复（night-05）

## 复现（必须）

```sh
P=/tmp/fresh; mkdir -p $P; export CREANCE_CONFIG=$P/config.json
creance init && creance setup && creance up
# warning: gate daemon not raised: No such file or directory (os error 2)
# warning: guest tunnel not established: No such file or directory (os error 2)
# Environment is up. …
pgrep -f gate-daemon   # 守护实际活着（spawn 成功，是后续 gate.pid 写入失败）
ls $P                  # 无 proxy/ 目录——pid/log 的父目录从未被创建
```

- **期望**: up 在没有任何代理操作的全新 profile 上同样成立（QUICKSTART 首条路径）。
- **实际**: `pidfile::write` 与 gate-daemon.log 的 `OpenOptions` 都假设 proxy/ 已存在；此前所有验证路径都先做过 proxy-import（store 创建了目录），掩盖了该缺口。R3 复现（/tmp/p1）恰好有 proxy/ 所以未触发。

## 修复

`pidfile::write` 创建父目录；`spawn_daemon` 在开日志前 `ensure_private_dir(proxy/)`。附带：workbench 端到端测试对默认端口 17896 的"瞬间拒绝"期待被本机运行中的 limactl 转发 socket 破坏（CLOSE_WAIT 挂 5s 超时）——测试改为显式指向无人可占用的端口 1，与宿主环境解耦。

## 附带

- 该缺陷与 F-019 叠加时的形态：守护无 pid 文件 + record 在 → 下一次 up 的活性校验（record+socket）反而正确工作，自愈成立。
