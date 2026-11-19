r5-race-probe — R5：spawn_daemon 去重分支 × 垂死守护（stop×up 竞态，F-035 候选）。
判定逻辑（retire_stale_record/daemon_serving/pidfile liveness）逐字复制 gate.rs/pidfile.rs
（workspace crate 无法从仓库外链接——zombie-pidfile 教训），被测守护为真实 release
`creance gate-daemon` 子进程，下游（Gate::start/watchdog/run_daemon/disown）全部生产代码。
四轮：r1 竞态（删 record 后立刻 spawn_daemon——Ok 而终态无守护即违规）；r2 健康去重对照；
r3 全新 spawn 对照；r4 损坏 record 重生 + disown 继任安全对照。
运行：rustc --edition 2021 -o /tmp/r5-race-probe main.rs && /tmp/r5-race-probe <release-creance>
