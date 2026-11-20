R8 探针：night-09 修复面回归（基线 985a5a2/v0.5.3）。真实 crate path-dep，无逻辑复刻。

H1 F-041 sync 矩阵 7 例（换锚/幂等/部分绑定×2/绑定完成/等价锚/un-bind）——全 PASS=fail-closed 符合设计。
H2 F-040 承诺面+up 刷戳（h2.3 FAIL=FINDING-044 假绿实证）。
H3 F-043 close_gates 正向+死记录清理。
H4 F-042 残余：check_running 五字段自述对账盲区（h4.1/h4.2）+负对照（h4.3）。

离线构建：`cp ../r7-sync-matrix/Cargo.lock . && cargo build --release --offline`
（crates.io 不可达环境；crates 缓存已在 CARGO_HOME）。
结果 19/20 PASS + 1 FAIL（即 F-044 实证）；全部 /tmp profile 用后即删。
