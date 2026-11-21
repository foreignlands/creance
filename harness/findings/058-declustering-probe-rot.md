# FINDING-058: 去集群化改名的隐藏消费者——四个 gate 探针套件手拼 `Host: cage` 已全数判死，两套编译不过，f052 夹具钉旧路径

- **编号**: 058
- **严重度**: S5（工具腐烂；下次复跑 = 大规模假警报或静默假绿）
- **攻击面**: 8c3fa14 改名波及面 / harness/tools
- **发现时间**: 2026-11-21T12:40:00Z
- **发现者会话**: r13
- **状态**: 待修复

## 复现（必须）

```sh
# (a) r7-sync-matrix：编译可过，运行即死
cd harness/tools/r7-sync-matrix && cargo run --offline
# → panic at src/main.rs:137:57: "EOF while parsing a value"
#   （首个手拼 "Host: cage" 请求被现 gate 403，探针 unwrap 非 JSON 响应体）

# (b) r8-regression：编译死 + 字面量死 双重
cd harness/tools/r8-regression && cargo check --offline
# → error[E0425]: cannot find function `refresh_fingerprint_stamp` in module `creance::escape`（v0.6.x 已删）
#   src/main.rs:156/181 仍手拼 "Host: cage"（即便编过也会全 403）

# (c) r9-regression：编译死
cd harness/tools/r9-regression && cargo check --offline
# → error[E0603]: struct `SetupOptions` is private（lima.rs 已私有化）
#   同目录 f052-up-branches.sh:57 夹具仍造 /tmp/cage-lima-*（现名 /tmp/vmhome-*，vm.rs:241）→ case4 夹具永久脱靶

# (d) 手拼字面量 vs 现校验（根因锚点）
grep -n 'Host: cage' harness/tools/r6-evidence-probe/src/main.rs harness/tools/r7-sync-matrix/src/main.rs harness/tools/r8-regression/src/main.rs harness/tools/c3-gate-hammer/hammer.sh
grep -n 'host != "gate"' crates/creance-gate/src/gate.rs   # :468
```

- **期望**: 8c3fa14/e1ae610 修了 escape 探针这一只隐藏消费者；同族 gate 侧探针
  应同步或显式声明停用。harness/tools 不在 ci.sh 覆盖内，腐烂无警报。
- **实际**: r7 运行即 panic；r8/r9 编译不过；c3/r6 每个请求 403。
  r5-race-probe 与 r2-url-probe 无恙（cage-gate.json 系刻意保留名）。

## 根因猜测

改名波及面清点只扫了 `crates/`（产品侧），e1ae610 修的也是产品内探针；
harness/tools 的手拼 HTTP 字面量没有消费者扫描工具（正是"协议常量改名 →
探针手拼字面量"教训的第二次踩踏）。

## 未验证想法

- r6-evidence-probe 若在 Lima VM 全链跑，除 403 外可能还受 hostname 改名
  （cage- → OEM 型）与 `session:` SOCKS 用户的双重夹具漂移——未实跑。

## 建议修复方向（供第二天的人参考，非结论）

统一改 `Host: gate`（或改用 GateClient 构造请求）；r8 改用现行 stamp API、
r9 改用 pub re-export 或降级为 lima.rs 内部测试；f052 夹具路径跟随
`vm.rs:241` 现名；长期：给 harness/tools 加一个 `tools-ci.sh` 最小编译门
（cargo check --offline 逐目录），让腐烂在提交时可见。
