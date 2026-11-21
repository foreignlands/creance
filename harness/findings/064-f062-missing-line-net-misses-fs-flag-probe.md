# FINDING-064: F-062 缺行网漏掉 probe() 助手路由的 fs-flag-readable——注释宣称与实际覆盖不符

- **编号**: 064
- **严重度**: S5（质量/覆盖不一致；安全契约未破——探针是遥测，宿主侧探针不经过 guest 传输）
- **攻击面**: E2（guest_script 探针本身）+ F-062 修复面回归
- **发现时间**: 2026-11-21T16:00Z
- **发现者会话**: night-auditor-v2（R14）
- **状态**: 待修复

## 复现（必须）

```sh
export RUSTUP_HOME=$PWD/.toolchain/rustup CARGO_HOME=$PWD/.toolchain/cargo \
  PATH=$PWD/.toolchain/cargo/bin:$PATH
cargo run --offline --manifest-path harness/tools/r14-convergence/Cargo.toml
# 观察 [A]/[A-OBS]/[E-OBS] 三节
```

- **期望**（按修复自身注释的宣称）：
  main.rs:372-375 注释 "every probe the script defines must answer, with a
  known verdict"、escape.rs:317-320 注释 "the host-side consumer now treats
  a missing probe line as failure"——脚本定义的**每一个**探针 id 缺行都应
  触发 transport ESCAPE（exit 1）。
- **实际**：
  - `[A] expected ids (22)`——提取器集合 = 11 个字面 id（各出现 2 次，
    重复判定幂等无害），**无 fs-flag-readable**；`[A-OBS]` 实证脚本
    escape.rs:332 定义了 `probe fs-flag-readable true`（经 probe() 助手、
    `echo "PROBE $id …"` 参数化发射）。
  - `[E-OBS]`：模拟真实 guest 输出 = 11 行字面探针 PASS + fs-flag-readable
    行整体被吞 → `missing=[]`（空）→ escape-test exit 0，transport ESCAPE
    不触发。该探针行可被单独致盲而缺行网无感。
  - 对照组（同探针）：[C] 健康输出零误报、[D] 全盲输出 11 个全 missing、
    [F] 11 id × 68 行子串碰撞矩阵无误匹配、[G] up 守门真值表 10 行全
    fail-closed——缺口仅 fs-flag-readable 一项。

## 根因猜测

crates/creance/src/main.rs:383-386——提取器只枚举 `echo "PROBE <字面>`
发射点并 `filter(|id| !id.contains('$'))`，把 probe() 助手的两个参数化
发射点（escape.rs:326/328 `echo "PROBE $id ESCAPE/PASS"`）连同唯一走该
助手的探针 fs-flag-readable 一起放弃。main.rs:379-382 的豁免理由
"parameterized emit sites, not statically knowable probe names"名不符实：
发射点参数化，但**调用点**（escape.rs:332 `probe fs-flag-readable true`）
的字面 id 完全静态可枚举——提取器选错了枚举源。night-15 commit message
自述的第一个提取器草稿"over-matched parameterized emit sites"被健康路径
打回后，修复收敛到了只覆盖字面发射点的保守形态，未回头覆盖调用点。

影响有界性（不拔高严重度的理由）：①mount 隔离属性（fs-flag-readable 的
命题）由宿主侧 mounts-workspace-only 探针兜底，宿主探针不经 guest 传输、
不受致盲影响；②完全伪造 PROBE 行本来就在 F-062 的如实边界内（README
"探针的定位"段），选择性致盲只是该边界内的弱一档形态；③剩余 11 个探针
的缺行网经 [C]/[D]/[F] 实证成立。故 S5 记档而非 S4。

## 未验证想法

- 植入 `grep -v "PROBE fs-flag-readable"` 形态的 .bashrc 过滤器在 Ubuntu
  实机上选择性吞该行的端到端验证（QEMU 传输形态与 `ssh … sh -s` 同验，
  归 U 系列实机回填）。
- guest 经 stdin 预读捕获脚本全文（bash -c 外层壳 source .bashrc 时
  `dd <&0` 截流）实现"知道全部 11 个 id 后整份伪造"的可行性推演——在
  如实边界内，未实测。

## 建议修复方向（供第二天的人参考，非结论）

提取器增补第二枚举源：对脚本行 `probe <id> …` 调用点抽 id（一行
filter_map，`l.split_once("probe ")` + 首词非 `$` 且非保留字即可），
或最简方案——把 fs-flag-readable 在脚本里改为字面 if/else 发射（与
其它 11 个探针同构），提取器无需改动。顺带修 main.rs:379-382 豁免注释
的措辞（调用点静态可枚举）。修复后以 r14-convergence [A] 节作裁判：
expected 集合应含 fs-flag-readable，[E-OBS] 场景应报 missing。
