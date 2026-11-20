# F-044 — up 无条件刷新 fingerprint stamp：stop→edit→up 把 guest 侧漂移洗绿（探针假 PASS，guest 从未重供给）

- **严重度**：S4（验收探针假绿——escape-test 六硬断言之"身份承诺一致"在真实例行路径上失真；egress 拓扑不受影响，非逃逸）
- **攻击面**：F-040 修复面回归（night-09 `3306e06`）· C7（fingerprint 稳定性）· E2（探针本身）
- **状态**：待修复（建议随 0.6 或下一夜修）
- **基线**：v0.5.3 `985a5a2`
- **复现**：纯 host 侧，`harness/tools/r8-regression` h2.2/h2.3（真实 `escape::host_probes` + `refresh_fingerprint_stamp`，无需 VM）

## 结论一句话

night-08 引入的 `refresh_fingerprint_stamp`（R6-H4："`up` 是当前 config 生效的时刻，戳跟着走"）的唯一正当理由是 **proxy_revision/proxy_url 进戳**（select 即漂移、探针永久红）。F-040 把戳改成 guest_fingerprint（timezone/locale/browser_language 三字段）后该理由消失——**host 侧字段不再进戳，`up` 刷戳从"修正误报"变成"洗白真漂移"**：stop→edit-timezone→up 一条完全合法的例行路径上，`up` 无条件把戳刷成新 config 的指纹（`main.rs:640`），而 `vm::up` 只是裸 `limactl start`（`vm.rs:226-228`，无 `--restart-provision`）——**Lima 的 provision（locale-gen/timezone）只在 create 首启执行，存量 VM 不重供给**。结果：guest 实际仍跑旧时区，config 与戳都说新时区，`fingerprint-consistent` 探针 Contained。

## 探针实证（r8-regression，19/20 PASS，唯一 FAIL 即本条）

```
h2.0 setup 后探针=Contained（承诺一致）                     PASS
h2.1 host 侧变化（revision+锚点）→ 探针保持绿（F-040 修复意图） PASS
h2.2 guest 侧变化（timezone）→ 探针红（诚实）                PASS  Escaped(...)
h2.3 模拟 up 刷戳后 → 观测 Contained                        FAIL  ← 假绿成立
```

h2.3 的 FAIL 是本 finding 的实证：刷戳前探针诚实红，`refresh_fingerprint_stamp` 一次调用后转绿，全程无任何重供给动作。

## 路径可达性（全链源码核实）

1. `creance stop` = 裸 `limactl stop`（`vm.rs:212-214`）；cage-running.json 不删，但死 PID 记录被 `running::check_running` 忽略（`running.rs:98` `record_alive` + `dead_pid_is_ignored` 测试）→ `up` 放行。
2. `cmd_up`：`running::check_running`（全量指纹锁）只挡"**活**记录+指纹异"（`running.rs:90-106`）——stop 后无活记录，锁不设防（这正是 F-040 注释"全量 fingerprint 仍守 running-record 锁"的盲区：锁只护 up-时-VM-在跑窗口）。
3. `vm::up` = `limactl start`（存量实例）→ 不重跑 provision → guest 时区/locale 保持旧值。
4. `record_running`（`main.rs:634`）把全量指纹也刷成新值（锁同时被重铸）；
5. `refresh_fingerprint_stamp`（`main.rs:640`）把戳刷成新 guest_fingerprint → 探针绿。

## 为什么 F-040 之后刷新只剩害处

- 刷戳的动机注释（`escape.rs:642-646` 测试 & `main.rs:635-639`）仍写着"proxy_revision is part of it"——**该前提已被 F-040 自己删除**（revision 不在 guest_fingerprint 里）。F-040 的回归测试 `host_only_config_changes_keep_the_probe_green`（escape.rs:601-640）证明 host 侧变化根本不需要刷戳就保持绿。
- 于是刷戳唯一能改变结果场景 = guest 三字段真实漂移——恰是需要 **re-setup**（重建 VM）而非刷戳的场景。`cmd_setup` 的文案自己也说"re-run setup after `creance stop` to re-pin"（main.rs:566-569），但 `up` 把这条纪律变成了可绕过项。
- `up_refreshes_a_stale_stamp` 测试把假绿行为奉为规范，修复时须反转该测试语义。

## 修复方向（记录，不实现）

1. **删** `refresh_fingerprint_stamp` 与 `main.rs:640` 的 up 调用（F-040 后它只会说谎）；`up` 改为：`cfg.guest_fingerprint() != stamp` 时**拒绝启动**并提示 re-setup（与 setup 文档语义一致）。漂移必须以"重建 VM"或"显式重供给"消化，不能以刷戳消化。
2. 若要保住"stop→up 不打断工作流"的 UX，替代方案是 up 时做真重供给（`limactl start --restart-provision` + lima.yaml 重生成）——成本高，属 0.6 权衡。
3. 回归面：反转 `up_refreshes_a_stale_stamp`；补"guest 字段漂移 + 模拟 up 刷戳后仍须红"的探针断言（r8-regression h2.3 可直接搬进 crate 测试）。

## 关联

- F-033（stamp 机制建立）、F-040（戳改 guest 三字段——本条是其修复引入的假阴性面）、C7（指纹稳定性矩阵）、E2（探针 PATH/oracle 面——本条是探针的"时间维"盲区：探针只比两份承诺，从不看 guest 实际值）。
