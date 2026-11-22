# harness/tools — 历史探针与回归工具

夜间审查循环（R1–R12，已收敛，见 `../state/STATE.md`）产出的独立
cargo 小工程。**都是历史工件**：它们冻结在各自轮次的目标代码上，
不随主代码演进——结论过时以主代码为准。

维护裁定（AUDIT-2026-11-21 待审 #10–#12，2026-11-21 拍板）：

- **个人路径依赖（#10，已修 2026-11-22）**：所有工具的 `Cargo.toml`
  已改为相对路径（`../../../crates/…`），shell 驱动里的绝对路径已
  参数化为 `CREANCE_REPO`/`CREANCE_BIN`（默认按脚本位置推导）。
- **平台限定（#11）**：`r11-regression`、`r9-regression`、
  `r8-regression`、`r7-sync-matrix`、`r5-race-probe` 调
  `vm::lima_home`（v0.6 起 macOS-only）——Linux 上编不过，属预期。
- **退休（F-058，2026-11-21）**：`r8-regression`（主体
  `refresh_fingerprint_stamp` 已被 F-044 修复**有意删除**，探针失去了
 测试对象）；`r9-regression`、`r12-provision-real`（依赖 v0.6.x 有意
  私有化的 `lima::SetupOptions` pub 面——不为探针放宽产品 API）。
  这三个目录保留存档，但不再是任何回归的裁判。
- **修复保活（F-058，2026-11-21）**：`r7-sync-matrix`、`c3-gate-hammer`、
  `r6-evidence-probe` 的手拼 `Host: cage` 全部改 `Host: gate`（去集群化
  改名的第二波隐藏消费者）；`r11-regression/f052-up-branches.sh` 夹具
  路径 `/tmp/cage-lima-*` 跟随现名 `/tmp/vmhome-*`。
- **裁判分级（R13.5 实测，2026-11-21）**：`r7-sync-matrix` 全 PASS
  无 panic，可作回归裁判；`r6-evidence-probe` 可编译可运行，但其 7 处
  断言仍是修复前形态（如 status 无 token 期望 200、实际 403——泄漏已闭；
  grant 期望直 Open、实际 409 Checking——语义已 fail-closed 演化），
  **不能作回归裁判**，仅作修复对照存档。
- **陈旧快照（#12）**：`a6-dns-probe` 用 2026-11-18 的 dnsmsg
  字节快照，缺 F-005 修复——它测的是不再发布的代码，仅存档。

新一轮夜间审计的工具按 `../OPERATOR-PROMPT.md` 惯例新建目录，
不复活旧探针。
