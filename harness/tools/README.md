# harness/tools — 历史探针与回归工具

夜间审查循环（R1–R12，已收敛，见 `../state/STATE.md`）产出的独立
cargo 小工程。**都是历史工件**：它们冻结在各自轮次的目标代码上，
不随主代码演进——结论过时以主代码为准。

维护裁定（AUDIT-2026-11-21 待审 #10–#12，2026-11-21 拍板）：

- **个人路径依赖（#10，缓修）**：部分工具的 `Cargo.toml` 以绝对
  路径依赖原作者机器上的 crate（`/Users/shenyiyu/...`）。在别的
  checkout 上编不了属于已知状态；需要复跑某探针时，把 path 指向
  本 checkout 的 `crates/` 即可。
- **平台限定（#11）**：`r11-regression`、`r9-regression`、
  `r8-regression`、`r7-sync-matrix`、`r5-race-probe` 调
  `vm::lima_home`（v0.6 起 macOS-only）——Linux 上编不过，属预期。
- **陈旧快照（#12）**：`a6-dns-probe` 用 2026-11-18 的 dnsmsg
  字节快照，缺 F-005 修复——它测的是不再发布的代码，仅存档。

新一轮夜间审计的工具按 `../OPERATOR-PROMPT.md` 惯例新建目录，
不复活旧探针。
