# FINDING-039: 幽灵 workspace 清单 crates/Cargo.toml（git tracked）阻断一切外部 path-dep 消费者——继承解析绑定 0.2.0 旧版并拼出 crates/crates/ 双倍路径

- **编号**: 039
- **严重度**: S5（仓库卫生/生态兼容；不影响 scripts/ci.sh 与发布二进制）
- **攻击面**: R6-C（收尾——审查工具链自身）
- **发现时间**: 2026-11-19T15:40:28Z
- **发现者会话**: R6
- **状态**: 待修复

## 复现（必须）

```sh
cd /tmp && cargo new probe-test && cd probe-test
# Cargo.toml 加: creance = { path = "<repo>/crates/creance" }
cargo build
# error: no matching package named `creance-gate` found
# location searched: <repo>/crates/crates/creance-gate        ← 双倍路径
# required by package `creance v0.2.0 (<repo>/crates/creance)` ← 版本错绑 0.2.0（真实为 0.5.1）
```

本会话实证：`harness/tools/r6-evidence-probe/` 首次 path-dep 直连仓库即此错误；改指 /tmp 快照（副本内删幽灵）后 16.59s 编译通过。

- **期望**: 外部 crate 能 path-dep 工作区成员（标准 Rust 工作区布局）。
- **实际**: 继承解析向上找最近的 `[workspace]` 清单，先撞 `crates/Cargo.toml`（内部依赖 path 相对它解析 → `crates/crates/*` 不存在；`workspace.package.version = 0.2.0`、repository = "your-org"）。

## 根因

`crates/Cargo.toml`（git tracked，引入于 ff286a6 "rename to creance, split into five layered crates"）是 crate 拆分时的**旧版根清单残尸**：其 members 路径按 crates/ 再拼一层全部失效。主仓构建不受影响——cargo 从根构建时对成员做归属校验会跳过幽灵继续向上找到真根；但**作为 path-dep 被外部加载时不做归属校验**，直接绑定幽灵。对比 ref Go 版无此问题（go.mod 单文件）。

## 未验证想法

- `cargo publish` creance-* 系列会同样撞幽灵（未实际 publish 验证）。
- 判定它是否为"故意嵌套工作区"：内容与根清单完全同构仅路径错位 + 版本停在 0.2.0 + your-org 占位，残尸特征明确。

## 建议修复方向（供第二天的人参考，非结论）

删除 `crates/Cargo.toml`（一行 git rm）；若确需嵌套工作区语义则改 members 路径为同级相对路径并同步版本。本审查遵守仓库只读铁律未动它，探针经 /tmp 快照绕行（快照基线 = HEAD 7368663 源码，见 r6-evidence-probe/Cargo.toml 注释）。
