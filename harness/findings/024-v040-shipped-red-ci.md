# FINDING-024: v0.4.0 终稿未过 CI——`cargo fmt --check` 11 处红（gate.rs/guestprofile.rs/lima.rs/main.rs）+ `lima::tests::yaml_carries_image_size_and_mount` 断言引用已删除的 YAML `hostname` 字段而恒失败

- **编号**: 024
- **严重度**: S3（发布过程缺陷：tag v0.4.0 与推送 2df07a6 时的树无法通过自家 `scripts/ci.sh`；R3 审查者声称的"CI 基线绿"与此不符——其基线只覆盖了 cargo test 的部分包）
- **攻击面**: night-05 基线核验（修复会话开工首跑 ci.sh 即暴露）
- **发现时间**: 2026-11-19T09:30:00Z
- **发现者会话**: night-05（主线修复会话）
- **状态**: 待修复

## 复现（必须）

```sh
git status   # 干净（harness/ 未跟踪文件除外）
sh scripts/ci.sh
# == fmt == 立即退出：Diff in crates/creance-gate/src/gate.rs:697 等 4 文件 11 处
# 手工 cargo test：lima::tests::yaml_carries_image_size_and_mount FAILED
#   assert!(v["hostname"].as_str().unwrap_or_default().starts_with("cage-"));
#   —— 0.3 移除 lima.yaml 的 hostname 字段（lima 会拒绝 unknown field，改为
#      provision 里 hostnamectl 落地）时测试断言未同步更新
```

- **期望**: 任何 tag/推送前 `scripts/ci.sh` 全绿是发版闸门（FIXER-PROMPT 协议明文）。
- **实际**: v0.4.0 会话末尾的批量编辑后没有再跑最后一轮 fmt+ci 就 commit+tag+push；`v["hostname"]` 对缺失键返回 Null→`""`，`"".starts_with("cage-")` 为 false，断言恒失败。

## 根因

上一会话（v0.4.0）在实机验证成功后做了收尾微调（注释/断言），跳过了最终 `cargo fmt` + ci.sh 重跑；工具链自 11-17 未变更（rustfmt 1.11.0-stable），排除版本漂移。教训与 engineering-lessons #13/#24 同族：**任何"最后一笔"编辑之后都必须重跑完整 CI，实机绿 ≠ CI 绿**。

## 建议修复方向

1. `cargo fmt` 全仓 + 修正 lima 测试断言（hostname 字段应断言**不存在**，hostnamectl 在 provision 中存在）。
2. R4 起审查者的"CI 基线"必须指 `sh scripts/ci.sh` 的完整输出，不接受 cargo test 部分包绿。

## 附带

- 工具链（.toolchain，rustfmt 1.11.0-stable 2026-11-09）与 v0.4.0 会话相同——非环境漂移。
