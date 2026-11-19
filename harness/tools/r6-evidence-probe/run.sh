#!/bin/sh
# R6 探针复现脚本：重建 /tmp 快照（绕过 F-039 幽灵清单）→ 编译 → 运行。
# 27 项断言全 PASS 且 RC=0 = 观测与预测一致（FINDING-036/037/038/040 的实证基座）。
# 快照基线 = HEAD 7368663（v0.5.1）源码；仓库更新后重跑前先重建快照。
set -e
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
export RUSTUP_HOME="$REPO/.toolchain/rustup" CARGO_HOME="$REPO/.toolchain/cargo"
export PATH="$CARGO_HOME/bin:$PATH" CARGO_TARGET_DIR=/tmp/r6-target

rm -rf /tmp/r6-snapshot /tmp/r6-target
mkdir -p /tmp/r6-snapshot
cp "$REPO/Cargo.toml" /tmp/r6-snapshot/
cp -R "$REPO/crates" /tmp/r6-snapshot/crates
rm /tmp/r6-snapshot/crates/Cargo.toml   # 删副本内幽灵清单（仓库原件只读不动）

cargo build --manifest-path "$(dirname "$0")/Cargo.toml"
/tmp/r6-target/debug/r6-evidence-probe
