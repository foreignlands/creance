# Cloud verification (Devin / any Linux CI machine)

creance 的强制面（launchd、lima/VZ）是 macOS-only 的，但**全部五个 crate 及
139 个测试在标准 Linux x86_64/aarch64 上构建并通过**——这让云端 AI（Devin
的云电脑）可以承担三件事，无需任何 macOS 资产：

## Devin 能做的（按价值排序）

1. **Linux 持续验证**（每轮推送后）：
   ```sh
   git clone https://github.com/foreignlands/creance && cd creance
   rustup toolchain install stable
   cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
   ```
   期望：全绿（与 `scripts/ci.sh` 相同基线；无 macOS 特有步骤）。任何
   红灯直接按 harness/findings 协议记录。

2. **夜间审查轮换的 Linux 侧**：跑 `harness/OPERATOR-PROMPT.md`（同
   GLM），重点是它擅长而本机弱的面——`scripts/*.sh` 在 bash 严格模式下的
   行为、Linux 构建（cfg!(target_os) 分支）、以及 findings 的 Linux 复现。

3. **发布前交叉检查**：`cargo build --release --target <linux-target>`，
   确认 `creance-net`（无平台分支）与 `creance-vm`（除 host.rs 的
   statvfs/paths 分支外无分支）在 Linux 目标上零警告。

## Devin 不能做的（留在 macOS 宿主）

- launchd 核心生命周期、VZ/lima VM 链路、`escape-test` 的 guest 探针——
  这些是 macOS 拓扑的一部分，云端只能做代码层审查（仍有价值：gate 状态机、
  import/store 纯逻辑全在云端可测）。

## 接入清单（一次性）

```sh
# 在 Devin 的云电脑：
gh repo clone foreignlands/creance
cd creance && cat harness/OPERATOR-PROMPT.md   # 审查员协议
cat harness/FIXER-PROMPT.md                     # 修复员协议
```

无需凭据即可 clone（公开仓库）；参与修复时用其自己的 fork+PR。
