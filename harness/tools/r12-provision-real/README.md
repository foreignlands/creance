R12 探针：F-055 修复面第三档验证——**真实生成文本**的 dash 实机执行（非逐字复刻，
复刻漂移教训见 F-033/r11 探针头注）。

- `src/`（`sh run.sh` 一键，仓库根 .toolchain 环境）：调真实 `creance_vm::lima::
  generate_lima_yaml`，从 YAML 取 provision 脚本原文，产出四个文本：
  byte-exact 原文 / 仅 /etc 重写的可执行变体 / 叠加 F-055 旧洞形态的负控变体 /
  工具链段摘录。随后 dash + stub 实机执行判定：
  - P1 修复形态 URL 含架构段（linux-arm64/linux-x64）
  - P2 负控复现空架构段（探针具鉴别力，非恒 PASS）
  - P3a 可执行变体与原文差异仅 5 处 /etc 重写 = 8 diff 行（macOS 宿主 /etc
    不可写 + set -e，落 rootfs stage；工具链段字节不动；rules.v4 与
    up.rules 共享一行）
  - P3b 工具链段与 r11 探针 heredoc 逐字节等价（仅 F-034 两行注释差）
  - P4 假 uname=aarch64 强制走真实 guest（Ubuntu arm64）分支 → linux-arm64
    （教训：stub 建完必须 chmod +x，PATH 会静默跳过无执行位文件回退真命令）
- 2026-11-20 实测（HEAD 39aff21）：全 PASS（TRUE_RC=0），整份生成脚本可在
  dash+stub 下从头跑到尾（real-exec rc=0）。
- 环境语义注：macOS `uname -m` 返回 `arm64`，直跑落 x64 分支；真实 guest 是
  Ubuntu（arm64 机 = `aarch64`）。P1（x64 分支）与 P4（aarch64 分支）已把
  两个分支都动态钉死。
