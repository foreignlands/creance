R11 探针：night-12 修复面收敛回归（基线 c20332d / v0.5.6）。

- `src/`（`cargo run --release`，仓库根 .toolchain 环境）：F-053 小写化矩阵
  （混合大小写折叠/instance_name 主路径/恢复路径/两入口同名）+ F-052 库侧锚
  （guest_fingerprint 摘要形状、stamp 路径恒等式）。
- `f052-up-branches.sh`：cmd_up 三分支+实例存在检查的 CLI 实机四 case
  （无戳拒/漂移拒/实例缺失拒/假 limactl 绿路径恰一次 start）——无需 VM。
- `f054-provision-quotes.sh`：**F-055 探针（当前 rc=1 = 洞在）**——逐字复刻
  provision 工具链段引号结构（dash + stub），证明 `'"$ARCH"'` 外层展开为空、
  URL 架构段缺失；修复后应 rc=0。
