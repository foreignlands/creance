# F-055 — provision 工具链段的 `'"$ARCH"'` 在外层 shell 展开，而 ARCH 只在内层 `sh -c` 里赋值：展开恒为空 → nodejs.org 主下载 URL 对**所有**架构 404，恒走 apt 兜底；night-12 ca22ea2 commit message 声称的 "the download URL is even right on arm64" 不成立

- **编号**: 055
- **严重度**: S4（正确性：主下载死代码、钉住版本永不生效；**不含安全面**——containment contract 在 F-054 修复后确实可达，apt 兜底自带超时，无 fail-open）
- **攻击面**: night-12 F-054 修复面回归（任务书 F-054 面：timeout 拼接语法 dash 逐字符验证）
- **发现时间**: 2026-11-20T14:55:00Z+08:00
- **发现者会话**: R11 (night-auditor)
- **状态**: 待修复

## 复现（必须）

```sh
sh harness/tools/r11-regression/f054-provision-quotes.sh
# 逐字复刻 crates/creance-vm/src/lima.rs 生成的引号结构（dash + stub curl/apt-get），
# 记录内层脚本实际收到的参数。rc=1 = 洞在（v0.5.6 现状）；rc=0 = 修复后。
```

- **期望**: `uname -m` 为 aarch64（lima guest）时主下载 URL 含 `linux-arm64`；x86_64 时含 `linux-x64`，pin 的 node v22.14.0 正常装上。
- **实际**（R11 实测记录）：

```
CURL: -fsSL -m 120 https://nodejs.org/dist/v22.14.0/node-v22.14.0-linux-/bin/node -o /usr/local/bin/node.new
APT: install -o Acquire::http::Timeout=20 -o Acquire::Retries=1 -y -qq nodejs npm
```

URL 架构段为**空字符串**（对所有架构）→ `curl -f` 404 → 恒走 apt 兜底（Ubuntu 24.04 = nodejs 18.x）。同 run 证明 F-054 其余修复真实有效：APT_OPTS 拼接正确到达内层（`install -o Acquire::http::Timeout=20 -o Acquire::Retries=1 ...`）、内层块有界结束、外层 `|| true` 吞 124、契约段（iptables/sudoers）可达。

## 根因猜测

`crates/creance-vm/src/lima.rs:185`（消费点）vs `:182`（赋值点）：

- `ARCH=$(case ...)` 在**内层** `sh -c '...'` 单引号文本里，由内层 shell 执行后赋给内层进程。
- 同一 URL 行上的 `node-v22.14.0-linux-'"$ARCH"'/bin/node` 的 `"$ARCH"` 处于单引号闭合段，由**外层** provision 脚本（dash）在组装 `sh -c` 参数时展开——外层从未赋值 ARCH → 空。
- 历史对照（ca22ea2 diff）：修复前整个 URL 在外层脚本平铺，`$(uname -m)` 在 guest 展开，但 `[[ ]]` 是 bashism → dash 下 `[[` 命令不存在（127）→ `|| echo x64` → **arm64 恒错**。修复把架构选择移进内层修好了方言，但消费点仍留在外层展开上下文——**行为未变，且把 x64 也拖下水**。commit message 与行为的这一落差与 F-052（night-11 工程陷阱 #49）同型：修复声称的每个符号必须运行验证，contains() 断言（lima.rs:309-317 只查 `TOOLCHAIN_BUDGET=300`/`-m 120`/无 `[[`）恰好都不触及 URL 完整性。
- 环境注记：本机 `/bin/sh` 是 bash 3.2，对 `$(case ...)` 直接语法错误（bash ≤3.2 解析限制）——**macOS-only 干扰项**，guest 的 `/bin/sh` 是 dash，解析正常（实测 ARCH=x64/arm64 均正确求值）；探针因此把 `sh` 换成 dash symlink 以隔离该干扰。

## 未验证想法

- apt 兜底装的 nodejs 18 是否满足 claude.ai/install.sh 的引擎要求：若不满足，claude CLI 供给在无网约束下静默缺失——工具链质量问题，不是 containment 面（供给脚本对工具链是 best-effort by design，F-031）。
- 同型排查：全脚本唯一另一处跨引号层展开 `"$APT_OPTS"` 已验证正确（值在外层赋值、在外层展开——作用域一致）；`'"$ARCH"'` 是唯一的"内层赋值外层消费"错配。

## 建议修复方向（供第二天的人参考，非结论）

把 URL 的架构段留在单引号内层消费内层变量：`node-v22.14.0-linux-$ARCH/bin/node`（内层 `"$ARCH"` 双引号）；或在 `timeout ...` 之前于**外层**赋值 ARCH（外层赋值+外层展开，与 APT_OPTS 同式；provision 本就运行在 guest 内，`uname -m` 语义不变）。补一条断言：生成的 script 不含 `'"$ARCH"'` 形态（或 URL 段含 `linux-$ARCH`/`linux-arm64` 之一）。
