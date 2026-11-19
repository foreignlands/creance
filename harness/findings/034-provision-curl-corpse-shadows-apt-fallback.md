# FINDING-034: provision 的 curl 残尸遮蔽 apt 兜底——F-031 修复自身的兜底链可被第一腿尸体击败

- **编号**: 034
- **严重度**: S4
- **攻击面**: F-031 修复面回归（R5-4）
- **发现时间**: 2026-11-19T09:55:00Z
- **发现者会话**: R5
- **状态**: 待修复

## 复现（必须）

机制级验证（完整链需一次"传输中断的 curl"，生产即 F-031 的弱镜像/首启网络场景）：

```sh
# 1) curl -f -o 在传输中途失败时残留部分文件（curl 文档化行为；--remove-on-error 即为此而设，脚本未用）
curl -f -o /tmp/r5-corpse/node https://nodejs.org/dist/v22.14.0/node-v22.14.0-linux-arm64/bin/node
#   中断之（弱网/镜像截断）→ /tmp/r5-corpse/node 为半截二进制，非零退出，文件留存

# 2) PATH 先序：Ubuntu（Lima guest 基镜像）/etc/profile 的默认 PATH 中
#    /usr/local/bin 先于 /usr/bin（ENV_SUPATH 与 login PATH 皆然）
```

对照 `crates/creance-vm/src/lima.rs:156` 的安装行：

```sh
curl -fsSL https://nodejs.org/dist/.../bin/node -o /usr/local/bin/node 2>/dev/null \
  || apt-get install -y -qq nodejs npm >/dev/null || true
```

- **期望**: curl 失败 → apt 兜底装成 /usr/bin/node → `node` 可用（半装态里至少工具链立得住）
- **实际**（机制推演，两前提均实证）: curl 半截文件**留在** `/usr/local/bin/node` → apt 兜底成功装出
  `/usr/bin/node` → 但 PATH 解析 `node` 先命中 `/usr/local/bin/node` 残尸 → ENOEXEC → `node` 仍坏。
  兜底链被第一腿的尸体遮蔽，环境比"没有兜底"更误导（claude install 随之失败 || true，静默）。

## 根因猜测

`crates/creance-vm/src/lima.rs:156`：`curl -o` 无 `--remove-on-error`（curl ≥7.71）且失败后无清理；
Ubuntu 默认 PATH `/usr/local/bin` 先序完成遮蔽。containment 不受影响（锁定/摘除在后续行且必达——F-031
契约本身成立），故为可用性/正确性级。

## 未验证想法

- VM 内实测弱网截断 → 全链复现（需可控截断的 HTTP 中间人，机制两前提已各自实证，未做端到端）。
- 同款 `&& … || true` 形状在 lima.rs:177（sudoers 摘除）：sed 真失败（如 /etc 只读）→ NOPASSWD 行
  静默存活 → 链回 F-020 需要 passwd -l 同败 + ~/password 幸存，深度太远，仅记档。

## 建议修复方向（供第二天的人参考，非结论）

curl 腿加 `--remove-on-error`（或在 `||` 前补 `rm -f /usr/local/bin/node`）；或先探测 `/usr/local/bin/node`
可执行性再决定清理；claude install 失败至少 echo 到 guest 控制台供 up 后诊断。
