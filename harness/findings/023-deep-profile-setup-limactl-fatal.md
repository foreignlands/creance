# FINDING-023: 深路径 profile 的 setup 撞 UNIX_PATH_MAX — 0.3 的"按物理 home 预算实例名"在 clamp 下限仍不够时 limactl 直接 fatal（原始错误抛给用户），creance 侧无预检与友好报错

- **编号**: 023
- **严重度**: S5（可用性：macOS 临时目录等深路径的 profile 无法 setup；行为 fail-closed 安全，但报错是 limactl 原始 fatal 而非 creance 诊断）
- **攻击面**: R3 → 0.3（4ab3c19 实例名预算）+ D1
- **发现时间**: 2026-11-19T07:05:00Z
- **发现者会话**: r3-s01
- **状态**: 待修复

## 复现（必须）

```sh
T=$(mktemp -d)   # macOS: /var/folders/52/…/tmp.XXXX（canonicalize 后 ≈70+ 字符）
export CREANCE_CONFIG=$T/config.json
creance setup
# limactl fatal: instance name `t-ee5ce70d` too long:
#   `/private/var/folders/52/blp24gv146s4_vhrk4tk405w0000gn/T/tmp.8qcTORO0S1/state/lima/
#    t-ee5ce70d/ssh.sock.1234567890123456` must be less than UNIX_PATH_MAX=104, but is 119
```

对照：浅路径（`/tmp/p1`）setup 正常成功（实测通过，后续 019/020/021 的实测都在它上面完成）。

- **期望**: 0.3 提交说明声明 "instance-name length budgets the PHYSICAL Lima home"——预算逻辑存在（vmname.rs home_limit），但物理 home 本身 >~75 字符时 `Limit.clamp(1, 76)` 的下限也无法满足 socket 预算（home 92 + name 1 + socket 27 > 103）。此时 creance 应在 setup 前**预检物理 home 长度**并给出可行动的报错（"profile 路径过深，请将 profile 移至更浅路径"），而不是把 limactl 的 fatal 原样抛出。
- **实际**: limactl create 阶段 fatal，用户只看到一条不看源码无法理解的 UNIX_PATH_MAX 消息。

## 根因猜测

`crates/creance-vm/src/vmname.rs` home_limit 的 `clamp(1, 76)` 在预算不足 1 时静默给 1；`lima.rs setup_instance`（stage → limactl create）与 `main.rs cmd_setup` 均无前置检查。注意预算对象是 **物理路径**（canonicalize 后）——F-010 修复后 limactl 内部会解析 symlink，/tmp 短链接不代表预算够。

## 未验证想法

- `creance setup` 之外，`list`/`up` 对同类深路径 profile 的报错形态（应一致地早失败）。
- macOS `/var/folders` 的长度是否随系统状态变化（临时目录哈希段）——影响面是"部分用户随机撞上"。

## 建议修复方向（供第二天的人参考，非结论）

`cmd_setup`/`setup_instance` 入口加预检：`paths::clean` 后的物理 home 长度 + 最长 socket 名（27）与 UNIX_PATH_MAX 比较，不足即返回中文可行动错误。或 setup 时把 Lima home 固定放在浅位置（如 `~/.creance/state/lima` 本身 <40 字符——但 per-profile 隔离的 home 是 F-010 的修复语义，需保持）。
