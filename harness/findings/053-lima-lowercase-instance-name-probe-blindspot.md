# F-053 — lima `create` 小写规范化 vs creance 实例名大小写保留：`instance_running` 名字恒等式断裂，F-049 探针守卫与 gate-record 探针在 setup 产物上永久失明（实测于 macOS）

- **编号**: 053
- **严重度**: S4（探针 oracle 假绿——F-049 修复的探针分支在 setup 创建的实例上**永不触发**；大小写敏感卷上 F-051 重建检测亦失效，死胡同回归）
- **攻击面**: night-11 F-049/F-051 修复面回归 + 探针质量（E1 谱系，F-033 同族）
- **发现时间**: 2026-11-20T06:45:00Z
- **发现者会话**: R10 (night-auditor)
- **状态**: 待修复

## 复现（必须）

macOS + lima 2.3.0；profile 路径含大写（mktemp 天然给出）：

```sh
T=$(mktemp -d /tmp/r10-e2e-XXXX)          # 例：/tmp/r10-e2e-9EaF
CREANCE_CONFIG="$T/config.json" target/release/creance init
CREANCE_CONFIG="$T/config.json" target/release/creance setup    # 走 limactl create
ls "$T/state/setup/"                       # → r10-e2e-9EaF-downloads-91987642.yaml（大写 stem）
LIMA_HOME="$T/state/lima" limactl list     # → NAME=r10-e2e-9eaf-downloads-91987642（被 lima 小写化！）
CREANCE_CONFIG="$T/config.json" target/release/creance up        # VM Running
rm "$T/state/fingerprint.txt"              # 漂移洗绿形态
CREANCE_CONFIG="$T/config.json" target/release/creance escape-test; echo $?
```

- **期望**: 运行中 VM + stamp 缺失 → `fingerprint-consistent` 报 `Escaped("fingerprint stamp missing on a running VM")`，escape-test 非零（F-049 修复分支）；无 gate record 且 VM 运行中 → `gate-record-private` 报 `Escaped("VM present without a gate record")`。
- **实际**（实机全程）：`fingerprint-consistent ⏭️ (layer not implemented yet)`、`gate-record-private ⏭️`，escape-test 对这两项报 **"contained (2 probe(s) awaiting their enforcement layer)"**。limactl list 的 `name` 是小写 `r10-e2e-9eaf-…`，creance `instance()` 保留大写 `r10-e2e-9EaF-…`，`v["name"] == instance` 恒 false → `instance_running` 恒 false。

## 根因猜测

1. `crates/creance-vm/src/lima.rs`（setup_instance）：staged yaml 以 creance 的 `instance()` 命名（大小写保留，`vmname.rs base_name` 只压非字母数字）；`vm.rs create` = `limactl create <yaml>`，lima 2.3.0 **将实例名小写化**（实测：yaml stem `r10-e2e-9EaF-…` → 实例目录 `r10-e2e-9eaf-…`）。而 `limactl start` 对不存在名字的自动创建**不**小写化（本次 CASE B 实测创建了大写目录）——lima 自身就不一致。
2. `crates/creance/src/escape.rs:221`：`v["name"] == instance` 精确字符串比较 → 名字带大写的 profile 上 `instance_running` 恒 false。受影响守卫：F-049 新分支（escape.rs:186）、"VM present without a gate record"（escape.rs:139-140）。
3. macOS 默认 APFS 大小写不敏感掩盖了**路径级**后果（F-051 重建检测 `lima_home/{instance}/lima.yaml`、gate record 目录解析仍命中）；在大小写敏感卷（case-sensitive APFS / Linux 宿主）上：setup 后重建检测必 miss → `limactl create` 撞 "already exists" → **F-051 修复的死胡同回归**。

## 未验证想法

- lima 是否有 `--name` 或规范化配置能让 create 保留/显式传名（修复路径 A：creance 显式传小写化后的名字并全局统一用小写；修复路径 B：instance_running 改大小写不敏感比较）。
- `creance stop`/`shell` 等其它把 `instance()` 传给 limactl 的命令在大小写敏感卷上的具体失败面未逐一实测（macOS 上被 FS 掩盖，全部正常）。
- 我的 r10 探针 h2.2 用假 limactl 回显 creance 原名所以 PASS——真 lima 回显的是规范化名；真实矩阵应以本文件实机步骤为准。

## 建议修复方向（供第二天的人参考，非结论）

单一事实源：creance 侧 `vmname` 直接小写化生成实例名（lima 既是事实规范化者，就让它成为规范），存量 profile 由 setup 重建自然迁移；`instance_running` 比较同时改 case-insensitive 兜底。补实机形态回归（setup 后 `limactl list` 名字 == creance `instance()`）。

## 关联

- F-052（同轮：up 侧 stamp 跳过——两个洞叠加时洗绿完整复活）；F-049/F-051（修复面）；F-033（探针死代码前科）。
