# FINDING-010: `limactl()` 自己删掉自己设置的 LIMA_HOME — 所有 VM 操作落在全局 ~/.lima，profile 隔离失效；探针读取路径与真实数据脱节

- **编号**: 010
- **严重度**: S2（安全语义破坏：profile 独立 LIMA_HOME 的隔离契约失效；数据落错位置；探针体系与真实状态脱节）
- **攻击面**: D2（lima_home 预占）+ E1（mounts 探针脱节）+ C6 关联
- **发现时间**: 2026-11-19T01:30:00Z
- **发现者会话**: s01
- **状态**: 待修复

## 复现（必须）

```sh
# 对照实验（四个场景全部列出全局 ~/.lima 的实例，profile 的 state/lima 完全被无视）：
python3 - <<'EOF'
import os, hashlib, subprocess, tempfile, shutil
creance = "/Users/shenyiyu/Documents/zcode/claude-cage-rs/target/release/creance"
p = tempfile.mkdtemp()
os.makedirs(os.path.join(p, "state", "lima", "fake-a"))
open(os.path.join(p, "state", "lima", "fake-a", "lima.yaml"), "w").write("vm-type: vz\n")
env = {**os.environ, "CREANCE_CONFIG": os.path.join(p, "config.json")}
r = subprocess.run([creance, "list"], capture_output=True, text=True, timeout=30, env=env)
print(r.stdout)  # 列出 ~/.lima 的既有实例（本机为 c-93b4d373），绝不列出 fake-a
EOF
```

直接证据链：
1. `crates/creance-vm/src/vm.rs:164-172`（`limactl`）：先 `cmd.env("LIMA_HOME", lima_home(profile))`，随后 `for name in STRIPPED { cmd.env_remove(name) }` —— 而 `STRIPPED`（vm.rs:134-152）**包含 "LIMA_HOME"**。Rust std 文档：`env_remove` 优先于 `env` —— 子进程永远拿不到 LIMA_HOME。
2. 黑盒四场景（正常 link+假实例 / 正常 link+空 / 攻击者预占 link / 正常创建）全部列出 `~/.lima` 全局实例；`LIMA_HOME=<dir> limactl list` 手动执行时 limactl 2.3.0 正确使用该目录（"No instance found"）——环境变量本身有效，是 creance 把它删了。

- **期望**: `limactl` 子进程 LIMA_HOME = profile 的 `/tmp/cage-lima-*` link（→ `state/lima`），实例数据与操作全部限于 profile。
- **实际**: LIMA_HOME 被删除，limactl 2.3.0 回落全局 `~/.lima`。

## 根因猜测

移植错误：Go 版（`cmd/cage/main.go:529-536`）用 `os.Setenv("AGENT_VM_STATE_DIR"/"AGENT_VM_LIMA_HOME"/"CAGE_LOGICAL_LIMA_HOME", ...)` **传递** lima home 且 unset 清单不含这些变量；Rust 把这五个传递用变量（LIMA_HOME/AGENT_VM_*/CAGE_*）放进 STRIPPED 又在 `limactl` 里先 env 后 remove——顺序颠倒。

**连带影响面**：
1. **profile 隔离失效**：所有 profile 的 VM 操作共享全局 `~/.lima` 实例池；`creance list` 泄漏全局实例列表；实例磁盘/状态写进 `~/.lima` 而非 profile 的 `state/lima`（profile 备份/迁移/删除语义全部失真）。
2. **探针体系脱节**（E1）：`escape.rs` 的 `mounts-workspace-only`/`gate-record-private` 探针读 `lima_home(profile)/<instance>/lima.yaml` —— 该路径下永远没有真实实例（真实数据在 ~/.lima）→ 探针恒 NotEnforced（文件不存在分支）或读到攻击者喂的文件（D2 预占 link 后）——**探针结论与真实 VM 状态无关**。
3. **D2 预占面**：`lima_home` 的 `/tmp/cage-lima-{uid}-{4hex}` 可预测 link（4hex=SHA256(profile)[:4]，可枚举），`read_link` 后**不校验目标指向 state/lima** 就采用（vm.rs:34-40）；攻击者预占后 `instance_name`/`environment_dir`/探针全部读攻击者目录。此面当前被 bug #1 "意外屏蔽"（limactl 不用 link），但文件系统侧（探针/instance_name/gate dir）直接暴露——修复 #1 时必须同步修 #3，否则预占立刻变成可利用的 LIMA_HOME 劫持。

## 未验证想法

- `create` 路径同样落 ~/.lima —— 之前 VM 全链"实测可用"其实是全局 home 自洽（create→up→shell→stop 都在 ~/.lima），profile 侧 `state/lima` 始终为空（未逐命令复验，逻辑推断）。
- instance_name 冲突面：两 profile 的 hash 名不同，但与用户手工 ~/.lima 实例同名的可能性未枚举。
- lima 2.3.0 对无效/悬空 LIMA_HOME 的行为（warning 而非 fallback，已在 /tmp/lima-envtest 对照确认）。

## 建议修复方向（供第二天的人参考，非结论）

`limactl()` 中把 `env("LIMA_HOME", …)` 挪到 STRIPPED 循环**之后**；或从 STRIPPED 移除 LIMA_HOME（保留其余四个传递变量的剥离，但它们已不在 limactl 路径使用，需按 Go 语义核对）。同修 `lima_home` 的 link 校验（read_link 后比对 target == state/lima 绝对路径，不匹配则重建），并让探针读 limactl 实际使用的 home（修好 #1 后二者自然一致）。
