# FINDING-033: fingerprint-consistent 探针是死代码——fingerprint.txt 全仓库无写入者

- **编号**: 033
- **严重度**: S5
- **攻击面**: C7 / E（探针本身）
- **发现时间**: 2026-11-19T09:45:00Z
- **发现者会话**: R5
- **状态**: 待修复

## 复现（必须）

```sh
grep -rn "fingerprint.txt" crates/ --include="*.rs"
# 唯一命中：crates/creance/src/escape.rs:179（读取者）
# 再对运行中的真实 profile 跑 escape-test：
CREANCE_CONFIG=<profile>/config.json ./target/release/creance escape-test
```

- **期望**: "profile changed since the VM was created" 漂移检测真实生效（探针存在即应有实现或删除）
- **实际**: `<state_dir>/fingerprint.txt` 从未被任何代码写入 → 探针恒走 `NotEnforced` 分支，escape-test 恒显示
  `⏭️ fingerprint-consistent [profile] (layer not implemented yet)`。0.4 的漂移检测实际由 `running.rs`
  （running record 携带 fingerprint，`check_running` 比对）承担，escape.rs 里这枚探针是迁移残留。

## 根因猜测

`crates/creance/src/escape.rs:171-194`：探针读取 `paths::join(&vm::state_dir(profile), "fingerprint.txt")`，
仓库内（含 scripts/、lima.rs provision）无任何写入点。0.4 用 running record 替代了文件戳，此探针未随迁。

影响：纯探针质量（诚实方向无恙——NotEnforced 不谎报 PASS；与 F-011 sock-abstract 硬编码 PASS 不同类）。
C7 结论（本条之外）：fingerprint 本体 = 结构体序列化 sha256（字段序固定 → 文件字节序/空白差异不影响；
exit_policy 先 normalized 再哈希 → 等价策略同指纹）；proxy_revision **有意入指纹**（select/refresh 即漂移，
由 running.rs 拦 `up`，是保守方向的设计选择）。

## 未验证想法

（无——本条为完整静态+运行时验证）

## 建议修复方向（供第二天的人参考，非结论）

删除该探针（诚实归 running.rs），或在 `record_running`/`vm::up` 时真正写入 fingerprint.txt 让两层互证。
