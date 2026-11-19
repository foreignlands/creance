# FINDING-040: F-033 修复面回归——setup 指纹戳覆盖全部 config 字段（含 proxy_url/revision/exit_policy），任何合法代理操作使 escape-test 从此恒报 Escaped

- **编号**: 040
- **严重度**: S4（正确性/语义分类：良性宿主侧操作被分类为逃逸；方向 fail-closed，不破坏 containment）
- **攻击面**: R6-B3（night-07 修复面回归：fingerprint 双源一致性）
- **发现时间**: 2026-11-19T15:40:28Z
- **发现者会话**: R6
- **状态**: 待修复

## 复现（必须）

探针：`harness/tools/r6-evidence-probe/` H4 段（真实 `config::fingerprint()` + `select_and_apply`）。

```sh
cd harness/tools/r6-evidence-probe && cargo run   # （工具链 env 见 F-036）
# H4 段全部 PASS，PROBE_RC=0：
#   select_and_apply rotates fingerprint (stamp F1 != current F2)   PASS
#   guest-visible fields unchanged by select                        PASS
```

端到端命令序列（逻辑必然，无需 VM：escape.rs:186 的比较代码路径 + H4 已证前提）：

```sh
creance setup            # 戳 fingerprint.txt = F1（全 config SHA256）
creance proxy-select <node>   # select_and_apply 轮换 revision、重写 config.json → F2
creance escape-test      # fingerprint-consistent 探针：F1 != F2 → Outcome::Escaped
```

- **期望**: "VM 承诺"= guest 可见快照（timezone/locale 等）；纯宿主侧变化（代理端点/revision/exit_policy 锚定）不应改变承诺，探针应 Contained。
- **实际**: `fingerprint()`（config.rs:115-120）对**整个 Config** 取 SHA256（仅 normalized exit_policy）；select 是一阶 CLI 命令、每次 start_managed 真重启也必轮换 revision——所以 setup 之后任何代理重配置都会使探针永久红（错误信息 "profile changed since the VM was created; run creance stop"，而 stop 不重写戳，只有重跑 setup 才恢复）。

## 根因

`crates/creance/src/escape.rs:173-196` 探针把"全 config 指纹漂移"分类为 `Outcome::Escaped`（逃逸！）。双源语义错位：
- **running record**（running.rs:98 check_running，up 时写）锁的是"活 VM vs 当前 config"——select 发生在 setup 与 up 之间时，record@up 写入 F2，把漂移**静默吸收**（up 锁此后以 F2 为基准，不再反映 VM 实际 provisioning 快照 F1）。
- **setup 戳**只被 escape 探针消费 → 永远停留在 F1 → 恒红。
- night-07 STATE 声称两源"互补不冲突"——实际冲突：同一漂移事件，record 源吸收、戳源报警且永不解除。

## 未验证想法

- `sync_proxy_revision` 采纳 revision 变更时会 `record_running` 刷新 record（gate.rs:668）——但从不触碰 setup 戳；up 后经 workbench 换节点（F-036 场景）同样恒红（未实机跑 VM 验证端到端输出，逻辑同上）。
- 戳只含 timezone/locale 时探针语义是否过窄（未来 guest 可见字段增加）——修复方向需先定义"承诺面"字段集。

## 建议修复方向（供第二天的人参考，非结论）

fingerprint 拆两半：guest 可见承诺面（timezone/locale/provision script 哈希）供 setup 戳与探针；宿主侧字段留在 running record 的 up 锁。或最低成本：探针降级——配置类漂移报独立的 `Outcome::Drift`（不与逃逸混同），提示 re-setup 而非 re-stop。
