# FINDING-014: store 并发写丢失更新 — 两个并发 import 各报成功、先保存者整个来源被覆盖消失；select_and_apply 非原子（store 写成功后 config 写失败残留不一致）

- **编号**: 014
- **严重度**: S4（正确性/数据丢失；无安全契约破坏——applied 一致性检查会把不一致状态 fail-closed）
- **攻击面**: C1（store 并发写）
- **发现时间**: 2026-11-19T02:45:00Z
- **发现者会话**: s01
- **状态**: 待修复

## 复现（必须）

```sh
T=$(mktemp -d)
export CREANCE_CONFIG=$T/config.json
# 构造两个不同的单节点订阅 a.yaml / b.yaml，然后：
creance proxy-import --name srcA --file $T/a.yaml &   # rc=0 "imported 1 nodes from srcA"
creance proxy-import --name srcB --file $T/b.yaml &   # rc=0 "imported 1 nodes from srcB"
wait
cat $T/proxy/sources.json | python3 -c "import json,sys; s=json.load(sys.stdin); print([x['name'] for x in s['sources']])"
# 实际（多次重复稳定复现）：['srcB']  —— srcA 整个来源消失，两个命令都报成功
```

第二处（同族）：

```sh
creance proxy-import --name srcA --file $T/a.yaml
# 并发：import srcC 与 proxy-select <nodeA> 同时跑（config.json 缺失/损坏时）
# select 的 store 保存成功（selected/revision 已写入 sources.json），随后 config::load 失败返回 Err
# 残留：store.selected/revision = 新值，config.json 无对应 endpoint/revision → applied() 不一致 → gate 关闭
```

- **期望**:
  1. 两个并发 import 都成功时最终 store 含两个来源（丢失更新应被检测/重试/串行化）。
  2. `select_and_apply` 应原子：config 读取失败时不留下已修改的 store（先读 config 再写 store，或失败回滚）。
- **实际**:
  1. 后保存者整体覆盖先保存者（load-modify-save 无锁无 CAS）。
  2. store 已落盘、config 写入被跳过，进入不一致状态（`applied()` 的 revision/endpoint 校验会 fail-closed 关闸，但用户需重新 select 才能恢复）。

## 根因猜测

1. `crates/creance-proxy/src/store.rs:114-134`（`load`）+ `137-150`（`save`）：无文件锁、无版本比对——CLI import、workbench import（serve.rs:136-162）、refresh（main.rs:394-440）三个入口都是独立进程 load-modify-save。`write_private`（temp+rename）保证了**单次写入**的原子性，但**读-改-写序列**没有互斥。
2. `crates/creance-proxy/src/store.rs:326-343`（`select_and_apply`）：`save(profile, &store)` 先于 `config::load(config_path)`——顺序颠倒导致部分完成状态。
3. 对照：Go 版 store.go 的锁机制（未逐行核对，本 finding 未声称漂移——Rust 侧独立缺陷）。

**触发面**：CLI 与 workbench 同时操作、refresh 定时器与用户操作竞争、脚本批量导入。危害=静默丢来源（用户以为导入成功）+操作非原子的残留不一致。

## 未验证想法

- 并发概率与真实用户节奏（两次 import 间隔 <load-save 窗口 ~10ms，人为并发可稳定复现；自然触发概率低但 refresh 定时器使窗口常态化）。
- flock/单实例锁（lockfile at profile）是否与 Go 版一致。
- select_and_apply 在 config 存在但 validate 失败时的残留形态（应同 fail-closed，未单测）。

## 建议修复方向（供第二天的人参考，非结论）

1. profile 级 flock（`fcntl` LOCK_EX 包住 load-modify-save 序列），或 store 里加 monotonic `store_version` 并在 save 前 CAS（load 时记录、save 时比对 rename 前文件）。
2. `select_and_apply` 调整顺序：先 `config::load` + 组装好新 config，再连续写 store+config；任一失败则两者都不写（或按已写的反向回滚）。
3. `start_managed` 的 save+write_private_config 序列同理审查（store.rs:349-367，同族非原子）。
