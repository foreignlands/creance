# F-051 — F-044 拒绝后的法定恢复路径不可达：全仓库无实例删除命令，`creance setup` 对存量实例必然失败（limactl create 不重建）——漂移用户被指向死胡同

- **严重度**：S5（可用性/语义：fail-closed 方向正确，但修复指引"请先 creance stop 再 creance setup 重建环境"在存量实例上不可完成；诚实红永久滞留，唯一出路是 QUICKSTART 的"删整个 profile 目录"）
- **攻击面**：night-10 F-044/F-045 修复面闭环（任务书 A1/A2 的"语义闭环"项）
- **状态**：待修复（低优先；与 F-049 联动——修 fail-open 时提示语会引更多用户进此死胡同）
- **基线**：v0.5.4 `35a02f8`（完整 `sh scripts/ci.sh` RC=0）
- **复现**：源码盘点（无需 VM；limactl create-存量-失败语义未实机重放，见"验证等级"）

## 结论一句话

F-044 修复把"guest 字段漂移"的处理从静默洗绿改成拒绝启动并指向 `creance setup`，但 **setup 从未支持重建**：`cmd_setup`→`setup_instance`（stage yaml）→`vm::create`（裸 `limactl create <yaml>`，vm.rs:232-238）——Lima 对已存在实例目录的 create 报"already exists"（limactl create 拥有实例目录，见 lima.rs:234 注释），create 返回非零→**stamp 不重写、旧 VM 原样、setup 失败**。全仓库（main.rs/vm.rs/lima.rs）无 delete/destroy/replace 命令（grep 证实），QUICKSTART 唯一的重来路径是"`creance stop` 后删 profile 目录"——把 workspace 一起删掉。即：改时区→up 拒→setup 失败→诚实红+guest 不可用，直到用户自find出删目录。

## 路径盘点（全链源码）

1. `cmd_setup`（main.rs:550-590）：load config → guest profile → stage yaml → `create` → create==0 才写 stamp。无删除分支。
2. `setup_instance`（lima.rs:217-245）：预算检查→stage→返回 yaml 路径。无删除分支。
3. `vm::create`（vm.rs:232-238）：`run_attached(profile, ["create", yaml])`。limactl create 语义=新建；存量实例→error（lima.rs:234-235 注释自证"limactl create owns the instance directory"）。
4. grep delete/destroy/reset：仅测试内 remove_dir_all。CLI 无子命令。
5. setup 的文档口径（main.rs setup 消息与 F-044 修复文案"re-run setup after creance stop to re-pin"）从未与 setup 的实际能力对齐——F-033/F-040/F-044 三轮都复述了这句指引，没人验证过它走不走得通。

## 验证等级（诚实）

- "setup 对存量实例失败"的最终锚定需要实机（limactl create on existing instance）；本轮以源码+lima.rs:234 注释+limactl 公认语义三级论证，未烧 VM 重放。修复时顺手实机确认即可。
- 此 wart 先于 night-10 存在（setup 语义未改），但 F-044 让它从"没人走的路径"变成"错误消息指定的法定路径"——修复面闭环（F-045 首启供给→re-setup→重供给）的最后一环实际断开。

## 修复方向（记录，不实现）

1. `cmd_setup`：存量实例时先 `limactl delete -f <instance>`（或 `--force` recreate）再 create——删的是 VM 磁盘不是 workspace（workspace 在 host 侧 environment_dir，virtiofs 挂载，不受影响）。删除前要求 stop。
2. 或最小修：setup 检测存量实例→明确报错文案"先 creance delete（或删 profile）"并把 delete 做成命令。
3. 回归：实机"漂移→up 拒→setup 重建→up 过→探针 Contained + cage-env.sh 三字段落地"全链一遍（同时兑现 F-049 修复方向 3）。

## 关联

- F-044（拒绝指引的可达性）、F-045（首启供给闭环的最后一环）、F-049（fail-open 修复后指引流量增大）、F-033/F-040（同指引的历史复述者）。
