# STATE — 2026-11-20T07:40:00Z（R9 纯回归收敛轮 · 终稿）

## 判定：**有新洞（4 条，048–051）→ 不满足停止条件，建议继续 R10**

R9 按任务书只查 night-10 四个修复面，不做新方向。四面全查尽，其中两面干净、
两面各出洞——**F-046 修复面出了重大回归（048）：night-10 的 /rules 对账对真实
核心恒假，gate-open 主路径 100% 不可用（fail-closed）**。

## 四面结论（各一句话）

1. **F-044 面**：修复主路径有效（漂移+stamp 在 → up 拒，探针红，无半启态，
   空白/尾随空白形态 fail-closed）——但 **stamp 读失败形态双 fail-open（049）**：
   `if let Ok` 跳过检查 + 探针报 NotEnforced 不计失败，rm 一个文件即复活洗绿
   路径；且拒绝指引指向的 re-setup 实际不可达（**051**：无 delete 命令，setup
   对存量实例必败）。
2. **F-045 面**：干净——三个 guest 字段白名单挡全 shell 元字符（8 变体全拒），
   heredoc 定界符带引号（供给时不展开），首启供给闭环成立（cage-env.sh 由
   provision 首启写出）；与 F-044 拒绝的语义闭环差最后一环（051 的 setup 重建）。
3. **F-046 面**：**重大回归（048）**——真实 mihomo `/rules` 返回
   `{"rules":[…]}` 包装对象，修复按裸数组断言 → check_running 恒
   Err("readiness: rules") → gate-open 全灭、proxy-start no-op 判定永不命中；
   实机冒烟+假核心双实证。修复 diff 零测试行、假核心不答 /rules、无真实冒烟
   （任务书明写"别猜"，CI 全绿=该路径零覆盖）。另 **对账对 load 失败
   fail-open（050）**：corrupt sources.json 单文件致盲两次对账。二次对账位置
   ✓（observe 后 evaluate 前）；GROUP 单常量一致 ✓。
4. **F-047 面**：干净——事务性成立（close 先行且致命：拒答假守护 → Err →
   select 不落地；close 成功+select 失败 = gate 已关+节点未换，一致
   fail-closed；store/config 原子+回滚（store.rs:397-413）；未知节点校验先于
   落盘；死记录就地清理）。

## 本轮产出

- findings 048/049/050/051（INDEX 已更新）
- `harness/tools/r9-regression`（13/13 PASS：H1 形状在环 / H2 stamp 矩阵 /
  H3 事务库侧件 / H4 fail-open 输入 / H5 白名单注入；真实形状来自
  2026-11-20 target/proxy-core/mihomo 实机冒烟，响应原样捕获在 048）
- 基线：v0.5.4 `35a02f8` 完整 `sh scripts/ci.sh` RC=0
- harness/ 变更未提交（审查员只写 harness/，提交留给修复会话惯例）

## 下一步（按序）

1. **R10 修复轮**（优先级序）：048（P0，gate-open 瘫痪——取 body["rules"]
   +真实响应固化单测）→ 049（stamp 读失败 fail-closed+探针改 Escaped+setup
   写戳失败改 fatal）→ 050（load Err 统一 fail-closed）→ 051（setup 重建：
   limactl delete -f 再 create，实机全链"漂移→拒→重建→绿"一遍）。
2. R11 纯回归复用 r9-regression（h1.1 真实形状必须转绿；048 修好后 F-046
   的 h4.* 负对照语义要重校）。
3. R11 无新洞 → 写"审查收敛，建议停止循环"（停止信号），剩余风险清单沿用
   STATE-r8（同 uid 设计地板、单源采样、二源交叉）。

## 关键记忆（非显然事实，≤10）

1. 真实 mihomo `GET /rules` = `{"rules":[{index,type:"Match",payload:"",proxy,size:-1,extra:{...}}]}`——
   包装对象 + MATCH 的 payload 是**空串**；`type` 值是 "Match"（混合大小写）。
2. `serde_json::Value::as_array()` 对对象返回 None——`is_some_and` 把"形状
   不符"静默折叠成 false，不 panic 不报错，恒假检查全绿过 CI。
3. escape.rs 的 Outcome 语义：NotEnforced **不计入失败**（exit 0）——任何
   "探针不绿但不红"的形态都是洗绿候选；"only FS/gate probes may be
   NotEnforced"注释与 fingerprint 探针的缺失形态矛盾。
4. `if let Ok(...)` 是 creance 安全检查的高频 fail-open 形态（up 的 stamp、
   cmd_gate 的 load，两连击）；对照：缺失 sources.json→默认 store→selection
   拒（防住了），损坏→Err→跳过（没防住）。
5. macOS 上 UnixListener::set_nonblocking 后 accept 出的流继承非阻塞——
   read_to_end 立即 WouldBlock 返回已读字节，假核心模式因此可用（r8/r9 同款）。
6. 全仓库无 VM 实例删除命令；`creance setup` 对存量实例必败（limactl create
   语义）；QUICKSTART 唯一重来路径=删整个 profile 目录（含 workspace）。
7. store.rs select_and_apply 的原子性：config 先读、store 落盘前存 previous
   字节、config 写失败回滚 store（FINDING-014 修复仍在位）。
8. guest 三字段白名单（timezone=zoneinfo 文件或 alnum/_/-、locale=alpha_
   alpha.UTF-8、language=^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$）在字符集层挡死
   shell 元字符——cage-env.sh 注入面闭合。
9. GROUP="CAGE" 单常量（store.rs:14）贯穿生成（runtime.rs:110/225）与对账
   （service.rs:167）——无漂移。
10. gate::open（gate.rs:960）不做对账——对账唯一执法点在 CLI cmd_gate；
    workbench 无 gate-open 路由。

## 会话统计

- R9：4 findings（048 S4 / 049 S4 / 050 S4 / 051 S5），0 修复（审查员不修）
- 累计 51 findings；47 已修复 + 4 待修复（R10 单）
- 探针 13/13 PASS（预测全中）；CI 基线 RC=0
