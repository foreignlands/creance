# STATE — 2026-11-20T07:40:00Z（R9 纯回归收敛轮 · 终稿）

## 判定：**有新洞（4 条，048–051）→ 不满足停止条件，建议继续 R10**

R9 按任务书只查 night-10 四个修复面，不做新方向。四面全查尽：两面干净
（F-045 / F-047）、两面出洞（F-044 / F-046）。**重大项 048：night-10 的
/rules 对账按裸数组断言，真实 mihomo 返回 `{"rules":[…]}` 包装对象 →
check_running 对诚实核心恒 Err → gate-open 主路径 100% 不可用（fail-closed）**。

## 新发现

- **048 S4**：/rules 对账形状回归（实机冒烟+假核心双实证；修复 diff 零测试行，
  任务书明写"别猜"）——P0。
- **049 S4**：F-044 修复对 stamp 读失败 fail-open（up 跳过检查+探针
  NotEnforced 不计失败）——rm fingerprint.txt 即复活洗绿路径。
- **050 S4**：cmd_gate 两处对账 `if let Ok(load)` fail-open——corrupt
  sources.json 单文件致盲 night-09+night-10 对账链。
- **051 S5**：F-044 拒绝指引的 re-setup 不可达（无 delete 命令，setup 对存量
  实例必败）；F-045 首启供给闭环差最后一环。

## 四面结论

1. F-044 面：主路径有效；stamp 异常态双 fail-open（049）+ re-setup 死胡同（051）。
2. F-045 面：干净——白名单挡全元字符（8 变体）、heredoc 带引号、首启供给闭环成立。
3. F-046 面：048 重大回归 + 050 fail-open；二次对账位置 ✓、GROUP 单常量 ✓。
4. F-047 面：干净——事务性成立（close 致命/原子+回滚/未知节点拒/死记录清理）。

## 本轮产出

findings 048–051（INDEX 已更新）；`harness/tools/r9-regression`（13/13 PASS，
真实形状来自 2026-11-20 实机冒烟）；基线 v0.5.4 `35a02f8` 完整 ci.sh RC=0；
harness/ 变更未提交（提交留给修复会话惯例）。

## 下一步（按序）

1. **R10 修复轮**：048（取 body["rules"]+真实响应固化单测，P0）→ 049（stamp
   读失败 fail-closed+探针 Escaped+setup 写戳失败 fatal）→ 050（load Err 统一
   fail-closed）→ 051（setup 重建：limactl delete -f 再 create，实机全链）。
2. R11 纯回归复用 r9-regression（h1.1 必须转绿；F-046 的 h4.* 负对照语义重校）。
3. R11 无新洞 → STATE 写"审查收敛，建议停止循环"；剩余风险清单沿用 STATE-r8。

## 关键记忆

真实 /rules 形状=`{"rules":[{index,type:"Match",payload:"",proxy,size:-1,extra}]}`（MATCH
payload 空串）；as_array() 对对象=None→is_some_and 静默恒假（不 panic、CI 绿）；
NotEnforced 不计失败=洗绿候选（escape.rs:459）；`if let Ok` 是 creance 检查的
高频 fail-open 形态（stamp/load 两连击）；macOS accept 流继承非阻塞（假核心
模式可用的根因）；全仓库无实例删除命令、setup 不重建存量实例；select_and_apply
原子性在位（store.rs:397-413）；guest 三字段白名单在字符集层挡死注入；GROUP 单
常量无漂移；对账唯一执法点在 CLI cmd_gate（gate::open 不查，workbench 无路由）。

## 会话统计

R9：4 findings（048/049/050 S4，051 S5），0 修复；累计 51（47 修复+4 待修）；
探针 13/13；CI 基线 RC=0。
