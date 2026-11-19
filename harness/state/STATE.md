# STATE — 2026-11-20T03:30:00Z（night-09 修复会话 · 终稿）

## 已完成（R7 全部 4 findings，4 commit；F-042 经实机验证修正修法）

- **F-041 ✅ 887e737**：night-08 回归修复——Unchanged 路径的比较现在包含 exit_policy（normalized 全等才算 Unchanged；锚点任何变化→"需重启"）。R7 矩阵 m1/m3（bound→bound 换锚、mode 迁移）入回归，m4 幂等保持。
- **F-040 ✅ 3306e06**：Config 新增 guest_fingerprint（timezone/locale/browser_language=guest 可感知承诺面）；setup 戳/刷新/探针全部改用——proxy_url/revision/exit_policy 等 host 侧字段不再触发探针红；全量 fingerprint 仍守 running-record 锁（up）。宿主侧操作与 guest 承诺分离。
- **F-042 ✅ 0493bf7+ac0d2ef（实机修正）**：mihomo **unix controller 无视 secret**（v1.19.34 实测 wrong-bearer 200，文件权限即鉴权=设计）——secret 保留（TCP 路径/纵深）+ 注释如实；**真执行面=gate-open 采样前的核心对账**（check_running 现含 mode 比对；被翻转核心不得供证）。
- **F-043 ✅ ac0d2ef**：select_and_apply 落地即 close_gates（CLI 与 workbench 两入口，对齐 Go applyProxy 的同步撤销语义）。

## 过程事故（记档防再犯）

两次 amend 失误：第一次把 F-041 并进已推送的 v0.5.2 release commit（reset --soft tag 救回）；第二次把 F-042 补丁并进 F-043（HEAD 未推送，消息改写如实）。**铁律：commit --amend 前必须 git log -1 确认 HEAD 是"刚才那个未推送的 commit"。**

## 版本

v0.5.3（tag 待打）。43/43 findings 七轮全闭环。

## 下一步（按序 3 条）

1. **R8 审查**（子代理实验——用户指定，主线直接 Agent/Workflow 承载，start-plan 模型）：night-09 修复面回归（guest_fingerprint 字段集边界、Unchanged 锚点比对与 binding_completed 交互、select 撤 gate 的失败分支、gate-open 核心对账的时序）+ F-042 残余（SAFE_PATHS 目录可写面的进一步收窄）+ E/C 收尾。
2. 0.6：Go 授权集完整对齐（11 项+config 指纹三维）或 multi-env/snapshots（按用户节奏）。
3. 模型驱动逃逸演练 + Devin（用户定时）。

## 会话统计

- night-09：4/4（040/041/042/043），4 commit（887e737→ac0d2ef），每 commit CI RC=0
- 累计 43 findings 全修复（R1 14+R2 4+R3 5+R4 4+R5 4+R6 4+R7 4+夜修自发现 4）
- 环境：/tmp/n9* 已清理；无 core/守护残留
