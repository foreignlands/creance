# STATE — 2026-11-20T00:30:00Z（night-08 修复会话 · 终稿）

## 已完成（R6 全部 4 findings + R6-H4 交互残留，全部 CI RC=0；r6 探针实证复验）

- **F-037 (S2) ✅ f5695a2**：token 启动时入内存（Go 语义）；record 读失败不再退化空串（chmod 000/关闭窗口的 fail-open 链断）；败者不再接受胜者 token。**r6 探针实证：empty-bearer 全链 403**。
- **F-039 ✅ cf8f385**：crates/Cargo.toml 幽灵清单删除；外部 path-dep 实证编译通过（探针已切直连仓库）。
- **F-036 ✅ 4efa224**：①CLI/serve 的 core 重启改为**先 sync 后重启**（换出口时 gate 在旧核心仍在服务时关闭，无"open gate+已换出口"窗口；workbench 原先完全不 sync）；②幂等 sync（无变化）不再无条件关 gate（与注释对齐）；③grant 绑定第一片：SafetyReport 带 run_id+created_at（gate::open 铸造、daemon 在 Checking 窗口内强校验、内外 report_id 对称）——**r6 探针实证：无绑定 grant 409**。Go 的 config 指纹维度=0.6 授权集对齐。
- **F-038 ✅ 373769d**：单目的地采样边界如实声明（TLS 只证"真到 Cloudflare"、核心单组只证"同节点"、节点对不同目的地差异化路由不可检测）；grant 证据键加 exit_sample=1.1.1.1-path 审计标注。二源交叉=0.6。
- **R6-H4/F-033 补丁 ✅ eab85aa**：fingerprint 含 proxy_revision→常规 select 后 setup 戳恒漂移（探针恒红）；up 时刷新戳（up=配置生效时刻），真实漂移仍由 check_running 在 up 顶部拦截。回归测试两态。

## 版本

v0.5.2（tag）：night-08 hardening。39/39 findings 六轮全闭环（R1 14+R2 4+R3 5+R4 4+R5 4+R6 4+夜修自发现 4）。

## 下一步（按序 3 条）

1. **R7 回归审查**：night-08 修复面（token 内存化的启动窗口、sync 先行的失败分支、幂等判定新语义、grant 绑定的时间源、戳刷新与 check_running 的竞态）+ 未尽项（Go 授权集完整对齐面、二源交叉设计审查、mihomo external-controller-unix 暴露面——R6 未验证想法）。
2. **0.6 multi-env/snapshots**（RELEASES 顺延主题）或 **Go 授权集完整对齐**（F-036 的 11 项+三维）——按用户节奏。
3. 模型驱动逃逸演练 + Devin 介入（用户定时）。

## 关键记忆（≤8 条）

1. R6 探针模式（path-dep 真实 crate + /tmp 快照绕幽灵清单）在 F-039 修复后可直连仓库——后续审查探针直接 path-dep。
2. grant 绑定的时间源：SystemTime now 与 CHECK_LEASE 窗口比对；created_at==0（serde default）天然被拒——旧版调用方（无绑定）自动失效，需同步更新所有 grant 构造方（本次只有 gate::open 一个）。
3. sync 先行的新语义：sync 失败（409）也照常重启核心——失败意味着"需重启环境"，核心重启无害；gate 已被 close。
4. `up` 刷新戳的语义边界：check_running 先拦（运行中改配置要求 stop），刷新只发生在"合法 up"路径——两者顺序（check_running 在前）保证了不会把违规漂移洗白。
5. token 内存化后 record 文件只是"发现凭证"（客户端用），服务端不再依赖它——record 损坏/不可读不影响运行中的 gate（仍可被 close_gates 的 daemon_serving/文件清理处理）。

## 会话统计

- night-08：5/5（036/037/038/039+H4 补丁），5 commit（f5695a2→eab85aa），每 commit 完整 ci.sh RC=0
- 累计 39 findings 全修复；环境无残留（daemons=0）
