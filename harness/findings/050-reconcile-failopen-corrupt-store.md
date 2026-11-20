# F-050 — gate-open 对账对 store load 失败 fail-open：corrupt sources.json 一个文件即把 night-09+night-10 两次对账（含采样后二次对账）整体致盲

- **严重度**：S4（同 uid 边界内修复链的覆盖面残余——单文件腐化使 F-042/F-046 修复的主要威胁通道（PUT 重载）免检出重新开放；边界仍受 F-046 残余面 4 的同 uid 设计地板约束，如实记档）
- **攻击面**：night-10 F-046 修复面回归（任务书 A3）· night-09 F-042 修复链
- **状态**：待修复
- **基线**：v0.5.4 `35a02f8`（完整 `sh scripts/ci.sh` RC=0）
- **复现**：假核心在环 `harness/tools/r9-regression` h4.1/h4.2 + 源码读（cmd_gate 两处 `if let Ok`）

## 结论一句话

`cmd_gate` 的**两处**对账都写成 `if let Ok(store) = creance_proxy::load(&profile)`（main.rs:291、main.rs:305）：load 返回 Err 时**静默跳过对账**，observe→evaluate→grant 照跑。而 `load` 对"存在但损坏"（非 JSON/超 32MiB/version≠1/auth 非 48hex）返回 Err（store.rs:125-132）——同 uid 翻转者写坏一个 `sources.json`，即可在 PUT 重载 evil yaml（F-042 实验四的规则级/直连级翻转）之后让出口证据采样在零对账下通过评估并授予 gate。修复链的"对账"通道被单文件致盲，恢复到 night-09 之前的可翻转面。

## 探针实证（r9-regression）

```
h4.1 sources.json 损坏 → load=Err（CLI 两处 if let Ok 全跳）        PASS ← 洞成立
h4.2 sources.json 缺失 → Ok(默认 store) → check_running 仍被 selection 拒 PASS ← 缺文件形态 fail-closed（不对称）
```

h4.2 的对照说明设计者想到过"store 不在"的形态（默认 store 的空 selected 必被 selection 检查拒），但**只防住了缺失、没防住损坏**：缺失→Ok→对账跑→拒；损坏→Err→对账不跑→不拒。

## 可达性与界限（如实）

- 威胁者=同 uid 进程（F-042 已锚定的翻转者），写 dir(profile)/sources.json 与写 proxy/config.yaml 同权——按 F-046 残余面 4 的结论，同 uid 内"最终地板"仍在；但修复链的全部意义就是把地板逐级抬高（对账使 PUT 重载必须自述合规），本条把这一级整个拆掉。
- 损坏 sources.json 的附带效果（diagnose 失真、proxy 状态报错）不影响 gate-open 主链：cfg（config.json）独立于 store，observe 走 cfg.proxy_url，grant（gate::open）不读 store。
- 二次对账（night-10）与首次对账共享同一 fail-open——TOCTOU 压缩的成果同样可被本条绕过。

## 修复方向（记录，不实现）

1. `cmd_gate` 两处：`match creance_proxy::load(&profile)`——`Err(e)` 一律 `return fail("代理配置不可读，拒绝采样出口证据：{e}")`（与缺失→默认→selection 拒的既有行为对齐成统一 fail-closed）。gate-open 是安全敏感路径，"读不出 store"没有理由放行。
2. 回归：h4.1 变体进 crate 测试（corrupt store → gate-open 拒）；假核心补"损坏 store+诚实核心"与"损坏 store+翻转核心"两形态。

## 关联

- F-042/F-046（本条是其修复链的整体旁路）、F-048（同修复面：对账先要能跑起来+跑起来后要能被信）、F-049（同族形态：up 对 stamp 读失败 fail-open——"读失败放行"模式两连击）、F-046 残余面 4（同 uid 设计地板）。
