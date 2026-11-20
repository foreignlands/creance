# F-046 — night-09 check_running 对账集不含 /rules：保 mode=rule + 伪装组选择的规则级重载自述可穿透对账（对账=对核心自述的对账）

- **严重度**：S4（边界=同 uid；night-09 修复对**已记录**攻击有效——负对照实测；本条是修复覆盖面之外的残余，非修复回归）
- **攻击面**：F-042 修复面回归（任务书 A3）· F3（控制通道）· F-038（单源证据边界）
- **状态**：待修复（0.6 硬化面；与 go-authz-alignment.md 三维绑定同批权衡）
- **基线**：v0.5.3 `985a5a2`
- **复现**：假核心在环，`harness/tools/r8-regression` h4.1/h4.2/h4.3（真实 `service::check_running`；无需真核心——信息集论证由 API 语义唯一决定，真核心行为已由 F-042 实机实验锚定）

## 结论一句话

night-09 的修复（`0493bf7`+`ac0d2ef`）给 gate-open 加了前置对账：`check_running` 现含 `mode=="rule"`，对 F-042 已记录的 `PATCH mode=direct` 有效（h4.3 负对照：拒 ✓）。但对账的**信息集**只有 `/configs` 的五字段（mixed-port/interface-name/mode/unified-delay + `/proxies/CAGE` 的 now）——**从不查询 `/rules`**（h4.2 实证）。于是 F-042 实验四的变体成立：同 uid 进程 PUT 一份 evil yaml（`mode: rule`、同端口、同 interface、`unified-delay: true`、保留名为 CAGE 的 selector 组并预选回 `store.selected`、`rules: [MATCH,DIRECT]` 或 MATCH→evil-chain），五字段自述与 store 全等 → `check_running` 通过 → gate-open 照常采样放行，而核心实际路由已被替换。**对账=对核心自述的对账，而自述完全受同一翻转者控制**（同源限度：check_running 经同一可翻转的 controller 查询）。

## 探针实证（假核心在环）

```
h4.1 规则级翻转形态的自述通过对账                     PASS（check_running=Ok）← 残余成立
h4.2 对账从未查询 /rules                            PASS（queries 仅 /configs + /proxies/CAGE）← 盲区实证
h4.3 mode=direct 自述被拒（night-09 修复有效）        PASS（Err）← 已记录攻击仍被挡
```

h4.1 的"假核心"自述即规则级翻转核心在 `/configs`+`/proxies/CAGE` 上的必然应答形态（F-042 实机已证 PUT 重载保 `mode` 字段于 evil yaml 所写值；selector 组的 `now` 受同一 API 控制，可预选回 `store.selected`）。

## 三个残余面的完整记档（任务书 A3 全项）

1. **对账集盲区（本条主面）**：`/rules` 不在对账集。修法方向：对账补 `GET /rules` 与生成配置的 `MATCH,{GROUP}` 规则比对（生成侧单 MATCH 结构固定，比对成本一次 API 调用）；或对账补 `/proxies/CAGE` 的完整 proxied 集合与 store.selected 节点集比对。
2. **TOCTOU（check→observe 窗口）**：gate-open 链 = check_running → observe（预算 25s，`evidence.rs:32`）→ evaluate → grant。check 通过后、采样完成前的窗口内翻转核心，采样即受控。但有界且受限：翻转是持久态，**下一次** 90s lease 到期后的 re-open 会重新 check_running——持久翻转必须每次都保持五字段自述合规（=回到残余面 1）。纯时序翻转（check 后翻、观测后翻回）不能供证任何超出残余面 1 的东西。结论：TOCTOU 不独立成洞，它的可达收益完全被残余面 1 吸收。
3. **同源限度**：check_running 经同一 unix controller 查询，控制器认证=文件权限（同 uid）——对账永远只能信"核心此刻的自述"。原则上唯一更强的对账是把生成配置的哈希与核心启动参数绑定（核心加载即哈希锚定），属 0.6 设计面。
4. **SAFE_PATHS 收窄结论（任务书 A3 第 3 项）**：SAFE_PATHS=核心 config 所在目录（proxy/），目录属主即同 uid——**同 uid 威胁边界内不可收窄**（任何子目录/重排布局都同样可写；chmod/chflags 对属主无效力）。现实收窄只剩：去 `external-controller-unix`（同时杀死翻转通道与 check_running 的查询通道——对账退化为端口对账，净收益为负）或核心降权运行（专用 uid，0.6 级改动）。**结论：同 uid 边界内该面已到设计地板，剩余风险如实记档即可。**

## 与 F-038 的关系

F-038 声明"证据=1.1.1.1 路径样本，整体出口取决于订阅的路由诚实性"。本条把该假设再收窄一层：**同 uid 攻击者不需要不诚实的订阅**——可以用一次重载自行安装 1.1.1.1→US-relay、其余→DIRECT 的洗地路由（F-042 实验四的定向版），五字段自述保持全绿。rests-on-the-subscription's-honesty 之下还有 rests-on-the-controller's-surface 一层，0.6 授权集对齐（Configuration 绑定/二源交叉）是收窄它的正道。

## 修复方向（记录，不实现）

1. 对账集补 `/rules` 比对（成本低、即时闭环残余面 1）。
2. 0.6 二源交叉采样（源二不经核心直连对照）——同时收窄 TOCTOU 与洗地面。
3. 观测后、grant 前再跑一次 `check_running`（把 25s TOCTOU 窗压到毫秒级，成本一次 API 调用）。

## 关联

- F-042（本条是其修复面的覆盖边界）、F-038（单源声明的再收窄）、F-041（对账与锚点比较的互补面）、go-authz-alignment.md（三维绑定落点）。
