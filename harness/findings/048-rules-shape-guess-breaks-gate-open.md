# F-048 — night-10 /rules 对账按裸数组解析，真实 mihomo 返回 `{"rules":[…]}` 包装对象：check_running 对诚实核心恒 Err → gate-open 全灭（形状是猜的，零测试零冒烟）

- **严重度**：S4（核心功能不可用——fail-closed 方向，不违反安全契约，但 gate 授予流程 100% 失败；修复 night-10 对真实核心从未验证）
- **攻击面**：night-10 F-046 修复面回归（任务书 A3 明确要求"真实响应形状，别猜"——猜错了）
- **状态**：待修复（最高优先：gate-open 主路径瘫痪）
- **基线**：v0.5.4 `35a02f8`（完整 `sh scripts/ci.sh` RC=0——CI 无此路径测试，所以全绿）
- **复现**：真实核心冒烟（target/proxy-core/mihomo + direct 配置 + unix controller）+ 假核心在环 `harness/tools/r9-regression` h1.1/h1.2

## 结论一句话

night-10 的修复（`68b86cf`）在 `service.rs:164` 用 `rules.as_array()` 断言 **响应体本身是数组**，而真实 mihomo `GET /rules` 返回 `{"rules":[{...}]}` **包装对象**（2026-11-20 实机冒烟，v1.19.x local direct）：`as_array()`→`None`→`honest_routing=false`→`check_running` 恒 `Err("readiness: rules")`——**每个诚实核心都被判"已偏离配置"**。`type=="Match"` 与 `proxy==GROUP` 两个字段名/大小写倒是猜对了，唯一错的是外壳。

## 实机冒烟（真实响应，原样捕获）

```
curl --unix-socket /tmp/r9-rules-smoke/cage.sock -H "Authorization: Bearer <48hex>" http://localhost/rules
{"rules":[{"index":0,"type":"Match","payload":"","proxy":"CAGE","size":-1,"extra":{"disabled":false,"hitCount":0,"hitAt":"1970-01-01T08:00:00+08:00","missCount":0,"missAt":"1970-01-01T08:00:00+08:00"}}]}
```

（配置形状 = runtime.rs 生成形：单 `MATCH,CAGE` 规则 + `CAGE` select 组 + `unified-delay: true` + external-controller-unix + secret。附带事实：MATCH 规则的 `payload` 是**空串**——修复若按 payload=="MATCH" 断言同样会恒假。）

## 假核心在环（r9-regression，预测全中）

```
h1.1 真实形状（包装对象）诚实核心 → check_running=Err("readiness: rules")  PASS ← 洞成立
h1.2 修复假设形状（裸数组）     → check_running=Ok(())                    PASS ← 只对虚构形状通过
```

## 爆炸半径（全链核实）

1. `cmd_gate open`（main.rs:292 首次对账）→ 首查即拒："核心运行态已偏离配置（readiness: rules），拒绝采样出口证据，外网保持关闭"——**gate 永远开不了，guest 无网**。二次对账（main.rs:307）同死。
2. `service::running()` 调用者全线失真：diagnose.rs:80/86（诊断恒报核心偏离）、main.rs:436 与 store.rs:430（proxy-start 的"已运行且匹配=no-op"判定永不命中 → 每次全量重启轮换）。
3. 唯一幸运处：fail-closed——拒绝方向正确，无安全语义破坏。

## 根因链（为什么夜修会 shipped-red-again）

修复 diff `68b86cf` 仅 +24 行源码、**零测试行**：service.rs 无单测，r8-regression 的假核心不答 /rules（R8 时 check_running 从不问它，注释在 r8-regression/src/main.rs:520），无真实核心冒烟。CI 全绿证明的是"没有测试覆盖这条路径"——与 F-024（v0.4.0 终稿未过 CI）同族的**验证纪律缺口**：任务书 A3 白纸黑字写了"本地 direct 冒烟核实 type 大小写/字段名，别猜"，修复会话没跑。

## 修复方向（记录，不实现）

1. `service.rs`：`let rules = api(...)?.get("rules").and_then(|v| v.as_array())` 再套原三断言（len==1 / type=="Match" / proxy==GROUP）。
2. 回归：把本 finding 的实机响应 JSON 原样固化为 service.rs 单测夹具（真实形状→Ok；规则级翻转形状 `{"rules":[{"type":"Match","proxy":"DIRECT"}]}`→Err）；r8-regression 假核心补 /rules 应答。
3. 顺带断言 `payload` 字段存在与否由真核心决定——按实机形状 `payload:""`，不要对 payload 加断言除非另做冒烟。

## 关联

- F-046（本条是其修复的形状回归）、F-042（同链）、F-024（验证纪律同族）、F-050（对账的 fail-open 输入——本条修好后对账才真正"每次都在跑"）。
