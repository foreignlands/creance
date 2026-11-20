# F-045 — browser_language 被 guest_fingerprint 承诺为"guest 可感知"，但全仓库无任何供给路径；Go 的 CAGE_* env 注入链整条缺失

- **严重度**：S5（承诺面语义真空 + Go 漂移：改 browser_language → 探针红 → 强制 re-setup → 重供给后依然什么都不变）
- **攻击面**：F-040 修复面回归（承诺面边界盘点，任务书 A2 问"还有什么 config 字段漏进/漏出承诺面"）· G4（Go 对照）
- **状态**：待修复（可并入 0.6 授权集/config 指纹对齐）
- **基线**：v0.5.3 `985a5a2`
- **复现**：源码盘点（grep 全仓库），无需运行

## 结论一句话

F-040 把承诺面定义为"{timezone, locale, browser_language} = guest 可感知的全部"（config.rs:122-127 注释），但 grep 证实 **browser_language 在 Rust 仓库除 config 定义/校验/指纹外零消费点**——不进 lima.yaml、不进 provision 脚本、不进 workbench、不进任何 guest 文件。改它→`guest_fingerprint` 漂移→`fingerprint-consistent` 探针红→按提示 re-setup→重建后**依然无任何东西消费它**。承诺既不可感知（对 guest 是空话），又触发真实运营成本（假红强制 re-setup）。

## Go 对照（真漂移，非共同语义）

- Go `internal/cage/guest.go:314-316`：`EnvironmentScript()` = `export CAGE_TZ=… / CAGE_LOCALE=… / CAGE_LANGUAGE=<BrowserLanguage>`，进 `StartScript()` → `GuestProfile.Linux(...)` 落 guest 启动面。**Go 的 guest 可感知 browser_language**。
- Rust `lima.rs provision_script`（lima.rs:139-199）只有 `CLAUDE_CAGE=1` / `CREANCE_SESSION_TOKEN` 两个 export，**CAGE_TZ/CAGE_LOCALE/CAGE_LANGUAGE 整条 env 注入缺失**。OS 层面 timezone（lima 原生字段）与 locale（locale-gen/update-locale）有供给，但 Go 给被 Cage 的 agent 暴露指纹的 env 出口在 Rust 不存在。
- 即 Rust 的三字段承诺面里：timezone/locale=有供给（OS 层）、browser_language=无供给（任何层）。

## 承诺面盘点结论（任务书 A2 的完整回答）

| config 字段 | guest 可感知？ | 供给路径 | 应否进 guest_fingerprint |
|---|---|---|---|
| timezone | 是（OS/lima） | lima.yaml timezone（create 时） | 应（已进）|
| locale | 是（OS） | provision locale-gen（首启） | 应（已进）|
| browser_language | **否（Rust）** | **无** | 现进=空承诺；Go 经 CAGE_LANGUAGE 可感知 |
| proxy_url/proxy_revision | 否（host 侧核心拓扑） | — | 不应（F-040 已排除 ✓）|
| exit_policy | 否（host 侧锚点） | — | 不应（F-040 已排除 ✓）|
| dns_url | **否——连 guest 解析路径都不影响** | core 的 DNS 段硬编码 bootstrap + 1.1.1.1（runtime.rs:49-59，`bootstrap_dns_urls()` store.rs:21-26；cfg.dns_url 只进 host 侧 Egress：fetch/observe） | 不应（F-040 排除正确 ✓；Go store.go:303 同形硬编码，非漂移）|

任务书问"dns_url 影响 guest 解析路径吗"——**不影响**：两版的 guest DNS 拓扑都走 core 的硬编码 DoH，cfg.dns_url 是纯 host 侧采样/订阅解析配置。F-040 把它排除在承诺面外是正确的。

## 修复方向（记录，不实现）

二选一，取决于 0.6 对 guest 指纹的产品意图：
1. **补供给**：provision/start 脚本注入 CAGE_TZ/CAGE_LOCALE/CAGE_LANGUAGE（对齐 Go guest.go:315）——browser_language 承诺兑现，同时恢复 Go 的 agent 指纹 env 面。
2. **缩承诺**：guest_fingerprint 降为 {timezone, locale}，browser_language 移出三字段（探针不再为它红）——承认 Rust 不供给它。当前状态两头都不占：既承诺又无实现。

## 关联

- F-040（承诺面收缩——本条盘点其边界完整性）、F-044（同一探针的时间维假绿；本条是其"字段维"假红）、F-033（stamp 机制）、G4。
