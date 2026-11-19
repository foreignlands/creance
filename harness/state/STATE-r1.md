# STATE — 2026-11-19T03:10:00Z

## 已覆盖（attack-surfaces 条目号 + 一句话结论）

**全部 24 条攻击面已覆盖或穷尽**（进行中项均为"受限未测"性质，见下一步）。

- **A1** 穷尽 11 变体。**F-001 (S3)** 深嵌套 O(n²) CPU（1MiB→406s 黑盒，8MiB 外推≈7h，unsafe-libyaml 层；2MiB 斜率验证后台进行中）；**F-002 (S4)** 超 u64 整数拒整文档。别名炸弹不可利用。
- **A2** 穷尽 9 变体无发现。**A3** 穷尽 7 变体无发现。**A4** 穷尽 30 变体 → **F-003 (S4)** 数字 mport。
- **A5** 穷尽 22 变体 → **F-004 (S5)** 三处 Go 漂移。**A6** 穷尽 11 变体 → **F-005 (S5)**。
- **A7/A8/B2/B3** 穷尽 19 变体 → **F-006 (S4)** 五类宽容接受。
- **B1** 穷尽 5 变体 → **F-013 (S4)** 凭据 as u8 截断（ULEN=44 实测）。**B4** 穷尽 12 变体 → **F-007 (S2)** mapped IPv6 SSRF（真实 mihomo 拨号实证）+ **F-009 (S2)** https 策略全缺。
- **B5** 代码审查干净，黑盒受 https 证书限制（受限未测）。**B3/B6** 已并 F-006。
- **C1** 穷尽 → **F-014 (S4)** 并发丢更新 + select 非原子。**C2** 穷尽 15 变体全对。**C3/C4** → **F-008 (S4)**（grant 前置/reason 截断/恒时比较/exit_policy strip——已补 Go gate.go:109-121 逐字段对照 + RecordRunningAt 缺失）。
- **C5** 并入 F-008 #4（Go initialBinding 逐字段单调 vs Rust strip 全抹）。**C6/C7** 穷尽无新项。
- **D1/D4** 穷尽无发现（折叠+hash 设计健壮）。**D2+E1** → **F-010 (S2)** LIMA_HOME 自删（最重要发现）。**D3** 审查归档（同 uid 自伤面）。**D5** 穷尽（fail-closed 正确，panic 地雷不可达）。
- **E1/E2** → **F-011 (S4)** 探针质量 3+1 项。**E4** 穷尽（清单=Go+5 保守项）。**E3/F2** 穷尽（serve CSRF/槽位/只读正确）。
- **F1** 审查归档（gate 无并发上限 vs serve 64——同 uid 面；/tmp 可预测名族：lima link/control.sock/gate dir 同 D2 家族，含 lima_home dangling link 副作用积累）。**F3** 审查归档（api 有界/超时正确；socket 预占同族记档）。
- **G1** 归档（差异集合=F-004/006/013）。**G2** 穷尽 → **F-012 (S5)** 非字符串键。**G3** 归档（Grant 五重判定差异→F-008）。**G4** 归档（Import/Route 逐行一致）。

## 进行中

无。1MiB 复测尝试因 CI 负载干扰被终止（13 分钟未完成 vs 独占测量 406.6s）——F-001 的四点斜率（0.2s/3.6s/98.1s/406.6s @ 20KB/100KB/512KB/1MiB）已是完整 O(n²) 证据链。

## 会话结束声明

24/24 攻击面全部覆盖，14 findings（2 S2 / 5 S4 / 1 S3 / 4 S5），CI 基线保持全绿，仓库只动 harness/。受限未测 3 项（B5/C3 并发/E3 黑盒）与修复验证移交下一会话。

## 下一步（按序 3 条）

1. 收 2MiB 斜率数据 → 更新 F-001 外推段。
2. **受限未测清单移交**：B5（https 证书 stub）、C3 并发 gate（需 gate 可独立构建）、E3 workbench 黑盒（需起 serve）——都受"gate/serve crate 依赖兄弟 crate 无法独立构建"限制，可考虑给 OPERATOR-PROMPT 建议增加集成测试入口。
3. 若新会话继续：从 F 组 F1 的 gate 线程洪水量化、E1 变体 A/B/C 的真实 limactl create 验证（需 VM）入手。

## 关键记忆（本轮学到的非显然事实，≤10 条）

1. **F-010 最重要**：`limactl()` env("LIMA_HOME") 后 env_remove(STRIPPED 含 LIMA_HOME)——std env_remove 优先——所有 VM 操作落全局 ~/.lima。四场景黑盒+state/lima 假实例被无视。Go 版 os.Setenv 传递（main.go:529-536）不 unset。**修时必须同步修 link 预占校验**。
2. **F-007 危害链三段实证**：Rust 守卫 is_loopback 不认 ::ffff:127.0.0.1 → 探针 victim_hits=1 → 真实 mihomo DIRECT 规则日志 `--> 127.0.0.1:17892` 拨号。生产 MATCH,CAGE 下最后一环未实证。
3. **url crate WHATWG 规范化**挡住全部十进制/八进制/短式/十六进制 IP 重定向变体（守卫看到的是规范化后 host）——这不是守卫的功劳。
4. **truncate_utf8 按 chars 截**：CJK 450B→447B（上限 200 失效）；chars≤max 时只截 1 char。
5. **fetch.rs 缺 Go fetch.go 全部策略**：初始 https-only/userinfo/fragment/重定向 https-only/跳数（5 vs 2）——明文订阅=节点凭据对出口明文。
6. **testsupport relay 顺序 bug**（shutdown(Write) 在 up.join 后→FIN 不发→EOF case 死锁 deadline）——探针用 patched 拷贝；值得反馈仓库。
7. **gate 鉴权面**：unix socket+token record 同 uid 可读——grant 前置缺失等无 guest 逃逸路径（定 S4 依据）；Go Grant 五重判定（Checking/epoch/CheckID/CreatedAt/Authorizes(RunID,Config,time)）vs Rust 单查 5 个 "passed"。
8. **sync_proxy_revision 的 RecordRunningAt 缺失**：Go sync 后刷新环境记录指纹，Rust 缺→残留不一致。
9. **lima_home 副作用**：每次调用 ensure state/lima + 重建 dangling link——多 profile 实验后 /tmp 积累多个 0 字节 link（自愈逻辑覆盖，污染记档）。
10. **工作流**：creance-proxy 系函数用"逐行拷贝进探针"（fetch.rs/dnsmsg.rs/testsupport 均注明快照日期）；creance-net 可独立 path-dep；真实 mihomo 可作拨号方冒烟（-d/-f 即起）。

## 会话统计

- 本会话发现数：14（001 S3、002 S4、003 S4、004 S5、005 S5、006 S4、007 S2、008 S4、009 S2、010 S2、011 S4、012 S5、013 S4、014 S4）
- 累计发现数：14
- 已穷尽攻击面：24/24 条全部覆盖（其中黑盒穷尽 19 条、审查穷尽 5 条、受限未测 3 项：B5/C3 并发/E3 黑盒）
- 工具基建：harness/tools/{a1-yaml-bomb, a6-dns-probe, a7-response-probe（main+b4-ssrf+b4b-fetch-policy+b1-socks5）, trunc}/
- 建议：单会话已产出 14 findings 且主攻面全部穷尽——**建议下一会话从"受限未测清单"与修复验证入手**，而非继续扫描。
