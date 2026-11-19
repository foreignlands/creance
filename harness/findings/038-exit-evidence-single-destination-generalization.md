# FINDING-038: 出口证据信任边界量化——单目的地采样被泛化为全流量锚定，出口节点可差异化路由洗白大陆出口；MITM 伪造与 parse 层已被验证封死

- **编号**: 038
- **严重度**: S4（设计边界：语义保证"出口=X"实际只在"出口=X 对 1.1.1.1"上成立）
- **攻击面**: R6-A1（trace 伪造/信任假设量化）
- **发现时间**: 2026-11-19T15:40:28Z
- **发现者会话**: R6
- **状态**: 待修复（指注释与文档层面承认该边界；协议层已封死部分记录在案）

## 量化结论（本轮三项验证 + 一条开放路径）

**已封死（验证过，非猜测）：**
1. **MITM 伪造 trace 不可行**：`crates/creance-net/src/egress.rs:616-630` TLS 用 webpki-roots 全量校验（无 dangerous verifier）；CONNECT 1.1.1.1:443 后恶意代理重定向到自己的服务器 → 证书校验失败 → observe 报错 → gate 保持关闭（fail-closed）。任务书假设的"假代理返回自定义 trace body"在协议层不成立。
2. **核心内差异化路由不可行**：runtime.rs:68-102 生成的 mihomo 配置单 select 组（仅选中节点）+ 单 `MATCH,<GROUP>` 规则，DNS 也走同组（`https://1.1.1.1/dns-query#GROUP`）——evidence 路径与 wire 路径在核心内强制同路。
3. **parse_trace 对畸形 body fail-closed**：探针 H1 全 15 项 PASS（真实函数）。BOM 前缀/键前导空格/`IP=` 大小写/v6/3 字母 loc/值内嵌 junk/空 body → 全部 Err；`\r\n` 正常；非 ASCII `µs`（3 字节）被 len 判拒；`loc=zz` parse 层接受但 `check_exit_country`（exit_policy.rs:263-266）拒 ZZ/XX；值前导空格 trim 后接受（宽松点，无安全增量）；重复键 last-wins（攻击者本控制全文，无增量）。

**开放路径（本 finding 的核心）：**
4. **出口节点自身的差异化路由不可检测**：TLS 保证的是"连接真实终止于 Cloudflare"，不保证"到达 Cloudflare 的路径=其它流量的路径"。恶意出口节点对 `1.1.1.1:443` 的连接经自己的美国 VPS 中转（Cloudflare 看到美国 IP），其余流量直连本地接口（真实出口可在大陆）——证据采样点与真实出口在**节点以外**分叉，锚定被洗白，强制大陆拒绝（exit_policy.rs:228 注释"mandatory regardless"）对被操纵订阅静默失效，审计记录写入假 exit_ip/exit_country。

## 根因

`crates/creance/src/evidence.rs:4-12` 注释声明了单源信任，但把边界表述为"trusts the proxy path to reach 1.1.1.1 ... the same trust the wire itself rests on"——**低估了一档**：wire 的信任是"流量经过代理"，锚定的信任是"代理运营者对所有目的地同路路由"，后者是未声明、未度量、不可用单源法度量的附加假设。trace 是**单目的地采样**，gate 把它泛化到全部流量。

## 复现

- 第 1/3 项：`harness/tools/r6-evidence-probe/`（H1 段 + tls_config 源码行）。
- 第 2 项：`crates/creance-proxy/src/runtime.rs:97-102` 源码即证。
- 第 4 项：不可在本机复现（需受控恶意出口节点）；逻辑上由 TLS+核心配置的两项验证**排除其余伪造路径**后唯一开放。作为设计边界记录，不作为可复现 bug。

## 未验证想法

- 二源交叉（如经同一 tunnel 拉 `https://www.cloudflare.com/cdn-cgi/trace` + 一个非 Cloudflare ip-echo，比对一致性）可检测节点级差异化路由的多数变体；两个源仍可能被同一个节点同时差异化——彻底封闭需把"出口位置"语义改为"到受信锚的路径位置"。
- mihomo `external-controller-unix`（runtime.rs:90）暴露的核心控制 socket 权限未在路径上审计——若可被同 uid 进程改路由（reload 规则），则核心内差异化路由也可行（探针未覆盖；与 F-037 同一信任域）。

## 建议修复方向（供第二天的人参考，非结论）

短期：注释如实声明"单目的地采样+节点同路假设"；审计事件把 exit_ip 标注为"1.1.1.1 路径样本"。中期：第二独立源交叉验证 + 检测核心 external-controller 的额外暴露面。
