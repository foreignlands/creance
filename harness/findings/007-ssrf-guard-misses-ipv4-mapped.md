# FINDING-007: 订阅重定向 SSRF 守卫漏掉 IPv4-mapped IPv6 — `http://[::ffff:127.0.0.1]:P/` 绕过检查，真实 mihomo 将其规范化为 127.0.0.1 并拨号

- **编号**: 007
- **严重度**: S2（SSRF 守卫绕过；危害链的最后一环依赖 core 对该 target 的拨号策略）
- **攻击面**: B4（重定向 SSRF）
- **发现时间**: 2026-11-19T00:15:00Z
- **发现者会话**: s01
- **状态**: 待修复

## 复现（必须）

探针（端到端）：`harness/tools/a7-response-probe/src/bin/b4-ssrf.rs`（fetch.rs 重定向循环逐行拷贝 + 受害者 listener 计数）。

```sh
cd harness/tools/a7-response-probe && cargo run --release --bin b4-ssrf
# [SSRF-REACHED-VICTIM] v4mapped-loopback -> … victim_hits=1
#   <<< 守卫绕过：连接到达 127.0.0.1 受害者
```

真实 core 确认（DIRECT 规则，mihomo = 生产捆绑的 `target/proxy-core/mihomo`）：

```sh
mkdir -p /tmp/mihomo-b4test
printf 'mixed-port: 17891\nbind-address: 127.0.0.1\nmode: rule\nrules: ["MATCH,DIRECT"]\n' > /tmp/mihomo-b4test/config.yaml
target/proxy-core/mihomo -d /tmp/mihomo-b4test -f /tmp/mihomo-b4test/config.yaml &
# 受害者挂在 127.0.0.1:17892
curl --proxy socks5h://127.0.0.1:17891 "http://[::ffff:127.0.0.1]:17892/" --max-time 8
# mihomo 日志: "[TCP] 127.0.0.1:60670 --> 127.0.0.1:17892 match Match using DIRECT"
# 受害者: VICTIM-HIT from 127.0.0.1
```

- **期望**: 守卫（fetch.rs:50-70）把重定向 target 里的**一切本机/私网变体**拒绝。`::ffff:127.0.0.1` 拨号时被 OS/mihomo 解释为 IPv4 127.0.0.1（实测），必须与 `127.0.0.1` 同等对待。
- **实际**: `bare.parse::<IpAddr>()` 解析为 `IpAddr::V6(::ffff:7f00:1)`，`is_loopback()` 只匹配 `::1` → 放行 → CONNECT 域名模式 → core 规范化后拨号 127.0.0.1（victim_hits=1）。`::ffff:169.254.169.254`（云 metadata link-local）同样放行（探针实测挂 30s——本机无 metadata 应答器；真实云环境可达）。

## 根因猜测

`crates/creance-proxy/src/fetch.rs:51-66`：V6 分支的判定集合 `{is_loopback, is_unspecified, is_multicast, ULA(fc00::/7), link-local(fe80::/10)}` 不含 **IPv4-mapped（::ffff:0:0/96）**。`std::net::Ipv6Addr::is_loopback()` 文档语义只覆盖 `::1`；`::ffff:127.0.0.1` 三项判定全 false。而 `to_ipv4_mapped()`（stable since 1.63）一眼即可识别。

**已在真实 core 上确认的机制**：mihomo 对 CONNECT 域名 `[::ffff:127.0.0.1]` unbracket + 规范化为 IPv4 `127.0.0.1` 后拨号（日志为证）。

**危害链说明（诚实分级）**：端到端 SSRF 的最后一环是 mihomo 用**什么规则**拨号该 target：
- 探针的 harness 模拟（MixedProxy 直连语义）与 DIRECT 规则的 mihomo：**连接到达本机**（已实证）；
- 生产配置 `MATCH,CAGE`（唯一出口节点）时 target 交给出口、最终解析发生在出口侧（未实测；若 mihomo 对 private IP 存在内建直连旁路则复发）。守卫的存在本身说明作者的威胁模型认定 LOCAL core 会拨号这类地址——在该威胁模型内 mapped 变体完全漏网。

**非问题（已排除）**：十进制 `2130706433` / 八进制 `0177.0.0.1` / 短式 `127.1` / 十六进制 `0x7f000001` 变体**全部被拒**——不是 fetch.rs 的功劳，而是 `url::Url::join`（WHATWG 解析器）在 `next.host_str()` 之前就把它们规范化成 `127.0.0.1`，守卫的 IP parse 正常命中（探针实测 4 变体全部"已拒绝"）。zone-id 变体被 join 的 IPv6 校验拒绝。

## 未验证想法

- 生产 `MATCH,CAGE` 规则下 mihomo 对 private IP target 的真实路由（可用真实出口节点实测；需要外网环境）。
- `64:ff9b::/96`（NAT64 形式的私网地址）——守卫放行，本机无 NAT64 网关未复现到达；真实 NAT64 部署下语义等同 mapped。
- `IPv4-compatible`（`::127.0.0.1`，非 mapped）——Rust parse 接受、守卫全 false；现代 OS 对该形式不再解释为 IPv4，风险更低（未测）。
- 守卫放行的地址在出口侧被解析后打到的"出口自己的 loopback"——对共享出口（机场）可能构成对**出口宿主**的探测（跨信任边界，值得 G 组讨论）。

## 建议修复方向（供第二天的人参考，非结论）

V6 分支开头加一步：`if let Some(v4) = v6.to_ipv4_mapped() { return reject_v4(v4) }`——把 mapped 家族折叠回 V4 判定集合。顺带评估是否连 `to_ipv4()`（含 compatible 形式）一起折叠，以及 NAT64 前缀是否纳入。
