# B 类反检测立项调研（2026-11-27）

调研目标：creance 要为"平台方反自动化检测"（Cloudflare/Google/X 风控）
做多少工程、按什么顺序做。方法论：只立项能在架构上闭环的项，不为
军备竞赛层做承诺。

## 架构事实（决定一切的前提）

```
guest-app ──TLS──> mihomo(loopback) ──tunnel──> exit-node ──> target
```

目标站看到的 TLS ClientHello 是 **guest 应用自己**的（隧道端到端），
不是 mihomo 的。所以指纹工程必须在 **guest 应用层**做，代理层做无可做。

## 社区现状核查

| 工具 | 状态 | 结论 |
|---|---|---|
| curl-impersonate | 停更 2024-07，指纹停在 Chrome 99-116 时代 | **死路**：过期指纹本身即检测信号 |
| uTLS (refraction-networking) | Go 库，活跃 | 与我们 Rust 栈不兼容，且无 Rust 等价物 |
| Camoufox | 13.7k★ 极活跃，C++ 级指纹注入（navigator/screen/WebGL/fonts/audio 全在 C++ 应答，JS 层零痕迹） | 架构正确但它是 **Firefox+自动化驱动**——与我们 CfT/Chrome 用户驱动模型不合 |
| patchright/undetected-chromedriver | 自动化检测补丁 | 打的是 CDP 痕迹，我们的浏览器不是自动化驱动的，不适用 |

## 按检测权重映射我们能做的

| 风控信号 | 权重 | 我们的现状/可做 |
|---|---|---|
| **IP 信誉** | 最高 | 不取决于我们——但**可测量**：出口 IP 风险评分进 gate 证据层（L3，见下） |
| **TLS ClientHello** | 高 | **浏览器路径已是满分**——真 Chrome 的 ClientHello 就是真 Chrome。缺口在非浏览器客户端（L2） |
| **浏览器指纹面** | 高 | **有真缺口**：VM 图形栈暴露 llvmpipe WebGL renderer、字体集稀疏、无 GPU——这些是"身处 VM"的强信号，且可被采集（L1） |
| **行为时序** | 中高 | 属 agent 使用模式，不在基础设施层；最多做节流整形，记档不做 |
| **账户/Cookie 历史** | 高 |  persona 持久化已解决（identity seed + bundles），天然合规 |

## 关键认知：浏览器路径已接近正确

CfT Chrome 在 guest 里跑 headful（Xvnc）——它的 TLS、HTTP/2、绝大部分
指纹面**就是真 Chrome**，不需要伪造。B 类的真正缺口集中在：

1. **VM 图形指纹**：WebGL `UNMASKED_RENDERER` = `llvmpipe/SwiftShader`
   ——消费级设备从不出现，这是比 DMI 强得多的 VM 信号（而且 JS 可读，
   DMI 读不到）。canvas/audio 噪声、字体清单、屏幕尺寸同理。
2. **非浏览器客户端**：agent 用 curl/python/node 直接打目标站时
   JA3/JA4 是库指纹不是浏览器指纹。维护中的拟真客户端生态贫瘠
   （curl-impersonate 已死）。

## 立项建议（按价值/成本比排序）

### L3 出口 IP 信誉探针（先做，小切口高价值）
- 在 gate 证据层加第三源：ipinfo/同类 API 的 `privacy`/`hosting` 标志
  ——出口 IP 是数据中心标记时对用户亮黄牌（不 fail，告警）。
- 成本：小（复用 trace 双源架构）；价值：用户第一时间知道自己的
  节点质量——这是 B 类防御里权重最高又最便宜的一项。

### L1 浏览器指纹面 persona 化（主工程）
- 目标：guest 浏览器应答的指纹值与 identity_seed 绑定的"设备画像"
  一致——WebGL renderer 报一个真实消费 GPU（按 SMBIOS OEM 故事
  配套：Dell→Intel UHD 等）、字体集、屏幕、hardwareConcurrency。
- 路径选项：
  a. **CDP/启动参数注入**（Page.addScriptToEvaluateOnNewDocument +
     flag 集）——低成本，但有 JS 层痕迹可被深度检测识破；
  b. **补丁级 chromium 构建**（Camoufox 路线）——干净但变成维护
     一个浏览器发行版，超出当前体量；
  c. **混合**：启动参数 + WebGL 参数钩子 + 字体包补齐——覆盖
     浅中层检测，承认深度对抗不承诺。
- 建议：(c)，并把"不承诺过最高等级风控"写进文档——诚实边界。

### L2 非浏览器客户端（记档，暂不做）
- 维护中的拟真客户端生态贫瘠；Rust 侧无成熟 uTLS 等价物。
- 替代设计：文档引导——敏感站点交互一律走 guest 浏览器（OAuth
  通道已具备该能力）；agent 的 HTTP 客户端流量如实上报是"工具
  指纹"，对其目标站诚实的策略优于半吊子伪装。
- 重估触发器：curl-impersonate 复活 / Rust TLS 指纹库成熟。

## 决策点（需要用户拍板）
1. L3 先做有没有异议？（我的答案：没有，下一版就做）
2. L1 选路径 a/c？（我建议 c）
3. "不承诺过最高等级风控"的边界声明写进 README 是否接受？
