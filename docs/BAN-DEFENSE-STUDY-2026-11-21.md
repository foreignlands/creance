# 封号防御研究 — 2026-11-21

三源调研：Claude Code v2.1.88 泄露源码（本仓同工作空间 `claude-code-src_1121`）
逐行扫描 + Claude-Cage 上游 433 个 issue 分析（`claude-cage-upstream_1121`，
HEAD 4250715 / v0.2.0-rc）+ 社区封号报告互证。所有源码结论带文件:行号。

## 一、封号机制全景（按信号强度排序）

### 1. 账号-设备绑定（最强；网络防御不可及）
- 每个请求体带 `metadata.user_id = {device_id, account_uuid, session_id}`
  （`src/services/api/claude.ts:503-528`）。device_id 是 `~/.claude.json`
  里的 `userID`（`randomBytes(32)` 持久随机，`src/utils/config.ts:1757`）。
- **"多设备/共享账号检测" = 同一 account_uuid 出现多个 device_id**。
  纯服务端判定；换 IP 无用；VM 重建随机重生 device_id 反而制造"新设备"。
- OAuth 账号信息（org/account uuid、email、订阅档）经
  `/api/claude_cli/bootstrap` 拉取后进入所有遥测与 GrowthBook 属性。

### 2. 客户端真实性证明（不可伪造）
- 消息指纹：`SHA256('59cf53e54c78'+…)[:3]` 硬编码盐（`fingerprint.ts:8`），
  声明"须与后端校验一致"。
- `cch` 原生 attestation：请求体里的占位 `cch=00000` 由 Bun 原生 HTTP 栈
  （Zig 层）覆写为计算哈希（`constants/system.ts:62-82`）。**改写 body 的
  中转站无法复现 → 中转流量自带"非真客户端"标记。**
- `cc_version/cc_entrypoint/cc_workload` 藏在 system prompt 首块——社区
  所谓"文本隐写"即此。

### 3. 中转站检测（源码实锤，社区互证）
- GrowthBook remoteEval 的 targeting attributes 含 **`apiBaseUrlHost`**
  （`growthbook.ts:439-449`）：`ANTHROPIC_BASE_URL` 的 host 名本身被上报
  给官方。即使把推理指到中转，bootstrap/GrowthBook/1P 遥测仍打
  `api.anthropic.com`。
- **推论：任何"中转站"路线在协议层自曝；纯 IP 层代理（SOCKS5、不改
  base URL）不触发此信号。**

### 4. 环境指纹（遥测元数据）
- 每个遥测事件带 platform/arch、**Linux 发行版 id/版本/内核**、终端、
  包管理器、node 版本、CI/WSL、**git remote URL 哈希 `rh`**（`metadata.ts:492,739`）、
  GitHub Actions actor/repo id。
- 客户端不采集 MAC/主机名/用户名（2.1.88 实测）；时区不在请求体。
  社区报告的"时区/Unicode/日期格式"判定属服务端启发式，无法从客户端
  证实，但与请求时间模式分析一致——按真实施加防御。

### 5. 网络层
- 出口 IP 信誉（机场共享 IP 拉黑名单）、同 IP 多账号、不支持地区
  （大陆）直连。社区归因约 45% 封号源于网络环境。

### 6. 遥测通道与开关
- 1P 事件 → `api.anthropic.com/api/event_logging/batch`（与推理同 host、
  401 也发、**失败落盘 `~/.claude/telemetry/` 重启后补发**）——封 host
  会连推理一起死；只堵"会话期间"无效。
- Datadog → `http-intake.logs.us5.datadoghq.com`（独立 host，**可无损封**）。
- 官方开关：`DISABLE_TELEMETRY=1`（杀 Datadog+1P+GrowthBook）、
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`（再杀更新/公告）——但
  服务端能察觉"应有事件缺失"，属信任客户端的开关。

## 二、creance 防御面对照

| 封号信号 | creance 现状 | 结论 |
|---|---|---|
| apiBaseUrlHost 上报 | 纯 SOCKS5 出口，base URL 不动 | ✅ **架构天然免疫**（与中转路线的本质区别） |
| 出口 IP 信誉/同 IP 多账号 | 单一出口锚定 + 出口证据链 + 大陆网段拒绝 | ✅ 已覆盖（IP 层风险已解） |
| host 环境泄漏 | VM 隔离，guest 是一致的 Ubuntu | ✅ host 的终端/distro/包管理器不泄漏 |
| 凭据交叉 | 会话一次性凭据 + 剥离宿主凭据 | ✅ 已覆盖 |
| device_id 与账号绑定 | 未管理：VM 重建即新 device_id | ❌ 缺口 1 |
| 客户端指纹/attestation | 不碰客户端、不改 body | ✅ 天然正确（我们只做 IP 层，不经手 body） |
| guest 机器身份集群化 | hostname=`cage-<hex>`、用户 `dev<hex>`、systemd `cage-*` 可见面 | ❌ 缺口 2（**常量前缀=集群签名**，Cage #173/#605 实锤同类坑） |
| 时区-出口一致性 | tz 跟 profile 不跟出口 | ❌ 缺口 3 |
| Datadog 遥测 | 未封 | ❌ 缺口 4（唯一可无损封的通道） |

## 三、Claude Cage 的教训（433 issue 提炼）

1. **#173/#605**：初期全fleet 同 username/hostname/分辨率 → 被批量聚类；
   修复后仍残留 `cage-*` systemd 单元名、`Cage-SystemInstaller/1.0` 下载
   UA 等常量——**任何跨安装恒同的字符串都是集群信号**。
2. **#105/#100**：封号是多因子（IP 信誉、邮箱域、账号来源），隔离环境
   只能降率不能归零——"千分之几仍被封"。**产品话术必须诚实**（Cage
   README 明确拒绝"防检测"承诺，#202 以此关闭）。
3. **#340 Identity Bundles**（最高价值贡献）：账号+专属静态出口节点+
   `~/.claude.json` 身份槽+浏览器存储擦除**原子切换**，切换前先关代理门。
4. **#550/#520**：出口探测端点要多样化+并发竞速（两个公共探测域被出口
   拉黑导致环境永远起不来）。
5. **#470**：DoH 硬编码 1.1.1.1 在大陆网络级联失败——解析器必须有序回退。
6. **#392/#494/#632**：gate 必须扛住宿主网络切换/睡眠唤醒，超时只计真实进展。
7. **#516/#586**：断电后状态写入需 crash-safe（rename 后 fsync 目录）。
8. 其机器身份设计：真实机型 hostname 目录（1593 个真实 PC 型号）、
   SMBIOS/UUID/MAC/machine-id 随机化并持久、clone 时再生成；浏览器
   明确**不伪造** UA（假串与渲染行为对不上）。

## 四、行动建议（并入 ROADMAP）

### 0.6.x（小步，高杠杆）
- **A. 去集群化清扫**（缺口 2 + 审计项 A4）：hostname/用户名改为
  真实机型风格目录采样（借设计不抄数据文件）；`cage-relay`→中性名、
  下载 UA 去品牌、systemd/路径/env 前缀去 `cage-`。
- **B. Datadog 域名拒绝**（缺口 4）：mihomo 规则加一条 REJECT——无损、
  一行配置 + escape 探针一条（"telemetry-datadog-contained"）。
- **C. 诚实边界声明**：README 增"scope"段（隔离≠不可检测；封号是多因子）。

### 0.7（与多环境/快照天然协同）
- **D. Identity Bundles**（缺口 1 核心解）：per-identity 持久 device_id
  （快照保留 `~/.claude.json`）+ 账号 ↔ 出口节点锁定 + 切换时 gate 先关。
  我们的 gate/租约/qcow2 快照三件套正好是它的地基。
- **E. 时区/语言跟随出口**（缺口 3）：出口证据链已实测国家码——tz 从
  实测出口推导而非 host 配置。

### 持续原则
- 永不做 body 改写/客户端伪装（cch attestation 不可伪造，伪装=自曝）；
  防御只做三件事：**IP 层一致性、设备身份持久性、环境去集群化**。

## 附：社区来源
- [Claude Code 为什么针对中国 IP 大规模封号](https://github.com/youngyangyang04/llm-master/blob/main/docs/llm/news/claude_code_china_ip_ban.md)
- [腾讯云：Claude Code 精准封号原因曝光](https://developer.cloud.tencent.com/article/2712155)
- [知乎：Claude Code 封号原因被曝光](https://zhuanlan.zhihu.com/p/2055638471432315031)
