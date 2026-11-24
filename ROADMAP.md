# ROADMAP

creance 的定位：**通用的 AI agent 隔离容器**（功能对标 Claude Cage，防范对象当前以 Claude 为主，架构不绑定任何单一模型）。

## v0.6.x — 硬化收尾（当前）

新排两项（验收标准先行）：
- **运行时常驻巡检/自动熔断**：常驻守护在 gate 租期内周期性经核心采样出口证据（IP/国别/核心存活），异常即自动关闸。**验收指标：断代理→切断 guest 出口的端到端延迟 ≤2s 且零泄漏**（把 0.5 的"开闸一次取证"升级为"租期持续取证"）。
- **浏览器进 guest**：官方 Chromium 预装。**定位先行**（0.6.x 内定案）：按需拉起的 OAuth/验证通道（用完即毁）vs 常驻——倾向按需。架构红利：浏览器在 guest 内，OAuth 的 localhost 回调天然闭环（第三方提示的剪贴板/回调割裂主要发生在宿主浏览器方案，我们天然规避）；成本约束=内存预算。**验收指标：出口国别↔时区↔语言↔浏览器 locale 四元组一致性校验（探针化，杜绝"US IP+中文语言+东八区"穿帮组合）**。
- **防探测层残余（新，源自第三方审视②）**：guest 内品牌串已清（v0.6.3 sweep），剩余=虚拟硬件特征审计与洗白——Linux/QEMU 的 virtio vendor、SMBIOS/DMI、/proc/cpuinfo hypervisor flag；macOS/vz 呈现 Apple 硬件属天然伪装（待审计确认）。进 attack-surfaces 新条目，0.6.x 排期。
- 存量：aarch64 实测、错误语言统一（缓）、harness 编译门（缓）。
- **长期循环项（单 Mac 现实，不阻塞主线）**：每版发布后 Ubuntu 侧 CI + U1–U5 类实机回填 + GPG 镜像验签 + Linux 长跑。

## v0.7 — 用户安心功能批（讨论清楚+完善；最后一个 0.7 版本全部收口，v0.8 前告一段落）

专项讨论议题（0.7 启动时逐个出技术方案，v0.8 冻结特性前全部定案）：
1. **Identity Bundles / 多账号接力**（核心卖点）：账号↔专属出口↔持久 device_id 原子切换，物理隔离账号身份（规避 Cage 同 VM 串联坑）。**Bundle 导出格式=双层加密容器**（第三方审视③采纳）：内层=虚拟指纹明文打包（跨设备一致），外层=主密码/手机审批动态解封——"换电脑不换虚拟指纹，没授权打不开包"。
2. **时区/指纹自动跟随实测出口** + **指纹一键重置**（re-setup 产品化）+ **一键切换 machine-id/user-id 类身份字段**（安心项）。
3. **整机迁移/多设备**：带身份迁移语义（与 Bundle 容器格式一体设计）。
4. **桌面打包**：**Tauri 优先**（复用 Rust 核心、小包体、托盘+巡检状态展示）——第三方审视④采纳。
5. **手机远程审批**：0.7 阶段**复用成熟通道**（Telegram Bot/飞书/Web Push+端到端签名回调），独立 App 推迟到 1.0 后——采纳。
6. **插件市场**：MCP 宿主受控执行，严格按 gate 证据/审批纪律（每次宿主调用=一次微型 gate-open），不做原生弹窗一键放行。
7. **访问控制（两层拆分，第三方审视②采纳）**：
   - **防越权层**（防非管理员用户）：二进制属主锁定+socket 0600+配置目录 0700+安装期属主绑定；
   - **防探测层**（防官方客户端在管理员权限下扫描本机）：guest 零残留（已部分完成）+虚拟硬件特征洗白（0.6.x 起步）+宿主通信通道隐蔽化。如实边界：管理员权限下的官方客户端扫描无法被"权限"挡住，只能靠特征卫生与架构隔离。
8. 技术债并行：Go 授权集 11 项对齐+config 指纹三维绑定、出口证据二源交叉。

## v0.8 — 外部 LLM 审核版（一）+ API 稳定化
其他 LLM 对抗审计+修复；rustdoc/MSRV/semver-checks 入 CI（发布准备）。特性冻结。

## v0.9 — 跨部门试用版
外部 LLM 审核轮（二）+ 用户点名的全量质量轮（bug/冗余/屎山一次清）。出口标准=跨部门同事可直接使用。

## v1.0.0 — GA + 付费宣发投流，直面市场。

## escape 探针清单（研究A产出，逐步翻绿；id 与代码的双向差集由 scripts/check-probe-inventory.sh 门禁看守，任何一侧漂移 CI 即红。标记块内只放纯 id——注释写在块外，门禁解析器不认多字节）

宿主侧（已强制）：
<!-- probe-inventory:host-enforced -->
config-valid / env-no-host-credentials / mounts-workspace-only / gate-record-private / credentials-are-session-only / fingerprint-consistent / exit-fingerprint-consistent
<!-- /probe-inventory:host-enforced -->

VM 内（已强制。sock-docker·lima-guestagent 是参数化 sock-$s 的三运行时家族名；fs-flag-readable 是旗标 oracle；net-icmp-external 0.6.4 新增；proxy-path 是出口正向控制——guest 输出任何含 " ESCAPE" 的行即 exit 1，PASS 需真实订阅节点）：
<!-- probe-inventory:guest-enforced -->
fs-flag-readable / guest-identity / guest-privilege / env-credentials / env-hex-tokens / ssh-material / sock-docker·lima-guestagent / net-direct-egress / net-dns-external / net-ipv6 / net-icmp-external / proxy-path
<!-- /probe-inventory:guest-enforced -->

VM 内（已知缺口，实现后转绿。sock-abstract 探针在场、如实 SKIP；其余为规划项：大陆出口命中拒依赖出口证据链的 gate 联动）：
<!-- probe-inventory:guest-todo -->
sock-abstract / 大陆出口命中拒 / AAAA-本地名围栏 / 供应链探针 / 时区-出口一致性
<!-- /probe-inventory:guest-todo -->

（原 proxy-numeric-endpoint 是永久绿的空探针，2026-11-21 E5 裁定删除——历史记录，不参与门禁。）
红队方法论参考 sandbox_escape_bench 的「宿主旗标 + 场景 setup」结构。

## 架构参考（研究A结论，已采纳/计划）

- 分层现实：microVM（VZ，已用）给硬件边界；用户态网络栈（gvisor-tap-vsock 模式）把「唯一出口」从配置约束升级为**拓扑约束**——guest 物理上不存在第二条路（0.3 采纳）。
- 数据面最小化：Lima 默认可写挂载与 root guestagent 是已知面——0.3 显式关 mounts/port-forwards；guest root 不视为信任边界。
- 出口审计 + 一次性凭据（0.4）。
- 判定为过度设计（不采纳）：gVisor-in-VM 嵌套、Kata/K8s、自建 Firecracker 栈、时序侧信道缓解、独立 TPM。
- 值得借鉴：apple/container（每容器独立只读块设备 rootfs）、containers/gvisor-tap-vsock、UKGovernmentBEIS/sandbox_escape_bench。

## 命名与发布（研究B结论，已采纳）

- **creance**：训鹰长绳（任其飞翔、不容逃逸）；crates.io 与 GitHub 双空闲；repo=crate=bin 同名（zellij 模式）。
- 多 crate：creance-net/-vm/-proxy/-gate + 根 crate creance；共享 [workspace.package]/[workspace.lints]；暂不拆 creance-core（勿提前）。
- 发布：Keep-a-Changelog CHANGELOG + semver 0.x（破坏性升 minor）+ cargo-release（计划）+ git-cliff；edition 2024 与 rust-version 留待 0.8 API 稳定时一并声明。
- 注意：MetaCubeX/mihomo 源码在 **Alpha 分支**（main 被无关项目占用）；release 资产 URL 不受影响。

## 与 Claude Cage (Go) 的对齐状态

| 能力 | 状态 |
|---|---|
| 配置/出口策略/大陆网段 | ✅ creance-vm（对齐 + 修复 Go 版 6 处缺陷） |
| 纯代理 egress + DoH | ✅ creance-net |
| 托管代理 | ✅ creance-proxy（macOS: launchd；Linux: 进程内 relay + pidfile） |
| gate 控制面 | ✅ creance-gate；**强制执行面 0.3** |
| VM 生命周期 | ✅ macOS: Lima(vz)；**Linux: 原生 QEMU + cloud-init（0.6）** |
| 订阅导入/URL 拉取 | ✅（键规范化先于计数、ws-headers 并集、SSRF 拒绝——均超 Go 版） |
| workbench | ✅ 精简版（loopback + CSRF 防护 + 连接上限） |
| guestprofile/多账号/移动端/desktop | 未实现（0.7+ 按需） |

## 已知简化

- gate 诊断端口（198.18.0.254:80）未实现。
- `environment_dir` 未实现嵌套 profile 相对路径特判；workbench 为单页最小实现。
- 在线冒烟测试需 `CAGE_ONLINE_PROXY=<真实节点> cargo test -- --ignored`。
