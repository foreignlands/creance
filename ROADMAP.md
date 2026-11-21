# ROADMAP

creance 的定位：**通用的 AI agent 隔离容器**（功能对标 Claude Cage，防范对象当前以 Claude 为主，架构不绑定任何单一模型）。

## 版本路线（详见 RELEASES.md）

- **0.3 — VM 网络强制面**：**DONE 2026-11-19**（拓扑 DROP + ssh -R single wire）。
- **0.4 — guest profile + 一次性凭据**：**DONE 2026-11-19**。
- **0.5 — 出口证据链**：**DONE 2026-11-19**。
- **0.6 — Linux 平台支持**：原生 QEMU + cloud-init 后端（无 Lima、无 root），mihomo 进程内托管（无 launchd/systemd 依赖），/proc 级 PID 复用防护。**已知跟进（0.6.x）**：slirp `restrict=on` 在已配置实例上启用（首启的 apt/node 供给需要 NAT，当前与 macOS vz 同姿态、由 guest 防火墙承担强制）；aarch64 主机实测。
- **0.7 — 多环境 + 快照**（qcow2 覆盖盘天然支持快照）。
- **0.8 — API 稳定化**（rustdoc、MSRV、semver-checks 入 CI）→ 0.9 RC → 1.0 GA。

## escape 探针清单（研究A产出，逐步翻绿）

已强制：config-valid / env-no-host-credentials / proxy-numeric-endpoint。
待强制面落地后翻绿：fs-flag-readable（VM 内旗标 oracle）/ net-direct-egress（杀掉 mihomo 后 curl 必须失败）/ net-dns-external（dig @8.8.8.8 拒）/ net-ipv6 / 大陆出口命中拒 / AAAA-本地名围栏 / 挂载点扫描 / ssh-material / docker.sock·lima socket / 供应链探针（恶意 postinstall 外传被拦）/ 时区-出口一致性。
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
- 发布：Keep-a-Changelog CHANGELOG + semver 0.x（破坏性升 minor）+ cargo-release（计划）+ git-cliff；edition 2024 与 rust-version 留待 0.6 API 稳定时一并声明。
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

- escape-test 的网络探针待 0.3 强制面；gate 诊断端口（198.18.0.254:80）未实现。
- `environment_dir` 未实现嵌套 profile 相对路径特判；workbench 为单页最小实现。
- 在线冒烟测试需 `CAGE_ONLINE_PROXY=<真实节点> cargo test -- --ignored`。
