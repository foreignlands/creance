# 交接：Ubuntu 会话 → macOS 会话（2026-11-21）

写给在 macOS 上继续的 ZCode 会话：Ubuntu 这台机器上一天内推完了三件事，
本文是接续所需的全部上下文。

## 已推送（GitHub foreignlands/creance，main = 0d00ae0）

| 提交 | 内容 |
|---|---|
| `4d3a435` v0.6.0 | **Linux 平台支持**：原生 QEMU+cloud-init 后端（无 Lima/无 root）、mihomo 进程内托管、/proc PID 复用防护、后端中立层（vm.rs 的 instances_root/SshTarget/guest_script 分发，macOS 路径行为不变）。七轮实机验证全链绿 |
| `f8af511` v0.6.1 | **审计轮**：9 个正确性修复 + ~500 行死代码 + 文档解冻。细节与待审清单见 `docs/AUDIT-2026-11-21.md` |
| `0d00ae0` | **封号防御研究** `docs/BAN-DEFENSE-STUDY-2026-11-21.md`：泄露客户端源码扫描 + Cage 上游 433 issue + 社区互证 |

tag `v0.6.0`/`v0.6.1` 已推；`feat/linux-port` 已快进至 main。

## 用户已拍板的决策
- **平台范围 = macOS + Ubuntu Linux，Windows 明确放弃**（全部 `cfg!(windows)` 幻想分支已删）。
- VM 后端 = 原生 QEMU+cloud-init 直驱；代理核心 = 进程内 spawn+pidfile（无 launchd/systemd 依赖）。
- 命名大扫除（去 `cage-` 品牌串）已裁定"应做"，排 0.6.x（依据封号研究：常量串=集群信号）。

## macOS 会话接手第一件事 ⚠️

**先跑 `sh scripts/ci.sh` + 一轮实机冒烟（init→proxy 链→setup→up→shell→escape-test→stop）再开新工作。**
Ubuntu 侧改动覆盖了部分 macOS 共享代码（limactl 环境纪律统一、
gate-daemon 的 process_group、死代码清扫触及 paths/vmname/running/service），
这些经过静态审查与 Linux CI，但 **macOS 路径未实机回归**。
预期全绿；若 clippy 在 macOS 报 cfg 差异项，属正常收尾。

## 待办指针（按优先级）
1. `docs/BAN-DEFENSE-STUDY-2026-11-21.md` §四：0.6.x 三件套（去集群化清扫——
   含把 guest hostname `cage-<hex>` 改真实机型风格、Datadog 域名无损拒绝、
   README 诚实边界段）；0.7 = Identity Bundles + 时区跟随实测出口。
2. `docs/AUDIT-2026-11-21.md` 待审 15 项（探针 3 空洞、孤儿 mihomo 收割、
   fetch-proxy-core 校验、harness 工具个人路径…）。
3. `harness/attack-surfaces.md` 攻击面地图零 0.6/Linux 条目——补图后才好
   开下轮夜间审计（GLM-5.3-Flash 循环协议仍在 harness/ 可复用）。
4. ROADMAP 0.6.x 其余：slirp `restrict=on` 按启停状态启用、aarch64 实测。

## 参考仓库（在 Ubuntu 机器 ~/mytest/ 下，Mac 端需要时重新 clone）
- `claude-cage-upstream_1121` — Lee-xeo/Claude-Cage（真身 sylvinus/agent-vm，
  v0.2.0-rc）：机器身份随机化设计（docs/guest-identity.md、真实机型
  hostname 目录）、Identity Bundles、netguard/exitpolicy 值得对标。
- `claude-code-src_1121` — 泄露 Claude Code v2.1.88 解包 TS 源码：遥测/
  指纹/attestation 全部带 file:line 的结论在封号研究文档里，不必重扫。

## 环境备忘（Ubuntu 这台机器）
- Rust 1.100 stable（rustup，`~/.cargo/bin`）；mihomo v1.19.34 linux-amd64
  在 `target/proxy-core/`（fetch 脚本在 GitHub API 限流时用 releases/latest
  302 取版本号绕行）。
- 本机网络对 guest NAT 直连 https 有 MITM 自签劫持（curl 有时过、python
  urllib 必死、apt http 可用）——工具链腿已按此加固，冒烟时 node 落地
  以 `/var/log/creance-toolchain.log` 为准。
- 冒烟 profile 在 `/tmp/creance-p5/`（临时，重启即失）。
