# ROADMAP — 实施状态

当前状态：**103 个测试全绿（clippy 0 警告，release 构建可用）**，以下 P0–P3 核心链路均已实现并实机验证。
参考仓库在 workspace 的 `refs/`（只读借鉴）。

## P0 — 核心链路 ✅

- [x] **mihomo 核心获取**：`scripts/fetch-proxy-core.sh`（v1.19.34 实机校验生成配置通过 `mihomo -t`）
- [x] **proxy-start 端到端**：launchd 自包含 job（`proxy/cage-relay` + `proxy/mihomo` 拷贝进 proxy 目录），
      生命周期全验证：start → `running:true` → stop → 干净 bootout → 重启幂等
      - 排障记录：launchd 下 dyld 对 `target/` 目录内二进制的 `open()` 被环境挂起——自包含拷贝同时解决
        生产打包问题；relay 的所有失败现在都写入 `proxy/proxy.log`（launchd 下无 stderr）
- [x] **在线冒烟**：2 个 `#[ignore]` 测试（`CAGE_ONLINE_PROXY` 环境变量指定真实节点后 `cargo test -- --ignored`）

## P1 — VM 主链 ✅

- [x] **cage setup**：生成 Lima 模板（Ubuntu 24.04 cloud image，vz，内存/CPU/磁盘参数），
      **Lima 原生 `timezone` 字段对齐 guest 指纹**，provision 只补 locale + 工具链；
      staging yaml 命名 `<instance>.yaml`（lima 2.x 以文件 stem 决定实例名）
- [x] **lima home symlink**：`/tmp/cage-lima-<uid>-<hash>` → `state/lima`（深层 mktemp 路径本身
      就会撑爆 UNIX_PATH_MAX——这是 Go 版 managed-storage-link 的同类设计）
- [x] **端到端实机验证**：setup（下载镜像 ~700MB）→ create → up（vz, aarch64, READY）→
      `cage shell /bin/sh -c 'uname -m'` → VM 内时区 = profile 配置的 Etc/UTC → `cage stop` 干净关机
- [x] **cage gate 控制面**：host 侧 unix socket HTTP（Bearer token + Host: cage + Origin 拒绝）、
      状态机（Closed/Checking/Open + epoch + 租期 watchdog）、5 个动作（check/fault/grant/renew/close/
      proxy-revision）、安全报告授权（5 项必需检查）、sync 快照语义（revision 变化或初次绑定补全可采纳，
      其余变更 409 需重启）、`proxy-start/stop` 自动同步 gate
      - **边界**：强制执行面（ Allows/DialContext/ExchangeDNS 挂到 VM 网络交换层）依赖 lima usernet
        hook（Go fork）——Rust 版需自建 VM 网络层，见「待办」
- [x] **订阅 URL 拉取**：`fetch.rs` 经 egress（纯代理、8 MiB 传输上限、≤5 跳重定向），
      `cage proxy-import --url` + `cage proxy-refresh`

## P2 — 状态与兼容 ✅

- [x] **state.rs**：marker 文件（Read/Write 原子/Rename/Forget/BaseLabel 日期格式）对齐 Go 语义
- [x] **instance_name 兼容**：legacy 截断恢复（唯一有效截断 + lima.yaml 确认）
- [x] **PID 复用防护**：`cage-running.json` 携带进程启动时间戳（macOS sysctl `kinfo_proc` 原始缓冲读
      `p_starttime`），liveness = PID 存活 + 启动时间匹配；fingerprint 不符 → 要求先 `cage stop`

## P3 — 外周 ✅（标注项除外）

- [x] **cage doctor**：limactl/核心/配置/应用节点/磁盘/内存/实例 七项判定（✅/⚠️/❌ + 可行动提示）
- [x] **cage serve**：精简 workbench——loopback HTTP API（status/nodes/import/select/start/stop/check）
      + 单页 UI（`workbench.html` 内嵌），CSRF 拒绝跨源 POST；端到端测试（UI 路由、CSRF、导入→选节点→应用）
- [x] **guestprofile**：**未实现**（无 VM provision 消费者前是半成品）——保持 ROADMAP 待办
- [x] **延迟测量 / Linux 分支**：未实现（保持待办）

## 待办（下一轮）

1. **VM 网络交换层**：Rust 版 usernet（或在 Lima hook 点接 gate）→ gate 强制执行面生效
2. **gate 强制执行**：`Egress::allows/dial` 接入 gate 状态机 + guest DoH（ExchangeDNS 已就绪）
3. **guestprofile** 生成器 + provisioning 消费
4. **Linux 平台**（systemd 替代 launchd、`physical_interface` Linux 分支）
5. **延迟测量**（mihomo `/proxies/<id>/delay` API 已在 control socket 上可达）

## 借鉴落地（来自同类型项目）

| 仓库 | 已采纳 |
|---|---|
| `refs/clash-rs` | 集成测试模式（RAII 服务器 + 随机端口 + 回环端到端）；认证失败语义；`#[serde(tag="type")]` 建模范式（待办） |
| `refs/mihomo`（Alpha） | mixed 端口 1 字节 peek 分流；authenticator 空用户表 = 不启用；`/configs` 字段语义 |
| `refs/leaf` | handler trait 分层（gate 强制执行面参考） |
| `refs/meow-rs` | Rust 版 mihomo（未来内置核心参考） |

注意：`MetaCubeX/mihomo` 的 **main 分支被无关项目占用**，Go 源码在 **Alpha 分支**。

## 已知简化（阅读代码时注意）

- `vm.rs::environment_dir`：未实现 `-downloads` 嵌套 profile 的相对路径特判
- `gate.rs`：租期 watchdog 是 500ms 轮询（原版 timer 精度更高）；诊断端口（198.18.0.254:80）未实现
- `egress.rs`：HTTP 头逐字节读取（每隧道一个请求，可接受）
- `config.rs::validate_timezone`：依赖 `/usr/share/zoneinfo`，无 tzdata 系统回退到结构校验
- workbench UI 是单页最小实现（无登录/多 profile 切换）
