# Claude Cage (Rust core)

**把 Claude 大小姐关起来** — Claude Cage 的 Rust 重写版，聚焦核心控制面。

这是 [Lee-xeo/Claude-Cage](https://github.com/Lee-xeo/Claude-Cage)（Go）的**核心功能对齐重构**：
不是逐行复刻（原项目 ~14 万行 Go + 桌面/移动端/UI），而是以高标准重写安全主链，
外周能力见 [ROADMAP](ROADMAP.md)。基于 agent-vm 二次开发的原项目以 MIT 许可发布，
本仓库沿用 MIT（见 `LICENSE-CAGE`，原 NOTICE 保留于上游）。

## 隔离契约（本仓库存在的意义）

一切模块围绕同一条安全主链，任何一环不满足，外网保持关闭：

```
config.json ──► managed proxy (mihomo, loopback+auth) ──► egress (唯一上行，零直连回退)
     │                                                        ▲
     └── exit_policy（大陆网段强制拒绝 + 国家/地区锚定）        │
                                                        VM 流量
```

- **单一上行**：SOCKS5 / HTTP(S) CONNECT，主机名不落本机解析器，代理失败绝不降级直连
- **DoH 域名解析**：走同一代理，AAAA 与本地名在闸门处 fenced
- **出口锚定**：静态 IP / 国家 / 州省 / 城市四级锚定 + 内嵌 6204 条大陆 IPv4 网段强制拒绝
- **端点一致性**：`proxy/sources.json`（store）是唯一事实源，`config.json` 的 revision
  不一致则闸门不开；每次真实启动轮换 revision
- **私有存储**：profile 目录 0700/0600，原子写（temp + fsync + rename）

## 目录结构

```
crates/cage-core/          核心库（对应原 internal/* 包，代码精简为职责单一模块）
├── config.rs              profile 配置 + 严格校验 + fingerprint
├── exit_policy.rs         出口策略 + 大陆网段库（src/data/mainland-ipv4.txt）
├── egress.rs              SOCKS5/CONNECT/TLS 隧道 + DoH + 内嵌最小 HTTP/1.1 客户端
├── dnsmsg.rs              DNS 线格式编解码（仅 DoH 所需）
├── paths.rs               宿主路径语义（Go filepath 语义对齐）
├── vmname.rs              实例命名（<base>-<sha256[:4]>，socket 路径预算）
├── private.rs             私有目录/文件权限
├── vm.rs                  limactl 编排 + 环境卫生（剥离代理/凭据环境）
└── proxy/
    ├── mod.rs             store（sources.json）、route（dialer-proxy 链）、applied 一致性
    ├── import.rs          Clash/Mihomo YAML 订阅导入（协议白名单、本机文件引用拒绝、环检测）
    ├── runtime.rs         mihomo config.yaml 生成 + 物理网卡绑定
    └── service.rs         核心生命周期（校验/启停/健康检查，launchd on macOS）

crates/cage/               cage CLI（对应原 cmd/cage）
```

## 构建与测试（环境隔离）

工具链装在**仓库内** `.toolchain/`（rustup + cargo，未写入任何全局路径/`~/.cargo`）：

```sh
export RUSTUP_HOME="$PWD/.toolchain/rustup" CARGO_HOME="$PWD/.toolchain/cargo"
export PATH="$PWD/.toolchain/cargo/bin:$PATH"

cargo test          # 103 个测试，全部离线可跑
cargo build --release
./target/release/cage --help
```

### 测试分层

- **单元测试**（`src/` 内嵌，92 个）：配置校验矩阵、出口策略语义、大陆网段强制拒绝、DNS 线格式
  （含压缩环防护）、SOCKS5 编码、订阅导入全部拒绝规则、路由链、mihomo 配置边界、gate 状态机
  （端到端 unix socket）、state 标记、Lima 模板
- **集成测试**（`tests/`，11 个）：回环 mixed 代理（mihomo 真实语义）端到端 egress、DoH 存根
  （AAAA/本地名围栏、重试语义）、workbench HTTP API（路由/CSRF/导入→选节点→应用）
- **在线冒烟**（`#[ignore]`，2 个）：`CAGE_ONLINE_PROXY=真实节点 cargo test -- --ignored`

### 测试分层

- **单元测试**（`src/` 内嵌）：配置校验矩阵、出口策略语义（静态/动态/国家/州省/城市）、
  大陆网段强制拒绝、DNS 线格式编解码（含压缩环攻击防护）、SOCKS5 目标编码、
  订阅导入的全部拒绝规则、路由链（dialer-proxy/显式链/环检测）、mihomo 配置生成边界
- **集成测试**（`tests/egress_loopback.rs` + `tests/support/`）：在回环端口上实现
  **mihomo 真实语义**的 mixed 代理（1 字节 peek 分流、RFC1929 认证、HTTP CONNECT 407），
  端到端验证 egress：socks5 无认证/有认证/错凭据、CONNECT、死代理零直连回退、
  DoH 存根（AAAA 与本地名在闸门处拦截、5xx 重试、4xx 终止、id 校验）

开发时代理核心从 `target/proxy-core/mihomo` 加载（脚本见下）；正式安装包随附。

## CLI（核心命令对齐）

```sh
cage init                      # 创建私有 profile（CLAUDE_CAGE_CONFIG 可指定 config.json 路径）
cage proxy-import --name X --file sub.yaml | --url https://…
                               # 导入 Clash/Mihomo 订阅（URL 走代理拉取，无直连回退）
cage proxy-refresh             # 重拉所有带 URL 的来源
cage proxy-select "US-Exit"    # 应用节点：store + config.json 端到端一致
cage proxy-start               # 启动托管核心（mihomo，launchd 管理，自动同步 gate）
cage proxy-status              # 端点 / 路由 / 运行态
cage proxy-stop                # 停核心 + 关闭所有实例 gate
cage check                     # 纯代理传输检查（无 VM，无直连回退）
cage setup                     # 生成 Lima 模板（Ubuntu 24.04，时区对齐 profile 指纹）
cage up | shell | list | stop  # VM 生命周期（limactl 驱动）
cage doctor                    # 七项诊断（工具链/核心/配置/节点/磁盘/内存/实例）
cage serve --port 5173         # 精简工作台（loopback HTTP + 单页 UI）
cage version
```

每个 profile 是一个独立目录（`~/.claude-cage/` 默认），共享范围、凭据、配置互不可见。

## 与原项目的对齐表

| 能力 | 原项目 (Go) | 本仓库 (Rust) |
|---|---|---|
| 配置模型 + 校验 | `internal/cage/config.go` | `config.rs` ✅ |
| 出口策略 + 大陆拒绝 | `internal/exitpolicy` | `exit_policy.rs` ✅ |
| 纯代理出口 + DoH | `internal/cage/egress.go` | `egress.rs` + `dnsmsg.rs` ✅ |
| 托管代理 store/路由/导入 | `internal/managedproxy` | `proxy/*` ✅ |
| 核心启停（macOS launchd） | `internal/managedproxy/core.go` | `proxy/service.rs` ✅ |
| 实例命名 / 路径语义 | `internal/vmname`, `internal/paths` | `vmname.rs`, `paths.rs` ✅ |
| VM 编排 | 内嵌 Lima 库（Go API） | `limactl` 外部驱动 + lima-home 短链接（设计差异） |
| VM 内闸门（控制面） | `internal/cage/gate*.go` | `gate.rs` ✅（强制执行面待 VM 网络层） |
| 订阅 URL 拉取 | `managedproxy/fetch.go` | `proxy/fetch.rs` ✅ |
| 精简工作台 | workbench（7.2 万行） | `serve.rs` + 单页 UI（核心 API 对齐） |
| guestprofile / 延迟测量 / Linux / desktop-mobile | 有 | ROADMAP 待办 |

## 设计差异说明

- **Lima 集成**：Go 版以库形式内嵌 Lima；Rust 版驱动 `limactl` 二进制（`LIMA_HOME`
  指向 profile 内 state/lima），磁盘与实例命名保持兼容。
- **DoH/HTTP 客户端**：不引入 tokio/hyper，`egress.rs` 内嵌 ~200 行最小 HTTP/1.1
  客户端（一条隧道一个请求的模式），依赖面 = rustls + url + serde 系。
- **错误信息**：保持中文用户文案与「请求不会改为直连」契约。

## 许可

MIT。`src/data/mainland-ipv4.txt` 来自原项目同源数据（原项目 MIT）。
Cage 是独立社区项目，与 Anthropic 无隶属关系。
