# creance 快速上手（内部测试版）

从零到"一个被隔离的 agent 工作区"，5 条命令。全程无需 root。

## 0. 安装

```sh
git clone https://github.com/foreignlands/creance.git && cd creance
sh scripts/fetch-proxy-core.sh   # 下载随附代理核心（首次）
sh scripts/install.sh            # 构建并安装 ~/.local/bin/creance
creance doctor                   # 自检：工具链/核心/磁盘/内存
```

平台要求：

- **macOS 14+ Apple Silicon**：VM 走 Lima(vz)，需 `limactl`
  （`brew install lima`，仅 VM 功能需要）。工具链可以完全用仓库内
  `.toolchain/`，不污染全局——首次自建（一次性）：

  ```sh
  mkdir -p .toolchain && cd .toolchain
  curl -fsSL https://static.rust-lang.org/rustup/dist/$( \
    uname -m)-apple-darwin/rustup-init -o rustup-init && chmod +x rustup-init
  CARGO_HOME=$PWD/cargo RUSTUP_HOME=$PWD/rustup ./rustup-init \
    -y --no-modify-path --profile minimal
  cd .. && export CARGO_HOME=$PWD/.toolchain/cargo RUSTUP_HOME=$PWD/.toolchain/rustup
  export PATH="$CARGO_HOME/bin:$PATH"     # 之后 cargo/ci.sh 全走仓库内工具链
  ```
- **Ubuntu Linux (x86_64)**：VM 走原生 QEMU + cloud-init（无 Lima、无
  root）。需 `sudo apt install qemu-system-x86 qemu-utils openssh-client
  curl`，以及可写的 `/dev/kvm`（BIOS 开虚拟化 + `sudo usermod -aG kvm
  $USER` 后重新登录）。`creance doctor` 会逐项检查。首次 `creance
  setup` 下载并校验 Ubuntu 24.04 云镜像（~600 MB，每 profile 一次）。

## 1. 配置代理

```sh
export CREANCE_CONFIG=~/.creance/config.json   # 默认即此，可省
creance init
creance proxy-import --name 我的订阅 --url https://example.com/sub.yaml
creance proxy-select "香港-01"     # 按名字或 ID
creance proxy-start                # 启动托管核心（macOS: launchd；Linux: 进程内守护，幂等）
creance check                      # 验证传输：失败也不回退直连
```

旧 Claude Cage 用户：`CLAUDE_CAGE_CONFIG` 与 `~/.claude-cage` 原样兼容。

## 2. 起环境（Ubuntu 24.04 VM）

```sh
creance setup        # 创建实例（macOS: Lima 配置；Linux: 镜像校验 + cloud-init 种子 + qcow2 覆盖盘）
creance up           # 启动；guest 时区/语言自动对齐 profile
creance shell bash   # 进去干活（装 claude code、跑任务）
```

### 出口锚定（gate-open 前必读）

0.5 起，`creance gate-open` 需要**实测出口证据**：出口 IP 经代理实测、
比对锚定规则 + 强制中国大陆网段拒绝。默认配置（`dynamic`/`country` 且
未绑定国家）会被如实拒绝。二选一，编辑 config.json 的 `exit_policy`：

```jsonc
// 方案 A：不锚国家，但出口落在中国大陆仍会被拒绝（最宽松）
{ "mode": "dynamic", "scope": "any" }

// 方案 B：锚定国家（出口实测国家必须一致）
{ "mode": "dynamic", "scope": "country", "country_code": "US" }

// 方案 C：锚定固定出口 IP
{ "mode": "static", "ip": "203.0.113.7" }
```

`region`/`city` 锚定暂无诚实的实测数据源（观测源只有 IP+国家码），
会以 Unknown 如实拒绝——待 GeoIP 数据源接入后放开。

## 3. 验收隔离

```sh
creance gate-open     # 出口证据通过后开闸（90s 租期，wire 跟随）
creance escape-test
```

输出 ✅（已强制层全过）/ ❌（逃逸，exit 1）/ ⏭️（未实现层如实标注）。
宿主 6 项探针与 guest 的文件系统旗标、身份/权限、凭据（环境变量/hex 令牌/
ssh 材料）、socket 暴露（sock-* 家族，参数化发射，门禁看守其发射点）与
网络（直连、外部 DNS、IPv6、外部 ICMP）探针均已强制；出口正向
控制（proxy-path）需真实订阅节点；sock-abstract（unix abstract socket）为
已知缺口、探针在场如实 ⏭️（ROADMAP 待做清单跟踪；清单与代码由
scripts/check-probe-inventory.sh 双向差集门禁看守）。
（原"数值端点"探针是永久绿 的空探针，2026-11-21 删除。）

## 4. 工作台（可选）

```sh
creance serve --port 5173    # 浏览器打开 http://127.0.0.1:5173
```

状态面板 / 订阅导入 / 节点切换 / 核心启停 / 出口检查，仅监听回环。

## 5. 收工

```sh
creance stop          # 关 VM + 停核心（保留磁盘与配置，下次直接 up）
```

## 在线冒烟（开发者）

无需自备节点——本地 mihomo 以 `direct` 节点出真网：

```sh
mkdir -p /tmp/creance-smoke
cat > /tmp/creance-smoke/config.yaml <<'YAML'
mixed-port: 7891
bind-address: 127.0.0.1
allow-lan: false
mode: rule
ipv6: false
dns: {enable: true, ipv6: false, default-nameserver: [https://1.1.1.1/dns-query], nameserver: [https://1.1.1.1/dns-query]}
proxies: [{name: D, type: direct}]
proxy-groups: [{name: S, type: select, proxies: [D]}]
rules: ['MATCH,S']
YAML
target/proxy-core/mihomo -d /tmp/creance-smoke -f /tmp/creance-smoke/config.yaml &
sleep 2
CAGE_ONLINE_PROXY=socks5://127.0.0.1:7891 cargo test --release -p creance-net --test egress_loopback -- --ignored --nocapture
kill %1
```

两行 `ok`（trace + DoH 真实出网往返）即冒烟通过。

## 身份与审批

多账号/迁移/手机审批三件套（v0.7.x 新面）：

```sh
creance persona-save us1            # 快照当前身份为 persona
creance persona-use us1             # 原子切换（会重建 VM 磁盘）
creance identity-reset              # 一键轮换指纹（需停机）
creance migrate-export --file mv.crb && creance bundle-import --file mv.crb
creance approve identity-reset      # 手机审批（需 config 配 approval_bot_token + approval_chat_id）
```

配置了审批通道后，`identity-reset`/`persona-use` 须持 10 分钟内批条。

## 常见问题

- **`proxy-start` 报端口占用**：换个 store 端口或找到占用者；creance 绝不
  附加到未知监听者。
- **VM 起不来**：`creance doctor`；镜像下载失败重跑 `creance setup`。
- **首启后 `node`/`claude` 没装上**：工具链腿是 best-effort（不阻塞隔离
  契约）。在 HTTPS 中间人网络（自签证书劫持直连）下，guest 的 pinned
  下载与 claude 安装必然失败，apt(http) 后备仍可装 nodejs。全过程日志在
  guest 的 `/var/log/creance-toolchain.log`。宿主代理凭证按设计**永不**进
  guest。
- **想彻底重来**：`creance stop` 后删 profile 目录（默认 `~/.creance`）。
