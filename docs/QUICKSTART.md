# creance 快速上手（内部测试版）

从零到"一个被隔离的 agent 工作区"，5 条命令。全程无需 root。

## 0. 安装

```sh
git clone https://github.com/foreignlands/creance.git && cd creance
sh scripts/fetch-proxy-core.sh   # 下载随附代理核心（首次）
sh scripts/install.sh            # 构建并安装 ~/.local/bin/creance
creance doctor                   # 自检：工具链/核心/磁盘/内存
```

要求：macOS 14+ Apple Silicon、`limactl`（`brew install lima`，仅 VM 功能
需要）。工具链可以完全用仓库内 `.toolchain/`，不污染全局。

## 1. 配置代理

```sh
export CREANCE_CONFIG=~/.creance/config.json   # 默认即此，可省
creance init
creance proxy-import --name 我的订阅 --url https://example.com/sub.yaml
creance proxy-select "香港-01"     # 按名字或 ID
creance proxy-start                # 启动托管核心（launchd，幂等）
creance check                      # 验证传输：失败也不回退直连
```

旧 Claude Cage 用户：`CLAUDE_CAGE_CONFIG` 与 `~/.claude-cage` 原样兼容。

## 2. 起环境（Ubuntu 24.04 VM）

```sh
creance setup        # 生成 Lima 配置并创建实例（首次下载镜像 ~700MB）
creance up           # 启动；guest 时区/语言自动对齐 profile
creance shell bash   # 进去干活（装 claude code、跑任务）
```

## 3. 验收隔离

```sh
creance escape-test
```

输出 ✅（已强制层全过）/ ⏭️（未实现层如实标注）。0.3 版之前，VM 内
网络"物理唯一出口"尚未落地（见 ROADMAP），网络类探针显示 SKIP。

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

## 常见问题

- **`proxy-start` 报端口占用**：换个 store 端口或找到占用者；creance 绝不
  附加到未知监听者。
- **VM 起不来**：`creance doctor`；镜像下载失败重跑 `creance setup`。
- **想彻底重来**：`creance stop` 后删 profile 目录（默认 `~/.creance`）。
