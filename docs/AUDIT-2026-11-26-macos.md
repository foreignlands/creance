# 2026-11-26 macOS 实机审计 — v0.7.22 → v0.7.23

在真实 macOS 主机（macOS 26.6.2 arm64、limactl 2.3.0、vz 驱动、宿主带
系统代理 127.0.0.1:7897）上对 v0.7.22 做的实机审计：构建、测试、
setup/up/stop/escape-test 全程实跑，并重建审计 VM 复验修复。云端
Linux CI 对这批问题全部不可见——每一个都只在 Mac 上现形。

## 发现与修复（v0.7.22 → 提交 1fa3026）

| # | 问题 | 影响 | 修法 |
|---|------|------|------|
| M1 | `cargo test` 在 macOS 不编译 | gateprobe 测试引用 `crate::qemu`（Linux-only cfg）→ E0433，整个 lib test target 死，clippy `--all-targets` 与 ci.sh 同挂 | 仅 Linux 有意义的 marker-arming 断言块 cfg 门控 |
| M2 | Lima 把宿主**系统代理**注入 guest | 实测三重破坏：①`creance-call` 的 loopback POST 被代理进黑洞，插件控制面静默失效；②provision 每次 `limactl start` 重放 + 封锁后死代理烧干 300s toolchain 预算（单次 boot 5m10s，socat 永远装不上）；③违反"宿主代理凭证不进 guest" | lima.yaml：`propagateProxyEnv: false` + `env:` 置空全部 10 个 proxy 拼写（双通道全堵）；`creance-call` 加 `--noproxy` |
| M2b | provision 重放在封锁后只能空转 | 每次 boot 烧满 toolchain 预算，尾部 extras 行（含 socat）必然死于耗尽 | toolchain leg 用 `/run/egress-armed` 做重放守卫（该 stamp 只在封锁后存在）；socat 前移到 apt update 之后、node fallback 之前 |
| M3 | gatewire 用户单元在 Mac 必然 crash-loop | 实测 NRestarts=99 持续上涨；且是 F-A1 活雷——socat 一旦就位即与 ssh -R 抢端口，sync 侧 `if cbridged` 挡不住 systemd 自己的 boot 触发 | 单元加 `ConditionPathExists=%h/.creance-vsock`；daemon 仅在 `cbridged` 时推送该 marker、fallback 时清扫并停单元 |
| M4 | `/tmp/vmhome-$UID-*` 短链接不回收 | 本机实测积累 434 个悬空链接 | `lima_home` 机会性 GC：只删目标已消失的软链 |
| M5 | setup 时 environment dir 可能不存在 | lima create 对缺失 mount 源告警 | setup 先 `create_dir_all` |

实机复验（重建审计 VM）：无代理注入日志；toolchain 全装（node rc=0、
socat 在场）；gatewire/creance-wire 合规 inactive（NRestarts=0）；
`creance-call` 端到端 403（桥通）；二次 `up` 从 5m10s → **17s**；
egress/DNS/IPv6/ICMP 封锁全死。

## 残留修复（v0.7.23，提交 081965e）

- **存量 guest `/etc/environment` 残留代理**：lima.yaml 置空只护新建
  实例。provision 新增**无条件** sed scrub 段（每次重放执行）——
  旧 guest 下次启动自愈，无需重建。
- **`proxy-path` 假 ESCAPE**：无 store（未配托管路由）时隧道目标
  按设计不存在，报 ESCAPE 是假警报、训练用户忽略真警报。改为
  `SKIP`；配置了但死了仍是真 ESCAPE。
- **workbench 无测试覆盖**：新增两测试——UI 引用的每个 `/api/` 路径
  打进真 dispatcher 断言不 404（防死按钮）；所有订阅可控字段的
  `esc()` 包裹钉死 + 禁止 UI 出现绝对 URL fetch。
- **平台边界显式化**：`compile_error!` 在 macOS/Linux 之外就地编译
  失败——平台矩阵收窄为二元，不再靠 qemu 引用深处炸出误导错误。

## 佐证（外部来源核实）

- **Lima `pkg/cidata/cidata.go` `setupEnv`**：env 合并顺序为
  `osutil.ProxySettings()`（macOS 系统代理，`propagateProxyEnv`
  管不到的通道）→ `env.*`（lima.yaml，覆盖系统值且无警告）→
  进程环境（仅 propagateProxyEnv 时）。源码注释明确："Delete
  settings with empty values, so the user can choose to ignore
  system settings"——`env: {http_proxy: ''}` 删键是官方逃生口。
- **systemd `ConditionPathExists`**：多条为 AND 语义；enabled 用户
  单元在 linger 下每次 boot 自行重评——sync 侧的 restart 守卫
  够不到这条触发路径（M3 修法的依据）。
- **自伤复验**：残留修复时注释里的撇号（`host's`）被 quote-parity
  钉当场转红——钉子在干活，已修。

## 原生虚拟化调研结论

- **macOS**：有原生虚拟化。`Virtualization.framework`（高层）/
  `Hypervisor.framework`（底层）——Lima `vz` 驱动即建立其上，
  不是额外安装。另：Apple 开源 **Containerization**（Swift，
  github.com/apple/containerization，macOS 26）——每容器一个轻量
  VM + vsock 的 vminitd，架构与本项目（VM + vsock 控制面）同构，
  可作未来参考；但它是 OCI 容器模型而非持久桌面 VM，不适合当前
  guest 形态（systemd + chrome + node toolchain 的长驻环境）。
- **Windows**：有。Hyper-V / Windows Hypervisor Platform（WHPX），
  WSL2、Windows Sandbox 均建立其上。本项目按收窄决定明确不支持
  Windows（`compile_error!` 编译期拒绝）。

## 前端打磨（同批）

- `workbench.html` 重写：自动明暗主题、live 指示、busy 态、事件
  委托节点选择、订阅可控字符串全转义（真 XSS 面）、删死按钮。
- Tauri 壳：真托盘菜单、关窗驻留托盘、最小窗口尺寸。

## 验证

- `cargo test` workspace：198 passed / 0 failed（creance-vm 68、
  creance-gate 19、creance 18 含新增 workbench 两钉）
- `cargo clippy --locked --all-targets -- -D warnings`：干净
- `cargo fmt --check`：干净；`check-probe-inventory.sh`：rc=0
- 审计 VM `creance-audit-downloads-84671b1e` 已删除，现场清理完毕
