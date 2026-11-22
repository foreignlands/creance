# creance

**A contained workspace for AI agents.**
*creance (falconry): the long line attached to a hawk's legs during training — free to fly, never lost.*

Run untrusted agents (today: Claude Code; tomorrow: any) inside a VM whose
every byte of network traffic leaves through exactly one proxy you control,
whose host credentials never enter, and whose containment you can *prove*
with an automated escape-probe suite. Rust, layer-decoupled, no black magic.

> Functional benchmark: [Claude Cage](https://github.com/Lee-xeo/Claude-Cage)
> (Go). creance is an independent, cleaner-slate implementation of the same
> containment goals — see [ROADMAP.md](ROADMAP.md) for alignment status.

## The containment contract

```
                 ┌──────────────────────────── host ────────────────────────────┐
 agent in VM ──► │  creance-net: one SOCKS5/HTTPS upstream, ZERO direct fallback │ ──► your proxy node
                 │  DoH via the same tunnel · AAAA/local names fenced at the gate │
                 │  creance-gate: state machine + exit anchor (mainland deny)    │
                 │  creance-vm: profile, mounts limited to the workspace         │
                 └───────────────────────────────────────────────────────────────┘
```

- **One egress, no fallback**: hostnames go to the proxy unresolved; a dead
  proxy means no traffic, never a direct connection.
- **Exit anchoring**: static IP / country / region / city, with a mandatory
  mainland-IPv4 deny list (6,204 prefixes embedded).
- **No privilege path in the guest**: the guest user is a generated
  identity (never the host account's name) with the cloud-init sudoers
  grant stripped and its password locked — nothing inside the VM can lift
  the OUTPUT DROP firewall (the R3 escape, closed in 0.4.1).
- **Provable containment**: `creance escape-test` runs host + in-guest
  probes; layers not yet enforced are reported as such — nothing fakes a pass.

## Layout (layered, no cycles)

| Crate | Owns |
|---|---|
| `creance-net` | egress tunnels (SOCKS5/CONNECT/TLS), DoH, DNS wire codec, wire helpers |
| `creance-vm` | profile config, paths/naming, PID-reuse guards, host facts, Lima lifecycle (macOS) / native QEMU backend (Linux), exit-policy data |
| `creance-proxy` | subscription store + import, mihomo runtime config, supervised core (launchd on macOS, in-process relay on Linux) |
| `creance-gate` | gate control plane (unix-socket HTTP state machine) |
| `creance` | CLI + workbench + diagnostics + escape suite (assembly) |

## Quick start

面向使用者的完整上手见 **[docs/QUICKSTART.md](docs/QUICKSTART.md)**（安装
→ 配代理 → 起 VM → 验收隔离，5 条命令）。概览：

```sh
sh scripts/install.sh         # 构建 + 安装 ~/.local/bin/creance
creance init && creance proxy-import --name my --url https://… && creance proxy-select "US-Exit" && creance proxy-start && creance check
creance setup && creance up && creance shell bash
creance escape-test           # 验收隔离
```

`CREANCE_CONFIG` selects a profile (legacy `CLAUDE_CAGE_CONFIG` honored;
existing `~/.claude-cage` profiles keep working).

## Night-audit harness

[`harness/`](harness/README.md) — 把一个 LLM（GLM 5.3 Flash）变成整夜
运转的对抗性审查员：循环协议、上下文压缩协议、findings 记录、45 项
攻击面地图，以及把模型关进 VM 让它全力逃逸的红队任务书。

## Escape-test: the acceptance harness

`creance escape-test` reports per-probe: ✅ contained · ❌ escaped (exit 1) ·
⏭️ not-enforced. Enforced live: the six host probes, and with a VM the
guest probes — filesystem flag oracle, identity/privilege, credentials
(env/hex tokens/ssh material), socket exposure (the sock-* family), the
network probes (direct egress, external DNS, IPv6, external ICMP) and
the positive egress control (proxy-path; PASS needs a real subscription
node). (The old "numeric proxy endpoint" probe was permanently green —
an empty probe, deleted 2026-11-21.) The exact id inventory below is
gate-checked against the code by scripts/check-probe-inventory.sh on
every CI run; ROADMAP.md tracks the honest-SKIP known gap (sock-abstract).

<!-- probe-inventory:readme-enforced -->
config-valid / env-no-host-credentials / mounts-workspace-only / gate-record-private / credentials-are-session-only / fingerprint-consistent / fs-flag-readable / guest-identity / guest-privilege / env-credentials / env-hex-tokens / ssh-material / sock-docker·lima-guestagent / net-direct-egress / net-dns-external / net-ipv6 / net-icmp-external / proxy-path
<!-- /probe-inventory:readme-enforced -->

## Status

v0.6.0 — Linux platform support (Ubuntu/KVM: native QEMU + cloud-init
backend, in-process proxy supervision, `/proc`-armed PID-reuse guard);
macOS unchanged. Live-verified on both: the full setup → up → shell →
escape-test → stop chain, escape-test green on every enforced layer.
Everything else on [ROADMAP.md](ROADMAP.md).

| Host | VM backend | Proxy supervision |
|---|---|---|
| macOS 14+ (Apple Silicon) | Lima (vz) | launchd |
| Ubuntu Linux (x86_64, KVM) | native QEMU + cloud-init | in-process relay + pidfile |

## Honest boundaries（诚实边界）

隔离降低风险，不把风险归零。这一段写给打算在真实账号上使用 creance
的人——三条设计地板、两类已知残余、以及我们明确不做的事。

**封号风险的现实**：上游 Claude Cage 的 433 个 issue 显示封号是多因子
判定（device_id 多设备、请求体 attestation、IP 信誉、遥测元数据），
社区报告"千分之几仍被封"——隔离容器只能收窄指纹面，无法承诺免封。
creance 的纯 SOCKS 架构天然免疫 `apiBaseUrlHost` 自曝（我们从不改写
请求体、不碰 base URL），v0.6.3 起去除了所有常量品牌串（hostname、
UA、组名——见 docs/BAN-DEFENSE-STUDY-2026-11-21.md）；但 device_id
绑定是服务端行为，同一账号多环境并发使用仍由服务端裁量。

**设计地板（同 uid 信任边界）**：host 侧的配置、pidfile、gate 记录对
同一操作系统用户可见可写。防的是 guest 里的 agent 逃逸，不是防你
自己——同 uid 攻击者的"自伤面"（伪造运行记录、篡改 store）在审查
中逐项记档于 harness/findings/，不重复立案。

**证据采样的单目的地边界**：gate-open 的出口证据经代理实测
1.1.1.1 的 trace（IP+国家码，25s 预算）。TLS 不保证同代理对不同目
的地同路由——出口节点若对 1.1.1.1 差异化路由，现有观测无法检测。
第二独立数据源（不经同一核心）排在后续版本。

**平台边界**：macOS 14+ Apple Silicon（Lima/vz）与 Ubuntu x86_64
（QEMU/KVM）。Windows 明确不支持（cfg 幻想分支已清除）。Linux 后端
较新（v0.6.0），对抗审查覆盖度低于 macOS 侧——攻击面地图 H 节
（harness/attack-surfaces.md）是其已知未覆盖清单，guest→slirp 宿主
别名（10.0.2.2）的可达性结论以 Ubuntu 侧实机探针为准。

**工具链是 best-effort**：供给段的 node/claude 安装失败不阻塞隔离
契约（超时+兜底有界），在 HTTPS 中间人网络下 pinned 下载必然失败，
apt(http) 兜底可用；全过程日志在 guest 的 /var/log/creance-toolchain.log。

**我们不做的事**：不改写请求体、不伪造 attestation、不注入宿主凭据
（guest 只持有会话令牌）、不在探针未实现时谎报通过（未实现层如实
标 SKIP）。诚实性优先于好看——包括这一段本身。

**探针的定位**：guest 内探针（escape-test 的 PROBE 行、up 的防火墙
守门）走 guest 登录 shell 传输，Ubuntu 的 bash 补丁使非交互会话也
source `~/.bashrc`——被监控方理论上可致盲或伪造这些行。消费端已按
"缺行即失败"处理，但**安全控制面是宿主侧的 gate 证据链与内核态防
火墙**，guest 探针是遥测与验收辅助（F-062 的如实结论）。

## License

MIT. Containment research and borrowed ideas are credited in ROADMAP.md.
creance is an independent community project, not affiliated with Anthropic.
