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
| `creance-vm` | profile config, paths/naming/state, PID-reuse guards, host facts, Lima lifecycle, exit-policy data |
| `creance-proxy` | subscription store + import, mihomo runtime config, launchd-managed core |
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
运转的对抗性审查员：循环协议、上下文压缩协议、findings 记录、20 项
攻击面地图，以及把模型关进 VM 让它全力逃逸的红队任务书。

## Escape-test: the acceptance harness

`creance escape-test` reports per-probe: ✅ contained · ❌ escaped (exit 1) ·
⏭️ not-enforced (its layer ships in 0.3). Current enforced set: profile
validity, no host credentials in child env, numeric proxy endpoint. With a
VM: filesystem flag oracle, guest env/SSH/socket probes, and the network
probes (SKIP until the enforcement plane lands — honest by design).

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

## License

MIT. Containment research and borrowed ideas are credited in ROADMAP.md.
creance is an independent community project, not affiliated with Anthropic.
