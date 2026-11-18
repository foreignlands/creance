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

```sh
# Toolchain stays inside the repo (nothing global is touched):
export RUSTUP_HOME="$PWD/.toolchain/rustup" CARGO_HOME="$PWD/.toolchain/cargo"
export PATH="$PWD/.toolchain/cargo/bin:$PATH"

scripts/ci.sh                 # fmt + clippy -D warnings + tests + release build
./target/release/creance --help
```

```sh
creance init                                # private profile (~/.creance)
creance proxy-import --name my --url https://…   # through the proxy, SSRF-guarded
creance proxy-select "US-Exit"              # apply end-to-end (store+config agree)
creance proxy-start                         # mihomo under launchd, idempotent
creance check                               # transport check, no direct fallback
creance setup && creance up                 # Ubuntu 24.04 VM, guest tz = profile
creance shell bash                          # work inside
creance escape-test                         # prove containment (or see what's pending)
creance doctor / serve / stop               # diagnose · workbench UI · teardown
```

`CREANCE_CONFIG` selects a profile (legacy `CLAUDE_CAGE_CONFIG` honored;
existing `~/.claude-cage` profiles keep working).

## Escape-test: the acceptance harness

`creance escape-test` reports per-probe: ✅ contained · ❌ escaped (exit 1) ·
⏭️ not-enforced (its layer ships in 0.3). Current enforced set: profile
validity, no host credentials in child env, numeric proxy endpoint. With a
VM: filesystem flag oracle, guest env/SSH/socket probes, and the network
probes (SKIP until the enforcement plane lands — honest by design).

## Status

v0.2.0 — 114 tests, clippy-clean, live-verified proxy lifecycle + VM chain.
The big open item is the **VM network enforcement plane** (guest traffic
physically routed through the gate); everything else on
[ROADMAP.md](ROADMAP.md).

## License

MIT. Containment research and borrowed ideas are credited in ROADMAP.md.
creance is an independent community project, not affiliated with Anthropic.
