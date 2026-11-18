# Changelog

All notable changes to creance are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/). During 0.x, breaking changes bump the minor.

## [0.2.0] — 2026-11-18

### Added
- Packaged for use: `scripts/install.sh` (build + install + bundled core),
  `docs/QUICKSTART.md`, online-smoke recipe (local mihomo `direct` core —
  real Internet round-trips without owning a node; verified live).
- Night-audit harness (`harness/`): operator prompt with loop/compression/
  findings protocols, 20-entry attack-surface map, escape-drill brief for
  in-VM model red-teaming.
- `escape-test` command: automated containment probes (host-side now,
  in-guest script with a flag-file oracle; unimplemented layers report
  `not enforced` instead of faking a pass).
- `proxy-refresh` (re-fetch URL-backed sources), `proxy-import --url`,
  `serve` workbench (loopback HTTP + single-page UI), `doctor` diagnostics,
  `setup`/`up`/`shell`/`stop` VM lifecycle via limactl, gate control plane
  (unix-socket HTTP state machine with lease watchdog and revision sync).

### Changed
- **Rename to creance**, split into five layered crates: `creance-net`,
  `creance-vm`, `creance-proxy`, `creance-gate`, `creance`. `CREANCE_CONFIG`
  env (legacy `CLAUDE_CAGE_CONFIG` still honored); default profile
  `~/.creance` with legacy `~/.claude-cage` fallback.
- Buffered header reads everywhere (8 KiB chunks + replay reader) replacing
  four byte-at-a-time copies.

### Fixed
- Subscription import: key canonicalization before counting (`Name:`-style
  nodes panicked or collided IDs), ws-headers union merge.
- SSRF: subscription redirects to literal loopback/private/link-local
  targets refused.
- mihomo core spawned with a clean environment (host proxies/credentials no
  longer leak in); relay signal handlers installed before spawn.
- Gate lifecycle: listener/watchdog ownership, socket-directory cleanup,
  poisoned-lock recovery.
- DoH/body reads: Content-Length exact reads (EOF-wait hang), oversize
  probe on length-less bodies, expired deadlines fail fast, dial/TLS honor
  the caller's budget.
- proxy-start idempotence (matching running core is a no-op), launchd
  bootstrap rollback, sha256-based relay/core copies.

## [0.1.0] — 2026-11-18

Initial Rust rewrite of the Claude Cage control plane: proxy-only egress
(SOCKS5/CONNECT/TLS/DoH, zero direct fallback), managed proxy under launchd,
VM lifecycle, exit policy with the mainland deny list, subscription store.
