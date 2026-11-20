# Changelog

All notable changes to creance are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/). During 0.x, breaking changes bump the minor.

## [0.5.7] — 2026-11-20

### Fixed — night-13: R11 finding 055

- **F-055**: the provision URL consumed the inner-script ARCH through
  a cross-quote expansion the outer shell never defined — the arch
  segment was empty on every architecture and the pinned node download
  was dead code on the apt fallback. ARCH now expands where it lives;
  the URL's completeness is asserted and probe-verified end to end.

## [0.5.6] — 2026-11-20

### Fixed — night-12: R10 findings 052–054

- **F-052**: night-11's up-refusal edit had been silently overwritten
  (the commit message claimed it; the code never had it) — a deleted
  stamp still skipped the drift check, and `limactl start` on an
  unknown name cloned Lima's default template: an unprovisioned VM
  behind a green exit. The refusal is real now (live-verified both
  cases) and `up` only starts instances this profile set up.
- **F-054**: every provision network step carries a deadline (curl -m,
  apt timeouts) inside one hard 300s toolchain budget — a TCP blackhole
  can no longer get the script killed before the lockdown and sudo
  retirement run. The arch check is POSIX now, so the node download URL
  is finally right on arm64.
- **F-053**: instance names are generated lowercase, matching lima's
  create-time lowercasing — mixed-case names made every existence check
  query a name that never existed.

## [0.5.5] — 2026-11-20

### Fixed — night-11: R9 findings 048–051

- **F-048 (grant path restored)**: the rules reconciliation guessed a
  bare array; the live core answers {"rules":[...]} — every honest core
  was judged divergent and gate-open failed 100% of the time. The
  captured live response is now the frozen fixture of a pure judge
  (with flip/smuggle/bare-array counter-examples).
- **F-049**: a missing or unreadable fingerprint stamp no longer skips
  the drift check — `up` refuses, the escape probe flags a running VM
  without its stamp, and a setup that cannot write the stamp fails.
- **F-050**: an unreadable store (one corrupted sources.json) no longer
  silently blinds both gate-open reconciliations — no store, no
  evidence.
- **F-051**: `creance setup` rebuilds an existing instance (limactl
  delete -f then create; the VM disk is replaced, the host workspace is
  untouched) — every "re-run setup" guidance is finally reachable.

## [0.5.4] — 2026-11-20

### Fixed — night-10: R8 findings 044–047

- **F-044**: `up` no longer refreshes the fingerprint stamp — after the
  promise narrowed to guest-visible fields, a refresh could only
  launder real drift (a bare start never re-provisions). Up now refuses
  to start on drift and points at re-setup.
- **F-045**: the promise fields have a real supply: provision writes
  CAGE_TZ/CAGE_LOCALE/CAGE_LANGUAGE to /etc/profile.d/cage-env.sh (Go
  injects the same trio); browser_language is no longer a vacuous
  promise.
- **F-046**: readiness reconciles the RULES now (a flipped core keeping
  every self-reported field honest while swapping MATCH,CAGE for
  MATCH,DIRECT used to pass), and gate-open reconciles again after the
  trace sample — the flip window shrinks to milliseconds.
- **F-047**: selecting a node is transactional — the old gate's
  revocation comes first and its failure aborts the selection (Go's
  applyProxy semantics), never an open gate behind a changed config
  reported as success.

## [0.5.3] — 2026-11-20

### Fixed — night-09: R7 findings 040–043

- **F-041**: night-08's idempotent sync path stripped exit_policy from
  its comparison, so an anchor change with an unmoved revision kept an
  OPEN gate running on evidence judged against the OLD anchor. The
  anchor is part of "unchanged" now; any drift demands a restart.
- **F-040**: the fingerprint stamp hashed the whole config, so any
  routine host-side operation (a select rotating the revision, an
  anchor tune) left the escape probe permanently red. The stamp now
  records the guest's promise only (timezone, locale, browser
  language); the full fingerprint still guards the up-time running
  lock.
- **F-042**: the core's control socket is enforced by reconciliation,
  not by its secret — live verification showed mihomo's unix controller
  ignores the configured secret entirely (file permissions ARE its
  auth). The secret stays for any TCP path, and gate-open now refuses
  to draw exit evidence from a core whose runtime diverged from its
  generated config (readiness checks mode among everything else).
- **F-043**: selecting a node revokes the gates at once (both CLI and
  workbench paths), matching Go's synchronous applyProxy revocation —
  no more open-gate-with-declared-different-exit window.

## [0.5.2] — 2026-11-20

### Fixed — night-08: R6 findings 036–039

- **F-037 (S2)**: the gate's bearer token lives in memory from start.
  The per-request re-read of the record degraded to an empty token
  when the file was unreadable (chmod 000, the close-removal window)
  and constant_time_eq("", "") passed — a credential-less process
  drove check → grant → open. Live-probe verified: the whole chain now
  403s. A renamed-over loser also no longer accepts the winner's token.
- **F-036**: the exit-drift window is closed. Core restarts (CLI and
  workbench) sync the gate FIRST — a changed exit closes the gate while
  the old core still serves; an idempotent no-change sync keeps the
  gate's state instead of force-retiring it; grants bind to the gate's
  run and the current instant (run_id + created_at minted by gate::open,
  enforced inside the check window, inner/outer report ids symmetric).
  The Go contract's configuration-fingerprint dimension lands with 0.6.
- **F-038**: the evidence's trust boundary is stated honestly — a
  single-destination sample (1.1.1.1-path, now an explicit audit key);
  TLS pins the sample to Cloudflare, single-group core config pins
  evidence to the wire's node, but per-destination routing by the node
  itself is undetectable by one source.
- **F-039**: the ghost workspace manifest at crates/ (a 0.2.0-era
  leftover) is gone; external path-deps resolve the real workspace.
- **R6-H4**: `up` re-pins the fingerprint stamp (proxy_revision is part
  of the fingerprint; a routine proxy-select between runs no longer
  leaves the escape probe permanently red).

## [0.5.1] — 2026-11-19

### Fixed — night-07: R5 findings 032–035

- **F-032**: subscription content can no longer forge the escape verdict.
  A 48-hex password inside imported subscription data (remote,
  attacker-chosen, never reaching the guest) tripped the credentials
  scan into a false escape and exit 1 — a subscription provider could
  weaponize the trust oracle. proxy/sources.json is now explicitly out
  of the probe's scope (whitelisting its fields would be worse: it
  would launder arbitrary hex into the issued set). Live-replayed via
  the poisoning CLI flow: contained, exit 0.
- **F-035**: spawn_daemon no longer dedups on a dying daemon. A live
  pid with no record meant "just starting" or "already exiting";
  deduping there reported up-success with nothing running. The branch
  waits one tick — a fresh daemon publishes its record, a dying one
  exits — then spawns; the run_id handoff absorbs any overlap.
- **F-033**: the fingerprint-consistent probe is alive. Setup pins the
  fingerprint the VM was promised at creation; the probe enforces
  agreement (fresh stamp → contained, drifted config → escape with
  re-pin guidance). Also fixes an intermittent test flake (parallel
  temp-name collisions on subsec-nanos alone).
- **F-034**: the provision node download is atomic (temp + move): a
  mid-transfer curl corpse can no longer sit in /usr/local/bin and
  shadow the apt fallback's working /usr/bin/node.

## [0.5.0] — 2026-11-19

### Added — exit-policy evidence chain (ROADMAP 0.5)

- **`creance gate-open` now grants on evidence, not assertion** (0.4's
  grant carried five self-declared checks, labelled as such): the exit
  is observed live through the configured proxy (Cloudflare trace:
  connecting IP + country), evaluated against the exit-policy anchor —
  static IP equality, dynamic country match, or `any` — under the
  mandatory mainland-IPv4 deny list (6,204 prefixes). Only a Passed
  verdict opens the wire; Failed/Unknown stay closed with the reason and
  the observed exit printed.
- The observation rides the grant as inert evidence keys (`exit_ip`,
  `exit_country`) — part of the record for audit.
- Honesty boundaries, enforced by refusal: region/city-scoped anchors
  evaluate Unknown (the trace source carries no honest region data —
  `colo` is a Cloudflare datacenter, not the exit's region) and stay
  closed until a GeoIP source lands; an unbound default policy refuses
  with binding guidance; a dead proxy means no evidence, never a pass.
- Trust assumption (documented in `evidence.rs`): the observation trusts
  the proxy path to reach 1.1.1.1 — the same trust the wire rests on.
  A second independent trace source for cross-checking is future work.
- `gate::open` takes the caller-supplied checks (the CLI assembles
  structural self-checks + the evidence verdict); the daemon-side
  REQUIRED-set enforcement is unchanged.

### Changed

- Default (unbound) exit policies no longer open: bind a scope in
  config.json first (QUICKSTART has the three recipes). This replaces
  0.4's open-by-default behavior — the gate is now evidence-first.

## [0.4.2] — 2026-11-19

### Fixed — night-06: R4 findings 027–030 + provision fail-open (031)

- **F-028 (S2, live-verified)**: the dual-daemon war. A spawn race or a
  direct `gate-daemon` invocation left a loser alive forever on "a record
  exists", its Closed-state watchdog murdering the winner's tunnel every
  500ms — gate=closed with an intermittently live wire, unmanageable by
  gate-close. The daemon loop now binds to the record's run_id: a
  renamed-over loser retires within a tick, disowned (its drop no longer
  deletes the winner's record — the first fix's live replay caught that
  cascade collapsing the whole gate system), and the watchdog refuses to
  touch the wire it no longer owns. Replay: two daemons converge to one,
  the tunnel pid is stable, the guest wire is continuously up under open
  and continuously down under closed.
- **F-029**: `creance up` mutinied merely slow daemons — any status
  failure (SIGSTOP, a 5s read timeout) deleted the live record, cut the
  tunnel, and spawned a replacement. Liveness evidence is now
  connect-level only (daemon_serving): a frozen daemon still accepts
  connects and is left alone; only ECONNREFUSED/ENOENT retires. retire
  and close_gates share the same errno-based helper (the "unreachable"
  string match is gone). Replay: a frozen daemon makes `up` a pure no-op.
- **F-027**: a dead tunnel ssh lingered as the gate daemon's zombie, and
  zombies pass kill(pid,0) AND keep their start token — ensure()
  short-circuited on the corpse forever (gate Open, wire dead). The
  pid-file liveness check now harvests the caller's own exited children
  via waitpid(WNOHANG); ensure() verifies the ssh survived its settle
  window; reap re-reads ownership before every kill. Replay: kill -9 the
  tunnel, it respawns in ~1s and the guest wire comes back.
- **F-030**: dial targets carrying C0 controls (R4 injected headers into
  an HTTP proxy's CONNECT line via a trailing numeric port) are refused
  at split_addr.
- **F-031**: provision's `set -e` meant a failed apt/mirror aborted the
  script BEFORE the firewall lockdown and sudoers retirement — shipping
  the guest with raw network and passwordless sudo. Installs are
  best-effort now; containment steps always run.
- credentials probe: the store revision (a 48-hex version marker written
  by proxy-select) joined the issued set — the live import+select flow
  tripped the scan as a false escape.

## [0.4.1] — 2026-11-19

### Fixed — night-05: R3 findings 019–023 + three found while fixing (024–026)

- **F-020 (S2, live-verified escape closed)**: the guest user now is the
  generated identity (lima `user:` block: name + neutral comment; uid
  stays host-mirrored — vz virtiofs passes uid numbers through, and that
  mirror is what keeps the writable workspace writable). The cloud-init
  sudoers grant is stripped in provision, the password locked, lima's
  `~/password` file removed: `sudo -n iptables -P OUTPUT ACCEPT` now
  fails — the one-command firewall lift R3 demonstrated is gone. escape
  -test gained `guest-identity` and `guest-privilege` probes. Recreate
  existing environments (`creance stop && creance setup`) to get the new
  guest user.
- **F-019**: a gate record now must prove a serving daemon. spawn_daemon
  pings the record's socket and retires stale records (plus their pid
  file and orphan tunnels) after SIGKILL/reboots; `stop` retires the gate
  via close_and_remove (record removal + immediate tunnel cut); the
  escape gate probe reports "gate record without a live daemon" as an
  ESCAPE instead of blessing the corpse. Live-verified: kill -9 → probe
  flips red → `up` self-heals → probe green, wire still down.
- **F-021**: pid files carry the process start-time token (`pidfile`
  module, shared with running.rs); tunnel/gate stop never signals a
  process the file cannot prove is theirs. A forged pid file against an
  innocent process kills no one.
- **F-022**: username wired end-to-end (ssh tunnel logs in as the
  generated user); load_or_create refuses to reset an unreadable profile
  instead of regenerating identity; the credentials probe scans the whole
  profile directory for token-shaped values against the issued set
  (session token, core auth, gate tokens) — stray secret files are
  escapes; in-guest `env-hex-tokens` probe makes the session token the
  only hex secret in the environment.
- **F-023**: profiles whose physical Lima home cannot fit the socket
  budget fail at setup with an actionable error instead of limactl's raw
  UNIX_PATH_MAX fatal.
- **F-024**: v0.4.0 shipped without its own CI passing (11 fmt diffs, a
  test asserting a removed YAML field) — baseline restored; the release
  gate is a full `scripts/ci.sh` run, always.
- **F-025**: a virgin profile's `up` misread the missing `proxy/`
  directory as daemon failure (spawn succeeded; pid/log writes ENOENT).
  Directories are now created before use; the workbench test no longer
  assumes port 17896 is dead on the host.
- **F-026**: orphan `ssh -R` forwards beyond the pid file's reach are
  reaped by signature (HostKeyAlias + the reverse-forward spec — the
  alias alone also lives in every `limactl shell` client, as the live
  machine demonstrated); "closed = wire down" no longer depends on one
  file's survival.

## [0.4.0] — 2026-11-19

### Added — gate daemon + guest identities (ROADMAP 0.4)
- **gate-daemon**: `creance up` raises a detached gate daemon per
  environment (record-deduped, pid-file managed, stderr logged); `stop`
  retires it via record removal. The gate's watchdog now OWNS the ssh -R
  wire: Closed gate → tunnel down, Open/Checking → tunnel up. Verified
  live: closed = no wire, `gate-open` = wire restored within a second.
- **`creance gate-open` / `gate-close`**: explicit control of the guest's
  only route. The open grant currently carries self-checks only (labelled
  as such); exit-policy evidence integration is 0.5.
- **Guest profiles** (`guest-profile.json`): generated identity —
  cage-<hash> hostname (applied via hostnamectl in provision), non-reserved
  username, 48-hex session token. Created once, never overwritten.
- **One-time credentials**: the ONLY secret the guest receives is the
  cage-issued `CREANCE_SESSION_TOKEN` (provision-time env); rotatable via
  profile rotation. escape-test now hunts host-shaped secrets (API keys /
  private keys) in the guest env — anything beyond the session token is an
  ESCAPE.
- escape-test gate probe enforced: a VM without a gate record is an escape.
- docs/CLOUD-DEVIN.md: Linux-side verification protocol for cloud agents.

## [0.3.0] — 2026-11-19

### Added — the guest network enforcement plane (ROADMAP 0.3)
- Topological containment: provisioned guests get `OUTPUT DROP` by default
  (lo/established/DHCP/ICMP allowed), external DNS and IPv6 disabled —
  direct egress is physically dropped, not merely discouraged. Verified
  live: `net-direct-egress` / `net-dns-external` / `net-ipv6` probes PASS.
- The guest's single wire out: an ssh reverse tunnel (raised by `creance up`,
  torn down by `creance stop`) carrying guest `127.0.0.1:<port>` to the
  host-side core's loopback — the core never leaves host loopback, no LAN
  exposure. Lima's NAT refusing RFC1918 targets and vz rejecting reverse
  portForwards were established experimentally; ssh -R survives both.
- `escape-test` network probes are ENFORCED now (no more SKIP), with a
  positive control (`proxy-path`) proving the only route works; in-guest
  ESCAPE lines fail the run (exit 1).
- `direct`-type nodes importable (explicit DIRECT exit, user-owned choice).

### Fixed
- Instance names budget their length on the PHYSICAL Lima home (deep
  profiles used to blow UNIX_PATH_MAX), restoring isolation after the
  F-010 LIMA_HOME fix exposed real paths.

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
