# Release plan

SemVer during 0.x: breaking changes bump the minor, fixes bump the patch.
Tags: `vX.Y.Z` on the workspace root. `cargo-release` is the intended tool
(not yet wired); until then, manual: bump `[workspace.package].version`,
update CHANGELOG, `git tag -s vX.Y.Z`.

| Version | Theme | Exit criteria |
|---|---|---|
| 0.2 | Rename + containment probes (this release) | 114 tests, escape-test live |
| 0.3 | VM network enforcement plane | **DONE 2026-11-19**: topology DROP + ssh -R single wire; three probes enforced live |
| 0.4 | Guest profiles + per-session credentials | **DONE 2026-11-19**: gate-daemon owns the wire; generated identity; session-only secrets, hunted by probes |
| 0.4.1 | night-05 hardening (R3 findings 019–026) | **DONE 2026-11-19**: guest privilege path removed (S2 escape closed, live-verified); gate records prove liveness; pid files start-time bound; orphan tunnels reaped |
| 0.4.2 | night-06 hardening (R4 findings 027–031) | **DONE 2026-11-19**: daemon war ended (run_id ownership + disown, live-verified); slow daemons never mutinied (connect-level evidence); zombies harvested (waitpid); dial CRLF refused; provision never skips containment |
| 0.5 | Exit-policy evidence chain | **DONE 2026-11-19**: gate-open grants on live exit observation (trace → anchor + mainland deny, Passed-only); unbound/region/city anchors refuse honestly; evidence keys ride the grant |
| 0.6 | Linux platform support | **DONE 2026-11-21**: QEMU+cloud-init backend live on Ubuntu/KVM — unattended setup→up→shell→escape-test→stop→delete green, node v22.14.0 provisioned, 7/7 host escape probes contained; mihomo in-process supervision green; PID-reuse guard armed via /proc |
| 0.7 | Multi-environment & snapshots | several contained environments per host, snapshot restore |
| 0.8 | API stabilization | rustdoc coverage, MSRV declared, semver-checks in CI |
| 0.9 | RC hardening | no breaking changes; docs complete; escape suite extended |
| 1.0 | Contained workspace GA | enforcement planes all live; published crates |

## Support window
Latest minor: full maintenance. Previous minor: security fixes only.
