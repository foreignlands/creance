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
| 0.5 | Exit-policy evidence chain | grant requires live exit-IP evidence against the anchor + mainland deny list (replaces self-check-only grant) |
| 0.6 | Multi-environment & snapshots | several contained environments per host, snapshot restore |
| 0.7 | API stabilization | rustdoc coverage, MSRV declared, semver-checks in CI |
| 0.6 | API stabilization | rustdoc coverage, MSRV declared, semver-checks in CI |
| 0.7–0.9 | RC hardening | no breaking changes; docs complete; escape suite extended |
| 1.0 | Contained workspace GA | enforcement planes all live; published crates |

## Support window
Latest minor: full maintenance. Previous minor: security fixes only.
