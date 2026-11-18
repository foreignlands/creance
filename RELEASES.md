# Release plan

SemVer during 0.x: breaking changes bump the minor, fixes bump the patch.
Tags: `vX.Y.Z` on the workspace root. `cargo-release` is the intended tool
(not yet wired); until then, manual: bump `[workspace.package].version`,
update CHANGELOG, `git tag -s vX.Y.Z`.

| Version | Theme | Exit criteria |
|---|---|---|
| 0.2 | Rename + containment probes (this release) | 114 tests, escape-test live |
| 0.3 | VM network enforcement plane | direct egress/DNS/IPv6 probes flip from SKIP to enforced in escape-test |
| 0.4 | Guest profiles + per-session credentials | fingerprint probe enforced; key injection revocable per session |
| 0.5 | Multi-environment & snapshots | several contained environments per host, snapshot restore |
| 0.6 | API stabilization | rustdoc coverage, MSRV declared, semver-checks in CI |
| 0.7–0.9 | RC hardening | no breaking changes; docs complete; escape suite extended |
| 1.0 | Contained workspace GA | enforcement planes all live; published crates |

## Support window
Latest minor: full maintenance. Previous minor: security fixes only.
