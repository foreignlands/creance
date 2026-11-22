# r25-negative-controls
Mutation controls for the v0.6.16 guards (F-090/F-091) + R24 regressions + new bypasses. `CREANCE_REPO=<repo> [ONLY="NC-X NC-Y"] sh run.sh`.
Protocol: cp backup → perl inject → grep -c before/after → `cargo test --locked -q -p <crate>` → cp restore → md5sum -c.
`compile-err=1` with `failed>0` is cargo's own "error: test failed" summary line, not a compile error. Evidence: `run.log`, `logs/`. Section C greens = F-093.
