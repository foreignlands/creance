# r30-negative-controls

Mutation matrix for R30 (v0.6.22). `cases.py` = 21 new R30 cases + r29 regression set (`r29cases.py`, anchors adapted where v0.6.22 changed them).

```sh
git worktree add --detach "$HOME/r30-wt" v0.6.22      # $HOME, not /tmp
CREANCE_REPO=$HOME/r30-wt [ONLY="NC-A NC-B"] python3 harness/tools/r30-negative-controls/run.py
```

Per case: backup → needle `grep -c` before → literal edits (exact-one anchor) → cargo fmt → needle after → `cargo test --workspace` → clippy -D warnings → restore → md5 check.
Results: `round1/` (full matrix, split over two worktrees), `referee-*.out` (re-run of every GREEN case), `cfg.out` (F-106 equivalent-cfg retry).
`HARNESS-ERROR(compile)` for NC-XMUTE/NC-XMUTE2 = expected: `mark_provisioned` is now `pub(crate)` so the cross-crate mint no longer compiles (sealed — counts as red).
