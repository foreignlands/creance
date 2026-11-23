# r31-negative-controls

Mutation matrix for v0.6.23 (F-111..F-116 fixes). Each case = exact literal edits on a detached worktree,
then `cargo fmt --all` → `cargo test --workspace --locked -q` → (if green) `cargo clippy --workspace --all-targets --locked -q -- -D warnings`,
then restore + md5 check. `needle before/after` = `grep -c` of the injected needle before/after injection.

```sh
git worktree add --detach $HOME/r31-wt v0.6.23        # keep under $HOME, not /tmp (temp-dir gates)
CREANCE_REPO=$HOME/r31-wt NC_LOGS=$PWD/logs ONLY="NC-…" python3 run.py
```

- `cases.py`: `NEW` (R31 attacks) + `REGR` (= r30cases.py incl. r29 set).
- `new.out`/`logs/`: NEW run 1; `ref.out`/`logs-ref/`: referee re-run of all GREENs; `ref2.out`: NC-UNITprintf2 2nd run.
- `regr.out`/`logs-regr/`: regression set — all red; NC-XGATE/XMUTE/XMUTE2 are expected compile red (E0603 private / unsafe lint = the guard).
- GREEN (filed 117–122): WRAPparam WRAPdead WRAPalias GPscript3 | ZMINT ZMINT2 VISfnptr | UPguard2 MAINxfile2 | HDindent HDexec HDandexit HDfalse | ENdisable2 UNITprintf2 | WDwarm WDsleep2.
- Controls red as expected: NC-ENenv, NC-UNITprintf (unsplit `egress-lock`).
