# r29-negative-controls

`CREANCE_REPO=<worktree under $HOME> [ONLY="NC-…"] [NC_LOGS=dir] python3 run.py` — mutation matrix (cases.py).
`CREANCE_REPO=… ONLY="…" python3 inventory.py` — scripts/check-probe-inventory.sh leg for green cases.
results-{A,B,C,D}.txt first run; results-judge*.txt second (referee) run; results-inventory.txt.
Real-machine FRESH leg: `LAB=$HOME/r29-lab CREANCE_BIN=target/release/creance sh ../r29-real-up/run.sh`.
