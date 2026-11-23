#!/bin/sh
# Repeat the watchdog lower/upper-bound test N times (run under load to probe CI jitter).
cd "${CREANCE_REPO:-$(dirname "$0")/../../..}" || exit 2
N=${N:-15}; pass=0; fail=0; i=0
while [ $i -lt $N ]; do
  if cargo test -q -p creance-gate watchdog_fuses_open_gate_when_core_unreachable >/dev/null 2>&1; then pass=$((pass+1)); else fail=$((fail+1)); fi
  i=$((i+1))
done
echo "N=$N pass=$pass fail=$fail load=$(cut -d' ' -f1-3 /proc/loadavg)"
