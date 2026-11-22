#!/bin/sh
# sequential driver: NC -> gate matrix -> judges (all touch crates/, never concurrently)
H=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sh "$H/r21-negative-controls/run.sh" > "$H/r21-negative-controls/evidence.log" 2>&1; echo "NC done RC=$?" >> "$H/r21-negative-controls/evidence.log"
sh "$H/r21-gate-matrix/run.sh" > "$H/r21-gate-matrix/evidence.log" 2>&1
sh "$H/r21-judges/run.sh" > "$H/r21-judges/evidence.log" 2>&1
echo ALLDONE > /tmp/r21-done
