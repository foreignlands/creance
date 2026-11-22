#!/bin/sh
# sequential driver: NC -> gate matrix -> judges (all touch crates/, never concurrently)
H=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sh "$H/r22-negative-controls/run.sh" > "$H/r22-negative-controls/evidence.log" 2>&1; echo "NC done RC=$?" >> "$H/r22-negative-controls/evidence.log"
sh "$H/r22-gate-matrix/run.sh" > "$H/r22-gate-matrix/evidence.log" 2>&1; echo "GM done RC=$?" >> "$H/r22-gate-matrix/evidence.log"
sh "$H/r22-judges/run.sh" > "$H/r22-judges/evidence.log" 2>&1; echo "J done RC=$?" >> "$H/r22-judges/evidence.log"
echo ALLDONE > /tmp/r22-done
