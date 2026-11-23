#!/bin/sh
# r28-judges — run the main r14/r15 judges (v0.6.20, F-089 writable flag) twice each; md5 vs the R25 reference
# (r14 2ecbd0c1, r15 965e444c = armed world); prove the temp flag is cleaned (before/after listing).
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=${CREANCE_REPO:-$(CDPATH= cd -- "$HERE/../../.." && pwd)}
cd "$REPO" || exit 2
E="$HERE/evidence"; mkdir -p "$E"; T=${TMPDIR:-/tmp}
flags() { ls "$T" 2>/dev/null | grep -cE '^creance-r1[45]-flag-'; }
echo "flags-before=$(flags)"
for j in r14-convergence r15-064-recheck; do
  for i in 1 2; do
    cargo run -q --manifest-path "harness/tools/$j/Cargo.toml" > "$E/r28-$j-$i.out" 2>&1
    echo "$j run$i RC=$? md5=$(md5sum < "$E/r28-$j-$i.out" | cut -c1-8) lines=$(wc -l < "$E/r28-$j-$i.out") flags-after=$(flags)"
  done
done
git checkout -- harness/tools/r14-convergence/Cargo.lock harness/tools/r15-064-recheck/Cargo.lock 2>/dev/null
