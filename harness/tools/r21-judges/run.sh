#!/bin/sh
# r21-judges — run the r14/r15 judges (main copies, signatures fixed in 23b0da2) twice each, md5 the outputs.
# (--offline dropped: the tool lockfiles pin clap 4.6.9, absent from the fresh cargo cache)
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=${CREANCE_REPO:-$(CDPATH= cd -- "$HERE/../../.." && pwd)}
cd "$REPO" || exit 2
E="$HERE/evidence"; mkdir -p "$E"
for j in r14-convergence r15-064-recheck; do
  for i in 1 2; do
    cargo run -q --manifest-path "harness/tools/$j/Cargo.toml" > "$E/r21-$j-$i.out" 2>&1
    echo "$j run$i RC=$? md5=$(md5sum < "$E/r21-$j-$i.out" | cut -c1-8) lines=$(wc -l < "$E/r21-$j-$i.out")"
  done
done
