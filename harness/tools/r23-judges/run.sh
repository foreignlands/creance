#!/bin/sh
# r23-judges — run the r14/r15 judges (main copies, v0.6.14 HEAD) twice each, md5 the outputs.
# (--offline dropped: the tool lockfiles pin clap 4.6.9, absent from the fresh cargo cache)
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=${CREANCE_REPO:-$(CDPATH= cd -- "$HERE/../../.." && pwd)}
cd "$REPO" || exit 2
E="$HERE/evidence"; mkdir -p "$E"
for j in r14-convergence r15-064-recheck; do
  for i in 1 2; do
    cargo run -q --manifest-path "harness/tools/$j/Cargo.toml" > "$E/r23-$j-$i.out" 2>&1
    echo "$j run$i RC=$? md5=$(md5sum < "$E/r23-$j-$i.out" | cut -c1-8) lines=$(wc -l < "$E/r23-$j-$i.out")"
  done
done
# R23 copies: identical judges, only the flag argument made writable (see */src/main.rs r23_flag)
for j in r14-convergence-r23 r15-064-recheck-r23; do
  for i in 1 2; do
    cargo run -q --manifest-path "$HERE/$j/Cargo.toml" > "$E/$j-$i.out" 2>&1
    echo "$j run$i RC=$? md5=$(md5sum < "$E/$j-$i.out" | cut -c1-8) lines=$(wc -l < "$E/$j-$i.out")"
  done
done
rm -f "${TMPDIR:-/tmp}"/r23-judge-flag-*
git checkout -- harness/tools/r14-convergence/Cargo.lock harness/tools/r15-064-recheck/Cargo.lock 2>/dev/null
