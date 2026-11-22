#!/bin/sh
# r20-negative-controls — behavioral guards for the v0.6.11 fixes (073 / 074 / restrict=on).
# Each case: cp backup -> inject (grep -c proves it landed) -> cargo test of the owning crate
# -> restore from backup -> md5sum -c. A guarded fix turns some test red; RC=0 = no guard.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=${CREANCE_REPO:-$(CDPATH= cd -- "$HERE/../../.." && pwd)}
cd "$REPO" || exit 2
B=$(mktemp -d /tmp/r20-nc.XXXXXX)
FILES="crates/creance/src/escape.rs crates/creance-vm/src/qemu/runner.rs crates/creance/src/main.rs crates/creance-vm/src/qemu/provision.rs crates/creance-vm/src/lima.rs"
md5sum $FILES > "$B/md5"
for f in $FILES; do mkdir -p "$B/$(dirname "$f")"; cp "$f" "$B/$f"; done
restore() { for f in $FILES; do cp "$B/$f" "$f"; done; }
trap 'restore; rm -rf "$B"' EXIT
case_run() { # $1=name $2=file $3=perl-expr $4=grep-after $5=crate
  perl -0pi -e "$3" "$2"
  n=$(grep -c -- "$4" "$2")
  cargo test --locked -q -p "$5" > "$B/$1.log" 2>&1; rc=$?
  echo "$1: inject-grep-c=$n crate=$5 test-RC=$rc failed=$(grep -c 'FAILED\|panicked' "$B/$1.log")"
  restore
}
case_run NC-R crates/creance-vm/src/qemu/runner.rs 's/if provisioned \{ "restrict=on," \}/if provisioned { "" }/' 'if provisioned { "" }' creance-vm
case_run NC-F crates/creance/src/main.rs 's/std::fs::write\(&flag, b"creance-escape-oracle\\n"\)\.is_ok\(\)/true/' 'let flag_placed = true;' creance
case_run NC-073q crates/creance-vm/src/qemu/provision.rs 's/&\["10\.0\.2\.2", "10\.0\.2\.3"\]/&["192.168.5.2", "192.168.5.3"]/' '"192.168.5.2", "192.168.5.3"' creance-vm
case_run NC-073l crates/creance-vm/src/lima.rs 's/&\["192\.168\.5\.2", "192\.168\.5\.3"\]/&["10.0.2.2", "10.0.2.3"]/' '"10.0.2.2", "10.0.2.3"' creance-vm
case_run NC-074 crates/creance/src/escape.rs 's/r#"echo "PROBE fs-flag-readable SKIP — oracle flag 未能落盘""#/r#"echo "PROBE fs-flag-readable PASS"\necho "PROBE fs-flag-readable SKIP — oracle flag 未能落盘""#/' 'r#"echo "PROBE fs-flag-readable PASS"$' creance
md5sum -c "$B/md5"
