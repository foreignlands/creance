#!/bin/sh
# r23-gate-matrix — probe-inventory gate (scripts/check-probe-inventory.sh) fail-closed matrix,
# R18/R19 scenario set. cp backup, inject, grep -c proves landing, run gate, restore, md5sum -c.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=${CREANCE_REPO:-$(CDPATH= cd -- "$HERE/../../.." && pwd)}
cd "$REPO" || exit 2
B=$(mktemp -d /tmp/r23-gm.XXXXXX)
F="README.md ROADMAP.md crates/creance/src/escape.rs scripts/check-probe-inventory.sh"
md5sum $F > "$B/md5"; for f in $F; do mkdir -p "$B/$(dirname "$f")"; cp "$f" "$B/$f"; done
restore() { for f in $F; do cp "$B/$f" "$f"; done; }
trap 'restore; rm -rf "$B"' EXIT
gate() { sh scripts/check-probe-inventory.sh > "$B/o" 2>&1; rc=$?; echo "$1: grep-c=$2 RC=$rc FAIL-lines=$(grep -c '^FAIL' "$B/o")"; grep '^FAIL' "$B/o" | sed 's/^/    /' | head -3; restore; }
sh scripts/check-probe-inventory.sh > "$B/o" 2>&1; echo "POS: RC=$? $(tail -1 "$B/o")"
perl -0pi -e 's/(<!-- probe-inventory:readme-enforced -->.*?proxy-path)/$1 \/ ghost-probe-r23/s' README.md; gate NC-A "$(grep -c ghost-probe-r23 README.md)"
perl -0pi -e 's/ \/ net-icmp-external//' README.md; gate NC-B "$(grep -c 'net-icmp-external' README.md)"
perl -0pi -e 's/(<!-- probe-inventory:guest-enforced -->.*?)proxy-path( \/ )?/$1/s' ROADMAP.md; gate NC1 "$(sed -n '/probe-inventory:guest-enforced -->/,/\/probe-inventory:guest-enforced/p' ROADMAP.md | grep -c proxy-path)"
perl -0pi -e 's/(<!-- probe-inventory:guest-enforced -->\n)/$1ghost-probe-r23 \/ /s' ROADMAP.md; gate NC2 "$(grep -c ghost-probe-r23 ROADMAP.md)"
perl -0pi -e 's/(echo "PROBE fs-flag-readable ESCAPE")/$1\necho "PROBE ghost-probe-r23 PASS"/' crates/creance/src/escape.rs; gate NC3 "$(grep -c ghost-probe-r23 crates/creance/src/escape.rs)"
perl -0pi -e 's/probe-inventory:guest-enforced/probe-inventory:guest-enforcedX/g' ROADMAP.md; gate NC5 "$(grep -c guest-enforcedX ROADMAP.md)"
perl -0pi -e 's/echo "PROBE sock-\$s ESCAPE"/echo "PROBE sock-\$s ESC"/' crates/creance/src/escape.rs; gate NC6v "$(grep -c 'PROBE sock-\$s ESCAPE' crates/creance/src/escape.rs)"
md5sum -c "$B/md5"
