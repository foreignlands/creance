#!/bin/sh
# r28-heredoc-ws — F-098: a stray terminator line with leading/trailing whitespace (which the v0.6.20
# structural test does not count as "EGRESSRULES") still runs as a command after the heredoc under set -e.
# Renders the REAL v0.6.20 bootstrap, injects each variant after the terminator, runs the rules.v4 heredoc block (+ stray line) with sh -e.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=${CREANCE_REPO:-$(CDPATH= cd -- "$HERE/../../.." && pwd)}
T=$(mktemp -d "${TMPDIR:-/tmp}/r28-hdws.XXXXXX"); trap 'rm -rf "$T"' EXIT
cargo run -q --manifest-path "$REPO/harness/tools/r28-render/Cargo.toml" bootstrap qemu > "$T/boot.sh" || exit 2
for v in none '  EGRESSRULES' '	EGRESSRULES' 'EGRESSRULES '; do
  awk -v v="$v" -v out="$T" 'BEGIN{print "set -e"} /^cat > \/etc\/iptables\/rules\.v4 /{on=1}
    on{gsub("/etc/iptables/rules.v4", out "/rules.v4"); print} /^EGRESSRULES$/{ if (v!="none") print v; print "echo REACHED-AFTER-HEREDOC"; exit }' "$T/boot.sh" > "$T/p.sh"
  sh -n "$T/p.sh"; n=$?
  sh "$T/p.sh" > "$T/o" 2>&1; rc=$?
  printf '%s: sh-n=%s RC=%s bare-count=%s | %s\n' "[$v]" "$n" "$rc" "$(grep -cx EGRESSRULES "$T/p.sh")" "$(tail -1 "$T/o")"
done
