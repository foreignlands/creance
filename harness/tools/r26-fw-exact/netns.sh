#!/bin/sh
# r26-fw-exact netns replay — v0.6.17 fw-armed exact-line allowlist vs live netfilter in throwaway netns (sudo -n unshare -n).
# Per case, two boots:
#   boot A ("this boot"): live = product rules.v4 + LIVE extra; rules.v4 file = product + LIVE extra + RULES-ONLY extra
#   boot B ("next boot"): iptables-restore of that rules.v4 file (what egress-lock replays at the next boot)
# Each boot: ExecStartPost stamp cmd (verbatim from provision.rs) -> shipped probe fw fragment as uid 65534
#   -> live OUTPUT verdict per destination (policy DROP counter delta, egress.sh).
# rules.v4 base = REAL guest_bootstrap heredoc; probe = REAL egress_probe_script (both dumped by this crate).
# usage: CREANCE_REPO=<repo> [BACKEND=qemu|lima] sh netns.sh
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=${CREANCE_REPO:-$(CDPATH= cd -- "$HERE/../../.." && pwd)}
BK=${BACKEND:-qemu}
W=$(mktemp -d /tmp/r26-fw.XXXXXX); chmod 755 "$W"; trap 'rm -rf "$W"' EXIT
cargo run -q --manifest-path "$HERE/Cargo.toml" probe "$BK" > "$W/probe.sh" || exit 2
cargo run -q --manifest-path "$HERE/Cargo.toml" rules "$BK" > "$W/base" || exit 2
sed -n '/^STAMP=/,$p' "$W/probe.sh" > "$W/fw.sh"
STAMP_CMD=$(sed -n "s/^ExecStartPost=\/bin\/sh -c '\(.*\)'\$/\1/p" "$REPO/crates/creance-vm/src/provision.rs" | sed "s|/run/egress-armed|$W/stamp|")
printf '%s\n' "$STAMP_CMD" > "$W/stamp.sh"
sed '$d' "$W/base" > "$W/head"   # base minus trailing COMMIT
case $BK in lima) GW=192.168.5.2 ADDR=192.168.5.15/24;; *) GW=10.0.2.2 ADDR=10.0.2.15/24;; esac
cp "$HERE/egress.sh" "$W/egress.sh"; sed -i "s/10\.0\.2\.2/$GW/g" "$W/egress.sh"
chmod 644 "$W"/*
echo "backend=$BK probe md5=$(md5sum < "$W/probe.sh" | cut -c1-8) rules md5=$(md5sum < "$W/base" | cut -c1-8)"
echo "stamp cmd: $STAMP_CMD"
boot() { # $1=ruleset file to restore; prints restore/fw/stamp/egress
  sudo -n unshare -n sh -c "ip link set lo up; ip link add d0 type dummy; ip link set d0 up; ip addr add $ADDR dev d0; ip route add default via $GW;
     rm -f $W/stamp; iptables-restore < $1 > $W/rerr 2>&1; rrc=\$?; head -2 $W/rerr | sed 's/^/restore-err: /'; echo restore-rc=\$rrc
     if [ \$rrc = 0 ]; then sh $W/stamp.sh; chmod 644 $W/stamp; else echo 'stamp: (unit failed -> ExecStartPost skipped, no stamp)'; fi
     printf 'fw: '; setpriv --reuid=65534 --regid=65534 --clear-groups env -i PATH=/usr/bin:/bin ${PLANG:+LANG=$PLANG} CREANCE_STAMP=$W/stamp CREANCE_RULES=$W/rules sh $W/fw.sh
     printf 'stamp: '; grep -E '^-A|^:' $W/stamp 2>/dev/null | tr '\n' ';'; echo
     printf 'egress: '; sh $W/egress.sh" 2>&1
}
# $1=name $2=LIVE extra (printf fmt, lands before COMMIT) [$3=RULES-ONLY extra]
run() {
  { cat "$W/head"; printf -- "$2"; echo COMMIT; } > "$W/live"
  { cat "$W/head"; printf -- "$2${3:-}"; echo COMMIT; } > "$W/rules"; chmod 644 "$W/live" "$W/rules"
  echo "== $1"
  boot "$W/live" | sed 's/^/   A /'
  if [ -n "${3:-}" ]; then boot "$W/rules" | sed 's/^/   B /'; fi
}
H=$GW
# runfull: $1=name; rules.v4 = the file given on stdin (live = clean product file); A + B
runfull() {
  cat > "$W/rules"; cp "$W/base" "$W/live"; chmod 644 "$W/live" "$W/rules"
  echo "== $1  (rules.v4 md5=$(md5sum < "$W/rules" | cut -c1-8) bytes=$(wc -c < "$W/rules"))"
  boot "$W/live" | sed 's/^/   A /'
  boot "$W/rules" | sed 's/^/   B /'
}
run P00-product-shape ''
runfull P01-product-file < "$W/base"
# --- F-092 regressions: R25 S01-S09 + R01/R02 (rules-only) ---
run R01-rules-only-comment-forged '' "-A OUTPUT -m comment --comment \"-d $H/32 -p icmp\" -j ACCEPT\n"
run R02-rules-only-qualified '' '-A OUTPUT -o e+ -j ACCEPT\n'
run S01-rules-insert '' '-I OUTPUT -j ACCEPT\n'
run S02-rules-insert-pos '' '-I OUTPUT 1 -j ACCEPT\n'
run S03-rules-long-append '' '--append OUTPUT -j ACCEPT\n'
run S04-rules-double-space '' '-A  OUTPUT -j ACCEPT\n'
run S05-rules-leading-space '' ' -A OUTPUT -j ACCEPT\n'
run S06-rules-tab '' '-A\tOUTPUT -j ACCEPT\n'
run S07-rules-replace '' '-R OUTPUT 1 -j ACCEPT\n'
run S08-rules-second-filter-table '' 'COMMIT\n*filter\n:OUTPUT ACCEPT [0:0]\n'
run S09-rules-policy-redeclared '' ':OUTPUT ACCEPT [0:0]\n'
run S10-rules-flush '' '-F OUTPUT\n'
run S11-rules-nat-table '' 'COMMIT\n*nat\n:OUTPUT ACCEPT [0:0]\n'
# --- live (stamp) side regressions ---
run N01-live-bare-accept '-A OUTPUT -j ACCEPT\n'
run N03-live-state-new '-A OUTPUT -m conntrack --ctstate NEW -j ACCEPT\n'
run B01-live-comment-forge "-A OUTPUT -m comment --comment \"-d $H/32 -p icmp\" -j ACCEPT\n"
run C04-live-dup-canonical "-A OUTPUT -o lo -j ACCEPT\n"
# --- (e) legal-equivalent / product-shape false-kill direction ---
run K03-rules-save-form '' "-A OUTPUT -d $H/32 -p udp -m udp --dport 67 -j ACCEPT\n"
run K04-rules-comment-line '' '# operator note\n'
runfull K05-rules-blank-lines <<X
$(sed 's/^\(:OUTPUT.*\)$/\1\n/' "$W/base")
X
runfull K06-rules-crlf <<X
$(sed 's/$/\r/' "$W/base")
X
# --- NEW (v0.6.17 whole-file check): line ORDER is not checked ---
# every line is allowlisted and each structural line occurs once, but COMMIT sits before :OUTPUT DROP:
# iptables-restore commits *filter with the boot-default OUTPUT ACCEPT policy and no rules, then errors on the rest.
runfull O01-commit-before-output-decl <<X
$(sed -n '1,3p' "$W/base"; echo COMMIT; sed -n '4,$p' "$W/base" | grep -vx COMMIT)
X
runfull O02-commit-right-after-filter <<X
$(sed -n '1p' "$W/base"; echo COMMIT; sed -n '2,$p' "$W/base" | grep -vx COMMIT)
X
runfull O03-filter-header-last <<X
$(sed -n '2,$p' "$W/base" | grep -vx COMMIT; echo '*filter'; echo COMMIT)
X
runfull O04-canonical-rules-after-commit <<X
$(grep -v '^-A' "$W/base"; grep '^-A' "$W/base")
X
# --- NEW: a NUL / invalid-UTF-8 byte flips GNU grep into binary mode: line output suppressed -> body empty ---
printf '%s' "$(sed '$d' "$W/base")" > "$W/zhead"
{ cat "$W/zhead"; printf '\n#\000\n-I OUTPUT -j ACCEPT\nCOMMIT\n'; } | runfull Z01-nul-comment-plus-insert
{ cat "$W/zhead"; printf '\n#\000\n-A OUTPUT -j ACCEPT\n-A OUTPUT -p tcp -j ACCEPT\nCOMMIT\n'; } | runfull Z02-nul-comment-plus-bare-accept
{ cat "$W/zhead"; printf '\n# \377\n-I OUTPUT -j ACCEPT\nCOMMIT\n'; } | runfull Z03-invalid-utf8-comment-plus-insert
