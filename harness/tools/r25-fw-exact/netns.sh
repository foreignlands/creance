#!/bin/sh
# r25-fw-exact netns replay — v0.6.16 fw-armed exact-line allowlist vs live netfilter in throwaway netns (sudo -n unshare -n).
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
W=$(mktemp -d /tmp/r25-fw.XXXXXX); chmod 755 "$W"; trap 'rm -rf "$W"' EXIT
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
     iptables-restore < $1 2>&1 | head -2 | sed 's/^/restore-err: /'
     sh $W/stamp.sh; chmod 644 $W/stamp
     printf 'fw: '; setpriv --reuid=65534 --regid=65534 --clear-groups env -i PATH=/usr/bin:/bin CREANCE_STAMP=$W/stamp CREANCE_RULES=$W/rules sh $W/fw.sh
     printf 'stamp: '; grep -E '^-A|^:' $W/stamp | tr '\n' ';'; echo
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
run P00-product-shape ''
# F-090 regressions (live + rules.v4)
run N01-bare-accept '-A OUTPUT -j ACCEPT\n'
run N02-qualified-oe '-A OUTPUT -o e+ -j ACCEPT\n'
run N03-state-new '-A OUTPUT -m conntrack --ctstate NEW -j ACCEPT\n'
run B01-comment-forges-nat-icmp "-A OUTPUT -m comment --comment \"-d $H/32 -p icmp\" -j ACCEPT\n"
run B02-comment-forges-conntrack '-A OUTPUT -m comment --comment "conntrack --ctstate ESTABLISHED" -j ACCEPT\n'
run B03-ctstate-new-established '-A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n'
run B04-negated-dst-negated-dport "-A OUTPUT ! -d $H/32 -p udp -m udp ! --dport 67 -j ACCEPT\n"
run B05-negated-dst-icmp "-A OUTPUT ! -d $H/32 -p icmp -j ACCEPT\n"
run B06-dport-range "-A OUTPUT ! -d $H/32 -p udp -m udp --dport 67:65535 -j ACCEPT\n"
run B07-tcp-to-nat-host-comment-icmp "-A OUTPUT -d $H/32 -p tcp -m comment --comment \"-p icmp\" -j ACCEPT\n"
run B08-comment-forged-all-tcp "-A OUTPUT -p tcp -m comment --comment \"-d $H/32 -p icmp\" -j ACCEPT\n"
# (c) allowlist self-bypass shapes (live): case, duplicate -d, -m between, subchain at chain top, duplicates of canonical lines
run C01-dup-dst "-A OUTPUT -d $H/32 -d 1.1.1.1/32 -p icmp -j ACCEPT\n"
run C02-m-between-accept "-A OUTPUT -d $H/32 -p icmp -m comment --comment x -j ACCEPT\n"
run C03-subchain-at-top '-N X\n-A X -j ACCEPT\n-I OUTPUT 1 -j X\n'
run C04-dup-canonical "-A OUTPUT -o lo -j ACCEPT\n-A OUTPUT -d $H/32 -p icmp -j ACCEPT\n"
run C05-uppercase-target '-A OUTPUT -o lo -j accept\n'
run C06-user-chain-unreferenced '-N Y\n-A Y -j ACCEPT\n'
# (d) rules.v4-only edits (live clean) — F-090 R01/R02 regressions
run R01-rules-only-comment-forged '' "-A OUTPUT -m comment --comment \"-d $H/32 -p icmp\" -j ACCEPT\n"
run R02-rules-only-qualified '' '-A OUTPUT -o e+ -j ACCEPT\n'
# NEW: rules.v4-only, iptables-restore-valid spellings the `^-A OUTPUT` selector never sees
run S01-rules-insert '' '-I OUTPUT -j ACCEPT\n'
run S02-rules-insert-pos '' '-I OUTPUT 1 -j ACCEPT\n'
run S03-rules-long-append '' '--append OUTPUT -j ACCEPT\n'
run S04-rules-double-space '' '-A  OUTPUT -j ACCEPT\n'
run S05-rules-leading-space '' ' -A OUTPUT -j ACCEPT\n'
run S06-rules-tab '' '-A\tOUTPUT -j ACCEPT\n'
run S07-rules-replace '' '-R OUTPUT 1 -j ACCEPT\n'
run S08-rules-second-filter-table '' 'COMMIT\n*filter\n:OUTPUT ACCEPT [0:0]\n'
run S09-rules-policy-redeclared '' ':OUTPUT ACCEPT [0:0]\n'
run S10-rules-flush-then-accept '' '-F OUTPUT\n'
# (e) rules.v4-only legal-equivalent forms (false-kill direction)
run K01-rules-icmp-no-slash32 '' "-A OUTPUT -p icmp -d $H -j ACCEPT\n"
run K02-rules-state-match '' '-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n'
run K03-rules-save-form '' "-A OUTPUT -d $H/32 -p udp -m udp --dport 67 -j ACCEPT\n"
run K04-rules-comment-line '' '# operator note\n'
