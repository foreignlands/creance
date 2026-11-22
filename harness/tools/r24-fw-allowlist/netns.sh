#!/bin/sh
# r24-fw-allowlist netns replay — v0.6.15 fw-armed allowlist vs live netfilter in throwaway netns (sudo -n unshare -n).
# rules.v4 (rendered product shape + extra) -> iptables-restore -> ExecStartPost stamp cmd (verbatim from provision.rs)
# -> shipped probe fw fragment (dumped by this crate from escape::egress_probe_script) as uid 65534
# -> what the live OUTPUT chain actually lets out (udp 8.8.8.8:53, udp 8.8.8.8:67, tcp 1.1.1.1:443, tcp 10.0.2.2:22, icmp 1.1.1.1).
# usage: CREANCE_REPO=<repo> sh netns.sh   (RULES_ONLY=1: hole only in rules.v4, stamp from clean live table)
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=${CREANCE_REPO:-$(CDPATH= cd -- "$HERE/../../.." && pwd)}
W=$(mktemp -d /tmp/r24-fw.XXXXXX); chmod 755 "$W"; trap 'rm -rf "$W"' EXIT
cargo run -q --manifest-path "$HERE/Cargo.toml" qemu > "$W/probe.sh" || exit 2
sed -n '/^STAMP=/,$p' "$W/probe.sh" > "$W/fw.sh"
STAMP_CMD=$(sed -n "s/^ExecStartPost=\/bin\/sh -c '\(.*\)'\$/\1/p" "$REPO/crates/creance-vm/src/provision.rs" | sed "s|/run/egress-armed|$W/stamp|")
printf '%s\n' "$STAMP_CMD" > "$W/stamp.sh"; chmod 644 "$W"/*.sh
# clean-stamp lines (iptables-save of the product shape) for the stamp-extra diff
printf '%s\n' ':OUTPUT DROP [0:0]' '-A OUTPUT -o lo -j ACCEPT' '-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' '-A OUTPUT -d 255.255.255.255/32 -p udp -m udp --dport 67 -j ACCEPT' '-A OUTPUT -d 10.0.2.2/32 -p udp -m udp --dport 67 -j ACCEPT' '-A OUTPUT -d 10.0.2.2/32 -p icmp -j ACCEPT' '-A OUTPUT -d 10.0.2.3/32 -p udp -m udp --dport 67 -j ACCEPT' '-A OUTPUT -d 10.0.2.3/32 -p icmp -j ACCEPT' > "$W/clean"
echo "probe md5=$(md5sum < "$W/probe.sh" | cut -c1-8) stamp cmd: $STAMP_CMD"
HDR='*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT DROP [0:0]\n-A OUTPUT -o lo -j ACCEPT\n-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n-A OUTPUT -p udp --dport 67 -d 255.255.255.255 -j ACCEPT\n-A OUTPUT -p udp --dport 67 -d 10.0.2.2/32 -j ACCEPT\n-A OUTPUT -p icmp -d 10.0.2.2/32 -j ACCEPT\n-A OUTPUT -p udp --dport 67 -d 10.0.2.3/32 -j ACCEPT\n-A OUTPUT -p icmp -d 10.0.2.3/32 -j ACCEPT\n'
# $1=name $2=extra rules (printf fmt) [$3=extra applied only to rules.v4 file, not live]
run() {
  printf "$HDR$2COMMIT\n" > "$W/live"; printf "$HDR$2${3:-}COMMIT\n" > "$W/rules"; chmod 644 "$W/live" "$W/rules"
  r=$(sudo -n unshare -n sh -c "ip link set lo up; ip link add d0 type dummy; ip link set d0 up; ip addr add 10.0.2.15/24 dev d0; ip route add default via 10.0.2.2;
     iptables-restore < $W/live || echo RESTORE-FAIL
     sh $W/stamp.sh; chmod 644 $W/stamp
     printf 'fw: '; setpriv --reuid=65534 --regid=65534 --clear-groups env -i PATH=/usr/bin:/bin CREANCE_STAMP=$W/stamp CREANCE_RULES=$W/rules sh $W/fw.sh
     printf 'stamp-extra: '; grep -vxF -f $W/clean $W/stamp | tr '\n' ';'; echo
     printf 'egress: '; sh $HERE/egress.sh" 2>&1)
  echo "== $1"; echo "$r" | sed 's/^/   /'
}
# controls
run P00-product-shape ''
run N01-bare-accept '-A OUTPUT -j ACCEPT\n'
run N02-qualified-oe '-A OUTPUT -o e+ -j ACCEPT\n'
run N03-state-new '-A OUTPUT -m conntrack --ctstate NEW -j ACCEPT\n'
# allowlist bypass candidates (each is a real OUTPUT hole)
run B01-comment-forges-nat-icmp '-A OUTPUT -m comment --comment "-d 10.0.2.2/32 -p icmp" -j ACCEPT\n'
run B02-comment-forges-conntrack '-A OUTPUT -m comment --comment "conntrack --ctstate ESTABLISHED" -j ACCEPT\n'
run B03-ctstate-new-established '-A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n'
run B04-negated-dst-negated-dport '-A OUTPUT ! -d 10.0.2.2/32 -p udp -m udp ! --dport 67 -j ACCEPT\n'
run B05-negated-dst-icmp '-A OUTPUT ! -d 10.0.2.2/32 -p icmp -j ACCEPT\n'
run B06-dport-range '-A OUTPUT ! -d 10.0.2.3/32 -p udp -m udp --dport 67:65535 -j ACCEPT\n'
run B07-tcp-to-nat-host-comment-icmp '-A OUTPUT -d 10.0.2.2/32 -p tcp -m comment --comment "-p icmp" -j ACCEPT\n'
run B08-comment-forged-all-tcp '-A OUTPUT -p tcp -m comment --comment "-d 10.0.2.3/32 -p icmp" -j ACCEPT\n'
# rules.v4-only (persisted drift; live clean)
run R01-rules-only-comment-forged '' '-A OUTPUT -m comment --comment "-d 10.0.2.2/32 -p icmp" -j ACCEPT\n'
run R02-rules-only-qualified '' '-A OUTPUT -o e+ -j ACCEPT\n'
# (e) false-kill direction: rules.v4-only legal-equivalent forms (live table = product shape)
run K01-rules-icmp-no-slash32 '' '-A OUTPUT -p icmp -d 10.0.2.2 -j ACCEPT\n'
run K02-rules-state-match '' '-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n'
run K03-rules-udp67-m-udp '' '-A OUTPUT -p udp -m udp --dport 67 -d 10.0.2.3/32 -j ACCEPT\n'
