#!/bin/sh
# r23-stamp-netns — host-side replay of the v0.6.14 fw-armed chain in throwaway netns (sudo -n unshare -n):
#   egress-lock ExecStartPost stamp command (provision.rs) -> /run/egress-armed stand-in -> up probe fw line (escape.rs)
# The stamp/probe text is extracted verbatim from the source (CREANCE_REPO), only the /run path is redirected.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=${CREANCE_REPO:-$(CDPATH= cd -- "$HERE/../../.." && pwd)}
W=$(mktemp -d /tmp/r23-stamp.XXXXXX); chmod 755 "$W"; trap 'rm -rf "$W"' EXIT
STAMP_CMD=$(sed -n "s/^ExecStartPost=\/bin\/sh -c '\(.*\)'\$/\1/p" "$REPO/crates/creance-vm/src/provision.rs" | sed "s|/run/egress-armed|$W/egress-armed|")
FW_LINE=$(grep -o "if \[ -f /run/egress-armed \].*fi" "$REPO/crates/creance/src/escape.rs" | sed "s|/run/egress-armed|$W/egress-armed|g")
printf '%s\n' "$STAMP_CMD" > "$W/stamp.sh"; printf '%s\n' "$FW_LINE" > "$W/fw.sh"; chmod 644 "$W"/*.sh
echo "stamp cmd: $STAMP_CMD"; echo "probe fw line: $FW_LINE"
HDR='*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT DROP [0:0]\n-A OUTPUT -o lo -j ACCEPT\n-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n-A OUTPUT -p udp --dport 67 -d 255.255.255.255 -j ACCEPT\n-A OUTPUT -p udp --dport 67 -d 10.0.2.2/32 -j ACCEPT\n-A OUTPUT -p icmp -d 10.0.2.2/32 -j ACCEPT\n'
# $1=name $2=extra rules (printf fmt, inside *filter) $3=post-stamp root commands (drift after the unit ran)
run() {
  printf "$HDR$2COMMIT\n" > "$W/rules"
  r=$(sudo -n unshare -n sh -c "ip link set lo up; ip link add d0 type dummy; ip link set d0 up; ip addr add 10.0.2.15/24 dev d0; ip route add default via 10.0.2.2;
     iptables-restore < $W/rules || echo RESTORE-FAIL
     sh $W/stamp.sh; chmod 644 $W/egress-armed
     ${3:-}
     printf 'fw (uid 65534, PATH=/usr/bin:/bin): '; setpriv --reuid=65534 --regid=65534 --clear-groups env -i PATH=/usr/bin:/bin sh $W/fw.sh
     printf 'live OUTPUT: '; iptables -S OUTPUT | tr '\n' ';'; echo
     printf 'stamp: '; tr '\n' ';' < $W/egress-armed; echo
     printf 'udp 8.8.8.8:53 send: '; timeout 2 bash -c 'echo x > /dev/udp/8.8.8.8/53' 2>/dev/null && echo SENT || echo blocked" 2>&1)
  echo "== $1"; echo "$r" | sed 's/^/   /'
}
run V01-product-shape ''
run V02-bare-accept '-A OUTPUT -j ACCEPT\n'
run V03-iface-accept '-A OUTPUT -o d0 -j ACCEPT\n'
run V04-wildcard-iface '-A OUTPUT -o d+ -j ACCEPT\n'
run V05-proto-accepts '-A OUTPUT -p tcp -j ACCEPT\n-A OUTPUT -p udp -j ACCEPT\n'
run V06-dst-0/0 '-A OUTPUT -d 0.0.0.0/0 -j ACCEPT\n'
run V07-comment-accept '-A OUTPUT -m comment --comment keep -j ACCEPT\n'
run V08-jump-userchain ':LEAK - [0:0]\n-A OUTPUT -j LEAK\n-A LEAK -j ACCEPT\n'
run V09-state-new '-A OUTPUT -m conntrack --ctstate NEW -j ACCEPT\n'
run V10-insert-first-bare '' 'iptables -I OUTPUT 1 -j ACCEPT'
run V11-post-stamp-policy-accept '' 'iptables -P OUTPUT ACCEPT'
run V12-post-stamp-flush '' 'iptables -F OUTPUT; iptables -P OUTPUT ACCEPT'
run V13-policy-accept-at-load ':OUTPUT ACCEPT [0:0]\n'
