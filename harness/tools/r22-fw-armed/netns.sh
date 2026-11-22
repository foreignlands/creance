#!/bin/sh
# r22-fw-armed/netns.sh — host-side replay of up's fw-armed probe line (main.rs:754) in throwaway
# network namespaces (sudo -n unshare -n): what the check accepts/rejects, independent of any guest.
set -u
LINE='if iptables -L OUTPUT -n 2>/dev/null | head -1 | grep -q "policy DROP"; then echo fw-armed; else echo fw-down; fi'
run() { # $1=name $2=rules(printf fmt) $3=PATH for the probe
  printf "$2" > /tmp/r22-fw.rules
  r=$(sudo -n unshare -n sh -c "iptables-restore < /tmp/r22-fw.rules && PATH=$3 sh -c '$LINE'; echo '  loaded OUTPUT:'; iptables -S OUTPUT | sed 's/^/    /'")
  echo "$1 (probe PATH=$3): $r"
}
DROP_OK='*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT DROP [0:0]\n-A OUTPUT -o lo -j ACCEPT\n-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\nCOMMIT\n'
DROP_MASK='*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT DROP [0:0]\n-A OUTPUT -j ACCEPT\nCOMMIT\n'
ACC='*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n'
run P1-product-shape "$DROP_OK"   /usr/sbin:/usr/bin:/bin
run P2-drop+accept-all "$DROP_MASK" /usr/sbin:/usr/bin:/bin
run P3-accept-policy "$ACC"       /usr/sbin:/usr/bin:/bin
run P4-product-shape "$DROP_OK"   /usr/bin:/bin
echo "P5 unprivileged (uid $(id -u)), full PATH: $(PATH=/usr/sbin:/usr/bin:/bin sh -c "$LINE")  stderr: $(PATH=/usr/sbin:/usr/bin:/bin iptables -L OUTPUT -n 2>&1 | head -1)"
rm -f /tmp/r22-fw.rules
