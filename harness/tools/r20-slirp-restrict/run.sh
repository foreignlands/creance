#!/bin/sh
# r20-slirp-restrict — v0.6.11 restrict=on second line of defense, behaviourally.
# Boots a throwaway guest on the SAME slirp netdev shape as qemu/runner.rs, with
# R20_RESTRICT=1 adding `restrict=on,` exactly as a provisioned boot does. The lab user has
# sudo so the run can model "guest defeated iptables" (root flush). Phases:
#   P1 rules.v4 (extracted from provision.rs, per-backend /32 as rendered for QEMU) intact
#   P2 root flushes iptables (policy ACCEPT) -> raw egress attempts
#   P3 sanctioned path: inbound ssh (hostfwd) + ssh -R reverse tunnel to a host listener
# Host tcpdump on all ifaces shows what actually left via slirp.
# usage: R20_IMG=<ubuntu-24.04 cloud img> R20_RESTRICT=0|1 sh run.sh
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=${CREANCE_REPO:-$(CDPATH= cd -- "$HERE/../../.." && pwd)}
IMG=${R20_IMG:?set R20_IMG}
RES=${R20_RESTRICT:-0}; PORT=${R20_PORT:-2399}; LPORT=${R20_LPORT:-18999}
[ "$RES" = 1 ] && R="restrict=on," || R=""
W=$(mktemp -d /tmp/r20-slirp.XXXXXX)
trap '[ -f "$W/q.pid" ] && kill "$(cat "$W/q.pid")" 2>/dev/null; [ -f "$W/h.pid" ] && kill "$(cat "$W/h.pid")" 2>/dev/null; rm -rf "$W"' EXIT
cd "$W"
# The QEMU-rendered ruleset: provision.rs template with {nat_rules} expanded for 10.0.2.2/.3
sed -n '/cat > \/etc\/iptables\/rules.v4 <<.EGRESSRULES./,/^EGRESSRULES$/p' "$REPO/crates/creance-vm/src/provision.rs" | sed '1d;$d' > t.v4
NAT=""; for h in 10.0.2.2 10.0.2.3; do NAT="$NAT-A OUTPUT -p udp --dport 67 -d $h/32 -j ACCEPT\n-A OUTPUT -p icmp -d $h/32 -j ACCEPT\n"; done
awk -v n="$NAT" '{gsub(/\{nat_rules\}/, n); gsub(/\{\{/,"{"); gsub(/\}\}/,"}"); print}' t.v4 | sed 's/\\n/\n/g' > rules.v4
echo "rules.v4: /32 lines=$(grep -c '/32' rules.v4) subnet lines=$(grep -c '/24' rules.v4)"
ssh-keygen -q -t ed25519 -N '' -f k
cat > user-data <<UD
#cloud-config
users:
  - name: agent
    shell: /bin/bash
    lock_passwd: true
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys: ["$(cat k.pub)"]
write_files:
  - path: /etc/iptables/rules.v4
    encoding: b64
    content: $(base64 -w0 rules.v4)
runcmd:
  - [sh, -c, "sysctl -w net.ipv6.conf.all.disable_ipv6=1; /usr/sbin/iptables-restore < /etc/iptables/rules.v4 && touch /run/r20-locked"]
UD
printf 'instance-id: r20-%s\nlocal-hostname: r20lab\n' "$$" > meta-data
genisoimage -quiet -output seed.iso -volid cidata -joliet -rock user-data meta-data
qemu-img create -q -f qcow2 -F qcow2 -b "$IMG" ov.qcow2 10G
qemu-system-x86_64 -enable-kvm -m 1536 -smp 2 -display none -daemonize -pidfile q.pid \
  -serial file:serial.log -drive file=ov.qcow2,if=virtio -drive file=seed.iso,if=virtio,media=cdrom \
  -netdev user,id=net0,${R}hostfwd=tcp:127.0.0.1:$PORT-:22 -device virtio-net-pci,netdev=net0
echo "netdev: user,id=net0,${R}hostfwd=tcp:127.0.0.1:$PORT-:22"
SSH="ssh -q -i k -p $PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 agent@127.0.0.1"
for i in $(seq 1 60); do $SSH 'test -e /run/r20-locked' 2>/dev/null && break; sleep 5; done
$SSH 'test -e /run/r20-locked' || { echo "guest never locked (ssh hostfwd dead?)"; exit 2; }
echo "P0 inbound ssh via hostfwd: OK"
sudo -n timeout 60 tcpdump -ni any -w cap.pcap 'host 192.168.5.77 or host 10.0.2.77 or host 1.1.1.1 or host 1.0.0.1' 2>/dev/null &
sleep 2
probe() { $SSH "sh -s $1" <<'G'
P=$1
timeout 5 bash -c '</dev/tcp/1.1.1.1/443' 2>/dev/null && echo "$P tcp 1.1.1.1:443 OPEN" || echo "$P tcp 1.1.1.1:443 blocked"
python3 -c '
import socket,sys
for d,p in [("192.168.5.77",67),("10.0.2.77",67),("1.0.0.1",53)]:
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try: s.sendto(b"R20-"+sys.argv[1].encode()+b"-UDP-"+d.encode(),(d,p)); print(sys.argv[1],"udp",d,p,"kernel-accepted")
    except Exception as e: print(sys.argv[1],"udp",d,p,"rejected",type(e).__name__)' "$P"
for d in 1.1.1.1 192.168.5.77 10.0.2.77; do sudo -n ping -c1 -W2 $d >/dev/null 2>&1; echo "$P icmp $d rc=$?"; done
G
}
probe P1
$SSH 'sudo -n iptables -P OUTPUT ACCEPT; sudo -n iptables -F; sudo -n iptables -S OUTPUT | head -2'
probe P2
python3 -m http.server "$LPORT" --bind 127.0.0.1 >/dev/null 2>&1 & echo $! > h.pid; sleep 1
$SSH -R "$LPORT:127.0.0.1:$LPORT" "curl -s -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:$LPORT/" > p3.out 2>&1
echo "P3 ssh -R tunnel guest->host listener http=$(cat p3.out)"
sleep 3; sudo -n pkill -INT -x tcpdump; sleep 1
echo "== host capture: packets that left the guest via slirp (count by dst):"
sudo -n tcpdump -nr cap.pcap 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i==">") {print $(i+1)}}' | sed 's/\.[0-9]*:$//;s/:$//' | sort | uniq -c
