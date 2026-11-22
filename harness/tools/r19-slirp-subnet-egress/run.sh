#!/bin/sh
# F-073 reproducer. Boots a throwaway QEMU guest with the SAME slirp netdev shape as
# runner.rs (user,hostfwd=tcp:127.0.0.1:P-:22), applies creance's rules.v4 verbatim
# (extracted from provision.rs), then as an UNPRIVILEGED guest user sends marked
# UDP/67 + ICMP to 192.168.5.77 / 10.0.2.77 / 1.1.1.1 while the host captures.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=${CREANCE_REPO:-$(CDPATH= cd -- "$HERE/../../.." && pwd)}
IMG=${R19_IMG:?set R19_IMG to an ubuntu-24.04 cloud image}
IFACE=${R19_IFACE:-any}
PORT=${R19_PORT:-2299}
W=$(mktemp -d /tmp/r19-slirp.XXXXXX)
trap '[ -f "$W/q.pid" ] && kill "$(cat "$W/q.pid")" 2>/dev/null; rm -rf "$W"' EXIT
cd "$W"
sed -n '/cat > \/etc\/iptables\/rules.v4 <<.EGRESSRULES./,/^EGRESSRULES$/p' "$REPO/crates/creance-vm/src/provision.rs" | sed '1d;$d' > rules.v4
ssh-keygen -q -t ed25519 -N '' -f k
cat > user-data <<UD
#cloud-config
users:
  - name: agent
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys: ["$(cat k.pub)"]
write_files:
  - path: /etc/iptables/rules.v4
    encoding: b64
    content: $(base64 -w0 rules.v4)
runcmd:
  - [sh, -c, "command -v iptables-restore || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables iputils-ping); sysctl -w net.ipv6.conf.all.disable_ipv6=1; /usr/sbin/iptables-restore < /etc/iptables/rules.v4 && touch /run/r19-locked"]
UD
printf 'instance-id: r19-%s\nlocal-hostname: r19lab\n' "$$" > meta-data
genisoimage -quiet -output seed.iso -volid cidata -joliet -rock user-data meta-data
qemu-img create -q -f qcow2 -F qcow2 -b "$IMG" ov.qcow2 10G
qemu-system-x86_64 -enable-kvm -m 1536 -smp 2 -display none -daemonize -pidfile q.pid \
  -serial file:serial.log -drive file=ov.qcow2,if=virtio -drive file=seed.iso,if=virtio,media=cdrom \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:$PORT-:22 -device virtio-net-pci,netdev=net0
SSH="ssh -q -i k -p $PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 agent@127.0.0.1"
for i in $(seq 1 60); do $SSH 'test -e /run/r19-locked' 2>/dev/null && break; sleep 5; done
$SSH 'test -e /run/r19-locked' || { echo "guest never locked"; exit 2; }
sudo -n timeout 40 tcpdump -ni "$IFACE" -w cap.pcap 'host 192.168.5.77 or host 10.0.2.77 or host 1.1.1.1' 2>/dev/null &
sleep 2
$SSH 'sh -s' <<'G'
echo "guest uid=$(id -u) sudo=$(sudo -n true 2>/dev/null && echo yes || echo no)"
timeout 5 bash -c '</dev/tcp/1.1.1.1/443' 2>/dev/null && echo "T-tcp 1.1.1.1:443 OPEN" || echo "T-tcp 1.1.1.1:443 blocked"
python3 -c '
import socket
for d,p in [("192.168.5.77",67),("10.0.2.77",67),("1.1.1.1",67)]:
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try: s.sendto(b"R19-EXFIL-UDP67-"+d.encode(),(d,p)); print("T-udp67",d,"kernel-accepted")
    except Exception as e: print("T-udp67",d,"rejected",e)'
for d in 1.1.1.1 192.168.5.77 10.0.2.77; do ping -c1 -W2 -p 5231392d4943 $d >/dev/null 2>&1; echo "T-icmp $d rc=$?"; done
G
sleep 3; sudo -n pkill -INT -x tcpdump; sleep 1
echo "== host capture (packets that left the guest via slirp):"
sudo -n tcpdump -nr cap.pcap -A 2>/dev/null | grep -E ' IP |R19' 
