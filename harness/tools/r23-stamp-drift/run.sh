#!/bin/sh
# r23-stamp-drift — real-guest check of the v0.6.14 fw-armed stamp (/run/egress-armed) against first-line
# failures the stamp cannot see. Precondition: LAB holds a creance binary + prof/ with a provisioned QEMU
# instance (setup + up#1 done, marker present => restrict=on). Each case: stop -> offline edit via qemu-nbd
# -> up (restrict=on) -> in-guest facts -> escape-test -> stop -> marker aside -> up CONTROL (no restrict)
# -> stop -> restore disk edit + marker.
#   D1 rules.v4 += "-A OUTPUT -o e+ -j ACCEPT"   (qualified accept: F-083 denylist only knows the bare form)
#   D2 extra root unit After=egress-lock.service: iptables -P OUTPUT ACCEPT; iptables -F OUTPUT
#      (drift after the stamp: the stamp is an apply-time snapshot, not the live table)
# usage: LAB=<dir> sh run.sh [D1|D2]   (needs sudo -n for modprobe nbd / qemu-nbd / mount; CREANCE_BIN overrides ./creance)
set -u
LAB=${LAB:?}; cd "$LAB" || exit 2
export CREANCE_CONFIG=$LAB/prof/config.json
C=${CREANCE_BIN:-./creance}; D=$(ls -d prof/state/qemu/*/ | head -1); M=/mnt/r23-drift
CASE=${1:?D1|D2}; E=$LAB/evidence/$CASE; mkdir -p "$E"
qpid() { python3 -c "import json;print(json.load(open('${D}qemu.pid'))['pid'])" 2>/dev/null; }
netdev() { p=$(qpid); [ -n "$p" ] && tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | grep -o -- '-netdev [^ ]*'; }
FACTS='export PATH=/usr/bin:/bin
echo "stamp: $(stat -c "%U %a %y" /run/egress-armed)"; sed "s/^/  /" /run/egress-armed
if [ -f /run/egress-armed ] && grep -q "^:OUTPUT DROP" /run/egress-armed && ! grep -qxF -- "-A OUTPUT -j ACCEPT" /run/egress-armed; then echo probe=fw-armed; else echo probe=fw-down; fi
echo "egress-lock=$(systemctl is-active egress-lock.service) drift-unit=$(systemctl is-active r23-drift.service 2>/dev/null)"
echo "rules.v4 tail: $(tail -3 /etc/iptables/rules.v4 | tr "\n" ";")"
/usr/bin/timeout 5 /bin/bash -c "</dev/tcp/1.1.1.1/443" 2>/dev/null && echo tcp-1.1.1.1:443=open || echo tcp-1.1.1.1:443=blocked
/usr/bin/timeout 5 /bin/bash -c "</dev/tcp/10.0.2.2/22" 2>/dev/null && echo tcp-10.0.2.2:22=open || echo tcp-10.0.2.2:22=blocked'
gfacts() { timeout 60 $C shell -- sh -s 2>&1 <<F
$FACTS
F
}
nbd() {
  sudo -n modprobe nbd max_part=8 && sudo -n qemu-nbd -c /dev/nbd0 "${D}disk.qcow2" && sleep 2 \
  && sudo -n mkdir -p $M && sudo -n mount /dev/nbd0p1 $M && eval "$1"; rc=$?
  sudo -n umount $M; sudo -n qemu-nbd -d /dev/nbd0 >/dev/null; return $rc
}
UNIT='[Unit]\nDescription=r23 drift simulation\nAfter=egress-lock.service\nRequires=egress-lock.service\n[Service]\nType=oneshot\nExecStart=/bin/sh -c "/usr/sbin/iptables -P OUTPUT ACCEPT; /usr/sbin/iptables -F OUTPUT"\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n'
$C stop > /dev/null 2>&1
case $CASE in
D1) nbd 'sudo -n cp $M/etc/iptables/rules.v4 $LAB/rules.v4.orig && sudo -n perl -0pi -e "s/\nCOMMIT\n/\n-A OUTPUT -o e+ -j ACCEPT\nCOMMIT\n/" $M/etc/iptables/rules.v4 && grep -c -- "-o e+ -j ACCEPT" $M/etc/iptables/rules.v4';;
D2) nbd 'printf "$UNIT" | sudo -n tee $M/etc/systemd/system/r23-drift.service >/dev/null && sudo -n ln -sf /etc/systemd/system/r23-drift.service $M/etc/systemd/system/multi-user.target.wants/r23-drift.service && ls -l $M/etc/systemd/system/multi-user.target.wants/r23-drift.service';;
esac
echo "== $CASE offline edit rc=$?"
timeout 1200 $C up > "$E/up-restrict.log" 2>&1; rc=$?
echo "== $CASE up (marker present) RC=$rc netdev: $(netdev)"; sed 's/^/    /' "$E/up-restrict.log"
echo "== $CASE in-guest (restrict=on):"; gfacts | tee "$E/facts-restrict.log" | sed 's/^/    /'
timeout 300 $C escape-test > "$E/escape-test.log" 2>&1; echo "== escape-test RC=$? net/fw verdicts:"; grep -E '^PROBE (net-|fw|proxy)' "$E/escape-test.log" | sed 's/^/    /'
$C stop > /dev/null 2>&1
mv "${D}provisioned" "$LAB/provisioned.aside"
timeout 1200 $C up > "$E/up-control.log" 2>&1; rc=$?
echo "== $CASE CONTROL up (marker absent) RC=$rc netdev: $(netdev)"; sed 's/^/    /' "$E/up-control.log"
$C stop > /dev/null 2>&1
case $CASE in
D1) nbd 'sudo -n cp $LAB/rules.v4.orig $M/etc/iptables/rules.v4 && ! grep -q -- "-o e+" $M/etc/iptables/rules.v4';;
D2) nbd 'sudo -n rm -f $M/etc/systemd/system/r23-drift.service $M/etc/systemd/system/multi-user.target.wants/r23-drift.service';;
esac
echo "== $CASE restored rc=$?"
mv "$LAB/provisioned.aside" "${D}provisioned"; echo "== marker restored: $(test -f ${D}provisioned && echo present)"
