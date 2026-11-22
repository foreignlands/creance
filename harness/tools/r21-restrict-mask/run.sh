#!/bin/sh
# r21-restrict-mask — does slirp restrict=on mask a dead in-guest firewall from up's F-059 egress guard?
# Precondition: LAB holds a creance binary + prof/ with a provisioned QEMU instance (setup + up#1 done).
# Steps: stop -> break the in-guest firewall offline (qemu-nbd: rules.v4 := ACCEPT-all) ->
#   up#2 (marker present => restrict=on) -> in-guest evidence + escape-test ->
#   stop -> marker moved aside -> up#3 (no restrict) = control -> restore rules.v4 + marker.
# usage: LAB=<dir> sh run.sh   (needs sudo -n for modprobe nbd / qemu-nbd / mount)
set -u
LAB=${LAB:?}; cd "$LAB" || exit 2
export CREANCE_CONFIG=$LAB/prof/config.json
C=./creance; D=$(ls -d prof/state/qemu/*/ | head -1); M=/mnt/r21-mask
qpid() { python3 -c "import json;print(json.load(open('${D}qemu.pid'))['pid'])" 2>/dev/null; }
netdev() { p=$(qpid); [ -n "$p" ] && tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | grep -o -- '-netdev [^ ]*'; }
gsh() { timeout 120 $C shell -- sh -c "$1" 2>&1; }
PROBE='export PATH=/usr/bin:/bin; head -c 400 /etc/iptables/rules.v4; echo; echo "--- systemctl:"; systemctl is-active egress-lock.service; /usr/bin/timeout 5 /bin/bash -c "</dev/tcp/1.1.1.1/443" 2>/dev/null && echo tcp-1.1.1.1:443-open || echo tcp-1.1.1.1:443-blocked'
echo "== up#1 (provisioning session) netdev: $(netdev)  marker=$(test -f ${D}provisioned && echo present || echo absent)"
echo "== up#1 in-guest:"; gsh "$PROBE"
$C stop > stop1.log 2>&1; echo "stop RC=$?"
nbd() {
  sudo -n modprobe nbd max_part=8 && sudo -n qemu-nbd -c /dev/nbd0 "${D}disk.qcow2" && sleep 2 \
  && sudo -n mkdir -p $M && sudo -n mount /dev/nbd0p1 $M && eval "$1"; rc=$?
  sudo -n umount $M; sudo -n qemu-nbd -d /dev/nbd0 >/dev/null; return $rc
}
nbd 'sudo -n cp $M/etc/iptables/rules.v4 $LAB/rules.v4.orig && printf "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n" | sudo -n tee $M/etc/iptables/rules.v4 >/dev/null'
echo "== firewall broken offline: rc=$? (rules.v4 := ACCEPT-all)"
timeout 1200 $C up > up2.log 2>&1; rc=$?
echo "== up#2 (marker present, firewall dead) RC=$rc netdev: $(netdev)"; sed 's/^/    /' up2.log
echo "== up#2 in-guest:"; gsh "$PROBE" | sed 's/^/    /'
timeout 300 $C escape-test > et2.log 2>&1; echo "== escape-test RC=$? verdicts:"; grep '^PROBE' et2.log | sed 's/^/    /'
$C stop > /dev/null 2>&1
mv "${D}provisioned" "$LAB/provisioned.aside"
timeout 1200 $C up > up3.log 2>&1; rc=$?
echo "== up#3 CONTROL (marker absent, firewall dead) RC=$rc"; sed 's/^/    /' up3.log
$C stop > /dev/null 2>&1
nbd 'sudo -n cp $LAB/rules.v4.orig $M/etc/iptables/rules.v4'; echo "== rules.v4 restored rc=$?"
mv "$LAB/provisioned.aside" "${D}provisioned"; echo "== marker restored: $(test -f ${D}provisioned && echo present)"
