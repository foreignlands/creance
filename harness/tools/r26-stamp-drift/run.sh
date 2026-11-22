#!/bin/sh
# r26-stamp-drift — real-guest check of the v0.6.17 exact-line fw-armed allowlist against rules.v4 spellings
# that iptables-restore applies but the probe's `^-A OUTPUT` selector never sees (F-092).
# Precondition: LAB holds a creance binary + prof/ with a provisioned QEMU instance (marker present => restrict=on).
# Each case: stop -> offline rules.v4 edit via qemu-nbd -> up (restrict=on) -> in-guest facts (shipped probe) -> escape-test
# -> stop -> marker aside -> up CONTROL (no restrict) -> stop -> restore rules.v4 + marker.
#   D3 rules.v4 += -A OUTPUT -m comment --comment "-d 10.0.2.2/32 -p icmp" -j ACCEPT   (F-090 regress: must now read fw-down)
#   E1 rules.v4 += -I OUTPUT -j ACCEPT        (not selected by ^-A OUTPUT)
#   E2 rules.v4 += :OUTPUT ACCEPT [0:0]       (policy redeclared after the DROP declaration)
#   O1 rules.v4 whole-file reorder: COMMIT moved before :OUTPUT DROP (F-094 candidate: every line allowlisted, counts 1/1/1)
#   Z1 rules.v4 += "#\0" + "-I OUTPUT -j ACCEPT" before COMMIT (F-094 candidate: NUL -> GNU grep binary mode hides lines)
# usage: LAB=<dir> PROBE=<dumped probe (r26-fw-exact probe qemu)> sh run.sh D3|E1|E2   (needs sudo -n for nbd/mount)
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LAB=${LAB:?}; PROBE=${PROBE:?}; cd "$LAB" || exit 2
export CREANCE_CONFIG=$LAB/prof/config.json
C=${CREANCE_BIN:-./creance}; D=$(ls -d prof/state/qemu/*/ | head -1); M=/mnt/r26-drift
CASE=${1:?D3|E1|E2|O1|Z1}; E=$HERE/evidence/$CASE; mkdir -p "$E"
case $CASE in
D3) RULE='-A OUTPUT -m comment --comment "-d 10.0.2.2/32 -p icmp" -j ACCEPT';;
E1) RULE='-I OUTPUT -j ACCEPT';;
E2) RULE=':OUTPUT ACCEPT [0:0]';;
O1) RULE='(reorder)'; GEN='{ sed -n "1,3p" $O; echo COMMIT; sed -n "4,\$p" $O | grep -vx COMMIT; }';;
Z1) RULE='-I OUTPUT -j ACCEPT'; GEN='{ sed "\$d" $O; printf "#\\000\\n-I OUTPUT -j ACCEPT\\nCOMMIT\\n"; }';;
*) exit 2;;
esac
qpid() { python3 -c "import json;print(json.load(open('${D}qemu.pid'))['pid'])" 2>/dev/null; }
netdev() { p=$(qpid); [ -n "$p" ] && tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | grep -o -- '-netdev [^ ]*'; }
gfacts() { { cat "$PROBE"; cat <<'F'
echo "--- stamp:"; sed 's/^/  /' /run/egress-armed
echo "--- rules.v4 OUTPUT:"; grep -E 'OUTPUT' /etc/iptables/rules.v4 | sed 's/^/  /'
/usr/bin/timeout 5 /bin/bash -c "</dev/tcp/10.0.2.2/22" 2>/dev/null && echo tcp-10.0.2.2:22=open || echo tcp-10.0.2.2:22=blocked
/usr/bin/timeout 5 /bin/bash -c "</dev/tcp/1.1.1.1/443" 2>/dev/null && echo tcp-1.1.1.1:443=open || echo tcp-1.1.1.1:443=blocked
F
} | timeout 60 $C shell -- sh -s 2>&1; }
nbd() {
  sudo -n modprobe nbd max_part=8 && sudo -n qemu-nbd -c /dev/nbd0 "${D}disk.qcow2" && sleep 2 \
  && sudo -n mkdir -p $M && sudo -n mount /dev/nbd0p1 $M && eval "$1"; rc=$?
  sudo -n umount $M; sudo -n qemu-nbd -d /dev/nbd0 >/dev/null; return $rc
}
$C stop > /dev/null 2>&1
export RULE
if [ -n "${GEN:-}" ]; then
nbd 'sudo -n cp $M/etc/iptables/rules.v4 $LAB/rules.v4.orig && O=$LAB/rules.v4.orig && eval "$GEN" > $LAB/rules.new && sudo -n cp $LAB/rules.new $M/etc/iptables/rules.v4 && echo "new md5=$(md5sum < $M/etc/iptables/rules.v4 | cut -c1-8) orig md5=$(md5sum < $O | cut -c1-8) nul-bytes=$(tr -cd "\\000" < $M/etc/iptables/rules.v4 | wc -c)" && od -c $M/etc/iptables/rules.v4 | tail -6 > $E/rules-od.txt'
else
nbd 'sudo -n cp $M/etc/iptables/rules.v4 $LAB/rules.v4.orig && printf "%s\n" "$RULE" > $LAB/rule.txt && sudo -n perl -0pi -e "BEGIN{open F,q($LAB/rule.txt);\$r=<F>} s/\nCOMMIT\n/\n\${r}COMMIT\n/" $M/etc/iptables/rules.v4 && grep -cF -- "$RULE" $M/etc/iptables/rules.v4'
fi
echo "== $CASE offline edit rc=$? rule: $RULE"
timeout 1200 $C up > "$E/up-restrict.log" 2>&1; rc=$?
echo "== $CASE up (marker present) RC=$rc netdev: $(netdev)"; sed 's/^/    /' "$E/up-restrict.log"
echo "== $CASE in-guest (restrict=on), shipped probe + facts:"; gfacts | tee "$E/facts-restrict.log" | sed 's/^/    /'
timeout 300 $C escape-test > "$E/escape-test.log" 2>&1; echo "== escape-test RC=$? net/fw verdicts:"; grep -E '^PROBE (net-|fw|proxy)' "$E/escape-test.log" | sed 's/^/    /'
$C stop > /dev/null 2>&1
mv "${D}provisioned" "$LAB/provisioned.aside"
timeout 1200 $C up > "$E/up-control.log" 2>&1; rc=$?
echo "== $CASE CONTROL up (marker absent) RC=$rc netdev: $(netdev)"; sed 's/^/    /' "$E/up-control.log"
$C stop > /dev/null 2>&1
nbd 'sudo -n cp $LAB/rules.v4.orig $M/etc/iptables/rules.v4 && cmp $LAB/rules.v4.orig $M/etc/iptables/rules.v4 && ! grep -qaF -- "-I OUTPUT" $M/etc/iptables/rules.v4'
echo "== $CASE restored rc=$?"
mv "$LAB/provisioned.aside" "${D}provisioned"; echo "== marker restored: $(test -f ${D}provisioned && echo present)"
