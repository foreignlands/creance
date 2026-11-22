#!/bin/sh
# r20-075-interrupt — F-075 full chain on a real QEMU instance + provisioned-marker lifecycle.
# setup (rebuild: marker must vanish) -> up -> kill creance+qemu mid modules:final -> marker absent?
# -> up again: must be either green WITH live 9p mount, or fail closed (never green unmounted).
# usage: LAB=<dir holding creance binary + prof/config.json> sh run.sh
set -u
LAB=${LAB:?}; cd "$LAB" || exit 2
export CREANCE_CONFIG=$LAB/prof/config.json
C=./creance; D=$(ls -d prof/state/qemu/*/ | head -1)
qpid() { python3 -c "import json;print(json.load(open('${D}qemu.pid'))['pid'])" 2>/dev/null; }
netdev() { p=$(qpid); [ -n "$p" ] && tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | grep -o -- '-netdev [^ ]*'; }
$C stop >/dev/null 2>&1
echo "marker before rebuild: $(test -f ${D}provisioned && echo present || echo absent)"
$C setup > s.log 2>&1; echo "setup RC=$?"; D=$(ls -d prof/state/qemu/*/ | head -1)
echo "marker after rebuild: $(test -f ${D}provisioned && echo present || echo absent)"
$C up > upA.log 2>&1 & UP=$!
for i in $(seq 1 120); do grep -q "modules:final" ${D}serial.log 2>/dev/null && break; sleep 2; done
sleep 15
echo "first boot netdev: $(netdev)"
P=$(qpid); kill -TERM $UP 2>/dev/null; [ -n "$P" ] && kill -KILL "$P"; wait $UP 2>/dev/null
sleep 2; echo "after interrupt: qemu alive=$(kill -0 "$P" 2>/dev/null && echo yes || echo no) marker=$(test -f ${D}provisioned && echo present || echo absent)"
timeout 1200 $C up > upB.log 2>&1; rc=$?
echo "up#2 RC=$rc; last line: $(tail -1 upB.log)"
echo "up#2 netdev: $(netdev)  marker=$(test -f ${D}provisioned && echo present || echo absent)"
W=$(python3 -c "import json;print(json.load(open('${D}instance.json'))['workspace'])")
[ "$rc" = 0 ] && timeout 60 $C shell -- "mountpoint $W" 
$C stop >/dev/null 2>&1; echo "stopped"
