#!/bin/sh
# r31-real-up — v0.6.23 (F-111..116 fixes) FRESH setup release binary on Linux QEMU: init+setup, up#1 (provisioning), facts, stop, up#2 (restrict=on), facts.
# usage: LAB=<dir outside repo> CREANCE_BIN=<release creance> sh run.sh
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LAB=${LAB:?}; mkdir -p "$LAB"; cd "$LAB" || exit 2
cp "${CREANCE_BIN:?}" "$LAB/creance"; C=$LAB/creance
export CREANCE_CONFIG=$LAB/prof/config.json
E=$HERE/evidence; mkdir -p "$E"
step() { n=$1; shift; s=$(date +%s); timeout 1500 "$@" > "$E/$n.log" 2>&1; rc=$?; echo "$n RC=$rc ($(( $(date +%s)-s ))s)" | tee -a "$E/$n.log"; }
echo "binary: $($C --version 2>&1) md5=$(md5sum < $C | cut -c1-8)"
step init $C init
step setup $C setup --memory 4 --cpus 4
step up1 $C up
$C shell -- sh -s < "$HERE/facts.sh" > "$E/facts-up1.log" 2>&1
step stop1 $C stop
step up2 $C up
D=$(ls -d prof/state/qemu/*/ | head -1); p=$(python3 -c "import json;print(json.load(open('${D}qemu.pid'))['pid'])")
tr '\0' ' ' < /proc/$p/cmdline | grep -o -- '-netdev [^ ]*' > "$E/up2-netdev.txt"
$C shell -- sh -s < "$HERE/facts.sh" > "$E/facts-up2.log" 2>&1
step escape2 $C escape-test
echo "marker: $(cat ${D}provisioned 2>&1)"; cat "$E/up2-netdev.txt"; echo "lab-fresh: $(stat -c %w "$LAB")"
