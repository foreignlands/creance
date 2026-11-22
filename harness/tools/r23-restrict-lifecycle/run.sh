#!/bin/sh
# r23-restrict-lifecycle — real QEMU lifecycle around the provisioned marker and the /run/egress-armed stamp.
# Precondition: LAB holds a creance binary + prof/ with a provisioned QEMU instance (marker present), VM stopped.
#   L0 up#A then up#B while running (we_started=false): idempotent, same qemu pid
#   L4 we_started=false + mount-missing: a root unit lazily unmounts the workspace 40s after boot; up#B reuses the VM
#   L3 active-oneshot restart: a root unit records the stamp mtime, runs `systemctl restart egress-lock.service`
#      on the already-active oneshot, records again (does restart re-run ExecStartPost?)
#   L2 old-instance upgrade: egress-lock.service without ExecStartPost (pre-v0.6.14 unit) -> up (restrict=on)
#   L1 marker deleted -> up (no restrict) -> marker re-written? -> up (restrict=on)
#   L5 instance dir renamed -> up
# Cases run in order given as args (default: all). systemd unit bodies escape %% (specifier).
# usage: LAB=<dir> sh run.sh   (needs sudo -n for qemu-nbd/mount; CREANCE_BIN overrides ./creance)
set -u
LAB=${LAB:?}; cd "$LAB" || exit 2
export CREANCE_CONFIG=$LAB/prof/config.json
C=${CREANCE_BIN:-./creance}; D=$(ls -d prof/state/qemu/*/ | head -1); M=/mnt/r23-life
WS=$(python3 -c "import json;print(json.load(open('${D}instance.json'))['workspace'])")
qpid() { python3 -c "import json;print(json.load(open('${D}qemu.pid'))['pid'])" 2>/dev/null; }
alive() { p=$(qpid); [ -n "$p" ] && kill -0 "$p" 2>/dev/null && echo "alive pid=$p" || echo dead; }
netdev() { p=$(qpid); [ -n "$p" ] && tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | grep -o -- '-netdev [^ ]*'; }
marker() { test -f "${D}provisioned" && echo present || echo absent; }
g() { timeout 60 $C shell -- sh -s 2>&1; }
nbd() {
  sudo -n modprobe nbd max_part=8 && sudo -n qemu-nbd -c /dev/nbd0 "${D}disk.qcow2" && sleep 2 \
  && sudo -n mkdir -p $M && sudo -n mount /dev/nbd0p1 $M && eval "$1"; rc=$?
  sudo -n umount $M; sudo -n qemu-nbd -d /dev/nbd0 >/dev/null; return $rc
}
addunit() { # $1=name $2=ExecStart body [$3=Type, default oneshot; simple = does not block boot targets]
  printf '[Unit]\nAfter=egress-lock.service\n[Service]\nType=%s\nExecStart=/bin/sh -c "%s"\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n' "${3:-oneshot}" "$2" | sudo -n tee $M/etc/systemd/system/$1.service >/dev/null \
  && sudo -n ln -sf /etc/systemd/system/$1.service $M/etc/systemd/system/multi-user.target.wants/$1.service
}
delunit() { sudo -n rm -f $M/etc/systemd/system/$1.service $M/etc/systemd/system/multi-user.target.wants/$1.service; }
up() { timeout 1200 $C up > "$1" 2>&1; echo "RC=$?"; }
L0() {
echo "### L0 idempotent re-up"
echo "up#A $(up L0a.log) netdev=$(netdev) $(alive)"; P1=$(qpid)
echo "up#B $(up L0b.log) $(alive) same-pid=$([ "$P1" = "$(qpid)" ] && echo yes || echo no)"; sed 's/^/    /' L0b.log
$C stop >/dev/null 2>&1
$C stop >/dev/null 2>&1
}
L4() {
echo "### L4 we_started=false + mount-missing (ws=$WS)"
nbd "addunit r23-umount 'sleep 150; umount -l $WS' simple"; echo "unit added rc=$?"
echo "up#A $(up L4a.log) $(alive)"; sed 's/^/    /' L4a.log
sleep 170; echo 'mountpoint -q '"$WS"' && echo mounted || echo unmounted' | g | sed 's/^/    guest: /'
echo "up#B $(up L4b.log) $(alive) marker=$(marker)"; sed 's/^/    /' L4b.log
$C stop >/dev/null 2>&1; nbd "delunit r23-umount"; echo "unit removed rc=$?"
$C stop >/dev/null 2>&1
}
L3() {
echo "### L3 active-oneshot restart"
nbd "addunit r23-restart 'sleep 5; stat -c before=%%y /run/egress-armed > /var/log/r23-restart.log; systemctl show -p ExecMainStartTimestamp egress-lock.service >> /var/log/r23-restart.log; sleep 2; systemctl restart egress-lock.service; echo restart-rc=\$? >> /var/log/r23-restart.log; sleep 1; stat -c after=%%y /run/egress-armed >> /var/log/r23-restart.log; systemctl show -p ExecMainStartTimestamp egress-lock.service >> /var/log/r23-restart.log'"; echo "unit added rc=$?"
echo "up $(up L3.log)"; sleep 15
printf 'cat /var/log/r23-restart.log\n' | g | sed 's/^/    guest: /'
$C stop >/dev/null 2>&1; nbd "delunit r23-restart; sudo -n rm -f $M/var/log/r23-restart.log"; echo "unit removed rc=$?"
$C stop >/dev/null 2>&1
}
L2() {
echo "### L2 old-instance (unit without ExecStartPost)"
nbd "sudo -n cp $M/etc/systemd/system/egress-lock.service $LAB/egress-lock.service.orig && sudo -n sed -i '/^ExecStartPost=/d' $M/etc/systemd/system/egress-lock.service && ! grep -q ExecStartPost $M/etc/systemd/system/egress-lock.service"; echo "unit downgraded rc=$?"
echo "up $(up L2.log) $(alive) marker=$(marker)"; sed 's/^/    /' L2.log
$C stop >/dev/null 2>&1; nbd "sudo -n cp $LAB/egress-lock.service.orig $M/etc/systemd/system/egress-lock.service && grep -c ExecStartPost $M/etc/systemd/system/egress-lock.service"; echo "unit restored rc=$?"
$C stop >/dev/null 2>&1
}
L1() {
echo "### L1 marker deleted"
rm -f "${D}provisioned"
echo "up#A $(up L1a.log) netdev=$(netdev) marker-after=$(marker)"; sed 's/^/    /' L1a.log
$C stop >/dev/null 2>&1
echo "up#B $(up L1b.log) netdev=$(netdev)"; $C stop >/dev/null 2>&1
$C stop >/dev/null 2>&1
}
L5() {
echo "### L5 instance dir renamed"
N=${D%/}.renamed; mv "${D%/}" "$N"
echo "up $(up L5.log)"; sed 's/^/    /' L5.log; ls prof/state/qemu/
$C stop >/dev/null 2>&1; mv "$N" "${D%/}"; echo "restored marker=$(marker)"
$C stop >/dev/null 2>&1
}
$C stop >/dev/null 2>&1
for c in ${*:-L0 L4 L3 L2 L1 L5}; do $c; done
