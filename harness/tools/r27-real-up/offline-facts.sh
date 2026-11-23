#!/bin/sh
# r27-real-up/offline-facts — VM stopped: mount guest disk via qemu-nbd and dump bootstrap outcome facts (needs sudo -n).
set -u
LAB=${LAB:?}; D=$(ls -d "$LAB"/prof/state/qemu/*/ | head -1); M=/mnt/r27-off
sudo -n modprobe nbd max_part=8 && sudo -n qemu-nbd -r -c /dev/nbd0 "${D}disk.qcow2" && sleep 2 && sudo -n mkdir -p $M && sudo -n mount -o ro /dev/nbd0p1 $M || exit 2
echo "--- cloud-init-output.log (EGRESSRULES / errors):"; sudo -n grep -a -n 'EGRESSRULES\|not found\|Failed\|runcmd\|scripts_user\|finished at' $M/var/log/cloud-init-output.log | tail -15
echo "--- rules.v4: $(sudo -n md5sum $M/etc/iptables/rules.v4 2>&1)"
echo "--- egress-lock.service: $(sudo -n ls -l $M/etc/systemd/system/egress-lock.service 2>&1)"
echo "--- enabled link: $(sudo -n ls $M/etc/systemd/system/multi-user.target.wants/ 2>&1 | tr '\n' ' ')"
echo "--- noipv6 drop-in: $(sudo -n cat $M/etc/sysctl.d/99-creance-noipv6.conf 2>&1)"
echo "--- toolchain log: $(sudo -n head -3 $M/var/log/creance-toolchain.log 2>&1 | tr '\n' ' ')"
echo "--- sudoers 90-cloud-init-users: $(sudo -n cat $M/etc/sudoers.d/90-cloud-init-users 2>&1 | grep -v '^#' | tr '\n' ' ')"
echo "--- cloud-init result: $(sudo -n cat $M/var/lib/cloud/data/result.json 2>&1 | tr -d '\n' | cut -c1-600)"
sudo -n umount $M; sudo -n qemu-nbd -d /dev/nbd0 >/dev/null
