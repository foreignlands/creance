r22-fw-armed — live + host-side evidence for F-082/F-083 (v0.6.13 up fw-armed probe).
- `LAB=<dir> sh race.sh`: after `creance setup` + a failed `creance up`, re-runs `up` and races `creance shell` into the guest
  before up's fail-closed stop, capturing uid / iptables visibility / persisted rules / egress-lock / direct egress.
  Caveat: `creance shell -- sh -c "$FACTS"` is re-split by ssh, so FACTS' own `export PATH=/usr/bin:/bin` does not apply
  (the env dump at the top of race.log is that `export`); the lines run under the login PATH. The uid / permission /
  sudo / rules facts do not depend on PATH; the PATH half is proven by netns.sh P4 and `ls /usr/bin/iptables` (absent).
- `sh netns.sh`: replays main.rs:754's probe line verbatim in throwaway `sudo -n unshare -n` namespaces (P1–P5).
- evidence/: s.log (setup), up1.log, up2.log, race.log, instance-dir-after-up2.txt; netns.log.
