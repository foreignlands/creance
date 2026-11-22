# r24-fw-allowlist
Dumps the shipped v0.6.15 egress probe (`escape::egress_probe_script(nat hosts)`) and replays its fw allowlist
against live netfilter in a throwaway netns. `cargo run -q -- qemu|lima > probe.sh`; `CREANCE_REPO=<repo> sh netns.sh` (needs `sudo -n`).
Evidence: `netns.log` (F-090 B01–B08/R01 bypass, N/R02 controls, K01–K03 false-kill direction). `probe-qemu.dump.sh` = the QEMU probe used on the real guest.
