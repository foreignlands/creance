# r25-fw-exact
netns replay of the v0.6.16 exact-line fw-armed check. The probe and rules.v4 are dumped from the product functions
(`cargo run -- probe|rules qemu|lima` → `creance::escape::egress_probe_script` / `creance_vm::provision::guest_bootstrap`).
`CREANCE_REPO=<repo> [BACKEND=lima] sh netns.sh` (needs sudo -n). A = current boot (live=stamp source), B = next boot (rules.v4 restored → fresh stamp).
Evidence: `netns.log` (qemu), `netns-lima.log` (lima). S01–S09 = F-092.
