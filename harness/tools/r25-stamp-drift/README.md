# r25-stamp-drift
Real QEMU guest: offline rules.v4 edit (qemu-nbd) → up with marker (restrict=on) → escape-test → CONTROL up without marker → restore.
`LAB=<lab> PROBE=<r25-fw-exact probe qemu dump> [CREANCE_BIN=<creance>] sh run.sh D3|E1|E2`. Evidence: `evidence-*.log`, `evidence/`.
D3 = F-090 regress; E1/E2 = F-092 spellings — at boot they are restored into live netfilter, the stamp shows them, up fails closed.
