# r23-stamp-drift

Real QEMU guest (v0.6.14 binary): D1 qualified ACCEPT in rules.v4, D2 root unit that flushes OUTPUT after the stamp. Each case runs up with restrict=on, collects in-guest facts + escape-test, then a no-marker control up, and restores disk + marker.

    LAB=<lab dir with creance binary + prof/> sh run.sh D1|D2   # CREANCE_BIN overrides ./creance

Evidence: evidence/. Supports F-086.
