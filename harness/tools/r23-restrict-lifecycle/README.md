# r23-restrict-lifecycle

Real QEMU lifecycle: L0 idempotent re-up (we_started=false), L4 we_started=false + mount-missing, L3 restart of an active egress-lock oneshot (does ExecStartPost re-run), L2 pre-v0.6.14 unit without ExecStartPost, L1 marker deleted, L5 instance dir renamed.

    LAB=<lab> sh run.sh [L0 L4 L3 L2 L1 L5]

Evidence: evidence/.
