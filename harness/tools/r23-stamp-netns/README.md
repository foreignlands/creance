# r23-stamp-netns

Host netns replay of the v0.6.14 fw-armed chain: ExecStartPost stamp line (provision.rs) and probe fw line (escape.rs) are extracted from source; only /run is redirected to a temp dir. Cases V01-V13 (qualified ACCEPTs, post-stamp drift). Needs `sudo -n unshare`.

    sh harness/tools/r23-stamp-netns/netns.sh   # -> netns.log

Supports F-086.
