# r23-real-up

v0.6.14 release binary on Linux QEMU: setup, up#1 (provisioning, no restrict), stop, up#2 (restrict=on). facts.sh is piped through `creance shell -- sh -s` after each up (stamp owner/mode/content, unit state, probe fw line, guest write attempt, direct tcp, sudo).

    export CREANCE_CONFIG=<lab>/prof/config.json; ${CREANCE_BIN:-./creance} setup --memory 4 --cpus 4; ./creance up; ./creance shell -- sh -s < facts.sh
