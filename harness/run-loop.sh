#!/bin/sh
# Night-run outer driver: restarts the agent session when it exits, so a
# crashed or context-full session never ends the night early.
#
# Usage: sh harness/run-loop.sh <start-agent-cmd...>
#   where <start-agent-cmd> launches a fresh agent session whose first
#   message is harness/OPERATOR-PROMPT.md and whose cwd is this repo.
#   Example (illustrative — adapt to your agent CLI):
#     sh harness/run-loop.sh zcode --message "$(cat harness/OPERATOR-PROMPT.md)"
#
# Safety: fixed iteration cap; refuses to run if STATE.md says STOP.
set -eu
cd "$(dirname "$0")/.."

MAX_SESSIONS="${MAX_SESSIONS:-40}"
i=0
while [ "$i" -lt "$MAX_SESSIONS" ]; do
    if grep -qE '^# STOP|建议停止' harness/state/STATE.md 2>/dev/null; then
        echo "run-loop: STATE.md requests stop."
        break
    fi
    i=$((i + 1))
    echo "=== session $i / $MAX_SESSIONS @ $(date -u +%FT%TZ) ==="
    if ! "$@"; then
        echo "run-loop: agent exited nonzero; cooling down 30s"
        sleep 30
    fi
    # The operator writes "# STOP" (or the verdict 建议停止) into STATE.md at budget exhaustion.
done
echo "run-loop: done ($i sessions). Findings:"
cat harness/findings/INDEX.md
