#!/bin/sh
# C3 gate concurrency hammer (R4). Usage: sh hammer.sh <profile-abs> <rounds>
# Per round: double-parallel `up` (daemon-raise race) -> concurrent control
# burst -> sample invariants -> drain close. Anomalies -> /tmp/r4-c3-anomalies.log
set -u
PROFILE="$1"; ROUNDS="${2:-10}"
CREANCE=${CREANCE_BIN:-$(cd "$(dirname "$0")/../../.." && pwd)/target/release/creance}
LIMADIR="$PROFILE/state/lima"
INST=$(ls "$LIMADIR" | grep -v '^_' | head -1)
RECORD="$LIMADIR/$INST/cage-gate.json"
ANOM=/tmp/r4-c3-anomalies.log
: > /tmp/r4-c3-anomalies.log
: > /tmp/r4-c3-ops.log

sock() { jq -r .socket "$RECORD" 2>/dev/null; }
tok() { jq -r .token "$RECORD" 2>/dev/null; }

ctl() {
  S=$(sock); T=$(tok)
  [ -n "$S" ] && [ -S "$S" ] || { echo "NOSOCK"; return; }
  curl -s --max-time 6 --unix-socket "$S" -H "Host: gate" -H "Authorization: Bearer $T" \
       -X POST -d "$1" http://cage/control 2>/dev/null
}
state() {
  S=$(sock); T=$(tok)
  [ -n "$S" ] && [ -S "$S" ] || { echo "NOSOCK"; return; }
  curl -s --max-time 6 --unix-socket "$S" -H "Host: gate" -H "Authorization: Bearer $T" \
       http://cage/status 2>/dev/null | jq -r '.state // "ERR"'
}
tunnels() { pgrep -f "HostKeyAlias=lima-$INST" 2>/dev/null | while read -r p; do
    ps -o stat= -p "$p" 2>/dev/null | grep -q '^Z' && echo "${p}Z" || { \
      ps -o command= -p "$p" 2>/dev/null | grep -q -- '-R .*127.0.0.1:' && echo "$p"; }
  done | tr '\n' ' '; }
daemons() { pgrep -f "gate-daemon $PROFILE" | wc -l | tr -d ' '; }

FAILS=0
r=0
while [ "$r" -lt "$ROUNDS" ]; do
  r=$((r+1))
  # 1) double-parallel raise (spawn_daemon race), then burst immediately
  "$CREANCE" up >/dev/null 2>&1 &
  U1=$!
  "$CREANCE" up >/dev/null 2>&1 &
  U2=$!
  "$CREANCE" gate-open >/dev/null 2>&1 &
  P1=$!
  ( sleep 0.05; ctl '{"action":"renew","report_id":"forged-id"}' >/dev/null ) &
  ( sleep 0.10; ctl '{"action":"fault"}' >/dev/null ) &
  ( sleep 0.15; ctl '{"action":"close","reason":"hammer-burst"}' >/dev/null ) &
  ( sleep 0.20; ctl '{"action":"grant","report_id":"x","report":{"report_id":"x","checks":{"a":"passed"}}}' >/dev/null ) &
  ( sleep 0.25; ctl '{"action":"proxy-revision"}' >/dev/null ) &
  ( sleep 0.30; ctl 'not-json' >/dev/null ) &
  wait $U1 $U2 $P1
  S1=$(state)
  sleep 1.5   # > watchdog period: let close-side reap/ensure settle
  T1=$(tunnels); DA=$(daemons); ST=$(stat -f %Su "$RECORD" 2>/dev/null)
  [ "$DA" != "1" ] && { echo "R$r daemons=$DA state=$S1" >> "$ANOM"; FAILS=$((FAILS+1)); }
  case "$S1" in
    Open)
      case "$T1" in
        ""|*Z*) echo "R$r OPEN-BAD-WIRE: [$T1]" >> "$ANOM"; FAILS=$((FAILS+1)); ;;
      esac
      LIVE=$(echo $T1 | tr ' ' '\n' | grep -vc Z)
      [ "$LIVE" -gt 1 ] && { echo "R$r MULTI-TUNNEL: [$T1]" >> "$ANOM"; FAILS=$((FAILS+1)); }
      ;;
    Closed|Checking) : ;;
    NOSOCK|ERR)
      echo "R$r status=$S1 record=$(test -f "$RECORD" && echo present || echo gone) daemons=$DA" >> "$ANOM"; FAILS=$((FAILS+1)); ;;
  esac
  # 2) drain
  "$CREANCE" gate-close >/dev/null 2>&1
  sleep 1.2
  D0=$(tunnels)
  [ -n "$D0" ] && { echo "R$r drain-left-tunnels: [$D0]" >> "$ANOM"; FAILS=$((FAILS+1)); }
  echo "R$r end_state=$S1 tunnels=[$T1] daemons=$DA"
done
echo "=== hammer done: rounds=$ROUNDS anomalies=$FAILS (see $ANOM) ==="
