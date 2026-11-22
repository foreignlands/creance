#!/bin/sh
# r22-fw-armed/race.sh — capture in-guest facts while `creance up` is between ssh-ready and its
# fail-closed stop: who runs the up probe, can that identity even see iptables, is the firewall armed.
# usage: LAB=<dir with ./creance + prof/ after setup> sh race.sh  (CREANCE_BIN overrides ./creance)
set -u
LAB=${LAB:?}; cd "$LAB" || exit 2
export CREANCE_CONFIG=$LAB/prof/config.json
C=${CREANCE_BIN:-./creance}
E=$LAB/evidence; mkdir -p "$E"
FACTS='export PATH=/usr/bin:/bin
echo "id: $(id)"
echo "command -v iptables (probe PATH=/usr/bin:/bin): $(command -v iptables || echo NOT-FOUND)"
ls -l /usr/bin/iptables /usr/sbin/iptables /etc/alternatives/iptables 2>&1
echo "--- probe line verbatim:"
if iptables -L OUTPUT -n 2>/dev/null | head -1 | grep -q "policy DROP"; then echo fw-armed; else echo fw-down; fi
echo "--- same with /usr/sbin on PATH, stderr shown:"
PATH=/usr/sbin:/usr/bin:/bin iptables -L OUTPUT -n 2>&1 | head -2
echo "--- sudo -n:"; sudo -n true 2>&1 | head -1
echo "--- persisted rules.v4 head:"; head -6 /etc/iptables/rules.v4
echo "--- egress-lock: $(systemctl is-active egress-lock.service)"
echo "--- direct tcp 1.1.1.1:443:"; /usr/bin/timeout 5 /bin/bash -c "</dev/tcp/1.1.1.1/443" 2>/dev/null && echo open || echo blocked'
( timeout 1500 $C up > "$E/up2.log" 2>&1; echo "up2 RC=$?" >> "$E/up2.log" ) &
UP=$!
i=0; : > "$E/race.log"
while kill -0 $UP 2>/dev/null && [ $i -lt 900 ]; do
  out=$(timeout 20 $C shell -- sh -c "$FACTS" 2>&1)
  if printf '%s' "$out" | grep -q '^id: '; then printf '%s\n' "$out" > "$E/race.log"; break; fi
  i=$((i+1)); sleep 1
done
wait $UP
echo "race tries=$i"; cat "$E/race.log"; cat "$E/up2.log"
