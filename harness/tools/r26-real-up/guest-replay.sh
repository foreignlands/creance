#!/bin/sh
# r26 guest-replay — run the SHIPPED v0.6.17 fw fragment inside the real guest (real grep/locale/stamp) against
# rules.v4 fixtures written to the guest user's /tmp (CREANCE_RULES override; stamp = real /run/egress-armed).
# Shows the boot-A verdict for F-094 shapes in the real guest userland. Fixtures derive from the guest's real rules.v4.
# usage: LAB=<lab with provisioned+running instance> PROBE=<r26-fw-exact probe qemu dump> [CREANCE_BIN] [HOST_LANG] sh guest-replay.sh
set -u
LAB=${LAB:?}; PROBE=${PROBE:?}; cd "$LAB" || exit 2
export CREANCE_CONFIG=$LAB/prof/config.json
C=${CREANCE_BIN:-./creance}
{ echo 'export PATH=/usr/bin:/bin'
  echo 'R=$(mktemp -d); cat > $R/fw.sh <<'"'FRAG'"
  sed -n '/^STAMP=/,$p' "$PROBE"
  echo 'FRAG'
  cat <<'G'
echo "guest: $(grep --version | head -1); LANG=${LANG:-unset} LC_ALL=${LC_ALL:-unset}; ssh-forwarded-locale: $(locale 2>/dev/null | head -1)"
P=/etc/iptables/rules.v4; H=$(sed '$d' $P)
cp $P $R/P01
{ printf '%s\n#\000\n-I OUTPUT -j ACCEPT\nCOMMIT\n' "$H"; } > $R/Z01
{ printf '%s\n# \377\n-I OUTPUT -j ACCEPT\nCOMMIT\n' "$H"; } > $R/Z03
{ sed -n '1,3p' $P; echo COMMIT; sed -n '4,$p' $P | grep -vx COMMIT; } > $R/O01
{ sed -n '2,$p' $P | grep -vx COMMIT; echo '*filter'; echo COMMIT; } > $R/O03
for f in P01 Z01 Z03 O01 O03; do
  for l in "" C.UTF-8; do
    printf '%s LANG=%-8s -> %s\n' $f "${l:-(env)}" "$(env ${l:+LANG=$l} CREANCE_RULES=$R/$f sh $R/fw.sh)"
  done
done
echo "--- Z01 grep view: lines-out=$(grep -v '^[[:space:]]*$' $R/Z01 | wc -l) stderr=[$(grep -v '^[[:space:]]*$' $R/Z01 2>&1 >/dev/null)]"
echo "--- O01 file:"; sed 's/^/    /' $R/O01
rm -rf $R
G
} > "$LAB/replay.sh"
${HOST_LANG:+env LANG=$HOST_LANG} timeout 60 $C shell -- sh -s < "$LAB/replay.sh" 2>&1
