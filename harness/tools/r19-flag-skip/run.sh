#!/bin/sh
# r19-flag-skip — behavioral witness for the F-068 fix (main.rs cmd_escape_test).
# Runs the REAL creance binary's escape-test against QEMU-backend fixtures whose
# "guest" transport is a fake `ssh` that executes the probe script on the host
# (host view = maximal escape). Cases:
#   A  flag placeable   -> expect fs-flag-readable ESCAPE (oracle has teeth) and flag removed after
#   B  flag unplaceable -> observe what the probe reports (vacuous PASS line + SKIP line?)
#   C  transport hangs, creance killed -> is the oracle file left on the host?
# Env: CREANCE_BIN (default <repo>/target/release/creance), CREANCE_REPO.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=${CREANCE_REPO:-$(CDPATH= cd -- "$HERE/../../.." && pwd)}
BIN=${CREANCE_BIN:-$REPO/target/release/creance}
[ -x "$BIN" ] || { echo "missing creance binary: $BIN"; exit 2; }
cargo build --quiet --manifest-path "$HERE/Cargo.toml" || exit 2
NAMER=$HERE/target/debug/r19-flag-skip
T=$(mktemp -d /tmp/r19-flag-skip.XXXXXX)
sleep 600 & HOLD=$!
trap 'kill $HOLD 2>/dev/null; rm -rf "$T"' EXIT
mkdir -p "$T/fakebin"
printf '#!/bin/sh\nexec sh -s\n' > "$T/fakebin/ssh"
printf '#!/bin/sh\nsleep 30\n' > "$T/fakebin-hang"
chmod +x "$T/fakebin/ssh" "$T/fakebin-hang"
RC=0

fixture() { # $1=case dir  $2=workspace path -> prints profile dir
  P=$T/$1/prof
  mkdir -p "$P"
  printf '{\n  "proxy_url": "socks5://127.0.0.1:17896",\n  "dns_url": "https://1.1.1.1/dns-query",\n  "timezone": "Etc/UTC",\n  "locale": "en_US.UTF-8",\n  "browser_language": "en-US"\n}\n' > "$P/config.json"
  printf '{"directory":"%s"}\n' "$2" > "$P/environment.json"
  INST=$("$NAMER" "$P" "$2")
  D=$P/state/qemu/$INST
  mkdir -p "$D"
  printf '{"version":1,"name":"%s","instance_id":"r19","ssh_local_port":1,"memory_gib":1,"cpus":1,"disk_gib":1,"arch":"amd64","workspace":"%s","created":"r19"}\n' "$INST" "$2" > "$D/instance.json"
  echo "$HOLD" > "$D/qemu.pid"
  echo "$P"
}

echo "== A: flag placeable (workspace parent writable)"
mkdir -p "$T/A/ws"
PA=$(fixture A "$T/A/ws")
CREANCE_CONFIG=$PA/config.json PATH=$T/fakebin:$PATH "$BIN" escape-test > "$T/A.out" 2>&1
grep 'fs-flag-readable' "$T/A.out" | sed 's/^/   /'
if grep -q 'PROBE fs-flag-readable ESCAPE' "$T/A.out"; then echo "   A oracle bites: MATCH"; else echo "   A oracle bites: MISMATCH"; RC=1; fi
if [ -e "$T/A/ws.escape-flag" ]; then echo "   A flag removed after run: MISMATCH"; RC=1; else echo "   A flag removed after run: MATCH"; fi

echo "== B: flag unplaceable (workspace parent does not exist)"
WSB=/nonexistent-r19-$$/ws
PB=$(fixture B "$WSB")
CREANCE_CONFIG=$PB/config.json PATH=$T/fakebin:$PATH "$BIN" escape-test > "$T/B.out" 2>&1
grep 'fs-flag-readable' "$T/B.out" | sed 's/^/   /'
N=$(grep -c '^PROBE fs-flag-readable' "$T/B.out")
echo "   B verdict lines for fs-flag-readable: $N (one honest SKIP expected per fix claim)"
if grep -q '^PROBE fs-flag-readable PASS' "$T/B.out" && grep -q '^PROBE fs-flag-readable SKIP' "$T/B.out"; then
  echo "   B observed: vacuous PASS line still printed, SKIP appended after it"
fi

echo "== C: transport hangs, creance terminated mid-run"
mkdir -p "$T/C/ws" "$T/C/fakebin"
cp "$T/fakebin-hang" "$T/C/fakebin/ssh"
PC=$(fixture C "$T/C/ws")
CREANCE_CONFIG=$PC/config.json PATH=$T/C/fakebin:$PATH "$BIN" escape-test > "$T/C.out" 2>&1 &
CP=$!
sleep 3
kill -TERM $CP 2>/dev/null; wait $CP 2>/dev/null
pkill -f "$T/C/fakebin/ssh" 2>/dev/null
if [ -e "$T/C/ws.escape-flag" ]; then echo "   C oracle left on host after interrupted run: yes ($(cat "$T/C/ws.escape-flag"))"; else echo "   C oracle left on host: no"; fi
exit $RC
