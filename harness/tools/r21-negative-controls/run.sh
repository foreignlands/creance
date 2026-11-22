#!/bin/sh
# r21-negative-controls — re-verify the F-076 guards (v0.6.12) and probe the v0.6.11..v0.6.12
# new surfaces (wire strict-CL, node sha256 pin, Lima digest pin, provisioned marker write).
# Each case: cp backup -> perl inject -> grep -c proves it landed -> cargo test -> cp restore -> md5sum -c.
# A guarded surface turns some test red (test-RC!=0); test-RC=0 = no behavioral guard.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=${CREANCE_REPO:-$(CDPATH= cd -- "$HERE/../../.." && pwd)}
cd "$REPO" || exit 2
B=$(mktemp -d /tmp/r21-nc.XXXXXX)
FILES="crates/creance/src/escape.rs crates/creance-vm/src/qemu/runner.rs crates/creance/src/main.rs crates/creance-vm/src/qemu/provision.rs crates/creance-vm/src/lima.rs crates/creance-vm/src/provision.rs crates/creance-vm/src/qemu/mod.rs crates/creance-net/src/wire.rs crates/creance/src/serve.rs"
md5sum $FILES > "$B/md5"
for f in $FILES; do mkdir -p "$B/$(dirname "$f")"; cp "$f" "$B/$f"; done
restore() { for f in $FILES; do cp "$B/$f" "$f"; done; }
trap 'restore; rm -rf "$B"' EXIT
case_run() { # $1=name $2=file $3=perl-expr $4=grep-after(fixed string) $5..=crates
  name=$1 file=$2 expr=$3 after=$4; shift 4
  perl -0pi -e "$expr" "$file"
  n=$(grep -cF -- "$after" "$file")
  pk=""; for c in "$@"; do pk="$pk -p $c"; done
  cargo test --locked -q $pk > "$B/$name.log" 2>&1; rc=$?
  echo "$name: inject-grep-c=$n crates=$* test-RC=$rc failed=$(grep -c 'FAILED\|panicked' "$B/$name.log") compile-err=$(grep -c '^error' "$B/$name.log")"
  grep -E '^test .* FAILED|^error' "$B/$name.log" | head -3 | sed 's/^/    /'
  restore
}
# --- A: F-076 guard re-verification (r20 five + variants) ---
case_run NC-R    crates/creance-vm/src/qemu/runner.rs 's/if provisioned \{ "restrict=on," \}/if provisioned { "" }/' 'if provisioned { "" }' creance-vm
case_run NC-R2   crates/creance-vm/src/qemu/runner.rs 's/if provisioned \{ "restrict=on," \}/if true { "restrict=on," }/' 'if true { "restrict=on," }' creance-vm
case_run NC-F    crates/creance/src/main.rs 's/std::fs::write\(&flag, b"creance-escape-oracle\\n"\)\.is_ok\(\)/true/' 'let flag_placed = true;' creance
case_run NC-073q crates/creance-vm/src/qemu/provision.rs 's/&\["10\.0\.2\.2", "10\.0\.2\.3"\]/&["192.168.5.2", "192.168.5.3"]/' '"192.168.5.2", "192.168.5.3"' creance-vm
case_run NC-073l crates/creance-vm/src/lima.rs 's/&\["192\.168\.5\.2", "192\.168\.5\.3"\]/&["10.0.2.2", "10.0.2.3"]/' '"10.0.2.2", "10.0.2.3"' creance-vm
case_run NC-074  crates/creance/src/escape.rs 's/r#"echo "PROBE fs-flag-readable SKIP — oracle flag 未能落盘""#/r#"echo "PROBE fs-flag-readable PASS"\necho "PROBE fs-flag-readable SKIP — oracle flag 未能落盘""#/' 'r#"echo "PROBE fs-flag-readable PASS"' creance
case_run NC-074b crates/creance/src/escape.rs 's/let fs_probe = if oracle_ready \{/let fs_probe = if true {/' 'let fs_probe = if true {' creance
case_run NC-074c crates/creance/src/escape.rs 's/let fs_probe = if oracle_ready \{/let fs_probe = if !oracle_ready {/' 'let fs_probe = if !oracle_ready {' creance
case_run NC-RO   crates/creance-vm/src/qemu/provision.rs 's/Yaml::from\(mount_script\(&options\.workspace, &options\.guest\.username\)\)/XXMOUNTXX/; s/Yaml::from\(bootstrap\)\]/Yaml::from(mount_script(&options.workspace, &options.guest.username))]/; s/XXMOUNTXX/Yaml::from(bootstrap.clone())/' 'Yaml::from(bootstrap.clone())' creance-vm
case_run NC-M    crates/creance-vm/src/qemu/mod.rs 's/let _ = std::fs::write\(&marker, b"ok\\n"\);/let _ = &marker;/' 'let _ = &marker;' creance-vm
# --- B: v0.6.12 new surfaces ---
case_run NC-CLd  crates/creance-net/src/wire.rs 's/\(None, Ok\(n\)\) => len = Some\(n\),/(_, Ok(n)) => len = Some(n),/' '(_, Ok(n)) => len = Some(n),' creance-net creance-gate creance
case_run NC-CLx  crates/creance-net/src/wire.rs 's/_ => return Err\("duplicate or invalid content-length"\),/_ => {}/' '_ => {}' creance-net creance-gate creance
case_run NC-TE   crates/creance/src/serve.rs 's/eq_ignore_ascii_case\("transfer-encoding"\)/eq_ignore_ascii_case("transfer-encodingX")/' 'transfer-encodingX' creance
case_run NC-NODE crates/creance-vm/src/provision.rs 's/b3996f0c2 ;;/b3996f0c3 ;;/' 'b3996f0c3 ;;' creance-vm
case_run NC-NOCK crates/creance-vm/src/provision.rs 's/if \[ -n "\$CREANCE_NODE_SHA256" \]; then/if false; then/' 'if false; then' creance-vm
case_run NC-DIG  crates/creance-vm/src/lima.rs 's/bc2510131e0b39c50348e/bc2510131e0b39c50348f/' 'bc2510131e0b39c50348f' creance-vm
case_run NC-DIG2 crates/creance-vm/src/lima.rs 's/"digest"\.into\(\)/"digestX".into()/' '"digestX".into()' creance-vm
md5sum -c "$B/md5"
