#!/bin/sh
# r23-negative-controls — mutation-verify the F-082..084 fixes (v0.6.14) + regress the F-076/078/079/081 guards.
# Each case: cp backup -> perl inject -> grep -c proves it landed -> cargo test -> cp restore -> md5sum -c.
# A guarded surface turns some test red (test-RC!=0); test-RC=0 = no behavioral guard.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=${CREANCE_REPO:-$(CDPATH= cd -- "$HERE/../../.." && pwd)}
cd "$REPO" || exit 2
B=$(mktemp -d /tmp/r23-nc.XXXXXX)
L=${NC_LOGS:-$HERE/logs}; mkdir -p "$L"
FILES="crates/creance/src/escape.rs crates/creance-vm/src/qemu/runner.rs crates/creance/src/main.rs crates/creance-vm/src/qemu/provision.rs crates/creance-vm/src/lima.rs crates/creance-vm/src/provision.rs crates/creance-vm/src/qemu/mod.rs crates/creance-net/src/wire.rs crates/creance/src/serve.rs"
md5sum $FILES > "$B/md5"
for f in $FILES; do mkdir -p "$B/$(dirname "$f")"; cp "$f" "$B/$f"; done
restore() { for f in $FILES; do cp "$B/$f" "$f"; done; }
trap 'restore; rm -rf "$B"' EXIT
case_run() { # $1=name $2=file $3=perl-expr $4=grep-after(fixed string) $5..=crates
  name=$1 file=$2 expr=$3 after=$4; shift 4
  n0=$(grep -cF -- "$after" "$file")
  perl -0pi -e "$expr" "$file"
  n=$(grep -cF -- "$after" "$file")
  pk=""; for c in "$@"; do pk="$pk -p $c"; done
  cargo test --locked -q $pk > "$L/$name.log" 2>&1; rc=$?
  echo "$name: grep-c before=$n0 after=$n crates=$* test-RC=$rc failed=$(grep -c 'FAILED\|panicked' "$L/$name.log") compile-err=$(grep -c '^error' "$L/$name.log")"
  restore
}
# --- A0: F-076 guards (regression) ---
case_run NC-R    crates/creance-vm/src/qemu/runner.rs 's/if provisioned \{ "restrict=on," \}/if provisioned { "" }/' 'if provisioned { "" }' creance-vm
case_run NC-R2   crates/creance-vm/src/qemu/runner.rs 's/if provisioned \{ "restrict=on," \}/if true { "restrict=on," }/' 'if true { "restrict=on," }' creance-vm
case_run NC-073q crates/creance-vm/src/qemu/provision.rs 's/&\["10\.0\.2\.2", "10\.0\.2\.3"\]/&["192.168.5.2", "192.168.5.3"]/' '"192.168.5.2", "192.168.5.3"' creance-vm
case_run NC-073l crates/creance-vm/src/lima.rs 's/&\["192\.168\.5\.2", "192\.168\.5\.3"\]/&["10.0.2.2", "10.0.2.3"]/' '"10.0.2.2", "10.0.2.3"' creance-vm
case_run NC-074  crates/creance/src/escape.rs 's/r#"echo "PROBE fs-flag-readable SKIP — oracle flag 未能落盘""#/r#"echo "PROBE fs-flag-readable PASS"\necho "PROBE fs-flag-readable SKIP — oracle flag 未能落盘""#/' 'r#"echo "PROBE fs-flag-readable PASS"' creance
case_run NC-074b crates/creance/src/escape.rs 's/let fs_probe = if oracle_ready \{/let fs_probe = if true {/' 'let fs_probe = if true {' creance
case_run NC-074c crates/creance/src/escape.rs 's/let fs_probe = if oracle_ready \{/let fs_probe = if !oracle_ready {/' 'let fs_probe = if !oracle_ready {' creance
case_run NC-RO   crates/creance-vm/src/qemu/provision.rs 's/Yaml::from\(mount_script\(&options\.workspace, &options\.guest\.username\)\)/XXMOUNTXX/; s/Yaml::from\(bootstrap\)\]/Yaml::from(mount_script(&options.workspace, &options.guest.username))]/; s/XXMOUNTXX/Yaml::from(bootstrap.clone())/' 'Yaml::from(bootstrap.clone())' creance-vm
# --- A1: F-078/F-084 oracle (guest_script now places the flag itself) ---
case_run NC-F    crates/creance/src/escape.rs 's/let oracle_ready = place_oracle_flag\(flag_path\);/let oracle_ready = { let _ = place_oracle_flag(flag_path); true };/' 'place_oracle_flag(flag_path); true };' creance
case_run NC-F2   crates/creance/src/escape.rs 's/std::fs::write\(path, b"creance-escape-oracle\\n"\)\.is_ok\(\)/{ let _ = path; true }/' '{ let _ = path; true }' creance
case_run NC-SIG  crates/creance/src/escape.rs 's/let oracle_ready = place_oracle_flag\(flag_path\);/let oracle_ready = std::path::Path::new(flag_path).exists();/' 'std::path::Path::new(flag_path).exists();' creance
case_run NC-RMF  crates/creance/src/main.rs 's/(\n\s*match creance_vm::vm::guest_script\(&profile, &instance, &script\) \{)/\n        let _ = std::fs::remove_file(&flag);$1/' 'let _ = std::fs::remove_file(&flag);' creance
# --- A2: F-079/F-084 wire / workbench / node pin / lima digest ---
case_run NC-CLd  crates/creance-net/src/wire.rs 's/\(None, Ok\(n\)\) => len = Some\(n\),/(_, Ok(n)) => len = Some(n),/' '(_, Ok(n)) => len = Some(n),' creance-net creance-gate creance
case_run NC-CLx  crates/creance-net/src/wire.rs 's/_ => return Err\("duplicate or invalid content-length"\),/_ => {}/' '_ => {}' creance-net creance-gate creance
case_run NC-TE   crates/creance/src/serve.rs 's/eq_ignore_ascii_case\("transfer-encoding"\)/eq_ignore_ascii_case("transfer-encodingX")/' 'transfer-encodingX' creance
case_run NC-TE2  crates/creance/src/serve.rs 's/if k\.eq_ignore_ascii_case\("transfer-encoding"\) \{\n\s*return reply\(&mut stream, 400, "chunked bodies are not supported"\);\n\s*\} else if/if/' 'chunked bodies are not supported' creance
case_run NC-CLs  crates/creance/src/serve.rs 's/Err\(_\) => return reply\(&mut stream, 400, "invalid content-length"\),/Err(_) => 0,/' 'Err(_) => 0,' creance
case_run NC-NODE crates/creance-vm/src/provision.rs 's/b3996f0c2 ;;/b3996f0c3 ;;/' 'b3996f0c3 ;;' creance-vm
case_run NC-NOCK crates/creance-vm/src/provision.rs 's/if \[ -n "\$CREANCE_NODE_SHA256" \]; then/if false; then/' 'if false; then' creance-vm
case_run NC-NOCK2 crates/creance-vm/src/provision.rs 's/sha256sum -c - >> \/var\/log\/creance-toolchain\.log 2>&1 \|\| rm -f \/tmp\/creance-node\.tar\.gz/sha256sum -c - >> \/var\/log\/creance-toolchain.log 2>&1 || true/' 'creance-toolchain.log 2>&1 || true' creance-vm
case_run NC-NOCK3 crates/creance-vm/src/provision.rs 's/(\n  \[ -f \/tmp\/creance-node\.tar\.gz \] && tar -xzf)/\n  echo "\$CREANCE_NODE_SHA256" > \/dev\/null # verify-result ignored: re-download below\n  curl -fsSL -m 240 -o \/tmp\/creance-node.tar.gz https:\/\/nodejs.org\/dist\/v22.14.0\/node-v22.14.0-linux-\$ARCH.tar.gz >> \/var\/log\/creance-toolchain.log 2>&1 || true$1/' 'verify-result ignored' creance-vm
case_run NC-DIG  crates/creance-vm/src/lima.rs 's/bc2510131e0b39c50348e"/bc2510131e0b39c50348f"/' 'bc2510131e0b39c50348f' creance-vm
case_run NC-DIG2 crates/creance-vm/src/lima.rs 's/"digest"\.into\(\)/"digestX".into()/' '"digestX".into()' creance-vm
case_run NC-URL  crates/creance-vm/src/lima.rs 's|/release-20261017/ubuntu-|/release/ubuntu-|' '/release/ubuntu-' creance-vm
# --- A3: F-082/F-083 stamp chain (provision.rs) ---
case_run NC-EXP  crates/creance-vm/src/provision.rs 's/^ExecStartPost=.*\n//m' 'ExecStartPost=' creance-vm
case_run NC-STAMP crates/creance-vm/src/provision.rs 's/grep -E "\^:OUTPUT\|\^-A OUTPUT"/grep -E "^:OUTPUT"/' 'grep -E "^:OUTPUT"' creance-vm
case_run NC-STAMPf crates/creance-vm/src/provision.rs "s/> \\/run\\/egress-armed'\\n/> \\/run\\/egress-armed; printf \":OUTPUT DROP [0:0]\\\\\\\\n\" > \\/run\\/egress-armed'\\n/" 'printf ":OUTPUT DROP' creance-vm
case_run NC-STAMPr crates/creance-vm/src/provision.rs 's/(ExecStartPost=\/bin\/sh -c .\/usr\/sbin\/iptables-save -t filter \| \/usr\/bin\/grep -E "\^:OUTPUT\|\^-A OUTPUT" > \/run\/egress-armed)/$1 || true; true/' '/run/egress-armed || true; true' creance-vm
case_run NC-RST  crates/creance-vm/src/provision.rs 's/^systemctl restart egress-lock\.service$/systemctl start egress-lock.service/m' 'systemctl start egress-lock.service' creance-vm
case_run NC-RST2 crates/creance-vm/src/provision.rs 's/^systemctl restart egress-lock\.service$/systemctl restart egress-lock.service; true/m' 'systemctl restart egress-lock.service; true' creance-vm
case_run NC-RST3 crates/creance-vm/src/provision.rs 's/^systemctl restart egress-lock\.service$/# systemctl restart egress-lock.service/m' '# systemctl restart egress-lock.service' creance-vm
# --- A4: F-083/F-084 probe + verdict (escape.rs) ---
case_run NC-FW   crates/creance/src/escape.rs 's/if tcp_ok && icmp_ok && fw_ok \{/if tcp_ok \&\& icmp_ok {/' 'if tcp_ok && icmp_ok {' creance
case_run NC-VOK  crates/creance/src/escape.rs 's/(pub fn egress_verdict\(out: &str\) -> Result<\(\), &.static str> \{)/$1\n    if !out.is_empty() { return Ok(()); }/' 'if !out.is_empty() { return Ok(()); }' creance
case_run NC-PRB  crates/creance/src/escape.rs "s/if \\[ -f \\/run\\/egress-armed \\] && grep -q '\\^:OUTPUT DROP' \\/run\\/egress-armed && ! grep -qxF -- '-A OUTPUT -j ACCEPT' \\/run\\/egress-armed; then echo fw-armed; else echo fw-down; fi/echo fw-armed/" 'echo fw-armed\n' creance
case_run NC-PRB2 crates/creance/src/escape.rs 's/then echo fw-armed; else echo fw-down; fi/then echo fw-armed; else echo fw-armed; fi/' 'else echo fw-armed; fi' creance
case_run NC-PRB3 crates/creance/src/escape.rs "s/&& ! grep -qxF -- '-A OUTPUT -j ACCEPT'/\\&\\& grep -qxF -- '-A OUTPUT -j ACCEPT'/" "&& grep -qxF -- '-A OUTPUT -j ACCEPT'" creance
case_run NC-PRB4 crates/creance/src/escape.rs "s/ && ! grep -qxF -- '-A OUTPUT -j ACCEPT' \\/run\\/egress-armed;/;/" "/run/egress-armed; then echo fw-armed" creance
case_run NC-PRB5 crates/creance/src/escape.rs "s/grep -q '\\^:OUTPUT DROP' \\/run\\/egress-armed &&/{ grep -q '^:OUTPUT DROP' \\/run\\/egress-armed || true; } \\&\\&/" "|| true; } &&" creance
# --- A5: F-081/F-084 marker-after-verdict ---
case_run NC-MK   crates/creance/src/main.rs 's/(\n\s*match creance_vm::vm::guest_script\(&profile, &instance, escape::egress_probe_script\(\)\))/\n        let _ = creance_vm::vm::mark_provisioned(&profile, &instance);$1/' 'let _ = creance_vm::vm::mark_provisioned(&profile, &instance);' creance
case_run NC-MK3  crates/creance/src/main.rs 's/(if let Err\(reason\) = escape::egress_verdict\(&out\) \{\n)/$1                    let _ = creance_vm::vm::mark_provisioned(&profile, &instance);\n/' 'let _ = creance_vm::vm::mark_provisioned(&profile, &instance);' creance
case_run NC-MK4  crates/creance/src/main.rs 's/(\n(\s*)Err\(e\) => \{\n\s*let _ = creance_vm::vm::stop_vm\(&profile, &instance\);\n\s*return fail\(format!\("无法在 guest 内验证)/\n$2Err(e) => {\n$2    let _ = creance_vm::vm::mark_provisioned(\&profile, \&instance);\n$2    let _ = creance_vm::vm::stop_vm(\&profile, \&instance);\n$2    return fail(format!("无法在 guest 内验证/' 'let _ = creance_vm::vm::mark_provisioned(&profile, &instance);' creance
case_run NC-MK2  crates/creance-vm/src/qemu/mod.rs 's/Ok\(out\) if out\.contains\("mount-ok"\) => 0,/Ok(out) if out.contains("mount-ok") => { let _ = mark_provisioned(profile, instance); 0 }/' 'let _ = mark_provisioned(profile, instance); 0 }' creance-vm creance
case_run NC-MP   crates/creance-vm/src/qemu/mod.rs 's/std::fs::write\(&marker, b"ok\\n"\)\.is_ok\(\)/{ let _ = &marker; true }/' '{ let _ = &marker; true }' creance-vm
md5sum -c "$B/md5"
