#!/bin/sh
# r24-negative-controls — mutation-verify the F-086/F-087 fixes (v0.6.15) + regress the R23 13 green cases.
# Each case: cp backup -> perl inject -> grep -c proves it landed -> cargo test -> cp restore -> md5sum -c.
# test-RC!=0 = guarded (red); test-RC=0 = no guard (green).
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=${CREANCE_REPO:-$(CDPATH= cd -- "$HERE/../../.." && pwd)}
cd "$REPO" || exit 2
B=$(mktemp -d /tmp/r24-nc.XXXXXX)
L=${NC_LOGS:-$HERE/logs}; mkdir -p "$L"
FILES="crates/creance/src/escape.rs crates/creance/src/main.rs crates/creance-vm/src/provision.rs crates/creance-vm/src/qemu/mod.rs crates/creance-vm/src/vm.rs crates/creance-vm/src/lima.rs"
md5sum $FILES > "$B/md5"
for f in $FILES; do mkdir -p "$B/$(dirname "$f")"; cp "$f" "$B/$f"; done
restore() { for f in $FILES; do cp "$B/$f" "$f"; done; }
trap 'restore; rm -rf "$B"' EXIT
case_run() { # $1=name $2=file $3=perl-expr $4=grep-after(fixed string) $5..=crates
  [ -n "${ONLY:-}" ] && case " $ONLY " in *" $1 "*) ;; *) return 0;; esac
  name=$1 file=$2 expr=$3 after=$4; shift 4
  n0=$(grep -cF -- "$after" "$file")
  perl -0pi -e "$expr" "$file"
  n=$(grep -cF -- "$after" "$file")
  pk=""; for c in "$@"; do pk="$pk -p $c"; done
  cargo test --locked -q $pk > "$L/$name.log" 2>&1; rc=$?
  echo "$name: grep-c before=$n0 after=$n crates=$* test-RC=$rc failed=$(grep -c 'FAILED\|panicked' "$L/$name.log") compile-err=$(grep -c '^error' "$L/$name.log")"
  restore
}
E=crates/creance/src/escape.rs; M=crates/creance/src/main.rs; P=crates/creance-vm/src/provision.rs; Q=crates/creance-vm/src/qemu/mod.rs; V=crates/creance-vm/src/vm.rs
# PRB5b/NOCK4b: format!-safe re-injections of PRB5/NOCK4 (first cut did not compile — harness error, not a guard)
# --- A: F-086 allowlist fragment (escape.rs) — task-book mutations ---
case_run NC-HRE   $E 's/\.map\(\|h\| h\.replace\(.\.., "\\\\\."\)\)/.map(|h| h.to_string())/' '.map(|h| h.to_string())' creance
case_run NC-HRE2  $E 's/\.join\("\|"\)/.join("")/' '.join("")' creance
case_run NC-ICMP  $E "s/\\|--dport 67\\.\\*-p udp\\|-p icmp'\\)/|--dport 67.*-p udp')/" "|--dport 67.*-p udp')" creance
case_run NC-D32   $E 's/\(\(\{hosts_re\}\)\/32\|/(({hosts_re})|/' '(({hosts_re})|' creance
case_run NC-LEAK  $E "s/grep -Ev -- '-j ACCEPT\\\$'\\)/grep -Ev -- '-j (ACCEPT|LEAK)\\\$')/" "-j (ACCEPT|LEAK)" creance
case_run NC-CTN   $E 's/conntrack --ctstate \.\*ESTABLISHED\.\*-j ACCEPT/conntrack --ctstate .*-j ACCEPT/' 'conntrack --ctstate .*-j ACCEPT' creance
case_run NC-CTN2  $E 's/conntrack --ctstate \.\*ESTABLISHED\.\*-j ACCEPT/conntrack --ctstate .*ESTABLISHED.*/' 'ESTABLISHED.*$' creance
case_run NC-RULES $E 's/ && grep -q .\^:OUTPUT DROP. \\"\$WANT\\"//' 'DROP'"'"' \"$STAMP\"; then' creance
case_run NC-CAT   $E 's/cat \\"\$STAMP\\" \\"\$WANT\\"/cat \\"$STAMP\\"/' 'cat \"$STAMP\" |' creance
case_run NC-NEG   $E "s/grep -Ev -- '-d \\(\\(/grep -Ev -- '(! )?-d ((/" "(! )?-d ((" creance
# --- B: R23 13 green cases re-run on the v0.6.15 shapes ---
case_run NC-PRB2  $E 's/then echo fw-armed; else echo fw-down; fi/then echo fw-armed; else echo fw-armed; fi/' 'else echo fw-armed; fi' creance
case_run NC-PRB5  $E "s/grep -q '\\^:OUTPUT DROP' \\\\\"\\\$STAMP\\\\\" &&/{ grep -q '^:OUTPUT DROP' \\\\\"\\\$STAMP\\\\\" || true; } \\&\\&/" '|| true; } &&' creance
case_run NC-MK3   $M 's/(Err\(reason\) => \{\n)/$1                    let _ = creance_vm::vm::mark_provisioned(&profile, &instance);\n/' 'mark_provisioned(&profile, &instance)' creance
case_run NC-MKpost $M 's/\n(\s*)if creance_vm::vm::mark_provisioned\(&profile, &instance\) \{\n\s*println!\(\n\s*"供给完成[^\n]*\n\s*\);\n\s*\}\n/\n/; s/(\n        println!\("Environment is up\.)/\n        if creance_vm::vm::mark_provisioned(&profile, &instance) {\n            println!("供给完成——下次 creance stop && creance up 起 slirp restrict=on 第二道防线生效");\n        }$1/' 'if creance_vm::vm::mark_provisioned(&profile, &instance) {' creance
case_run NC-MK4m  $M 's/\n(\s*)if creance_vm::vm::mark_provisioned\(&profile, &instance\) \{\n\s*println!\(\n\s*"供给完成[^\n]*\n\s*\);\n\s*\}\n/\n/; s/(\n(\s*)Err\(e\) => \{\n)(\s*let _ = creance_vm::vm::stop_vm\(&profile, &instance\);\n\s*return fail\(format!\("无法在 guest 内验证)/$1$2    let _ = creance_vm::vm::mark_provisioned(&profile, &instance);\n$3/' 'let _ = creance_vm::vm::mark_provisioned(&profile, &instance);' creance
case_run NC-MKalias $M 's/(Err\(reason\) => \{\n)/$1                    let _ = creance_vm::vm::mark_provisioned(&*profile, &instance);\n/' 'mark_provisioned(&*profile, &instance)' creance
case_run NC-MK2   $Q 's/Ok\(out\) if out\.contains\("mount-ok"\) => 0,/Ok(out) if out.contains("mount-ok") => {\n            let _ = mark_provisioned(profile, instance);\n            0\n        }/' 'let _ = mark_provisioned(profile, instance);' creance-vm creance
case_run NC-MK5   $V 's/(\n\s*)crate::qemu::up\(profile, instance\)\n/$1let rc = crate::qemu::up(profile, instance);$1if rc == 0 {$1    let _ = mark_provisioned(profile, instance);$1}$1rc\n/' 'let _ = mark_provisioned(profile, instance);' creance-vm creance
case_run NC-MP    $Q 's/std::fs::write\(&marker, b"ok\\n"\)\.is_ok\(\)/{ let _ = &marker; true }/' '{ let _ = &marker; true }' creance-vm
case_run NC-MP2   $Q 's/(fn write_marker\(dir: &str\) -> bool \{\n)/$1    if !dir.contains("creance-mk-") { return true; }\n/' 'if !dir.contains("creance-mk-") { return true; }' creance-vm
case_run NC-STAMPf $P "s/(ExecStartPost=\\/bin\\/sh -c .\\/usr\\/sbin\\/iptables-save[^\\n]*\\n)/\$1ExecStartPost=\\/bin\\/sh -c 'printf \":OUTPUT DROP [0:0]\\\\\\\\n\" > \\/run\\/egress-armed'\\n/" 'printf ":OUTPUT DROP' creance-vm
case_run NC-STAMPr $P 's/(> \/run\/egress-armed)'"'"'\n/$1 || true'"'"'\n/' '/run/egress-armed || true' creance-vm
case_run NC-STAMPr2 $P 's/^ExecStartPost=\/bin\/sh -c /ExecStartPost=-\/bin\/sh -c /m' 'ExecStartPost=-/bin/sh' creance-vm
case_run NC-RST2  $P 's/^systemctl restart egress-lock\.service$/systemctl restart egress-lock.service; true/m' 'systemctl restart egress-lock.service; true' creance-vm
case_run NC-RST3  $P 's/^systemctl restart egress-lock\.service$/# systemctl restart egress-lock.service/m' '# systemctl restart egress-lock.service' creance-vm
case_run NC-RST4  $P 's/^systemctl restart egress-lock\.service$/systemctl restart egress-lock.service\n\/usr\/sbin\/iptables -P OUTPUT ACCEPT/m' 'iptables -P OUTPUT ACCEPT' creance-vm
case_run NC-NOCK  $P 's/if \[ -n "\$CREANCE_NODE_SHA256" \]; then/if false; then/' 'if false; then' creance-vm
case_run NC-NOCKb $P 's/if \[ -n "\$CREANCE_NODE_SHA256" \]; then/if [ -n "\$CREANCE_NODE_SHA256" ] \&\& false; then/' '] && false; then' creance-vm
case_run NC-NOCK3 $P 's/(\n  \[ -f \/tmp\/creance-node\.tar\.gz \] && tar -xzf)/\n  echo "\$CREANCE_NODE_SHA256" > \/dev\/null # verify-result ignored: re-download below\n  curl -fsSL -m 240 -o \/tmp\/creance-node.tar.gz https:\/\/nodejs.org\/dist\/v22.14.0\/node-v22.14.0-linux-\$ARCH.tar.gz >> \/var\/log\/creance-toolchain.log 2>&1 || true$1/' 'verify-result ignored' creance-vm
case_run NC-NOCK4 $P 's/(\n  \[ -f \/tmp\/creance-node\.tar\.gz \] && tar -xzf)/\n  curl -fsSL -m 240 -o \/tmp\/creance-node.tar.gz "https:\/\/nodejs.org\/dist\/v22.14.0\/node-v22.14.0-\${ARCH:+linux}-\$ARCH.tar.gz" 2>\/dev\/null || true # verify-result ignored$1/' 'verify-result ignored' creance-vm
case_run NC-NAT1  crates/creance-vm/src/vm.rs 's/pub const NAT_HOSTS_QEMU: &\[&str\] = &\["10\.0\.2\.2", "10\.0\.2\.3"\];/pub const NAT_HOSTS_QEMU: \&[\&str] = \&["10.0.2.2", "10.0.2.3", "8.8.8.8"];/' '"8.8.8.8"' creance-vm creance
case_run NC-PRB5b $E "s/grep -q '\\^:OUTPUT DROP' \\\\\"\\\$STAMP\\\\\" &&/{{ grep -q '^:OUTPUT DROP' \\\\\"\\\$STAMP\\\\\" || true; }} \\&\\&/" '|| true; }} &&' creance
case_run NC-NOCK4b $P 's/(\n  \[ -f \/tmp\/creance-node\.tar\.gz \] && tar -xzf)/\n  curl -fsSL -m 240 -o \/tmp\/creance-node.tar.gz https:\/\/nodejs.org\/dist\/v22.14.0\/node-v22.14.0-linux-\$ARCH.tar.gz.sig 2>\/dev\/null || true$1/' 'node-v22.14.0-linux-$ARCH.tar.gz.sig' creance-vm
md5sum -c "$B/md5"
