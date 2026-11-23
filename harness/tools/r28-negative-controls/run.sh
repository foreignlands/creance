#!/bin/sh
# r28-negative-controls — mutation-verify the F-096/F-097 fixes (v0.6.20) + v0.6.19 watchdog fuse + new bypass candidates.
# Each case: cp backup -> perl inject -> grep -c proves it landed -> cargo test -> cp restore; md5sum -c at end.
# test-RC!=0 = guarded (red); test-RC=0 = no guard (green). compile-err>0 = harness error, not a guard.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=${CREANCE_REPO:-$(CDPATH= cd -- "$HERE/../../.." && pwd)}
cd "$REPO" || exit 2
B=$(mktemp -d /tmp/r28-nc.XXXXXX)
L=${NC_LOGS:-$HERE/logs}; mkdir -p "$L"
FILES="crates/creance/src/escape.rs crates/creance/src/main.rs crates/creance-vm/src/provision.rs crates/creance-vm/src/qemu/mod.rs crates/creance-vm/src/vm.rs crates/creance-vm/src/lima.rs crates/creance-gate/src/gate.rs crates/creance/src/lib.rs"
md5sum $FILES > "$B/md5"
for f in $FILES; do mkdir -p "$B/$(dirname "$f")"; cp "$f" "$B/$f"; done
restore() { for f in $FILES; do cp "$B/$f" "$f"; done; [ -n "${NEWF:-}" ] && rm -f "$NEWF"; NEWF=""; }
trap 'restore; rm -rf "$B"' EXIT
case_run() { # $1=name $2=file $3=perl-expr $4=grep-after(fixed string) $5..=crates
  [ -n "${ONLY:-}" ] && case " $ONLY " in *" $1 "*) ;; *) return 0;; esac
  name=$1 file=$2 expr=$3 after=$4; shift 4
  n0=$(grep -cF -- "$after" "$file")
  perl -0pi -e "$expr" "$file"
  [ -n "${X2F:-}" ] && perl -0pi -e "$X2E" "$X2F"
  [ -n "${NEWF:-}" ] && mkdir -p "$(dirname "$NEWF")" && printf '%s' "$NEWC" > "$NEWF"
  n=$(grep -cF -- "$after" "$file")
  pk=""; for c in "$@"; do pk="$pk -p $c"; done
  cargo test --locked -q $pk > "$L/$name.log" 2>&1; rc=$?
  echo "$name: grep-c before=$n0 after=$n crates=$* test-RC=$rc failed=$(grep -c 'FAILED\|panicked' "$L/$name.log") compile-err=$(grep -c '^error' "$L/$name.log")"
  restore; X2F=""
}
E=crates/creance/src/escape.rs; M=crates/creance/src/main.rs; P=crates/creance-vm/src/provision.rs; Q=crates/creance-vm/src/qemu/mod.rs; V=crates/creance-vm/src/vm.rs
MK='if creance_vm::vm::mark_provisioned(&profile, &instance) {'
OKBLK='\n(\s*)if creance_vm::vm::mark_provisioned\(&profile, &instance\) \{\n\s*println!\(\n\s*"供给完成[^\n]*\n\s*\);\n\s*\}\n'
# --- A: F-093 regressions (R25 shapes; expected red) ---
case_run NC-MKuse   $M 's/(Err\(reason\) => \{\n)/$1                    {\n                        use creance_vm::vm::mark_provisioned as arm_restrict;\n                        let _ = arm_restrict(\&profile, \&instance);\n                    }\n/' 'let _ = arm_restrict(' creance
case_run NC-MKparen $M 's/(Err\(reason\) => \{\n)/$1                    let _ = (creance_vm::vm::mark_provisioned)(\&profile, \&instance);\n/' '(creance_vm::vm::mark_provisioned)(' creance
case_run NC-MKswap  $M "s/$OKBLK/\\n/; s/(\\n\\s*)(Err\\(reason\\) => \\{\\n)(.*?\\n\\s{16}\\}\\n)(\\s*Ok\\(\\(\\)\\) => \\{\\n.*?\\n\\s{16}\\}\\n)/\$1\$4                Err(reason) => {\\n                    let _ = creance_vm::vm::mark_provisioned(\\&profile, \\&instance);\\n\$3/s" 'let _ = creance_vm::vm::mark_provisioned(&profile, &instance);' creance
case_run NC-MKarrow $M 's/(\n(\s*)if creance_vm::vm::mark_provisioned\(&profile, &instance\) \{)/\n$2let () = match 0u8 { _ => () };$1/' 'let () = match 0u8 { _ => () };' creance
case_run NC-MK6     $V 's/\{\n(\s*)crate::qemu::mark_provisioned\(profile, instance\)\n/{\n$1let _ = (profile, instance);\n$1false\n/; s/(\n\s*)crate::qemu::up\(profile, instance\)\n/$1let rc = crate::qemu::up(profile, instance);$1if rc == 0 {$1    let _ = crate::qemu::mark_provisioned(profile, instance);$1}$1rc\n/' 'let _ = crate::qemu::mark_provisioned(profile, instance);' creance-vm
case_run NC-WM      $Q 's/Ok\(out\) if out\.contains\("mount-ok"\) => 0,/Ok(out) if out.contains("mount-ok") => {\n            let _ = write_marker(\&dir);\n            0\n        }/' 'let _ = write_marker(&dir);' creance-vm
case_run NC-MP3     $Q 's/(fn write_marker\(dir: &str\) -> bool \{\n)/$1    if !dir.starts_with(std::env::temp_dir().to_string_lossy().as_ref()) { return true; }\n/' 'if !dir.starts_with(std::env::temp_dir()' creance-vm
case_run NC-MP2     $Q 's/(fn write_marker\(dir: &str\) -> bool \{\n)/$1    if !dir.contains("creance-mk-") { return true; }\n/' 'if !dir.contains("creance-mk-")' creance-vm
case_run NC-STAMPf2 $P "s/(ExecStartPost=\\/bin\\/sh -c .\\/usr\\/sbin\\/iptables-save[^\\n]*\\n)/\$1ExecStartPost=\\/bin\\/sh -c 'echo \":OUTPUT DROP [0:0]\" >\\/run\\/egress-armed'\\n/" 'echo ":OUTPUT DROP [0:0]" >/run/egress-armed' creance-vm
case_run NC-STAMPf3 $P "s/(ExecStartPost=\\/bin\\/sh -c .\\/usr\\/sbin\\/iptables-save[^\\n]*\\n)/\$1ExecStartPost=\\/bin\\/sh -c 'echo \":OUTPUT DROP [0:0]\" | tee \\/run\\/egress-armed'\\n/" '| tee /run/egress-armed' creance-vm
case_run NC-STAMPc  $P 's/(\nmkdir -p \/etc\/iptables\n)/\n# stamp lives at \/run\/egress-armed$1/' '# stamp lives at /run/egress-armed' creance-vm
case_run NC-RST4    $P 's/^systemctl restart egress-lock\.service$/systemctl restart egress-lock.service\n\/usr\/sbin\/iptables -P OUTPUT ACCEPT/m' 'iptables -P OUTPUT ACCEPT' creance-vm
case_run NC-RST5    $P 's/^systemctl restart egress-lock\.service$/systemctl restart egress-lock.service\nnft flush ruleset/m' 'nft flush ruleset' creance-vm
case_run NC-NOX     $E 's/grep -vxF \{grep_args\}/grep -vF {grep_args}/g' 'grep -vF {grep_args}' creance
# --- C: F-087 regressions (expected red) ---
case_run NC-MK4m    $M "s/$OKBLK/\\n/; s/(Ok\\(out\\) => match escape::egress_verdict.*?\\n(\\s*)Err\\(e\\) => \\{\\n)/\$1\$2    let _ = creance_vm::vm::mark_provisioned(\\&profile, \\&instance);\\n/s" 'let _ = creance_vm::vm::mark_provisioned(&profile, &instance);' creance
case_run NC-MK3     $M 's/(Err\(reason\) => \{\n)/$1                    let _ = creance_vm::vm::mark_provisioned(&profile, &instance);\n/' 'let _ = creance_vm::vm::mark_provisioned(&profile, &instance);' creance
case_run NC-WMtrue  $Q 's/(fn write_marker\(dir: &str\) -> bool \{\n)/$1    if !dir.is_empty() { return true; }\n/' 'if !dir.is_empty() { return true; }' creance-vm
case_run NC-ESPor   $P "s/(> \\/run\\/egress-armed)'\\n/\$1 || true'\\n/" "> /run/egress-armed || true'" creance-vm
case_run NC-RSTc    $P 's/\nsystemctl restart egress-lock\.service\n/\n# systemctl restart egress-lock.service\n/' '# systemctl restart egress-lock.service' creance-vm
case_run NC-NOCKb   $P 's/if \[ -n "\$CREANCE_NODE_SHA256" \]; then/if [ -n "\$CREANCE_NODE_SHA256" ] \&\& false; then/' '] && false; then' creance-vm
case_run NC-CTNEW   $E 's/--ctstate RELATED,ESTABLISHED -j ACCEPT"\.to_owned\(\),/--ctstate RELATED,ESTABLISHED -j ACCEPT".to_owned(),\n        "-A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".to_owned(),/' 'NEW,ESTABLISHED -j ACCEPT".to_owned()' creance
case_run NC-NAT1    $V 's/pub const NAT_HOSTS_QEMU: &\[&str\] = &\["10\.0\.2\.2", "10\.0\.2\.3"\];/pub const NAT_HOSTS_QEMU: \&[\&str] = \&["10.0.2.2", "10.0.2.3", "8.8.8.8"];/' '"8.8.8.8"' creance-vm
# --- D: F-095 regressions (R26 green shapes; expected red on v0.6.18) ---
X2F=$E X2E='s/(\n#\[cfg\(test\)\]\nmod tests \{)/\npub fn arm_after(p: \&str, i: \&str) -> bool {\n    creance_vm::vm::mark_provisioned(p, i)\n}\n$1/' \
case_run NC-MKmod   $M 's/(Err\(reason\) => \{\n)/$1                    let _ = escape::arm_after(\&profile, \&instance);\n/' 'let _ = escape::arm_after(&profile, &instance);' creance
case_run NC-MKcfg   $M 's/(Err\(reason\) => \{\n)/$1                    arm_unverified(\&profile, \&instance);\n/; s/(\nfn cmd_shell\()/\n\/\/ #[cfg(test)] marker-free helper\nfn arm_unverified(p: \&str, i: \&str) {\n    let _ = creance_vm::vm::mark_provisioned(p, i);\n}\n$1/' 'arm_unverified(&profile, &instance);' creance
case_run NC-VERD    $M 's/match escape::egress_verdict\(&out\) \{/match escape::egress_verdict(\&out).or_else(|_| Ok::<(), \&str>(())) {/' '.or_else(|_| Ok::<(), &str>(()))' creance
case_run NC-VMuse   $V 's/(\n\s*)crate::qemu::up\(profile, instance\)\n/$1use crate::qemu::mark_provisioned as arm_now;$1let rc = crate::qemu::up(profile, instance);$1if rc == 0 {$1    let _ = arm_now(profile, instance);$1}$1rc\n/' 'let _ = arm_now(profile, instance);' creance-vm
case_run NC-WMparen $Q 's/Ok\(out\) if out\.contains\("mount-ok"\) => 0,/Ok(out) if out.contains("mount-ok") => {\n            let _ = (write_marker)(\&dir);\n            0\n        }/' 'let _ = (write_marker)(&dir);' creance-vm
case_run NC-WMuse   $Q 's/Ok\(out\) if out\.contains\("mount-ok"\) => 0,/Ok(out) if out.contains("mount-ok") => {\n            use self::write_marker as wm;\n            let _ = wm(\&dir);\n            0\n        }/' 'let _ = wm(&dir);' creance-vm
case_run NC-MP4     $Q 's/(fn write_marker\(dir: &str\) -> bool \{\n)/$1    if dir.contains("\/state\/qemu\/") { return true; }\n/' 'if dir.contains("/state/qemu/")' creance-vm
case_run NC-UNIT1   $P "s/(ExecStartPost=\\/bin\\/sh -c .\\/usr\\/sbin\\/iptables-save[^\\n]*\\n)/\$1ExecStartPost=\\/usr\\/sbin\\/iptables -P OUTPUT ACCEPT\\n/" 'ExecStartPost=/usr/sbin/iptables -P OUTPUT ACCEPT' creance-vm
case_run NC-UNIT2   $P "s/(ExecStartPost=\\/bin\\/sh -c .\\/usr\\/sbin\\/iptables-save[^\\n]*\\n)/\$1ExecStartPost=-\\/usr\\/sbin\\/nft flush ruleset\\n/" 'ExecStartPost=-/usr/sbin/nft flush ruleset' creance-vm
case_run NC-STAMPdot $P "s/(ExecStartPost=\\/bin\\/sh -c .\\/usr\\/sbin\\/iptables-save[^\\n]*\\n)/\$1ExecStartPost=\\/bin\\/sh -c 'echo \":OUTPUT DROP [0:0]\" > \\/run\\/.\\/egress-armed'\\n/" '> /run/./egress-armed' creance-vm
case_run NC-STAMPvar $P "s/(ExecStartPost=\\/bin\\/sh -c .\\/usr\\/sbin\\/iptables-save[^\\n]*\\n)/\$1ExecStartPost=\\/bin\\/sh -c 'echo \":OUTPUT DROP [0:0]\" > \\/var\\/run\\/egress-armed'\\n/" '> /var/run/egress-armed' creance-vm
. "$HERE/cases-r28.sh"
md5sum -c "$B/md5"
