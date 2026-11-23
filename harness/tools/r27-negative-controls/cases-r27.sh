# r27 cases (sourced by run.sh). Expected: E = red (guarded); G? = green candidate (no guard).
L2=crates/creance-vm/src/lima.rs
ERR='s/(Err\(reason\) => \{\n)/$1                    '
# --- E: F-094 cmp-probe mutations ---
case_run NC-CMPtrue  $E 's/cmp -s \\"\$WANT\\" - <</true <</' "&& true <<'CREANCE" creance
case_run NC-HDQ      $E "s/- <<'CREANCE_RULESET_EOF'/- <<CREANCE_RULESET_EOF/" '- <<CREANCE_RULESET_EOF' creance
case_run NC-CMPnoS   $E 's/&& cmp -s \\"\$WANT\\" -/&& cmp \\"\$WANT\\" -/' '&& cmp \"$WANT\" -' creance
case_run NC-CMPn     $E 's/cmp -s \\"\$WANT\\" - <</cmp -s \\"\$WANT\\" - -n 8 <</' '- -n 8 <<' creance
case_run NC-CMPskip  $E 's/cmp -s \\"\$WANT\\" - <</cmp -s \\"\$WANT\\" - 0 0 <</' '- 0 0 <<' creance
case_run NC-CMPswap  $E 's/cmp -s \\"\$WANT\\" - <</cmp -s - \\"\$WANT\\" <</' 'cmp -s - \"$WANT\" <<' creance
case_run NC-TRUNC    $E 's/(let expected = creance_vm::provision::rules_v4_text\(nat_hosts\));/$1.replacen("COMMIT\\n", "", 1);/' '.replacen("COMMIT\n", "", 1);' creance
case_run NC-PDRIFT   $E 's/(let expected = creance_vm::provision::rules_v4_text\(nat_hosts\));/$1.replace("-o lo", "-o  lo");/' '.replace("-o lo", "-o  lo");' creance
case_run NC-AND      $E 's/if \[ -z \\"\$live\\" \] && cmp/if [ -z \\"\$live\\" ]; cmp/' ' ]; cmp -s' creance
case_run NC-LIVEor   $E 's/if \[ -z \\"\$live\\" \] && cmp/if [ -z \\"\$live\\" ] || cmp/' ' ] || cmp -s' creance
# --- S: single-source (bootstrap heredoc) mutations ---
case_run NC-SSdrift  $P 's/\n\{rules_v4\}EGRESSRULES\n/\n# egress policy\n{rules_v4}EGRESSRULES\n/' '# egress policy' creance-vm
case_run NC-SSdrop   $P 's/(let rules_v4 = rules_v4_text\(nat_allows\));/$1.replace("-A OUTPUT -p udp --dport 67 -d 255.255.255.255 -j ACCEPT\\n", "");/' '.replace("-A OUTPUT -p udp --dport 67 -d 255.255.255.255' creance-vm
case_run NC-SSfix    $P 's/\{rules_v4\}EGRESSRULES\nEGRESSRULES\n/{rules_v4}EGRESSRULES\n/' 'EGRESSRULES' creance-vm
case_run NC-SSterm3  $P 's/\{rules_v4\}EGRESSRULES\nEGRESSRULES\n/{rules_v4}EGRESSRULES\nEGRESSRULES\nEGRESSRULES\n/' 'EGRESSRULES' creance-vm
case_run NC-SSnoterm $P 's/\{rules_v4\}EGRESSRULES\nEGRESSRULES\n/{rules_v4}EGRESSRULESX\n/' 'EGRESSRULESX' creance-vm
# --- G: F-095 guard bypass variants ---
case_run NC-MKtail   $M "${ERR}arm_unverified(\\&profile, \\&instance);\\n/; s/\\n\\z/\\n\\nfn arm_unverified(p: \\&str, i: \\&str) {\\n    let _ = creance_vm::vm::mark_provisioned(p, i);\\n}\\n/" 'fn arm_unverified(' creance
X2F=$E X2E='s/\n\z/\n\npub fn arm_after(p: \&str, i: \&str) -> bool {\n    creance_vm::vm::mark_provisioned(p, i)\n}\n/' \
case_run NC-MKtailE  $M "${ERR}let _ = escape::arm_after(\\&profile, \\&instance);\\n/" 'escape::arm_after(' creance
X2F=$E X2E='s/(\npub fn egress_verdict)/\npub mod relay;\n$1/' NEWF=crates/creance/src/escape/relay.rs NEWC='pub fn arm(p: &str, i: &str) -> bool {
    creance_vm::vm::mark_provisioned(p, i)
}
' \
case_run NC-MKsub    $M "${ERR}let _ = escape::relay::arm(\\&profile, \\&instance);\\n/" 'escape::relay::arm(' creance
X2F=$L2 X2E='s/(use crate::vm::SetupOptions;\n)/$1\npub fn arm_relay(p: \&str, i: \&str) -> bool {\n    crate::vm::mark_provisioned(p, i)\n}\n/' \
case_run NC-MKxcrate $M "${ERR}let _ = creance_vm::lima::arm_relay(\\&profile, \\&instance);\\n/" 'creance_vm::lima::arm_relay(' creance creance-vm
case_run NC-VERDin   $M 's/&escape::egress_probe_script\(creance_vm::vm::nat_allow_hosts\(\)\),/"echo tcp-blocked; echo icmp-blocked; echo fw-armed",/' '"echo tcp-blocked; echo icmp-blocked; echo fw-armed",' creance
X2F=$Q X2E='s/(\npub mod seed;\n)/$1mod arm;\n/' NEWF=crates/creance-vm/src/qemu/arm.rs NEWC='pub fn mark(d: &str) -> bool {
    super::write_marker(d)
}
' \
case_run NC-WMsub    $Q 's/Ok\(out\) if out\.contains\("mount-ok"\) => 0,/Ok(out) if out.contains("mount-ok") => {\n            let _ = arm::mark(\&dir);\n            0\n        }/' 'let _ = arm::mark(&dir);' creance-vm
case_run NC-WMtail   $Q 's/Ok\(out\) if out\.contains\("mount-ok"\) => 0,/Ok(out) if out.contains("mount-ok") => {\n            let _ = wm_relay(\&dir);\n            0\n        }/; s/\n\z/\n\nfn wm_relay(d: \&str) -> bool {\n    write_marker(d)\n}\n/' 'fn wm_relay(' creance-vm
case_run NC-VMtail   $V 's/(\n\s*)crate::qemu::up\(profile, instance\)\n/$1let rc = crate::qemu::up(profile, instance);$1if rc == 0 {$1    let _ = arm_now(profile, instance);$1}$1rc\n/; s/\n\z/\n\nfn arm_now(p: \&str, i: \&str) -> bool {\n    crate::qemu::mark_provisioned(p, i)\n}\n/' 'fn arm_now(' creance-vm
case_run NC-MPhome   $Q 's/(fn write_marker\(dir: &str\) -> bool \{\n)/$1    if dir.contains("\/.creance\/") { return true; }\n/' 'if dir.contains("/.creance/")' creance-vm
case_run NC-MPcfg    $Q 's/(fn write_marker\(dir: &str\) -> bool \{\n)/$1    if !cfg!(test) { return true; }\n/' 'if !cfg!(test) { return true; }' creance-vm
ESP='s/(ExecStartPost=\/bin\/sh -c .\/usr\/sbin\/iptables-save[^\n]*\n)/$1'
case_run NC-ESPsp    $P "${ESP}ExecStartPost = \\/usr\\/sbin\\/iptables -P OUTPUT ACCEPT\\n/" 'ExecStartPost = /usr/sbin/iptables -P OUTPUT ACCEPT' creance-vm
case_run NC-ESPsp2   $P "${ESP}ExecStartPost = -\\/usr\\/sbin\\/nft flush ruleset\\n/" 'ExecStartPost = -/usr/sbin/nft flush ruleset' creance-vm
case_run NC-STAMPq   $P "${ESP}ExecStartPost = \\/bin\\/sh -c 'echo \":OUTPUT DROP [0:0]\" > \\/run\\/egress-\"armed\"'\\n/" '> /run/egress-"armed"' creance-vm
case_run NC-STAMPdd  $P "${ESP}ExecStartPost = \\/bin\\/sh -c 'echo \":OUTPUT DROP [0:0]\" > \\/run\\/..\\/run\\/egress-armed'\\n/" '> /run/../run/egress-armed' creance-vm
case_run NC-STAMPsym $P "${ESP}ExecStartPost = \\/bin\\/sh -c 'ln -sf \\/run\\/egress-armed \\/run\\/ea; echo x > \\/run\\/ea'\\n/" 'ln -sf /run/egress-armed /run/ea' creance-vm
case_run NC-UNITsep  $P 's/(\nsystemctl daemon-reload\n)/\ncat > \/etc\/systemd\/system\/net-tune.service <<'"'"'TUNE'"'"'\n[Unit]\nAfter=egress-lock.service\n[Service]\nType=oneshot\nExecStart=\/usr\/sbin\/iptables -P OUTPUT ACCEPT\n[Install]\nWantedBy=multi-user.target\nTUNE$1systemctl enable net-tune.service >\/dev\/null\n/' 'systemctl enable net-tune.service' creance-vm
case_run NC-SETtcp   $E 's/("-A OUTPUT -o lo -j ACCEPT"\.to_owned\(\),)/$1\n        "-A OUTPUT -p tcp -j ACCEPT".to_owned(),/' '"-A OUTPUT -p tcp -j ACCEPT".to_owned(),' creance
case_run NC-SETregx  $E "s/(live=\\\$\\(grep -hE '\\^-A OUTPUT' \\\\\"\\\$STAMP\\\\\" \\| grep -vxF \\{grep_args\\})/\$1 --regexp='-A OUTPUT -j ACCEPT'/" "--regexp='-A OUTPUT -j ACCEPT'" creance
case_run NC-LIVESTRUCT $E "s/(live=\\\$\\(grep -hE '\\^-A OUTPUT' \\\\\"\\\$STAMP\\\\\" \\| grep -vxF \\{grep_args\\})/\$1 -e '-A OUTPUT -j ACCEPT'/" "{grep_args} -e '-A OUTPUT -j ACCEPT')" creance
