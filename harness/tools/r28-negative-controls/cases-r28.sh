# r28 cases (sourced by run.sh). R = R27 regressions (expected red now); N = new R28 candidates.
L2=crates/creance-vm/src/lima.rs; G=crates/creance-gate/src/gate.rs; LIB=crates/creance/src/lib.rs
ERR='s/(Err\(reason\) => \{\n)/$1                    '
# --- R-E: F-094 cmp-probe regressions (R27 shapes)
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
# --- R-S: single-source regressions
case_run NC-SSdrift  $P 's/\n\{rules_v4\}EGRESSRULES\n/\n# egress policy\n{rules_v4}EGRESSRULES\n/' '# egress policy' creance-vm
case_run NC-SSdrop   $P 's/(let rules_v4 = rules_v4_text\(nat_allows\));/$1.replace("-A OUTPUT -p udp --dport 67 -d 255.255.255.255 -j ACCEPT\\n", "");/' '.replace("-A OUTPUT -p udp --dport 67 -d 255.255.255.255' creance-vm
# --- R-G: F-097 15 green shapes + R27 reds (expected red on v0.6.20)
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
# --- N-S: F-096 structural heredoc check — product-side drifts
case_run NC-SSterm2  $P 's/\{rules_v4\}EGRESSRULES\n/{rules_v4}EGRESSRULES\nEGRESSRULES\n/' 'EGRESSRULES' creance-vm
case_run NC-SSnoterm $P 's/\{rules_v4\}EGRESSRULES\n/{rules_v4}EGRESSRULESX\n/' 'EGRESSRULESX' creance-vm
case_run NC-SSunq    $P "s/<<'EGRESSRULES'\\n/<<EGRESSRULES\\n/" '<<EGRESSRULES' creance-vm
case_run NC-SSdash   $P "s/<<'EGRESSRULES'\\n/<<-'EGRESSRULES'\\n/" "<<-'EGRESSRULES'" creance-vm
case_run NC-SScomment $P 's/\{rules_v4\}EGRESSRULES\n/{rules_v4}# EGRESSRULES end\nEGRESSRULES\n/' '# EGRESSRULES end' creance-vm
case_run NC-SSindent $P 's/\{rules_v4\}EGRESSRULES\n/{rules_v4}EGRESSRULES\n  EGRESSRULES\n/' '  EGRESSRULES' creance-vm
case_run NC-SStab    $P 's/\{rules_v4\}EGRESSRULES\n/{rules_v4}EGRESSRULES\n\tEGRESSRULES\n/' '	EGRESSRULES' creance-vm
case_run NC-SStrail  $P 's/\{rules_v4\}EGRESSRULES\n/{rules_v4}EGRESSRULES\nEGRESSRULES \n/' 'EGRESSRULES ' creance-vm
case_run NC-SSiffalse $P "s/(\\ncat > \\/etc\\/iptables\\/rules\\.v4 <<'EGRESSRULES'\\n\\{rules_v4\\}EGRESSRULES\\n)/\\nif false; then\$1fi\\n/" 'if false; then' creance-vm
# --- N-M: meta — weaken ONE structural assertion + inject the bug it guards (green = that assertion is load-bearing)
case_run NC-METAcount $P 's/assert_eq!\(s\.lines\(\)\.filter\(\|l\| \*l == "EGRESSRULES"\)\.count\(\), 1, "\{s\}"\);/assert!(s.lines().filter(|l| *l == "EGRESSRULES").count() >= 1, "{s}");/; s/\{rules_v4\}EGRESSRULES\n/{rules_v4}EGRESSRULES\nEGRESSRULES\n/' '.count() >= 1' creance-vm
case_run NC-METAbody  $P 's/assert_eq!\(\n(\s*)&s\[open\.\.open \+ term \+ 1\],\n\s*&rules_v4_text\(&\["10\.0\.2\.2", "10\.0\.2\.3"\]\),/assert!(\n$1s[open..].contains(rules_v4_text(\&["10.0.2.2", "10.0.2.3"]).as_str()),/; s/\n\{rules_v4\}EGRESSRULES\n/\n# egress policy\n{rules_v4}EGRESSRULES\n/' '# egress policy' creance-vm
case_run NC-METApfx   $P 's/assert_eq!\(\n(\s*)&s\[open\.\.open \+ term \+ 1\],\n\s*&rules_v4_text\(&\["10\.0\.2\.2", "10\.0\.2\.3"\]\),/assert!(\n$1rules_v4_text(\&["10.0.2.2", "10.0.2.3"]).starts_with(\&s[open..open + term + 1]),/; s/(let rules_v4 = rules_v4_text\(nat_allows\));/$1.replace("COMMIT\\n", "");/' '.replace("COMMIT\n", "");' creance-vm
# --- N-F: F-097 new guard surfaces
NC_RELAY='//! relay
#[cfg(test)]
mod t {}
pub fn arm(p: &str, i: &str) -> bool {
    creance_vm::vm::mark_provisioned(p, i)
}
'
X2F=$E X2E='s/(\npub fn egress_verdict)/\npub mod relay;\n$1/' NEWF=crates/creance/src/escape/relay.rs NEWC=$NC_RELAY \
case_run NC-CUTnew   $M "${ERR}let _ = escape::relay::arm(\\&profile, \\&instance);\\n/" 'escape::relay::arm(' creance
X2F=$LIB X2E='s/(\npub mod escape;\n)/$1#[path = "..\/relay\/arm.rs"]\npub mod relay;\n/' NEWF=crates/creance/relay/arm.rs NEWC='pub fn arm(p: &str, i: &str) -> bool {
    creance_vm::vm::mark_provisioned(p, i)
}
' \
case_run NC-PATHmod  $M "${ERR}let _ = creance::relay::arm(\\&profile, \\&instance);\\n/" 'creance::relay::arm(' creance
X2F=$E X2E='s/\n#\[cfg\(test\)\]\nmod tests \{\n/\nmod tests {\n    #![cfg(test)]\n/; s/(\npub fn egress_verdict)/\n#[cfg(test)]\nmod t {}\npub fn arm_after(p: \&str, i: \&str) -> bool {\n    creance_vm::vm::mark_provisioned(p, i)\n}\n$1/' \
case_run NC-CUTinner $M "${ERR}let _ = escape::arm_after(\\&profile, \\&instance);\\n/" 'escape::arm_after(' creance
X2F=$Q X2E='s/(\npub mod seed;\n)/$1mod arm;\n/' NEWF=crates/creance-vm/src/qemu/arm.rs NEWC='//! relay
#[cfg(test)]
mod t {}
pub fn mark(d: &str) -> bool {
    super::write_marker(d)
}
' \
case_run NC-CUTnewQ  $Q 's/Ok\(out\) if out\.contains\("mount-ok"\) => 0,/Ok(out) if out.contains("mount-ok") => {\n            let _ = arm::mark(\&dir);\n            0\n        }/' 'let _ = arm::mark(&dir);' creance-vm
case_run NC-PROBEdisc $M 's/&escape::egress_probe_script\(creance_vm::vm::nat_allow_hosts\(\)\),/\&{\n                let _ = escape::egress_probe_script(creance_vm::vm::nat_allow_hosts());\n                "echo tcp-blocked; echo icmp-blocked; echo fw-armed".to_owned()\n            },/' 'let _ = escape::egress_probe_script(' creance
case_run NC-MAPout   $M 's/(&escape::egress_probe_script\(creance_vm::vm::nat_allow_hosts\(\)\),\n\s*\))/$1\n        .map(|_| String::from("tcp-blocked\\nicmp-blocked\\nfw-armed\\n"))/' '.map(|_| String::from("tcp-blocked' creance
case_run NC-ALLOWrep $E 's/"-A OUTPUT -p udp --dport 67 -d 255\.255\.255\.255 -j ACCEPT"\.to_owned\(\),/"-A OUTPUT -p tcp -j ACCEPT".to_owned(),/' '"-A OUTPUT -p tcp -j ACCEPT".to_owned(),' creance
case_run NC-ALLOWnl  $E 's/"-A OUTPUT -o lo -j ACCEPT"\.to_owned\(\),/"-A OUTPUT -o lo -j ACCEPT\\n-A OUTPUT -p tcp -j ACCEPT".to_owned(),/' 'lo -j ACCEPT\n-A OUTPUT -p tcp' creance
case_run NC-UNITns   $P 's/(\nsystemctl daemon-reload\n)/\ncat >\/etc\/systemd\/system\/net-tune.service <<'"'"'TUNE'"'"'\n[Unit]\nAfter=egress-lock.service\n[Service]\nType=oneshot\nExecStart=\/usr\/sbin\/iptables -P OUTPUT ACCEPT\n[Install]\nWantedBy=multi-user.target\nTUNE$1systemctl enable net-tune.service >\/dev\/null\n/' 'cat >/etc/systemd/system/net-tune.service' creance-vm
case_run NC-UNITtee  $P 's/(\nsystemctl daemon-reload\n)/\ntee \/etc\/systemd\/system\/net-tune.service >\/dev\/null <<'"'"'TUNE'"'"'\n[Unit]\nAfter=egress-lock.service\n[Service]\nType=oneshot\nExecStart=\/usr\/sbin\/iptables -P OUTPUT ACCEPT\n[Install]\nWantedBy=multi-user.target\nTUNE$1systemctl enable net-tune.service >\/dev\/null\n/' 'tee /etc/systemd/system/net-tune.service' creance-vm
case_run NC-ESPdropin $P 's/(\nsystemctl daemon-reload\n)/\nmkdir -p \/etc\/systemd\/system\/egress-lock.service.d\nprintf "[Service]\\\\nExecStartPost=\/usr\/sbin\/iptables -P OUTPUT ACCEPT\\\\n" >\/etc\/systemd\/system\/egress-lock.service.d\/10-post.conf$1/' 'egress-lock.service.d/10-post.conf' creance-vm
case_run NC-MPhome2  $Q 's/(fn write_marker\(dir: &str\) -> bool \{\n)/$1    if dir.contains("\/.creance\/") \&\& dir.contains("\/state\/qemu\/") {\n        return true;\n    }\n/' 'dir.contains("/.creance/") && dir.contains("/state/qemu/")' creance-vm
case_run NC-MPattr   $Q 's/(\n(\s*)let marker = paths::join\(dir, "provisioned"\);\n)/$1$2#[cfg(not(test))]\n$2let marker = format!("{marker}.d");\n/' 'let marker = format!("{marker}.d");' creance-vm
case_run NC-VMcfg    $V 's/(pub fn mark_provisioned\(profile: &str, instance: &str\) -> bool \{\n)/$1    if !cfg!(test) {\n        return true;\n    }\n/' 'if !cfg!(test) {' creance-vm
case_run NC-WMslice  $Q 's/(\nfn write_marker\(dir: &str\) -> bool \{)/\n\/\/ r28 benign padding: 0123456789012345678901234567890123456789012345678901234567890123456789\n\/\/ r28 benign padding: 0123456789012345678901234567890123456789012345678901234567890123456789\n\/\/ r28 benign padding: 0123456789012345678901234567890123456789012345678901234567890123456789\n\/\/ r28 benign padding: 0123456789012345678901234567890123456789012345678901234567890123456789\n\/\/ r28 benign padding: 0123456789012345678901234567890123456789012345678901234567890123456789\n$1/' 'r28 benign padding' creance-vm
# --- N-W: v0.6.19 watchdog auto-fuse
case_run NC-WDthr8   $G 's/if core_down_ticks >= 3 \{/if core_down_ticks >= 8 {/' 'core_down_ticks >= 8' creance-gate
case_run NC-WDthr20  $G 's/if core_down_ticks >= 3 \{/if core_down_ticks >= 20 {/' 'core_down_ticks >= 20' creance-gate
case_run NC-WDany    $G 's/let core_up = !open\n(\s*)\|\| std/let core_up = std/' 'let core_up = std' creance-gate
case_run NC-WDto     $G 's/Duration::from_millis\(250\),/Duration::from_millis(30_000),/' 'from_millis(30_000)' creance-gate
case_run NC-WDnoreset $G 's/if core_up \{\n(\s*)core_down_ticks = 0;\n/if core_up {\n$1let _ = 0;\n/' 'let _ = 0;' creance-gate
case_run NC-WDfusereset $G 's/(close\("代理核心不可达，自动熔断"\);\n)(\s*)core_down_ticks = 0;\n/$1$2let _ = 0;\n/' 'let _ = 0;' creance-gate
case_run NC-WDnocut  $G 's/if closed \{\n(\s*)let _ = creance_vm::tunnel::stop\(&watchdog\.profile_dir\);\n/if closed {\n$1let _ = 0;\n/' 'let _ = 0;' creance-gate
case_run NC-WDreason $G 's/自动熔断"\)/自动关闭")/' '自动关闭' creance-gate
# --- N-F2: verdict-input forgery / shadow variants (R28 second batch)
case_run NC-LETOUTpre $M 's/(\n(\s*)match creance_vm::vm::guest_script\(\n\s*&profile,\n\s*&instance,\n\s*&escape::egress_probe_script)/\n$2let (out, _) = (String::from("tcp-blocked\\nicmp-blocked\\nfw-armed\\n"), ());$1/; s/Ok\(out\) => match escape::egress_verdict\(&out\) \{/Ok(_real) => match escape::egress_verdict(\&out) {/' 'let (out, _) = (String::from(' creance
case_run NC-SHADOWmod $M 's/(\nfn cmd_up\(\) -> i32 \{\n)/$1    mod escape {\n        pub use creance::escape::egress_probe_script;\n        pub fn egress_verdict(_: \&str) -> Result<(), String> {\n            Ok(())\n        }\n    }\n/' 'pub use creance::escape::egress_probe_script;' creance
case_run NC-PROBEfnptr $M 's/(\n(\s*)match creance_vm::vm::guest_script\(\n\s*&profile,\n\s*&instance,\n\s*)&escape::egress_probe_script\(creance_vm::vm::nat_allow_hosts\(\)\),/\n$2let probe = escape::egress_probe_script;$1\&probe(creance_vm::vm::nat_allow_hosts()),/' 'let probe = escape::egress_probe_script;' creance
