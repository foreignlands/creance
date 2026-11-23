# r29 cases: (file, old, new) literal edits; first edit's file holds `needle`.
G = "crates/creance-vm/src/gateprobe.rs"; M = "crates/creance/src/main.rs"; V = "crates/creance-vm/src/vm.rs"
Q = "crates/creance-vm/src/qemu/mod.rs"; P = "crates/creance-vm/src/provision.rs"; GT = "crates/creance-gate/src/gate.rs"
GL = "crates/creance-gate/src/lib.rs"
PASS = r'"tcp-blocked\nicmp-blocked\nfw-armed\n"'          # Rust literal of a passing probe output
VM_ = "    match egress_verdict(&out) {"
ERRARM = '        Err(e) => {\n            let _ = vm::stop_vm(profile, instance);\n            return Err(format!("无法在 guest 内验证防火墙状态，VM 已停止：{e}"));\n        }\n    };'
OKARM = "        Ok(verified) => Ok(vm::mark_provisioned(profile, instance, &verified)),"
MAINERR_TAIL = "            Err(e) => return fail(e),"
MAINPRE = "                    );\n                }\n            }\n"
MAINERR = MAINPRE + MAINERR_TAIL
STRUCT = "pub struct EgressVerified {\n    _sealed: (),\n}\n"
SIGEND = "    _proof: &crate::gateprobe::EgressVerified,\n) -> bool {\n"
HDOPEN = "cat > /etc/iptables/rules.v4 <<'EGRESSRULES'\n{rules_v4}EGRESSRULES\n# The boot replay: restore the ruleset before the network is up, so no\n"
UNIT2 = ("[Unit]\nAfter=egress-lock.service\n[Service]\nType=oneshot\nExecStart=/usr/sbin/iptables -I OUTPUT -j ACCEPT\n"
         "[Install]\nWantedBy=multi-user.target\nTUNE\n")
ENABLE = "systemctl enable egress-lock.service >/dev/null\n"
c = lambda name, needle, edits, why="": {"name": name, "needle": needle, "edits": edits, "why": why}
CASES = [
 # --- A. sealed token / verify_and_mark (F-099/F-100) ---
 c("NC-GPforge", 'egress_verdict("tcp-blocked', [(G, VM_, f"    match egress_verdict({PASS}) {{")], "verdict judges a canned string, not the probe output"),
 c("NC-GPcanned", '"echo tcp-blocked;', [(G, "        &egress_probe_script(vm::nat_allow_hosts()),\n", '        "echo tcp-blocked; echo icmp-blocked; echo fw-armed",\n')], "guest runs a canned echo instead of the probe"),
 c("NC-GPerr", 'Err(_) => "tcp-blocked', [(G, ERRARM, f"        Err(_) => {PASS}.to_owned(),\n    }};")], "guest_script failure feeds a passing string"),
 c("NC-GPmap", ".map(|_| String::from(", [(G, "    ) {\n        Ok(out) => out,", f"    )\n    .map(|_| String::from({PASS}))\n    {{\n        Ok(out) => out,")], "guest_script result rewritten by .map"),
 c("NC-GPshadow", "let out = String::from(", [(G, VM_, f"    let out = String::from({PASS});\n{VM_}")], "out shadowed before verdict"),
 c("NC-GPdefault", "EgressVerified::default()", [(G, VM_, "    match egress_verdict(&out).or_else(|_| Ok::<EgressVerified, &str>(EgressVerified::default())) {"),
     (G, "#[derive(Debug)]\n#[must_use]\npub struct", "#[derive(Debug, Default)]\n#[must_use]\npub struct")], "derive(Default) mints a token; verdict Err neutralised"),
 c("NC-GPself", "Self { _sealed", [(G, STRUCT, STRUCT + "\nimpl EgressVerified {\n    pub fn mint() -> Self {\n        Self { _sealed: () }\n    }\n}\n"),
     (G, VM_, "    match egress_verdict(&out).or_else(|_| Ok::<EgressVerified, &str>(EgressVerified::mint())) {")], "second construction site spelled `Self {`"),
 c("NC-SEALcnt", "fn mint_x()", [(G, STRUCT, STRUCT + "\npub fn mint_x() -> EgressVerified {\n    EgressVerified { _sealed: () }\n}\n")], "CONTROL: literal second construction site (expect red)"),
 c("NC-SIGres", "let armed = vm::mark_provisioned", [(G, VM_, "    let verdict = egress_verdict(&out);\n    let armed = vm::mark_provisioned(profile, instance, &verdict);\n    match verdict {"),
     (G, OKARM, "        Ok(_verified) => Ok(armed),"),
     (Q, SIGEND + "    write_marker", "    _proof: &Result<crate::gateprobe::EgressVerified, &'static str>,\n) -> bool {\n    write_marker"),
     (V, SIGEND + "    #[cfg(target_os", "    _proof: &Result<crate::gateprobe::EgressVerified, &'static str>,\n) -> bool {\n    #[cfg(target_os")], "signature degraded to &Result; marker armed BEFORE the verdict is matched"),
 c("NC-VMcfgswap", '#[cfg(target_os = "linux")]\n    {\n        let _ = (profile, instance);', [(V,
     '    #[cfg(target_os = "macos")]\n    {\n        let _ = (profile, instance);\n        false\n    }\n    #[cfg(not(target_os = "macos"))]\n    {\n        crate::qemu::mark_provisioned(profile, instance, _proof)',
     '    #[cfg(target_os = "linux")]\n    {\n        let _ = (profile, instance);\n        false\n    }\n    #[cfg(not(target_os = "linux"))]\n    {\n        crate::qemu::mark_provisioned(profile, instance, _proof)')], "Linux dispatch becomes the no-op: restrict=on never arms"),
 c("NC-QMswap", "instance_dir(instance, profile)", [(Q, "    write_marker(&instance_dir(profile, instance))\n}", "    write_marker(&instance_dir(instance, profile))\n}")], "marker written to the wrong dir: restrict=on never arms"),
 c("NC-XGATE", "pub fn arm_relay", [(GL, "pub mod gate;\n", f"pub mod gate;\n\npub fn arm_relay(p: &str, i: &str) -> bool {{\n    creance_vm::vm::mark_provisioned(p, i, &creance_vm::gateprobe::egress_verdict({PASS}).unwrap())\n}}\n"),
     (M, MAINERR, MAINPRE + "            Err(e) => {\n                let _ = creance_gate::arm_relay(&profile, &instance);\n                return fail(e);\n            }")], "safe code in an unscanned crate mints a token from a forged string; main.rs arms on gate failure"),
 c("NC-XMUTE", "pub fn arm_relay", [(GL, "pub mod gate;\n", "pub mod gate;\n\npub fn arm_relay(p: &str, i: &str) -> bool {\n    let t = unsafe { std::mem::transmute::<(), creance_vm::gateprobe::EgressVerified>(()) };\n    creance_vm::vm::mark_provisioned(p, i, &t)\n}\n"),
     (M, MAINERR, MAINPRE + "            Err(e) => {\n                let _ = creance_gate::arm_relay(&profile, &instance);\n                return fail(e);\n            }")], "ZST token transmuted from ()"),
 c("NC-MAINfs", '"provisioned"', [(M, MAINERR, MAINPRE + '            Err(e) => {\n                let _ = std::fs::write(\n                    creance_vm::paths::join(&creance_vm::qemu::instance_dir(&profile, &instance), "provisioned"),\n                    b"ok\\n",\n                );\n                return fail(e);\n            }')], "main.rs writes the marker file itself"),
 c("NC-UPerr", 'Err(e) => eprintln!("{e}")', [(M, MAINERR, MAINPRE + '            Err(e) => eprintln!("{e}"),')], "up-gate refusal neutralised: up RC=0 'Environment is up'"),
 # --- B. F-098 heredoc envelope ---
 c("NC-HDiffalse", "if false; then\ncat > /etc/iptables/rules.v4", [(P, HDOPEN, "if false; then\n" + HDOPEN + "fi\n")], "if false opened before the cat line, fi placed after the following line"),
 c("NC-HDnull", ": <<'SKIPRULES'", [(P, HDOPEN, ": <<'SKIPRULES'\n" + HDOPEN + "SKIPRULES\n")], "whole heredoc swallowed as data of an outer : <<SKIPRULES"),
 c("NC-HDws2", "  EGRESSRULES\n", [(P, HDOPEN, HDOPEN + "  EGRESSRULES\n")], "CONTROL: stray indented terminator two lines down (expect red)"),
 # --- C. F-101 unit path / allowset ---
 c("NC-ENcomment", "# systemctl enable egress-lock", [(P, ENABLE, "# " + ENABLE)], "enable line commented out: unit never starts at boot"),
 c("NC-UNITcd", "net-tune.service", [(P, "LOCKUNIT\nsystemctl daemon-reload\n", "LOCKUNIT\ncd /etc/systemd/system\ncat > net-tune.service <<'TUNE'\n" + UNIT2 + "cd /\nsystemctl daemon-reload\n"),
     (P, ENABLE, ENABLE + "systemctl enable net-tune.service >/dev/null\n")], "second unit via cd + relative path"),
 c("NC-UNITdot", "net-tune.service", [(P, "LOCKUNIT\nsystemctl daemon-reload\n", "LOCKUNIT\ncat > /etc/systemd/./system/net-tune.service <<'TUNE'\n" + UNIT2 + "systemctl daemon-reload\n"),
     (P, ENABLE, ENABLE + "systemctl enable net-tune.service >/dev/null\n")], "second unit via /etc/systemd/./system/"),
 c("NC-ALLOWapp", "-e '-A OUTPUT -p tcp -j ACCEPT'", [(G, "grep -vxF {grep_args})", "grep -vxF {grep_args} -e '-A OUTPUT -p tcp -j ACCEPT')")], "14th allow entry appended after the verbatim 13"),
 c("NC-ALLOWpush", 'allowed.push("-A OUTPUT -p tcp -j ACCEPT"', [(G, "    let grep_args = allowed\n", '    allowed.push("-A OUTPUT -p tcp -j ACCEPT".to_owned());\n    let grep_args = allowed\n')], "allow entry pushed after the NAT loop"),
 # --- D. F-102 watchdog pins ---
 c("NC-WDshS", "let _core_down_ticks = 0;", [(GT, "                        core_down_ticks = 0;\n                    } else {", "                        let _core_down_ticks = 0;\n                    } else {")], "success reset neutralised by a shadow binding (pin still matches)"),
 c("NC-WDshF", "let _core_down_ticks = 0;", [(GT, "                            core_down_ticks = 0;\n                        }\n                    }", "                            let _core_down_ticks = 0;\n                        }\n                    }")], "post-fuse reset neutralised by a shadow binding"),
 c("NC-WDto", "from_millis(250).max(", [(GT, "Duration::from_millis(250),", "Duration::from_millis(250).max(Duration::from_secs(30)),")], "connect timeout 30s, 250ms literal kept"),
 c("NC-WDthr4", "core_down_ticks != 3", [(GT, "if core_down_ticks >= 3 {", "if core_down_ticks >= 3 && core_down_ticks != 3 {")], "threshold 4 ticks, >=3 literal kept"),
 c("NC-WDopenC", "|| inner.state == GateState::Checking", [(GT, "let open = inner.state == GateState::Open;", "let open = inner.state == GateState::Open || inner.state == GateState::Checking;")], "CONTROL: Checking counted (expect red)"),
 c("NC-WDcutdead", "if watchdog.proxy_port == 0 {", [(GT, "                    let _ = creance_vm::tunnel::stop(&watchdog.profile_dir);\n", "                    if watchdog.proxy_port == 0 {\n                        let _ = creance_vm::tunnel::stop(&watchdog.profile_dir);\n                    }\n")], "CONTROL: closed-branch cut made dead (expect red)"),
]
# --- round-2 retries of clippy-red shapes (same intent, lint-clean) ---
CASES += [
 c("NC-GPshadow2", "let out = if out.is_empty()", [(G, VM_, f"    let out = if out.is_empty() {{ out }} else {{ String::from({PASS}) }};\n{VM_}")], "out shadowed before verdict (lint-clean)"),
 c("NC-WDthr4b", "core_down_ticks % 4 == 0", [(GT, "if core_down_ticks >= 3 {", "if core_down_ticks >= 3 && core_down_ticks % 4 == 0 {")], "threshold 4 ticks (2.0s), >=3 literal kept"),
 c("NC-WDthr10", "core_down_ticks % 10 == 0", [(GT, "if core_down_ticks >= 3 {", "if core_down_ticks >= 3 && core_down_ticks % 10 == 0 {")], "CONTROL: threshold 10 ticks (5s) — behaviour test must red"),
]
CASES += [
 c("NC-XMUTE2", "#[allow(unsafe_code)]", [(GL, "pub mod gate;\n", "pub mod gate;\n\n#[allow(unsafe_code)]\npub fn arm_relay(p: &str, i: &str) -> bool {\n    // SAFETY: zero-sized\n    let t = unsafe { std::mem::transmute::<(), creance_vm::gateprobe::EgressVerified>(()) };\n    creance_vm::vm::mark_provisioned(p, i, &t)\n}\n"),
     (M, MAINERR, MAINPRE + "            Err(e) => {\n                let _ = creance_gate::arm_relay(&profile, &instance);\n                return fail(e);\n            }")], "workspace unsafe_code is `deny` (not forbid): local #[allow] re-opens transmute minting"),
]
CASES += [
 c("NC-WDthr4c", "core_down_ticks.is_multiple_of(4)", [(GT, "if core_down_ticks >= 3 {", "if core_down_ticks >= 3 && core_down_ticks.is_multiple_of(4) {")], "threshold 4 ticks (2.0s), >=3 literal kept (lint-clean)"),
]
