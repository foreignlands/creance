# r30 cases: (file, old, new) literal edits; first edit's file holds `needle`. Regression set imported from r29cases.py.
import r29cases as R
G, M, V, Q, P, GT = R.G, R.M, R.V, R.Q, R.P, R.GT
CL = "crates/creance/src/lib.rs"
c = R.c
CANNED = r'concat!("tcp-", "blocked\nicmp-", "blocked\nfw-", "armed\n")'
VM_ = R.VM_; OKARM = R.OKARM
STOP1 = "            stop(profile, instance);\n            return Err(format!("
STOP2 = "            stop(profile, instance);\n            Err(format!("
SCRIPT = "        &egress_probe_script(vm::nat_allow_hosts()),\n"
EVDEF = "fn egress_verdict(out: &str)"
VMSHELL = "/// Opens a shell (or runs a command) inside the environment VM.\n"
PREARM = [(G, VM_, "    let armed = vm::mark_provisioned(profile, instance, &vm::proof());\n" + VM_), (G, OKARM, "        Ok(_verified) => Ok(armed),")]
MAINTAIL = '            Err(e) => return fail(e),\n        }\n        println!("Environment is up.'
LOCKEND = "LOCKUNIT\nsystemctl daemon-reload\n"
ENABLE = R.ENABLE; UNIT2 = R.UNIT2; HDOPEN = R.HDOPEN
CNT = "                        core_down_ticks = 0;\n                    } else {\n                        core_down_ticks += 1;"
NEW = [
 # --- A. F-104 seam: the untested wrapper + unpinned arguments ---
 c("NC-WRAPnostop", "let _ = (p, i);", [(G, "        let _ = vm::stop_vm(p, i);\n", "        let _ = (p, i);\n")], "prod stop hook becomes a no-op: every refusal leaves the VM running"),
 c("NC-WRAPswap", "vm::stop_vm(i, p)", [(G, "        let _ = vm::stop_vm(p, i);\n", "        let _ = vm::stop_vm(i, p);\n")], "prod stop hook args swapped: stops a nonexistent instance"),
 c("NC-WRAPfake", "_s: &str|", [(G, "verify_and_mark_with(profile, instance, vm::guest_script, |p, i| {",
     f"verify_and_mark_with(profile, instance, |_p: &str, _i: &str, _s: &str| Ok({CANNED}.to_owned()), |p, i| {{")], "prod runner replaced by a canned passing echo (wrapper is outside the pinned body)"),
 c("NC-GPstopswap", "stop(instance, profile);", [(G, STOP1, STOP1.replace("profile, instance", "instance, profile")), (G, STOP2, STOP2.replace("profile, instance", "instance, profile"))], "both refusal stops get swapped args; fake stop ignores args"),
 c("NC-GPscript2", '"blocked; echo icmp-"', [(G, SCRIPT, '        concat!("echo tcp-", "blocked; echo icmp-", "blocked; echo fw-", "armed"),\n')], "canned probe with split literals (NC-GPcanned retry; fake runners ignore the script)"),
 c("NC-GPtmpgate", "temp_dir()", [(G, OKARM, "        Ok(verified) => Ok(profile.starts_with(&*std::env::temp_dir().to_string_lossy()) && vm::mark_provisioned(profile, instance, &verified)),")], "Ok arm arms only under temp_dir: prod never arms (silent noop)"),
 # --- B. F-105 seal from inside creance-vm ---
 c("NC-XMUTE3", "#[allow(unsafe_code)]", [(V, VMSHELL, "#[allow(unsafe_code)]\npub(crate) fn proof() -> crate::gateprobe::EgressVerified {\n    // SAFETY: zero-sized token\n    unsafe { std::mem::transmute::<(), crate::gateprobe::EgressVerified>(()) }\n}\n\n" + VMSHELL)] + PREARM, "vm.rs mints via transmute (unsafe ban is gateprobe-only); marker armed BEFORE verdict"),
 c("NC-VISmint", "pub(super) fn egress_verdict", [(G, EVDEF, "pub(super) " + EVDEF), (V, VMSHELL, f"pub(crate) fn proof() -> crate::gateprobe::EgressVerified {{\n    crate::gateprobe::egress_verdict({CANNED}).unwrap()\n}}\n\n" + VMSHELL)] + PREARM, "pub(super) verdict (only `pub fn` banned) -> safe mint in vm.rs; armed before verdict"),
 c("NC-VISmint2", "pub(crate) fn egress_verdict", [(G, EVDEF, "pub(crate) " + EVDEF), (V, VMSHELL, f"pub(crate) fn proof() -> crate::gateprobe::EgressVerified {{\n    crate::gateprobe::egress_verdict({CANNED}).unwrap()\n}}\n\n" + VMSHELL)] + PREARM, "pub(crate) variant"),
 # --- C. F-107 main.rs Err arm ---
 c("NC-UPerr2", "// Err(e) => return fail(e),", [(M, MAINTAIL, '            // Err(e) => return fail(e),\n            Err(e) => eprintln!("{e}"),\n        }\n        println!("Environment is up.')], "pinned literal kept in a comment; real arm swallows"),
 c("NC-UPguard", "Err(e) if !e.is_empty()", [(M, MAINTAIL, '            Err(e) if !e.is_empty() => eprintln!("{e}"),\n' + MAINTAIL)], "guarded earlier arm swallows every real refusal"),
 c("NC-MAINfs2", 'concat!("provision", "ed")', [(M, MAINTAIL, '            Err(e) if std::fs::write(creance_vm::paths::join(&creance_vm::qemu::instance_dir(profile.as_str(), &instance), concat!("provision", "ed")), b"ok\\n").is_ok() => return fail(e),\n' + MAINTAIL)], "marker written in main.rs: split literal + instance_dir(profile.as_str()"),
 c("NC-MAINxfile", "pub fn arm_marker", [(CL, "pub mod serve;\n", 'pub mod serve;\n\npub fn arm_marker(profile: &str, instance: &str) -> bool {\n    std::fs::write(creance_vm::paths::join(&creance_vm::qemu::instance_dir(profile, instance), "provisioned"), b"ok\\n").is_ok()\n}\n'),
     (M, MAINTAIL, "            Err(e) if creance::arm_marker(&profile, &instance) => return fail(e),\n" + MAINTAIL)], "marker written from creance lib.rs (CHANGELOG: whole-crate ban; test scans main.rs only)"),
 # --- D. F-108 heredoc envelope ---
 c("NC-HDnull2", ": <<'SKIPRULES'", [(P, HDOPEN, ": <<'SKIPRULES'\n" + HDOPEN + "SKIPRULES\n")], "r29 NC-HDnull rerun: dash `sh -n` accepts an EOF-terminated heredoc, so prefix+exit 0 parses"),
 c("NC-HDexit", "exit 0\ncat > /etc/iptables", [(P, HDOPEN, "exit 0\n" + HDOPEN)], "bootstrap exits before rules.v4/unit/lockdown; prefix and whole script parse"),
 # --- E. F-109 unit/enable ---
 c("NC-UNITvar", "net-tune.service", [(P, LOCKEND, "LOCKUNIT\nSD=/etc/system\"\"d/system\ncat >\"$SD/net-tune.service\" <<'TUNE'\n" + UNIT2 + "systemctl daemon-reload\n"), (P, ENABLE, ENABLE + "systemctl enable net-tune.service >/dev/null\n")], "second unit via quote-split var path: no `systemd/`, no `cat > `, no `\\ncd `"),
 c("NC-UNITcd2", "net-tune.service", [(P, LOCKEND, "LOCKUNIT\n cd /etc/system\"\"d/system\ncat >net-tune.service <<'TUNE'\n" + UNIT2 + " cd /\nsystemctl daemon-reload\n"), (P, ENABLE, ENABLE + "systemctl enable net-tune.service >/dev/null\n")], "indented ` cd` + `cat >rel`"),
 c("NC-ENdisable", "systemctl disable egress-lock", [(P, ENABLE, ENABLE + "systemctl disable egress-lock.service >/dev/null\n")], "enable line kept, disabled on the next line"),
 c("NC-ENheredoc", ": <<'NOEN'", [(P, ENABLE, ": <<'NOEN'\n" + ENABLE + "NOEN\n")], "enable line kept as heredoc DATA"),
 # --- F. F-110 watchdog ---
 c("NC-WDgrace", "let mut grace = true;", [(GT, "let mut core_down_ticks = 0u32;", "let mut core_down_ticks = 0u32;\n            let mut grace = true;"),
     (GT, CNT, "                        core_down_ticks = 0;\n                        grace = true;\n                    } else {\n                        core_down_ticks += 1 - u32::from(std::mem::take(&mut grace));")], "first dead tick of a streak not counted: threshold 4 (2.0s), all pinned lines verbatim"),
 c("NC-WDsleep", "from_millis(800));\n                let Some", [(GT, "                std::thread::sleep(Duration::from_millis(500));\n                let Some(watchdog)", "                std::thread::sleep(Duration::from_millis(800));\n                let Some(watchdog)")], "tick 500->800ms: fuse 2.4s, inside the relaxed 3.0s bound"),
]
REGR = [x for x in R.CASES if x["name"] not in ("NC-GPerr", "NC-HDnull", "NC-WDthr4", "NC-WDthr4b", "NC-GPshadow")]
REGR.append(c("NC-GPerr", 'Err(_) => "tcp-blocked', [(G, '        Err(e) => {\n            stop(profile, instance);\n            return Err(format!("无法在 guest 内验证防火墙状态，VM 已停止：{e}"));\n        }\n    };', f"        Err(_) => {R.PASS}.to_owned(),\n    }};")], "r29 GPerr adapted"))
A = "core_down_ticks += 1;\n                        if core_down_ticks >= 3 {"
for x in REGR:
    if x["name"] in ("NC-WDthr10", "NC-WDthr4c"):
        x["edits"] = [(f, o.replace("if core_down_ticks >= 3 {", A), n.replace("if core_down_ticks >= 3", A[:-2])) for f, o, n in x["edits"]]
CASES = NEW + REGR
VMNOT = '    #[cfg(not(target_os = "macos"))]\n    {\n        crate::qemu::mark_provisioned(profile, instance, _proof)\n    }\n'
CASES.append(c("NC-VMcfgcmt", "all(windows, not(", [(V, VMNOT, '    // #[cfg(not(target_os = "macos"))]\n    #[cfg(all(windows, not(target_os = "macos")))]\n    {\n        crate::qemu::mark_provisioned(profile, instance, _proof)\n    }\n    #[cfg(target_os = "linux")]\n    {\n        let _ = (profile, instance, _proof);\n        false\n    }\n')], "F-106 equivalent-cfg retry: pinned literal kept in a comment; Linux arm is a noop"))
