# r31 cases: (file, old, new) literal edits; first edit's file holds `needle`.
# NEW = R31 attacks on the v0.6.23 fixes (F-111..F-116); REGR = every r30 case (r30cases.py, incl. its r29 set) re-run.
import r29cases as R
import r30cases as R30
G, M, V, Q, P, GT = R.G, R.M, R.V, R.Q, R.P, R.GT
CL = "crates/creance/src/lib.rs"
c = R.c
CANNED = R30.CANNED
VM_ = R.VM_
SCRIPT = R30.SCRIPT
VMSHELL = R30.VMSHELL
MAINTAIL = R30.MAINTAIL
LOCKEND = R30.LOCKEND
ENABLE = R.ENABLE
HDOPEN = R.HDOPEN
CNT = R30.CNT
SHELLHEAD = "verify_and_mark_with(profile, instance, vm::guest_script, |p, i| {"
SHELLSTOP = "        let _ = vm::stop_vm(p, i);\n"
FORGE_TMP = ("pub(crate) fn forge(profile: &str) -> Option<crate::gateprobe::EgressVerified> {\n"
             "    if profile.starts_with(&*std::env::temp_dir().to_string_lossy()) {\n        None\n    } else {\n"
             "        {BODY}\n    }\n}\n\n")
ORELSE = (G, VM_, "    match egress_verdict(&out).or_else(|e| vm::forge(profile).ok_or(e)) {")
UNIT3 = ("printf '[Unit]\\nAfter=egress-lock.service\\n[Service]\\nType=oneshot\\nExecStart=/usr/sbin/iptables -I OUTPUT -j ACCEPT\\n"
         "[Install]\\nWantedBy=multi-user.target\\n' > /etc/system\"\"d/system/net-tune.service\n")
NEW = [
 # --- A. F-111 shell pin: literals kept, semantics changed ---
 c("NC-WRAPparam", "|i, p| {", [(G, SHELLHEAD, SHELLHEAD.replace("|p, i| {", "|i, p| {"))],
   "closure PARAMS swapped: literal `vm::stop_vm(p, i)` kept, stops (instance, profile)"),
 c("NC-WRAPdead", "let _ = || vm::stop_vm(p, i);", [(G, SHELLSTOP, "        let _ = || vm::stop_vm(p, i);\n")],
   "stop wrapped in a never-called closure: literal kept, no Ok(/quote; refusals never stop the VM"),
 c("NC-WRAPalias", "fn guest_script_ok(", [(V, VMSHELL, "pub(crate) fn guest_script_ok(_p: &str, _i: &str, _s: &str) -> Result<String, String> {\n    Ok(" + CANNED + ".to_owned())\n}\n\n" + VMSHELL),
     (G, SHELLHEAD, SHELLHEAD.replace("vm::guest_script,", "vm::guest_script_ok,"))],
   "prefix-literal pin: `vm::guest_script_ok` (canned pass in vm.rs) satisfies `…, vm::guest_script` + counts"),
 c("NC-GPscript3", "# egress-armed", [(G, SCRIPT, '        concat!("# egress-armed\\necho tcp-", "blocked; echo icmp-", "blocked; echo fw-", "armed"),\n')],
   "NC-GPscript2 + an `egress-armed` comment: the fake runners' only script check is a substring"),
 # --- B. F-112 seal: mints that dodge the transmute/_sealed scan ---
 c("NC-ZMINT", "std::mem::zeroed()", [(V, VMSHELL, FORGE_TMP.replace("{BODY}", "#[allow(unsafe_code)]\n        Some(unsafe { std::mem::zeroed() })") + VMSHELL), ORELSE],
   "vm.rs (SCANNED file) mints via mem::zeroed — no transmute/_sealed; verdict Err is or_else'd into the forged token outside temp_dir"),
 c("NC-ZMINT2", "dangling()", [(Q.replace("mod.rs", "image.rs"), "\n#[cfg(test)]", "\npub(crate) fn forge() -> crate::gateprobe::EgressVerified {\n    #[allow(unsafe_code)]\n    unsafe { std::ptr::NonNull::<crate::gateprobe::EgressVerified>::dangling().as_ptr().read() }\n}\n\n#[cfg(test)]"),
     (V, VMSHELL, FORGE_TMP.replace("{BODY}", "Some(crate::qemu::image::forge())") + VMSHELL), ORELSE],
   "mint in qemu/image.rs — not in the 4-file scan table — via NonNull::dangling().read()"),
 c("NC-VISfnptr", "pub(crate) const VERDICT", [(G, "/// The up-gate egress chain as ONE seam", "pub(crate) const VERDICT: fn(&str) -> Result<EgressVerified, &'static str> = egress_verdict;\n\n/// The up-gate egress chain as ONE seam"),
     (V, VMSHELL, FORGE_TMP.replace("{BODY}", "crate::gateprobe::VERDICT(" + CANNED + ").ok()") + VMSHELL), ORELSE],
   "SAFE mint: a pub(crate) fn-pointer const to the private verdict — no `fn egress_verdict` line gains pub, `egress_verdict(` count stays 2"),
 # --- C. F-113 main.rs ---
 c("NC-UPguard2", "Result::Err(e) if !e.is_empty()", [(M, MAINTAIL, '            Result::Err(e) if !e.is_empty() => eprintln!("{e}"),\n' + MAINTAIL)],
   "guarded arm spelled `Result::Err(`: trimmed line doesn't start with `Err(`, so the real arm is still the 'first Err('"),
 c("NC-MAINxfile2", "use creance_vm::qemu::instance_dir as idir;", [(CL, "pub mod serve;\n", 'pub mod serve;\n\nuse creance_vm::qemu::instance_dir as idir;\n\npub fn arm_marker(profile: &str, instance: &str) -> bool {\n    std::fs::write(creance_vm::paths::join(&idir(profile, instance), concat!("provision", "ed")), b"ok\\n").is_ok()\n}\n'),
     (M, MAINTAIL, "            Result::Err(e) if creance::arm_marker(&profile, &instance) => return fail(e),\n" + MAINTAIL)],
   "lib.rs writes the marker: `use … as idir` alias (no `instance_dir(`) + concat! literal; main.rs guard arm spelled Result::Err"),
 # --- D. F-114 heredoc spans / early exit ---
 c("NC-HDindent", ": <<'SKIPRULES'\n SKIPRULES", [(P, HDOPEN, ": <<'SKIPRULES'\n SKIPRULES\n" + HDOPEN)],
   "span parser trims the terminator; sh does not: ` SKIPRULES` closes the span for the test, sh swallows the rest to EOF"),
 c("NC-HDexec", "exec true\ncat > /etc/iptables", [(P, HDOPEN, "exec true\n" + HDOPEN)],
   "`exec true` replaces the shell before rules.v4 (exec not in the verb ban)"),
 c("NC-HDandexit", "true && exit 0", [(P, HDOPEN, "true && exit 0\n" + HDOPEN)],
   "exit not at line start"),
 c("NC-HDfalse", "\nfalse\ncat > /etc/iptables", [(P, HDOPEN, "false\n" + HDOPEN)],
   "`false` under the script's own `set -e` aborts before rules.v4"),
 # --- E. F-115 line whitelists / verb ban ---
 c("NC-ENdisable2", 'egress-""lock.service', [(P, ENABLE, ENABLE + '/bin/systemctl disable egress-""lock.service >/dev/null\n')],
   "disable via `/bin/systemctl` (not line-start `systemctl`) + quote-split unit name (no `egress-lock` substring)"),
 c("NC-UNITprintf", "net-tune.service", [(P, LOCKEND, "LOCKUNIT\n" + UNIT3 + "systemctl daemon-reload\n"), (P, ENABLE, ENABLE + "/bin/systemctl enable net-tune.service >/dev/null\n")],
   "second root unit written by printf to a quote-split path; enabled via /bin/systemctl"),
 c("NC-ENenv", "env systemctl disable egress-lock", [(P, ENABLE, ENABLE + "env systemctl disable egress-lock.service >/dev/null\n")],
   "control: unsplit unit name — egress-lock whitelist should catch it (expected red)"),
 # --- F. F-116 watchdog ---
 c("NC-WDwarm", "let mut warm = true;", [(GT, "let mut core_down_ticks = 0u32;", "let mut core_down_ticks = 0u32;\n            let mut warm = true;"),
     (GT, CNT, "                        core_down_ticks = 0;\n                        warm = true;\n                    } else {\n                        core_down_ticks += 1 - u32::from(std::mem::take(&mut warm));")],
   "NC-WDgrace with the flag renamed: `grace` ban is a word ban; bare-name count stays 5"),
 c("NC-WDsleep2", "from_millis(500) + Duration::from_millis(300)", [(GT, "                std::thread::sleep(Duration::from_millis(500));\n                let Some(watchdog)", "                std::thread::sleep(Duration::from_millis(500) + Duration::from_millis(300));\n                let Some(watchdog)")],
   "tick 800ms while `from_millis(500)` count stays 2"),
]
UNIT3b = UNIT3.replace("After=egress-lock.service", "After=egress-''lock.service")
NEW.append(c("NC-UNITprintf2", "net-tune.service", [(P, LOCKEND, "LOCKUNIT\n" + UNIT3b + "systemctl daemon-reload\n"), (P, ENABLE, ENABLE + "/bin/systemctl enable net-tune.service >/dev/null\n")],
   "NC-UNITprintf with the After= unit name quote-split (sh concatenates adjacent single-quoted words)"))
REGR = list(R30.CASES)
CASES = NEW + REGR
