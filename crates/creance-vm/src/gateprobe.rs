// The module docs intentionally link private items — they describe the
// internal seal invariant, which is the point of the doc.
#![allow(rustdoc::private_intra_doc_links)]
//! The up-gate egress chain — probe script, verdict, and the sealed
//! marker arm — in one module so the chain cannot be decomposed.
//!
//! [`EgressVerified`] is a sealed token: its field is private, so the
//! only way any code obtains one is [`egress_verdict`] returning Ok.
//! [`crate::vm::mark_provisioned`] requires a borrow of it — every
//! marker write that did not flow out of a real passing verdict is a
//! COMPILE error, not a red test (F-099/F-100: five rounds of textual
//! call-site pins were each bypassed; the invariant now lives in the
//! type system). [`verify_and_mark`] is the single orchestration seam:
//! it produces the probe, runs it, judges it, and stops the instance
//! on any refusal — a caller cannot interleave a forged input or a
//! neutralized error between the steps.

use crate::vm;

/// Proof that [`egress_verdict`] ran and passed. The field is private:
/// outside this module the type can be named and borrowed, never
/// constructed — not with `{}`, not via a trait, not by transmuting
/// public fields. (A mutation INSIDE this file that mints a second
/// construction site is pinned by the test below.)
#[derive(Debug)]
#[must_use]
pub struct EgressVerified {
    _sealed: (),
}

/// The `creance up` in-guest egress probe (F-059/F-081/F-082). Runs as
/// the unprivileged guest user — every check must be readable without
/// root. `fw-armed` reads /run/egress-armed: a root-owned stamp the
/// egress-lock unit writes from the LIVE ruleset after each restore
/// (unprivileged users cannot create files in /run, so the stamp
/// cannot be forged from the guest account).
pub fn egress_probe_script(nat_hosts: &[&str]) -> String {
    format!(
        "export PATH=/usr/bin:/bin\n\
         if /usr/bin/timeout 1 /bin/true; then /usr/bin/timeout 5 /bin/bash -c '</dev/tcp/1.1.1.1/443' 2>/dev/null && echo tcp-open || echo tcp-blocked; else echo tcp-unknown; fi\n\
         if [ -x /usr/bin/ping ]; then /usr/bin/timeout 3 /usr/bin/ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 && echo icmp-open || echo icmp-blocked; else echo icmp-unknown; fi\n\
         {fw}",
        fw = fw_probe_fragment(nat_hosts)
    )
}

/// The fw-armed fragment — every `-A OUTPUT` line in BOTH the live
/// stamp and the persisted rules.v4 must EXACTLY equal one of the
/// canonical sanctioned lines (F-086/F-090). Whole-line `grep -vxF`
/// comparison, not substring patterns: a `-m comment` quoting a
/// sanctioned token, a `!` negation, a port range, an extra ctstate,
/// or a chain jump all fail to equal a canonical line and read
/// fw-down. Both spellings are allowed because iptables-save renders
/// the same rules differently from the rules.v4 we write (dst first,
/// `-m udp`, `/32`, RELATED,ESTABLISHED). The env overrides exist for
/// the executed truth-table test (F-087); defaults are the real paths.
/// Residual: intra-boot drift of live netfilter state by a privileged
/// actor cannot be observed unprivileged — by design no unprivileged
/// path can modify it either.
fn fw_probe_fragment(nat_hosts: &[&str]) -> String {
    // Canonical OUTPUT lines — the union of the rules.v4 written form
    // and the iptables-save rendering of the same rules. Single-quoted
    // for `grep -e`; the lines contain no `'`.
    let mut allowed: Vec<String> = vec![
        "-A OUTPUT -o lo -j ACCEPT".to_owned(),
        "-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT".to_owned(),
        "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_owned(),
        "-A OUTPUT -p udp --dport 67 -d 255.255.255.255 -j ACCEPT".to_owned(),
        "-A OUTPUT -d 255.255.255.255/32 -p udp -m udp --dport 67 -j ACCEPT".to_owned(),
    ];
    for host in nat_hosts {
        allowed.push(format!(
            "-A OUTPUT -p udp --dport 67 -d {host}/32 -j ACCEPT"
        ));
        allowed.push(format!(
            "-A OUTPUT -d {host}/32 -p udp -m udp --dport 67 -j ACCEPT"
        ));
        allowed.push(format!("-A OUTPUT -p icmp -d {host}/32 -j ACCEPT"));
        allowed.push(format!("-A OUTPUT -d {host}/32 -p icmp -j ACCEPT"));
    }
    let grep_args = allowed
        .iter()
        .map(|line| format!("-e '{line}'"))
        .collect::<Vec<_>>()
        .join(" ");
    // F-094: the persisted rules.v4 is compared BYTE-EXACT against
    // `provision::rules_v4_text` — the same renderer the bootstrap
    // heredoc embeds. An allowset+counts check left two lanes open:
    // a NUL byte flips GNU grep into binary mode (every line filter
    // emits nothing → `-I OUTPUT -j ACCEPT` read as armed), and line
    // counts cannot pin ORDER (`COMMIT` early / `*filter` last reads
    // armed while iptables-restore rejects → next boot unarmed). cmp
    // closes the whole encoding/order/spelling surface at once. The
    // live stamp keeps the `-A OUTPUT` allowlist (save output is
    // already normalized); the heredoc feeds cmp's expected side so
    // rules.v4 itself never parses.
    let expected = crate::provision::rules_v4_text(nat_hosts);
    format!(
        "STAMP=${{CREANCE_STAMP:-/run/egress-armed}}; WANT=${{CREANCE_RULES:-/etc/iptables/rules.v4}}\n\
         ok=0\n\
         if [ -f \"$STAMP\" ] && [ -f \"$WANT\" ] && grep -q '^:OUTPUT DROP' \"$STAMP\"; then\n\
           live=$(grep -hE '^-A OUTPUT' \"$STAMP\" | grep -vxF {grep_args})\n\
           if [ -z \"$live\" ] && cmp -s \"$WANT\" - <<'CREANCE_RULESET_EOF'\n\
         {expected}CREANCE_RULESET_EOF\n\
         then ok=1; fi\n\
         fi\n\
         if [ \"$ok\" = 1 ]; then echo fw-armed; else echo fw-down; fi\n"
    )
}

/// Verdict of the up-gate probe output. Err(reason) refuses delivery —
/// fail-closed: any missing or unexpected evidence is a refusal, never
/// a soft pass (F-062/F-081/F-083). The Ok value is the sealed token:
/// reaching `mark_provisioned` requires it.
/// F-105: PRIVATE — a token minted anywhere but inside this module's
/// own probe→verdict chain is a compile error across the workspace.
fn egress_verdict(out: &str) -> Result<EgressVerified, &'static str> {
    let tcp_ok = out.contains("tcp-blocked") && !out.contains("tcp-open");
    let icmp_ok = out.contains("icmp-blocked")
        || (out.contains("icmp-unknown") && !out.contains("icmp-open"));
    // F-081: once slirp restrict=on arms, tcp/icmp stay "blocked" even
    // with the in-guest firewall flushed — the second line masks a dead
    // first line. Require fw-armed or a disarmed guest goes green.
    let fw_ok = out.contains("fw-armed");
    if tcp_ok && icmp_ok && fw_ok {
        return Ok(EgressVerified { _sealed: () });
    }
    Err(if out.contains("tcp-open") || out.contains("icmp-open") {
        "guest 防火墙未生效（直连可达）"
    } else if !fw_ok {
        "guest 第一道防线（iptables 锁闭）未在武装状态——restrict=on 下的绿色直连判定不可信，按未验证拒绝交付"
    } else {
        "无法取得防火墙正向证据（探针输出缺失或被干扰，按未验证拒绝交付）"
    })
}

/// The up-gate egress chain as ONE seam (F-099/F-100): run the probe
/// inside the instance, judge its output, and only on a real pass arm
/// the `provisioned` marker (slirp `restrict=on` on the next boot —
/// the marker arms the second line only after the first verified).
/// Every refusal stops the instance and returns the user-facing
/// reason — fail-closed end to end. Returns true only when this call
/// armed the marker.
pub fn verify_and_mark(profile: &str, instance: &str) -> Result<bool, String> {
    verify_and_mark_with(profile, instance, vm::guest_script, |p, i| {
        let _ = vm::stop_vm(p, i);
    })
}

/// The seam with the guest runner and stop action injected — the
/// behavioural tests drive it with fakes (F-104): bad output must
/// refuse AND stop, good output must arm.
fn verify_and_mark_with<F, S>(
    profile: &str,
    instance: &str,
    run: F,
    stop: S,
) -> Result<bool, String>
where
    F: FnOnce(&str, &str, &str) -> Result<String, String>,
    S: FnOnce(&str, &str),
{
    let out = match run(
        profile,
        instance,
        &egress_probe_script(vm::nat_allow_hosts()),
    ) {
        Ok(out) => out,
        Err(e) => {
            stop(profile, instance);
            return Err(format!("无法在 guest 内验证防火墙状态，VM 已停止：{e}"));
        }
    };
    match egress_verdict(&out) {
        Err(reason) => {
            stop(profile, instance);
            Err(format!(
                "{reason}，VM 已停止；请 creance stop 后 creance setup 重建环境。探针原始输出：{out:?}"
            ))
        }
        // F-081/F-087/F-099: the marker sits behind the sealed token —
        // arming on ANY failure path is a compile error now, not a
        // convention a mutation can quietly relax.
        Ok(verified) => Ok(vm::mark_provisioned(profile, instance, &verified)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_verdict_is_fail_closed_per_branch() {
        // F-084: every refusal branch must be reachable — a verdict
        // that lost the fw_ok or open-check branch goes silently green.
        assert!(egress_verdict("tcp-blocked\nicmp-blocked\nfw-armed\n").is_ok());
        // Open direct path → the "direct reachable" reason.
        assert_eq!(
            egress_verdict("tcp-open\nicmp-blocked\nfw-armed\n").unwrap_err(),
            "guest 防火墙未生效（直连可达）"
        );
        assert_eq!(
            egress_verdict("tcp-blocked\nicmp-open\nfw-armed\n").unwrap_err(),
            "guest 防火墙未生效（直连可达）"
        );
        // First line disarmed → the dedicated fw reason (not the generic).
        assert!(egress_verdict("tcp-blocked\nicmp-blocked\nfw-down\n")
            .unwrap_err()
            .contains("第一道防线"));
        // Missing/garbled evidence → fw evidence absent takes priority;
        // fw-armed alone (tcp/icmp lines missing) → generic refusal.
        assert!(egress_verdict("").unwrap_err().contains("第一道防线"));
        assert!(egress_verdict("garbage")
            .unwrap_err()
            .contains("第一道防线"));
        assert!(egress_verdict("fw-armed").unwrap_err().contains("正向证据"));
        // ICMP tool absent is not a failure; ICMP open is.
        assert!(egress_verdict("tcp-blocked\nicmp-unknown\nfw-armed\n").is_ok());
    }

    #[test]
    fn verdict_seals_the_token() {
        // F-099/F-100/F-105: the Ok value is what arms the marker — it
        // must exist ONLY here. A second construction site anywhere in
        // the crate (a `mint()` helper, `Self { _sealed }`, a `Default`
        // or `Clone` derive, an `unsafe` mint) means a forged input can
        // arm without a real verdict. `_sealed: ()` appears exactly
        // twice: the field decl and the single mint.
        let src = include_str!("gateprobe.rs");
        let prod = &src[..src.rfind("\n#[cfg(test)]").unwrap()];
        assert_eq!(
            prod.matches("_sealed: ()").count(),
            2,
            "field decl + the single mint inside egress_verdict"
        );
        assert_eq!(
            prod.matches("EgressVerified { _sealed").count(),
            1,
            "EgressVerified の構築点は egress_verdict の Ok 分岐のみ"
        );
        assert_eq!(
            prod.matches("Self { _sealed").count(),
            0,
            "Self-spelled construction is a second mint site"
        );
        assert!(
            !prod.contains("impl EgressVerified"),
            "no impl block may mint the token"
        );
        assert!(
            !prod.contains("Default") && !prod.contains("Clone"),
            "a Default/Clone mint is a second construction site"
        );
        assert!(
            !prod.contains("unsafe") && !prod.contains("transmute"),
            "an unsafe mint defeats the seal"
        );
        // The verdict fn stays private — ANY `pub`-qualified spelling
        // (`pub(super)`/`pub(crate)`/`pub(in …)`) lets the rest of the
        // crate feed it a literal and mint (F-105/F-112/XGATE).
        assert!(
            prod.lines()
                .filter(|l| l.contains("fn egress_verdict"))
                .all(|l| !l.contains("pub")),
            "egress_verdict must carry no pub qualifier"
        );
        assert_eq!(prod.matches("fn egress_verdict(").count(), 1);
        assert_eq!(prod.matches("egress_verdict(").count(), 2, "{src}");
        assert_eq!(
            prod.matches("verify_and_mark(").count(),
            1,
            "def only — the single call site lives in creance's main.rs"
        );
        assert_eq!(
            prod.matches("verify_and_mark_with").count(),
            2,
            "def + the one production call inside verify_and_mark"
        );
        // F-104: inside verify_and_mark_with the verdict's input must be
        // the REAL guest output — the body's literal is
        // `match egress_verdict(&out)`, `let out` binds exactly once,
        // no `.map`/rebind may sit between run() and the verdict, and
        // the body must not contain the pass-strings it judges (a
        // canned `"tcp-blocked"/"fw-armed"` literal IS the forgery).
        let def = prod.find("fn verify_and_mark_with").unwrap();
        let body_end = def + prod[def..].find("\n}").unwrap();
        let body = &prod[def..body_end];
        assert_eq!(body.matches("egress_verdict(&out)").count(), 1);
        assert_eq!(body.matches("let out").count(), 1, "{body}");
        assert!(!body.contains(".map("), "{body}");
        assert!(!body.contains("tcp-blocked"), "{body}");
        assert!(!body.contains("fw-armed"), "{body}");
        assert!(!body.contains("icmp-blocked"), "{body}");
        // F-111/F-112: arg ORDER and call ORDER are pinned — a swapped
        // `stop(instance, profile)` or a mark placed before the verdict
        // fails, and the Ok arm is one verbatim line with no condition.
        assert_eq!(body.matches("stop(profile, instance)").count(), 2, "{body}");
        let verdict_at = body.find("egress_verdict(&out)").unwrap();
        let mark_at = body.find("mark_provisioned(").unwrap();
        assert!(
            verdict_at < mark_at,
            "marker write must sit after the verdict"
        );
        assert!(
            body.lines().any(|l| l.trim()
                == "Ok(verified) => Ok(vm::mark_provisioned(profile, instance, &verified)),"),
            "Ok arm must be the unconditional marker call"
        );
        assert!(body.contains("return Err"), "{body}");
        assert_eq!(body.matches("mark_provisioned(").count(), 1, "{body}");
    }

    #[test]
    fn verify_and_mark_shell_is_pinned() {
        // F-111: the production entry is a literal shell — the runner is
        // vm::guest_script, the stop is vm::stop_vm in (profile,
        // instance) order, nothing else. A canned-pass runner or a
        // no-op stop in the wrapper is a test red.
        let src = include_str!("gateprobe.rs");
        let prod = &src[..src.rfind("\n#[cfg(test)]").unwrap()];
        let def = prod.find("pub fn verify_and_mark(").unwrap();
        let body_end = def + prod[def..].find("\n}").unwrap();
        let body = &prod[def..body_end];
        // F-117: substring pins keep semantics-free — the WHOLE body is
        // verbatim. `|i, p|` swapped closure params, a dead-closure
        // `let _ = || vm::stop_vm(p, i);`, and a `guest_script_ok`
        // prefix-satisfying canned runner all change these bytes.
        assert_eq!(
            body.trim(),
            concat!(
                "pub fn verify_and_mark(profile: &str, instance: &str) -> Result<bool, String> {\n",
                "    verify_and_mark_with(profile, instance, vm::guest_script, |p, i| {\n",
                "        let _ = vm::stop_vm(p, i);\n",
                "    })"
            ),
            "{body}"
        );
    }

    #[test]
    fn verify_and_mark_refuses_and_stops_on_every_bad_input() {
        // F-104: drive the seam with injected runners — the verdict
        // must see the REAL probe output, and every refusal must stop.
        let stopped = std::cell::RefCell::new(Vec::<(String, String)>::new());
        let run = |_p: &str, _i: &str, s: &str| -> Result<String, String> {
            // F-111/F-117: a canned-pass wrapper feeds a dead literal
            // script — a `contains("egress-armed")` check is satisfied
            // by a comment, so the fake demands byte equality with the
            // real probe render.
            assert_eq!(
                s,
                egress_probe_script(vm::nat_allow_hosts()).as_str(),
                "injected script is the real probe"
            );
            Ok("tcp-open\nicmp-blocked\nfw-armed\n".to_owned())
        };
        let res = verify_and_mark_with("/tmp/nope", "nope", run, |p, i| {
            stopped.borrow_mut().push((p.to_owned(), i.to_owned()));
        });
        let err = res.unwrap_err();
        assert!(err.contains("直连可达"), "{err}");
        // F-111: the stop must carry (profile, instance) in that order —
        // a swapped `stop(instance, profile)` stops nothing real.
        assert_eq!(
            stopped.borrow().as_slice(),
            &[("/tmp/nope".to_owned(), "nope".to_owned())],
            "refusal must stop the VM with (profile, instance)"
        );
        // Runner error → refuse + stop (a canned-pass conversion would
        // have to swallow this — the Err arm pins it textually too).
        let res = verify_and_mark_with(
            "/tmp/nope",
            "nope",
            |_p, _i, _s| Err("ssh dead".to_owned()),
            |p, i| stopped.borrow_mut().push((p.to_owned(), i.to_owned())),
        );
        let err = res.unwrap_err();
        assert!(err.contains("无法"), "{err}");
        assert_eq!(stopped.borrow().len(), 2);
        // Passing output arms the marker AT the instance's own dir.
        let profile = std::env::temp_dir()
            .join(format!("creance-vam-{}", std::process::id()))
            .to_string_lossy()
            .into_owned();
        let dir = crate::qemu::instance_dir(&profile, "good-inst");
        std::fs::create_dir_all(&dir).unwrap();
        let res = verify_and_mark_with(
            &profile,
            "good-inst",
            |p, i, s| {
                assert_eq!((p, i), (profile.as_str(), "good-inst"));
                assert_eq!(s, egress_probe_script(vm::nat_allow_hosts()).as_str());
                Ok("tcp-blocked\nicmp-blocked\nfw-armed\n".to_owned())
            },
            |_p, _i| panic!("a pass must not stop"),
        );
        assert_eq!(res, Ok(true), "{res:?}");
        assert!(std::path::Path::new(&crate::paths::join(&dir, "provisioned")).exists());
        let _ = std::fs::remove_dir_all(&profile);
    }

    /// Run the shipped fw fragment — sliced out of the real
    /// `egress_probe_script` output, so the executed test covers the
    /// product's own NAT-host expansion, not a hand-written pattern
    /// (F-091).
    fn run_fw_fragment(
        nat_hosts: &[&str],
        stamp: &std::path::Path,
        want: &std::path::Path,
    ) -> String {
        let script = egress_probe_script(nat_hosts);
        let frag = &script[script.find("STAMP=").expect("fw fragment")..];
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(frag)
            .env("CREANCE_STAMP", stamp)
            .env("CREANCE_RULES", want)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    #[test]
    fn egress_probe_reads_only_unprivileged_evidence() {
        // F-082: no netfilter read (needs root), no PATH outside
        // /usr/bin:/bin binaries — the stamp file is the contract.
        let p = egress_probe_script(&["10.0.2.2", "10.0.2.3"]);
        // No netfilter READ command (needs root) — the /etc/iptables/
        // rules.v4 FILENAME is data, not a command, so it stays.
        for cmd in [
            "iptables -",
            "iptables-save",
            "iptables-restore",
            "nft ",
            "nftables",
        ] {
            assert!(!p.contains(cmd), "{cmd} in {p}");
        }
        assert!(p.contains("/run/egress-armed"), "{p}");
        assert!(p.contains("^:OUTPUT DROP"), "{p}");
        // F-090/F-093/F-094: whole-line exact match (grep -vxF) on the
        // live stamp; the persisted rules.v4 is a BYTE-EXACT cmp
        // against provision::rules_v4_text — no allowset/counts/
        // encoding lane remains (NUL → cmp differs; reorder → differs).
        assert_eq!(p.matches("grep -vxF").count(), 1, "{p}");
        assert!(p.contains("cmp -s \"$WANT\" -"), "{p}");
        // F-095/F-097/F-101: the allowset line is pinned VERBATIM —
        // counting `-e '` alone cannot see a swapped entry, an entry
        // with an embedded newline, or a replaced line (all preserve
        // the count). Build the expected line from the canonical list.
        let hosts = ["10.0.2.2", "10.0.2.3"];
        let mut allowed: Vec<String> = vec![
            "-A OUTPUT -o lo -j ACCEPT".to_owned(),
            "-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT".to_owned(),
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_owned(),
            "-A OUTPUT -p udp --dport 67 -d 255.255.255.255 -j ACCEPT".to_owned(),
            "-A OUTPUT -d 255.255.255.255/32 -p udp -m udp --dport 67 -j ACCEPT".to_owned(),
        ];
        for host in hosts {
            allowed.push(format!(
                "-A OUTPUT -p udp --dport 67 -d {host}/32 -j ACCEPT"
            ));
            allowed.push(format!(
                "-A OUTPUT -d {host}/32 -p udp -m udp --dport 67 -j ACCEPT"
            ));
            allowed.push(format!("-A OUTPUT -p icmp -d {host}/32 -j ACCEPT"));
            allowed.push(format!("-A OUTPUT -d {host}/32 -p icmp -j ACCEPT"));
        }
        let expected_args = allowed
            .iter()
            .map(|l| format!("-e '{l}'"))
            .collect::<Vec<_>>()
            .join(" ");
        let grep_line = p
            .lines()
            .find(|l| l.contains("grep -vxF"))
            .expect("allowset line");
        // F-109/NC-ALLOWapp: FULL-line equality, not `contains` — a
        // trailing `-e '…'` appended after the canonical args would
        // keep a prefix-contains check green.
        assert_eq!(
            grep_line,
            format!("live=$(grep -hE '^-A OUTPUT' \"$STAMP\" | grep -vxF {expected_args})"),
            "allowset line must be the canonical list and nothing else"
        );
        // NC-ALLOWpush: the builder may only assemble the set through
        // the seeded vec + the per-host loop — count every `allowed.`
        // use in fw_probe_fragment: 4 pushes (one per line shape in
        // the loop) + 1 `.iter()` = 5. An extra push/extend/insert is
        // count 6+.
        let gp = include_str!("gateprobe.rs");
        let prod = &gp[..gp.rfind("\n#[cfg(test)]").unwrap()];
        let fs = prod.find("fn fw_probe_fragment").unwrap();
        let fend = fs + prod[fs..].find("\n}").unwrap();
        assert_eq!(
            prod[fs..fend].matches("allowed").count(),
            6,
            "vec decl + 4 loop pushes + the .iter() read — an extra push/extend/insert bumps the count"
        );
        assert_eq!(prod[fs..fend].matches("allowed.push(").count(), 4);
        assert!(!p.contains("-e '-A OUTPUT -j ACCEPT'"), "{p}");
        assert!(!p.contains("conntrack --ctstate .*"), "{p}");
        assert!(p.contains("/etc/iptables/rules.v4"), "{p}");
        assert!(p.contains("/dev/tcp/1.1.1.1/443"), "{p}");
        // F-062: PATH reset survives.
        assert!(p.contains("export PATH=/usr/bin:/bin"), "{p}");
        // F-087: fixtures override paths via env, defaults stay real.
        assert!(p.contains("${CREANCE_STAMP:-/run/egress-armed}"), "{p}");
        assert!(
            p.contains("${CREANCE_RULES:-/etc/iptables/rules.v4}"),
            "{p}"
        );
        // The probe embeds this backend's NAT hosts as literal lines.
        assert!(
            p.contains("-A OUTPUT -d 10.0.2.2/32 -p udp -m udp --dport 67 -j ACCEPT"),
            "{p}"
        );
        assert!(
            p.contains("-A OUTPUT -d 10.0.2.3/32 -p icmp -j ACCEPT"),
            "{p}"
        );
    }

    #[test]
    fn fw_probe_fragment_real_shell_truth_table() {
        // F-087/F-090: actually run the fragment under sh against
        // fixtures — the allowlist is too subtle to trust unread.
        let dir = std::env::temp_dir().join(format!("creance-fw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stamp = dir.join("stamp");
        let want = dir.join("want");
        let hosts = &["10.0.2.2", "10.0.2.3"];
        let run = |stamp_c: &str, want_c: &str| -> String {
            std::fs::write(&stamp, stamp_c).unwrap();
            std::fs::write(&want, want_c).unwrap();
            run_fw_fragment(hosts, &stamp, &want)
        };
        // F-094: the expected file is the renderer's own output — the
        // probe byte-compares against it, so the fixture must be the
        // same bytes (a hand-written copy would silently drift).
        let want_good = crate::provision::rules_v4_text(hosts);
        // The stamp lines the egress-lock unit actually writes
        // (iptables-save order: dst first, -m udp, /32 appended,
        // RELATED,ESTABLISHED).
        let stamp_good = "# Generated by egress-lock\n:OUTPUT DROP [0:0]\n-A OUTPUT -o lo -j ACCEPT\n-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A OUTPUT -d 255.255.255.255/32 -p udp -m udp --dport 67 -j ACCEPT\n-A OUTPUT -d 10.0.2.2/32 -p udp -m udp --dport 67 -j ACCEPT\n-A OUTPUT -d 10.0.2.2/32 -p icmp -j ACCEPT\n-A OUTPUT -d 10.0.2.3/32 -p udp -m udp --dport 67 -j ACCEPT\n-A OUTPUT -d 10.0.2.3/32 -p icmp -j ACCEPT\n";
        assert_eq!(run(stamp_good, &want_good), "fw-armed");
        // Missing evidence.
        std::fs::remove_file(&stamp).unwrap();
        assert_eq!(run("", &want_good), "fw-down");
        // Bare blanket ACCEPT (F-083), qualified ACCEPTs (F-086), and
        // F-090's comment-forged tokens / negations / ranges / mixed
        // ctstate — every line not literally a canonical rule.
        for hole in [
            "-A OUTPUT -j ACCEPT",
            "-A OUTPUT -o e+ -j ACCEPT",
            "-A OUTPUT -p tcp -d 10.0.2.2/32 -j ACCEPT",
            "-A OUTPUT -p udp --dport 67 -d 8.8.8.8/32 -j ACCEPT",
            "-A OUTPUT -j LEAK",
            "-A OUTPUT -m conntrack --ctstate NEW -j ACCEPT",
            "-A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT",
            "-A OUTPUT -m conntrack --ctstate ESTABLISHED -j LEAK",
            // F-093/NC-NOX: a line CONTAINING a canonical line as a
            // substring — only `-x` (whole-line) rejects it.
            "-A OUTPUT -o lo -j ACCEPT -m comment --comment x",
            "-A OUTPUT -m comment --comment \"-d 10.0.2.2/32 -p icmp\" -j ACCEPT",
            "-A OUTPUT -m comment --comment \"conntrack --ctstate ESTABLISHED\" -j ACCEPT",
            "-A OUTPUT ! -d 10.0.2.2/32 -p udp -m udp ! --dport 67 -j ACCEPT",
            "-A OUTPUT ! -d 10.0.2.2/32 -p icmp -j ACCEPT",
            "-A OUTPUT ! -d 10.0.2.3/32 -p udp -m udp --dport 67:65535 -j ACCEPT",
            "-A OUTPUT -d 10.0.2.2/32 -p tcp -m comment --comment \"-p icmp\" -j ACCEPT",
            "-A OUTPUT -p tcp -m comment --comment \"-d 10.0.2.3/32 -p icmp\" -j ACCEPT",
        ] {
            assert_eq!(
                run(&format!("{stamp_good}{hole}\n"), &want_good),
                "fw-down",
                "{hole}"
            );
        }
        // OUTPUT policy not DROP in either file.
        assert_eq!(
            run(&stamp_good.replace("DROP", "ACCEPT"), &want_good),
            "fw-down"
        );
        // rules.v4 carries the hole (post-provision file edit) — even
        // when the live stamp alone is clean.
        assert_eq!(
            run(
                stamp_good,
                &format!(
                    "{want_good}-A OUTPUT -m comment --comment \"-d 10.0.2.2/32 -p icmp\" -j ACCEPT\n"
                )
            ),
            "fw-down"
        );
        assert_eq!(
            run(
                stamp_good,
                &want_good.replace(":OUTPUT DROP", ":OUTPUT ACCEPT")
            ),
            "fw-down"
        );
        // F-092: every spelling iptables-restore still applies but a
        // `^-A OUTPUT` line filter skips — insert/replace/append,
        // whitespace variants, comments (never written by the
        // renderer), and structural re-declarations all read fw-down.
        for hole in [
            "-I OUTPUT -j ACCEPT",
            "-I OUTPUT 1 -j ACCEPT",
            "--append OUTPUT -j ACCEPT",
            "-A  OUTPUT -j ACCEPT",
            " -A OUTPUT -j ACCEPT",
            "-A\tOUTPUT -j ACCEPT",
            "-R OUTPUT 1 -j ACCEPT",
            "# a comment line",
            "*filter",
            "COMMIT",
            ":OUTPUT ACCEPT [0:0]",
            ":OUTPUT DROP [0:0]",
        ] {
            assert_eq!(
                run(stamp_good, &format!("{want_good}{hole}\n")),
                "fw-down",
                "{hole}"
            );
        }
        assert_eq!(
            run(
                stamp_good,
                &format!("{want_good}COMMIT\n*filter\n:OUTPUT ACCEPT [0:0]\n")
            ),
            "fw-down"
        );
        // F-094: byte-exact also covers the lanes the allowset+counts
        // check could not. Z01–Z03: a NUL byte flips GNU grep into
        // binary mode — under the old check every line filter emitted
        // nothing and an injected `-I OUTPUT -j ACCEPT` still read
        // fw-armed; cmp just sees different bytes.
        assert_eq!(
            run(stamp_good, &format!("#\u{0}nul\n{want_good}")),
            "fw-down"
        );
        assert_eq!(
            run(
                stamp_good,
                &format!("{want_good}-I OUTPUT -j ACCEPT\u{0}\n")
            ),
            "fw-down"
        );
        // Trailing whitespace / extra newline: not the same bytes.
        assert_eq!(run(stamp_good, &format!("{want_good}\n")), "fw-down");
        // O01–O03: every line canonical, wrong ORDER — counts 1/1/1
        // could not pin it; iptables-restore rejects or applies a
        // different ruleset → next boot unarmed.
        let order_cases: Vec<String> = {
            let lines: Vec<&str> = want_good.lines().collect();
            let mut early_commit = lines.clone();
            let c = early_commit.pop().unwrap();
            early_commit.insert(1, c); // COMMIT before the rules
            let mut out_after_rule = lines.clone();
            let decl = out_after_rule.remove(3); // :OUTPUT DROP
            out_after_rule.insert(4, decl); // declared after a -A line
            let mut filter_last = lines.clone();
            let f = filter_last.remove(0);
            filter_last.insert(filter_last.len() - 1, f); // *filter after rules
            vec![
                format!("{}\n", early_commit.join("\n")),
                format!("{}\n", out_after_rule.join("\n")),
                format!("{}\n", filter_last.join("\n")),
            ]
        };
        for tampered in &order_cases {
            assert_eq!(run(stamp_good, tampered), "fw-down", "{tampered}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
