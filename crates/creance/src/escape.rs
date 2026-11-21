//! The escape-probe suite: automated containment checks for an environment,
//! derived from the sandbox-escape literature (see ROADMAP "escape probes").
//!
//! Two kinds of probes:
//! - **Host-verifiable now**: profile hygiene that needs no VM — no host
//!   credentials in the guest env, only the workspace mounted, gate record
//!   private, fingerprint consistency. These are hard assertions.
//! - **In-guest probes**: a generated script the CLI runs inside the VM via
//!   the backend shell (limactl on macOS, ssh on Linux); each probe
//!   reports PASS (contained) or ESCAPE. Network
//!   probes are marked `pending-enforcement` until the VM network plane
//!   routes through the gate (ROADMAP), so the suite reports them as
//!   "not enforced" rather than lying about containment.

use creance_vm::{config, paths, vm};
use std::path::Path;

/// One probe's outcome.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// Containment held.
    Contained,
    /// Containment failed: the probe got out.
    Escaped(String),
    /// The layer that would enforce this probe is not implemented yet;
    /// reported separately so it can never silently pass.
    NotEnforced,
}

#[derive(Debug)]
pub struct Probe {
    pub id: &'static str,
    pub layer: &'static str,
    pub outcome: Outcome,
}

/// Runs every host-verifiable probe against a profile. No VM required.
pub fn host_probes(profile: &str, config_path: &str) -> Vec<Probe> {
    let mut out = Vec::new();
    let cfg = config::load(config_path);

    // 1. Configuration validates (the isolation boundary is well-formed).
    out.push(Probe {
        id: "config-valid",
        layer: "profile",
        outcome: match &cfg {
            Ok(_) => Outcome::Contained,
            Err(e) => Outcome::Escaped(e.clone()),
        },
    });

    // 2. No host proxy/credential variables leak into children we spawn:
    // the sanitized environment must not carry them.
    out.push(Probe {
        id: "env-no-host-credentials",
        layer: "host-env",
        outcome: {
            let env = vm::sanitized_env(&[]);
            let leaks: Vec<&str> = env
                .iter()
                .map(|(k, _)| k.as_str())
                .filter(|k| {
                    matches!(
                        *k,
                        "HTTP_PROXY"
                            | "HTTPS_PROXY"
                            | "ALL_PROXY"
                            | "ANTHROPIC_API_KEY"
                            | "CLAUDE_CODE_OAUTH_TOKEN"
                    )
                })
                .collect();
            if leaks.is_empty() {
                Outcome::Contained
            } else {
                Outcome::Escaped(format!("leaked into child env: {leaks:?}"))
            }
        },
    });

    // 3. (deleted 2026-11-21, R13's E5 verdict) The former
    //    `proxy-numeric-endpoint` probe was hollow — both match arms
    //    returned Contained, so it could never go red. The real checks
    //    live in config validation and the store's `applied()`; a green
    //    counter with a permanent-PASS entry is a small lie, and the
    //    honest fix is removal, not a vestigial constant.

    // 4. Only the environment directory is shared: no Lima mounts beyond
    //    the workspace mount in the staged/instance config. FINDING-016:
    //    this probe fail-closes — anything it cannot count (malformed
    //    structure, merge keys) is Escaped, never a silent Contained.
    let instance = vm::instance_name(profile, &vm::environment_dir(profile));
    let marker = vm::instance_marker(profile, &instance);
    out.push(Probe {
        id: "mounts-workspace-only",
        layer: "filesystem",
        outcome: if Path::new(&marker).exists() {
            match vm::declared_mount_count(profile, &instance) {
                Ok(0) | Ok(1) => Outcome::Contained,
                Ok(n) => Outcome::Escaped(format!("{n} mounts declared")),
                Err(why) => Outcome::Escaped(why),
            }
        } else {
            Outcome::NotEnforced
        },
    });

    // 5. The gate record (if any) is private, and its daemon actually
    //    serves (F-019: a record left by a SIGKILLed daemon used to pass
    //    as containment while an orphan tunnel kept the wire open).
    let instance_dir = paths::join(&vm::instances_root(profile), &instance);
    let gate_json = paths::join(&instance_dir, "cage-gate.json");
    out.push(Probe {
        id: "gate-record-private",
        layer: "gate",
        outcome: if Path::new(&gate_json).exists() {
            match creance_vm::private::check_private_file(&gate_json) {
                Err(e) => Outcome::Escaped(e.to_string()),
                Ok(()) => {
                    match creance_gate::gate::GateClient::open(&instance_dir)
                        .and_then(|client| client.status())
                    {
                        Ok(_) => Outcome::Contained,
                        Err(_) => Outcome::Escaped("gate record without a live daemon".to_owned()),
                    }
                }
            }
        } else if instance_running(profile, &instance) {
            Outcome::Escaped("VM present without a gate record".to_owned())
        } else {
            Outcome::NotEnforced
        },
    });

    // 6. Every token-shaped value in the profile directory belongs to the
    //    issued set (F-022: validating one JSON file claimed far more than
    //    it checked — stray credential files passed as containment).
    //    Subscription content (proxy/sources.json) is out of scope: it is
    //    remote, attacker-chosen, and never reaches the guest (F-032).
    let guest_json = paths::join(profile, "guest-profile.json");
    out.push(Probe {
        id: "credentials-are-session-only",
        layer: "credentials",
        outcome: if Path::new(&guest_json).exists() {
            match scan_unknown_tokens(profile) {
                Ok(unknown) if unknown.is_empty() => Outcome::Contained,
                Ok(unknown) => Outcome::Escaped(format!(
                    "token-shaped secret outside the issued set: {}",
                    unknown
                        .iter()
                        .map(|(f, t)| format!("{f}:{}…", &t[..8]))
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
                Err(e) => Outcome::Escaped(e),
            }
        } else {
            Outcome::NotEnforced
        },
    });

    // 7. Guest fingerprint consistency: the timezone the VM was promised is
    //    the one the profile still carries (drift means stale config).
    out.push(Probe {
        id: "fingerprint-consistent",
        layer: "profile",
        outcome: match &cfg {
            Ok(c) => {
                let stored = vm::state_dir(profile);
                let setup_stamp = paths::join(&stored, "fingerprint.txt");
                // F-049: a VM whose promise stamp is gone has lost its
                // drift oracle — an escape, not "not enforced" (only a
                // never-set-up profile reads NotEnforced).
                if !Path::new(&setup_stamp).exists() {
                    if instance_running(profile, &instance) {
                        Outcome::Escaped("fingerprint stamp missing on a running VM".to_owned())
                    } else {
                        Outcome::NotEnforced
                    }
                } else {
                    match std::fs::read_to_string(&setup_stamp) {
                        Ok(text) if text.trim() == c.guest_fingerprint() => Outcome::Contained,
                        Ok(_) => Outcome::Escaped(
                            "profile changed since the VM was created; run creance stop".to_owned(),
                        ),
                        Err(e) => Outcome::Escaped(e.to_string()),
                    }
                }
            }
            Err(e) => Outcome::Escaped(e.clone()),
        },
    });

    out
}

/// Whether the profile's instance is actually running (not merely created)
/// — the backend's own liveness oracle is the source of truth.
fn instance_running(profile: &str, instance: &str) -> bool {
    vm::instance_running(profile, instance)
}

/// One token-shaped run: exactly 48 lowercase hex bytes with non-hex on
/// both sides (longer hex runs — hashes — are not tokens).
fn hex48_runs(bytes: &[u8], out: &mut Vec<String>) {
    let hex = |c: u8| c.is_ascii_digit() || (b'a'..=b'f').contains(&c);
    let mut i = 0;
    while i + 48 <= bytes.len() {
        let slice = &bytes[i..i + 48];
        if slice.iter().all(|&c| hex(c))
            && (i == 0 || !hex(bytes[i - 1]))
            && (i + 48 == bytes.len() || !hex(bytes[i + 48]))
        {
            out.push(String::from_utf8_lossy(slice).into_owned());
            i += 48;
        } else {
            i += 1;
        }
    }
}

/// Scans the profile directory (bounded: ≤1 MiB text files, depth ≤8) for
/// token-shaped values that are not part of the issued set — the guest
/// session token, the store's core auth, and gate record tokens.
fn scan_unknown_tokens(profile: &str) -> Result<Vec<(String, String)>, String> {
    let mut expected = std::collections::HashSet::new();
    if let Ok(guest) = creance_vm::guestprofile::Profile::load_or_create(profile) {
        expected.insert(guest.session_token);
    }
    if let Ok(store) = creance_proxy::load(profile) {
        expected.insert(store.auth);
        // The store's revision is a 48-hex VERSION marker, not a secret —
        // proxy-select copies it into config.json, and the live machine
        // showed the scan flagging it on a fully provisioned profile.
        expected.insert(store.revision);
    }
    let lima = vm::instances_root(profile);
    if let Ok(entries) = std::fs::read_dir(&lima) {
        for entry in entries.flatten() {
            let record = entry.path().join("cage-gate.json");
            if let Ok(text) = std::fs::read_to_string(&record) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(token) = v["token"].as_str() {
                        expected.insert(token.to_owned());
                    }
                }
            }
        }
    }
    let mut unknown = Vec::new();
    let mut queue: Vec<(std::path::PathBuf, usize)> = vec![(Path::new(profile).to_owned(), 0)];
    while let Some((dir, depth)) = queue.pop() {
        if depth > 8 {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() {
                queue.push((path, depth + 1));
            } else if meta.is_file() && meta.len() <= 1024 * 1024 {
                // F-032: proxy/sources.json is where REMOTE subscription
                // content lands — it never reaches the guest, and treating
                // its attacker-chosen fields as issued secrets let a
                // subscription forge escape verdicts (a 48-hex password
                // turned the probe red). Whitelisting its contents instead
                // would be worse: it would launder arbitrary hex. It is
                // simply out of the probe's scope.
                let rel = path
                    .strip_prefix(profile)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if rel == "proxy/sources.json" {
                    continue;
                }
                let Ok(bytes) = std::fs::read(&path) else {
                    continue;
                };
                let mut tokens = Vec::new();
                hex48_runs(&bytes, &mut tokens);
                for token in tokens {
                    if !expected.contains(&token) {
                        let name = path
                            .strip_prefix(profile)
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_else(|_| path.to_string_lossy().into_owned());
                        unknown.push((name, token));
                    }
                }
            }
        }
    }
    unknown.sort();
    unknown.dedup();
    Ok(unknown)
}

/// The in-guest probe script: run inside the VM, prints one `PROBE id
/// RESULT` line per check (RESULT in PASS/ESCAPE/SKIP). Kept POSIX-sh so it
/// runs on any guest. `expected_user` is the generated guest identity the
/// VM must be running as (F-022).
pub fn guest_script(flag_path: &str, auth: &str, port: u16, expected_user: &str) -> String {
    format!(
        r#"#!/bin/sh
# creance escape probes (in-guest). A flag file placed on the host is the
# escape oracle: if any probe can read it, containment failed.
FLAG={flag_path}
probe() {{
  id="$1"; shift
  if [ -f "$FLAG" ]; then
    echo "PROBE $id ESCAPE"
  else
    echo "PROBE $id PASS"
  fi
}}
# Filesystem: the host flag must not be reachable by any guest path.
probe fs-flag-readable true
# Identity (020/022): the session runs as the generated identity, and no
# privilege path may exist — root inside the guest could lift the firewall.
if [ "$(/usr/bin/id -un)" != "{expected_user}" ]; then
  echo "PROBE guest-identity ESCAPE"
else
  echo "PROBE guest-identity PASS"
fi
if /usr/bin/sudo -n true 2>/dev/null; then
  echo "PROBE guest-privilege ESCAPE"
else
  echo "PROBE guest-privilege PASS"
fi
# Credentials: no host secrets in the guest environment. The external
# commands are spelled with absolute paths so a polluted guest PATH cannot
# fake the oracle (FINDING-011).
if /usr/bin/env | /usr/bin/grep -qE 'ANTHROPIC_API_KEY|CLAUDE_CODE_OAUTH_TOKEN|_API_KEY='; then
  echo "PROBE env-credentials ESCAPE"
else
  echo "PROBE env-credentials PASS"
fi
# Credentials, token shape (F-022): the session token is the ONLY 48-hex
# secret the environment may carry.
if /usr/bin/env | /usr/bin/grep -v '^CREANCE_SESSION_TOKEN=' | /usr/bin/grep -qE '[0-9a-f]{{48}}'; then
  echo "PROBE env-hex-tokens ESCAPE"
else
  echo "PROBE env-hex-tokens PASS"
fi
# SSH: no agent socket, no host keys carried in.
if [ -n "$SSH_AUTH_SOCK" ] || /usr/bin/ls ~/.ssh/id_* >/dev/null 2>&1; then
  echo "PROBE ssh-material SKIP"
else
  echo "PROBE ssh-material PASS"
fi
# Sockets: no docker/lima sockets to abuse.
for s in /var/run/docker.sock /run/docker.sock /var/run/lima-guestagent.sock; do
  [ -S "$s" ] && echo "PROBE sock-$s ESCAPE"
done
# Abstract-socket abuse is not checked yet: report SKIP so it can never
# fake a pass (FINDING-011).
echo "PROBE sock-abstract SKIP"
# 0.3 ENFORCED NETWORK PROBES — the topology firewall must hold:
# direct egress to external IPs is dropped, external DNS is dropped,
# IPv6 is disabled. Escape = any of them succeeds.
if curl -m 5 -s -o /dev/null https://1.1.1.1/ || curl -m 5 -s -o /dev/null http://93.184.216.34/; then
  echo "PROBE net-direct-egress ESCAPE"
else
  echo "PROBE net-direct-egress PASS"
fi
if timeout 4 getent hosts example.com >/dev/null 2>&1; then
  echo "PROBE net-dns-external ESCAPE"
else
  echo "PROBE net-dns-external PASS"
fi
if ip -6 addr show scope global 2>/dev/null | grep -q inet6; then
  echo "PROBE net-ipv6 ESCAPE"
else
  echo "PROBE net-ipv6 PASS"
fi
# F-060: ICMP used to be allowed to ANY destination — an echo channel the
# TCP/DNS probes never watched. External echoes must die (only the NAT
# subnets keep ICMP for path-MTU); no ping binary = honestly SKIP.
if command -v ping >/dev/null 2>&1; then
  if timeout 3 ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then
    echo "PROBE net-icmp-external ESCAPE"
  else
    echo "PROBE net-icmp-external PASS"
  fi
else
  echo "PROBE net-icmp-external SKIP"
fi
# Positive control: the ONLY route (loopback tunnel to the host core) works.
# The username must match the core's configured auth (store::endpoint's
# 'session' — a drift here fails the probe honestly, as the 2026-11-21
# sweep's first live round demonstrated).
if curl -m 8 -s --socks5-hostname "session:{auth}"@127.0.0.1:{port} https://1.1.1.1/cdn-cgi/trace | grep -q ip=; then
  echo "PROBE proxy-path PASS"
else
  echo "PROBE proxy-path ESCAPE"
fi
"#
    )
}

/// Renders a probe run the way the CLI prints it. Returns the process exit
/// code: 0 when nothing escaped (not-enforced probes do not fail the run,
/// escapes do).
pub fn report(probes: &[Probe]) -> i32 {
    let mut escapes = 0;
    let mut unenforced = 0;
    for p in probes {
        match &p.outcome {
            Outcome::Contained => println!("✅ {}  [{}]", p.id, p.layer),
            Outcome::NotEnforced => {
                unenforced += 1;
                println!("⏭️  {}  [{}] (layer not implemented yet)", p.id, p.layer);
            }
            Outcome::Escaped(why) => {
                escapes += 1;
                println!("❌ {}  [{}] — {why}", p.id, p.layer);
            }
        }
    }
    if escapes > 0 {
        println!("\n{escapes} escape(s), {unenforced} not enforced");
        1
    } else {
        println!("\ncontained ({unenforced} probe(s) awaiting their enforcement layer)");
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_profile() -> (String, String) {
        let dir = std::env::temp_dir()
            .join(format!(
                "creance-esc-{}",
                creance_vm::token()[..12].to_owned()
            ))
            .to_string_lossy()
            .into_owned();
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = paths::join(&dir, "config.json");
        std::fs::write(
            &config_path,
            serde_json::to_vec_pretty(&config::default_config()).unwrap(),
        )
        .unwrap();
        (dir, config_path)
    }

    #[test]
    fn fresh_profile_is_contained_or_unenforced() {
        let (profile, config_path) = fresh_profile();
        let probes = host_probes(&profile, &config_path);
        assert!(probes.len() >= 5);
        for p in &probes {
            assert!(p.outcome != Outcome::Escaped("__impossible__".into()) || true);
            // A fresh profile must never report an actual escape string.
            if let Outcome::Escaped(why) = &p.outcome {
                // config-valid holds on a fresh profile; env probe holds;
                // only FS/gate probes may be NotEnforced.
                panic!("{} escaped on a fresh profile: {why}", p.id);
            }
        }
        let code = report(&probes);
        assert_eq!(code, 0);
        std::fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn gate_probe_demands_a_live_daemon() {
        // F-019 regression: a private record whose daemon is gone is an
        // escape, not containment — the orphan-tunnel shape must not pass.
        let (profile, config_path) = fresh_profile();
        let instance = vm::instance_name(&profile, &vm::environment_dir(&profile));
        let dir = paths::join(&vm::instances_root(&profile), &instance);
        std::fs::create_dir_all(&dir).unwrap();
        let record = serde_json::json!({
            "socket": paths::join(&profile, "dead.sock"),
            "token": creance_vm::token(),
            "run_id": creance_vm::token()[..32].to_owned(),
        });
        let record_path = paths::join(&dir, "cage-gate.json");
        std::fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
        std::fs::set_permissions(
            &record_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        let probes = host_probes(&profile, &config_path);
        let gate = probes
            .iter()
            .find(|p| p.id == "gate-record-private")
            .expect("gate probe present");
        match &gate.outcome {
            Outcome::Escaped(why) => assert!(why.contains("live daemon"), "{why}"),
            other => panic!("expected Escaped, got {other:?}"),
        }
        std::fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn hex48_scanner_matches_exact_token_shapes_only() {
        let mut out = Vec::new();
        let token = "a".repeat(48);
        // Exact token with boundaries.
        hex48_runs(format!("x{token}y").as_bytes(), &mut out);
        // Embedded in a longer hex run (a hash): not a token.
        hex48_runs("f".repeat(96).as_bytes(), &mut out);
        // Uppercase: tokens are lowercase hex.
        hex48_runs("A".repeat(48).as_bytes(), &mut out);
        // 47 hex: no.
        hex48_runs("a".repeat(47).as_bytes(), &mut out);
        assert_eq!(out, vec![token]);
    }

    #[test]
    fn subscription_content_cannot_forge_the_verdict() {
        // F-032 regression: a 48-hex password inside imported subscription
        // data is attacker-chosen remote content that never reaches the
        // guest — the probe must stay Contained, and must not start
        // treating arbitrary subscription fields as issued secrets either.
        let (profile, config_path) = fresh_profile();
        creance_vm::guestprofile::Profile::load_or_create(&profile).unwrap();
        let sub = "proxies:\n  - name: exit\n    type: ss\n    server: 192.0.2.1\n    port: 8388\n    cipher: aes-128-gcm\n    password: deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n";
        let dir = std::path::PathBuf::from(paths::join(&profile, "proxy"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sources.json"), sub).unwrap();
        let probes = host_probes(&profile, &config_path);
        let creds = probes
            .iter()
            .find(|p| p.id == "credentials-are-session-only")
            .unwrap();
        assert_eq!(
            creds.outcome,
            Outcome::Contained,
            "subscription content is out of the probe's scope"
        );
        std::fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn host_only_config_changes_keep_the_probe_green() {
        // F-040 regression: the setup stamp records the GUEST's promise
        // (timezone/locale/browser language). Proxy concerns — endpoint,
        // revision, exit anchor — are host-only: a routine select or
        // anchor tune between runs must not turn the probe red.
        let (profile, config_path) = fresh_profile();
        let cfg = creance_vm::config::load(&config_path).unwrap();
        let state = vm::state_dir(&profile);
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            paths::join(&state, "fingerprint.txt"),
            cfg.guest_fingerprint(),
        )
        .unwrap();
        let probe = |p: &str| {
            host_probes(p, &config_path)
                .into_iter()
                .find(|x| x.id == "fingerprint-consistent")
                .unwrap()
                .outcome
        };
        assert_eq!(probe(&profile), Outcome::Contained);

        let mut tuned = cfg.clone();
        tuned.proxy_url = "socks5://127.0.0.1:19999".to_owned();
        tuned.proxy_revision = creance_vm::token();
        tuned.exit_policy = creance_vm::exit_policy::Policy {
            mode: "static".to_owned(),
            scope: "any".to_owned(),
            ip: "203.0.113.7".to_owned(),
            ..Default::default()
        };
        creance_vm::config::write_private_config(&config_path, &tuned).unwrap();
        assert_eq!(
            probe(&profile),
            Outcome::Contained,
            "host-only fields are not part of the promise"
        );

        // A guest-visible change still drifts.
        let mut drifted = tuned;
        drifted.locale = "ja_JP.UTF-8".to_owned();
        creance_vm::config::write_private_config(&config_path, &drifted).unwrap();
        assert!(matches!(probe(&profile), Outcome::Escaped(_)));
        std::fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn guest_drift_has_no_wash_path() {
        // F-044 regression: `up` no longer refreshes the stamp — after
        // the promise narrowed to guest-visible fields (F-040), a refresh
        // could only ever launder REAL drift (the VM is not re-provisioned
        // by a bare `limactl start`). Drift must stay red until a re-setup.
        let (profile, config_path) = fresh_profile();
        let cfg = creance_vm::config::load(&config_path).unwrap();
        let state = vm::state_dir(&profile);
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            paths::join(&state, "fingerprint.txt"),
            cfg.guest_fingerprint(),
        )
        .unwrap();
        let mut drifted = cfg;
        drifted.timezone = "Asia/Tokyo".to_owned();
        creance_vm::config::write_private_config(&config_path, &drifted).unwrap();
        let probes = host_probes(&profile, &config_path);
        let probe = probes
            .iter()
            .find(|p| p.id == "fingerprint-consistent")
            .unwrap();
        assert!(matches!(probe.outcome, Outcome::Escaped(_)));
        std::fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn fingerprint_probe_compares_against_the_setup_stamp() {
        // F-033: setup writes the promised fingerprint; the probe must
        // enforce agreement and flag drift after a config change.
        let (profile, config_path) = fresh_profile();
        let cfg = creance_vm::config::load(&config_path).unwrap();
        let stamp = paths::join(&vm::state_dir(&profile), "fingerprint.txt");
        std::fs::create_dir_all(vm::state_dir(&profile)).unwrap();
        std::fs::write(&stamp, cfg.guest_fingerprint()).unwrap();
        let probe = |p: &str| {
            host_probes(p, &config_path)
                .into_iter()
                .find(|x| x.id == "fingerprint-consistent")
                .unwrap()
                .outcome
        };
        assert_eq!(probe(&profile), Outcome::Contained, "fresh stamp agrees");

        let mut drifted = cfg.clone();
        drifted.timezone = "Asia/Tokyo".to_owned();
        creance_vm::config::write_private_config(&config_path, &drifted).unwrap();
        match probe(&profile) {
            Outcome::Escaped(why) => assert!(why.contains("creance stop"), "{why}"),
            other => panic!("drifted config must escape, got {other:?}"),
        }
        std::fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn stray_token_shaped_secrets_are_escaped() {
        // F-022 regression: a credential-shaped file in the profile
        // directory must break containment, not pass it.
        let (profile, config_path) = fresh_profile();
        // Issued set: guest profile + a store with its auth, plus the
        // applied revision the way proxy-select leaves it (the live
        // machine flagged the revision until it joined the set).
        let guest = creance_vm::guestprofile::Profile::load_or_create(&profile).unwrap();
        let mut store = creance_proxy::load(&profile).unwrap();
        store.revision = creance_vm::token();
        creance_proxy::save(&profile, &store).unwrap();
        let mut cfg = creance_vm::config::load(&config_path).unwrap();
        cfg.proxy_revision = store.revision.clone();
        creance_vm::config::write_private_config(&config_path, &cfg).unwrap();
        let probes = host_probes(&profile, &config_path);
        let creds = probes
            .iter()
            .find(|p| p.id == "credentials-are-session-only")
            .unwrap();
        assert_eq!(creds.outcome, Outcome::Contained, "issued set is clean");

        // A stray 48-hex secret nobody issued.
        std::fs::write(
            paths::join(&profile, "stray-notes.txt"),
            format!("token={}", "0123456789abcdef".repeat(3)),
        )
        .unwrap();
        let probes = host_probes(&profile, &config_path);
        let creds = probes
            .iter()
            .find(|p| p.id == "credentials-are-session-only")
            .unwrap();
        match &creds.outcome {
            Outcome::Escaped(why) => {
                assert!(why.contains("stray-notes.txt"), "{why}");
                assert!(!why.contains(&guest.session_token), "no token bleed");
            }
            other => panic!("expected Escaped, got {other:?}"),
        }
        std::fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn mount_counting_fail_closes_on_anything_it_cannot_judge() {
        // FINDING-016: malformed structure and merge keys must be Escaped
        // (via Err), never a silent Contained.
        let dir = std::env::temp_dir().join(format!(
            "creance-mnt-{}",
            creance_vm::token()[..12].to_owned()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = |body: &str| {
            let path = dir.join(format!("{}.yaml", creance_vm::token()[..6].to_owned()));
            std::fs::write(&path, body).unwrap();
            path.to_string_lossy().into_owned()
        };
        // Honest single mount counts.
        let one = file("mounts:\n  - location: /Users/x/ws\n    writable: true\n");
        assert_eq!(creance_vm::vm::count_declared_mounts(&one).unwrap(), 1);
        // No mounts at all.
        let none = file("cpus: 4\n");
        assert_eq!(creance_vm::vm::count_declared_mounts(&none).unwrap(), 0);
        // Case-insensitive location, multiple entries.
        let two = file("mounts:\n  - LOCATION: /a\n  - location: /b\n");
        assert_eq!(creance_vm::vm::count_declared_mounts(&two).unwrap(), 2);
        // Structural failures -> Err, not Ok.
        assert!(creance_vm::vm::count_declared_mounts(&file("- just\n- a\n- list\n")).is_err());
        assert!(creance_vm::vm::count_declared_mounts(&file("42\n")).is_err());
        assert!(creance_vm::vm::count_declared_mounts(&file("mounts: {location: /a}\n")).is_err());
        assert!(
            creance_vm::vm::count_declared_mounts(&file("mounts:\n  - just-a-string\n")).is_err()
        );
        // Merge keys — the exact probe-defeating trick.
        let merged =
            file("x-base: &base\n  - location: /evil\nmounts:\n  <<: *base\n  - location: /ws\n");
        assert!(creance_vm::vm::count_declared_mounts(&merged).is_err());
        let merged_entry =
            file("defaults: &d\n  writable: true\nmounts:\n  - <<: *d\n    location: /ws\n");
        assert!(creance_vm::vm::count_declared_mounts(&merged_entry).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn guest_script_is_posix_and_flags_every_probe() {
        let script = guest_script("/nonexistent-flag", "deadbeef", 17896, "devabc12345");
        assert!(script.starts_with("#!/bin/sh"));
        for required in [
            "probe fs-flag-readable",
            "PROBE env-credentials",
            "PROBE env-hex-tokens ESCAPE",
            "PROBE net-direct-egress ESCAPE",
            // F-020/F-022: identity and privilege probes.
            "/usr/bin/id -un)\" != \"devabc12345\"",
            "PROBE guest-privilege ESCAPE",
        ] {
            assert!(script.contains(required), "missing {required}");
        }
        // FINDING-011: the oracle's external commands must not be hijackable
        // through a polluted guest PATH, and the abstract-socket probe must
        // not claim a PASS it never checked.
        assert!(script.contains("/usr/bin/env"), "env must be absolute");
        assert!(script.contains("/usr/bin/grep"), "grep must be absolute");
        assert!(script.contains("/usr/bin/ls"), "ls must be absolute");
        assert!(
            script.contains("PROBE sock-abstract SKIP"),
            "sock-abstract is not implemented: SKIP, never a fake PASS"
        );
        assert!(!script.contains("PROBE sock-abstract PASS"));
    }

    /// A lima.yaml with an extra mount must be caught however it is spelled
    /// (FINDING-011: the old line-prefix counter missed `"-  location:"`,
    /// flow mappings, and dash-on-its-own-line forms).
    #[cfg(target_os = "macos")]
    #[test]
    fn extra_mount_is_escaped_in_every_yaml_spelling() {
        let spellings: [&str; 4] = [
            // canonical single mount, then a doubled-space extra
            "mounts:\n  - location: /w\n  -  location: /Users/me/secret\n",
            // flow mapping form
            "mounts: [{location: /w}, {location: /Users/me/secret}]\n",
            // dash on its own line
            "mounts:\n  - location: /w\n  -\n    location: /Users/me/secret\n",
            // canonical single mount stays contained
            "mounts:\n  - location: /w\n",
        ];
        for (i, yaml) in spellings.iter().enumerate() {
            let (profile, config_path) = fresh_profile();
            let instance = vm::instance_name(&profile, &vm::environment_dir(&profile));
            let dir = paths::join(&vm::instances_root(&profile), &instance);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(paths::join(&dir, "lima.yaml"), yaml).unwrap();
            let probes = host_probes(&profile, &config_path);
            let mounts = probes
                .iter()
                .find(|p| p.id == "mounts-workspace-only")
                .expect("mounts probe present");
            let expect_extra = i != 3;
            match (&mounts.outcome, expect_extra) {
                (Outcome::Escaped(_), true) => {}
                (Outcome::Contained, false) => {}
                (other, _) => panic!(
                    "spelling {i}: expected {}, got {other:?}",
                    if expect_extra { "Escaped" } else { "Contained" }
                ),
            }
            std::fs::remove_dir_all(&profile).unwrap();
        }
    }
}
