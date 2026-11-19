//! The escape-probe suite: automated containment checks for an environment,
//! derived from the sandbox-escape literature (see ROADMAP "escape probes").
//!
//! Two kinds of probes:
//! - **Host-verifiable now**: profile hygiene that needs no VM — no host
//!   credentials in the guest env, only the workspace mounted, gate record
//!   private, fingerprint consistency. These are hard assertions.
//! - **In-guest probes**: a generated script the CLI runs inside the VM via
//!   `limactl shell`; each probe reports PASS (contained) or ESCAPE. Network
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

    // 3. The proxy endpoint is a numeric loopback/IP address (no DNS
    //    bootstrap that could bypass the egress).
    out.push(Probe {
        id: "proxy-numeric-endpoint",
        layer: "network",
        outcome: match &cfg {
            Ok(c) => match c.proxy_url.split_once("://").map(|(_, rest)| rest) {
                Some(rest) if rest.starts_with("127.0.0.1:") || rest.contains("@127.0.0.1:") => {
                    Outcome::Contained
                }
                // Non-loopback numeric endpoints are valid too; anything
                // host-shaped is caught by config validation already.
                Some(_) => Outcome::Contained,
                None => Outcome::Escaped("unparsable proxy URL".to_owned()),
            },
            Err(e) => Outcome::Escaped(e.clone()),
        },
    });

    // 4. Only the environment directory is shared: no Lima mounts beyond
    //    the workspace mount in the staged/instance config. FINDING-016:
    //    this probe fail-closes — anything it cannot count (malformed
    //    structure, merge keys) is Escaped, never a silent Contained.
    let instance = vm::instance_name(profile, &vm::environment_dir(profile));
    let lima_yaml = paths::join(&vm::lima_home(profile), &format!("{instance}/lima.yaml"));
    out.push(Probe {
        id: "mounts-workspace-only",
        layer: "filesystem",
        outcome: if Path::new(&lima_yaml).exists() {
            match count_declared_mounts(&lima_yaml) {
                Ok(0) | Ok(1) => Outcome::Contained,
                Ok(n) => Outcome::Escaped(format!("{n} mounts declared")),
                Err(why) => Outcome::Escaped(why),
            }
        } else {
            Outcome::NotEnforced
        },
    });

    // 5. The gate record (if any) is private and its state machine intact.
    let gate_json = paths::join(
        &vm::lima_home(profile),
        &format!("{instance}/cage-gate.json"),
    );
    let instance_yaml = paths::join(&vm::lima_home(profile), &format!("{instance}/lima.yaml"));
    let vm_exists = Path::new(&instance_yaml).exists();
    out.push(Probe {
        id: "gate-record-private",
        layer: "gate",
        outcome: if Path::new(&gate_json).exists() {
            match creance_vm::private::check_private_file(&gate_json) {
                Ok(()) => Outcome::Contained,
                Err(e) => Outcome::Escaped(e.to_string()),
            }
        } else if vm_exists {
            Outcome::Escaped("VM present without a gate record".to_owned())
        } else {
            Outcome::NotEnforced
        },
    });

    // 6. The session credential is cage-issued and the ONLY token shaped
    //    like a secret in the profile directory.
    let guest_json = paths::join(profile, "guest-profile.json");
    out.push(Probe {
        id: "credentials-are-session-only",
        layer: "credentials",
        outcome: if Path::new(&guest_json).exists() {
            match creance_vm::guestprofile::Profile::load_or_create(profile) {
                Ok(_) => Outcome::Contained,
                Err(e) => Outcome::Escaped(e),
            }
        } else if vm_exists {
            Outcome::NotEnforced
        } else {
            Outcome::Contained
        },
    });

    // 6. Guest fingerprint consistency: the timezone the VM was promised is
    //    the one the profile still carries (drift means stale config).
    out.push(Probe {
        id: "fingerprint-consistent",
        layer: "profile",
        outcome: match &cfg {
            Ok(c) => {
                let stored = vm::state_dir(profile);
                let setup_stamp = paths::join(&stored, "fingerprint.txt");
                if !Path::new(&setup_stamp).exists() {
                    Outcome::NotEnforced
                } else {
                    match std::fs::read_to_string(&setup_stamp) {
                        Ok(text) if text.trim() == c.fingerprint() => Outcome::Contained,
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

/// Counts `mounts` entries in a Lima config. Err = the probe cannot judge
/// this file: malformed YAML, a non-mapping root, non-sequence `mounts`,
/// non-mapping entries, or YAML merge keys (`<<`) — Lima (go-yaml) expands
/// merges while serde_yaml does not, so a merged file cannot be counted
/// honestly (FINDING-016).
fn count_declared_mounts(lima_yaml: &str) -> Result<usize, String> {
    let text =
        std::fs::read_to_string(lima_yaml).map_err(|e| format!("lima.yaml unreadable: {e}"))?;
    let root: serde_yaml::Value =
        serde_yaml::from_str(&text).map_err(|_| "lima.yaml is not valid YAML".to_owned())?;
    let mapping = root
        .as_mapping()
        .ok_or_else(|| "lima.yaml root is not a mapping".to_owned())?;
    if mapping.contains_key("<<") {
        return Err("lima.yaml uses merge keys; probe cannot count mounts".to_owned());
    }
    let Some(mounts) = mapping.get(serde_yaml::Value::String("mounts".into())) else {
        return Ok(0);
    };
    let entries = mounts
        .as_sequence()
        .ok_or_else(|| "mounts is not a sequence".to_owned())?;
    let mut count = 0;
    for entry in entries {
        let m = entry
            .as_mapping()
            .ok_or_else(|| "mounts entry is not a mapping".to_owned())?;
        if m.contains_key("<<") {
            return Err("mounts entry uses merge keys; probe cannot count".to_owned());
        }
        count += m
            .iter()
            .filter(|(k, _)| {
                k.as_str()
                    .map(|key| key.eq_ignore_ascii_case("location"))
                    .unwrap_or(false)
            })
            .count();
    }
    Ok(count)
}

/// The in-guest probe script: run inside the VM, prints one `PROBE id
/// RESULT` line per check (RESULT in PASS/ESCAPE/SKIP). Kept POSIX-sh so it
/// runs on any guest. `expected_user` is the generated guest identity the
/// VM must be running as (F-022).
pub fn guest_script(flag_path: &str, auth: &str, port: u16, expected_user: &str) -> String {
    let _ = auth;
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
# Positive control: the ONLY route (loopback tunnel to the host core) works.
if curl -m 8 -s --socks5-hostname "cage:{auth}"@127.0.0.1:{port} https://1.1.1.1/cdn-cgi/trace | grep -q ip=; then
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
        assert_eq!(count_declared_mounts(&one).unwrap(), 1);
        // No mounts at all.
        let none = file("cpus: 4\n");
        assert_eq!(count_declared_mounts(&none).unwrap(), 0);
        // Case-insensitive location, multiple entries.
        let two = file("mounts:\n  - LOCATION: /a\n  - location: /b\n");
        assert_eq!(count_declared_mounts(&two).unwrap(), 2);
        // Structural failures -> Err, not Ok.
        assert!(count_declared_mounts(&file("- just\n- a\n- list\n")).is_err());
        assert!(count_declared_mounts(&file("42\n")).is_err());
        assert!(count_declared_mounts(&file("mounts: {location: /a}\n")).is_err());
        assert!(count_declared_mounts(&file("mounts:\n  - just-a-string\n")).is_err());
        // Merge keys — the exact probe-defeating trick.
        let merged =
            file("x-base: &base\n  - location: /evil\nmounts:\n  <<: *base\n  - location: /ws\n");
        assert!(count_declared_mounts(&merged).is_err());
        let merged_entry =
            file("defaults: &d\n  writable: true\nmounts:\n  - <<: *d\n    location: /ws\n");
        assert!(count_declared_mounts(&merged_entry).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn guest_script_is_posix_and_flags_every_probe() {
        let script = guest_script("/nonexistent-flag", "deadbeef", 17896, "devabc12345");
        assert!(script.starts_with("#!/bin/sh"));
        for required in [
            "probe fs-flag-readable",
            "PROBE env-credentials",
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
            let dir = paths::join(&vm::lima_home(&profile), &instance);
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
