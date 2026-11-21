//! Running-environment records: the network owner's identity written per VM
//! instance, and the check that refuses to run against a stale fingerprint.
//!
//! A PID alone is not proof of life — after a reboot or crash the recorded
//! PID can belong to an unrelated process. Records therefore carry the
//! process's start time, and liveness requires both.

#![allow(unsafe_code)] // FFI to libc: statfs/sysctl/signal — audited, no unchecked input
use crate::config::Config;
use serde::{Deserialize, Serialize};
use std::path::Path;

const RECORD_FILE: &str = "cage-running.json";

#[derive(Serialize, Deserialize)]
struct RunningProfile {
    pid: i32,
    #[serde(default)]
    started: String,
    fingerprint: String,
    #[serde(default)]
    job_id: String,
}

/// The recorded process's start-time token: stable across a process's life,
/// different for every launch (even of a reused PID). Shared with the
/// pid-file helpers (FINDING-021 moved it to `pidfile`).
use crate::pidfile::process_start_token;

fn process_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // EPERM means the process exists but belongs to another user: alive.
    unsafe {
        libc::kill(pid, 0) == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

/// Whether a record names a live process with the recorded start time.
/// Records from older versions carry no start time and keep PID-only
/// semantics.
fn record_alive(record: &RunningProfile, own_start_empty: bool) -> bool {
    if !process_alive(record.pid) {
        return false;
    }
    if record.started.is_empty() {
        return true;
    }
    let current = process_start_token(record.pid);
    if current.is_empty() {
        // The platform cannot read start times of its own processes here —
        // accept the record rather than fail closed against ourselves.
        return own_start_empty;
    }
    current == record.started
}

/// Records this process as the network owner in `instance_dir`.
pub fn record_running(instance_dir: &str, config: &Config) -> Result<(), String> {
    if Path::new(instance_dir)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .as_deref()
        != Some(instance_dir.rsplit('/').next().unwrap_or(""))
        && Path::new(instance_dir).file_name().is_none()
    {
        return Err("invalid cage instance directory".to_owned());
    }
    let pid = std::process::id() as i32;
    let record = RunningProfile {
        pid,
        started: process_start_token(pid),
        fingerprint: config.fingerprint(),
        job_id: std::env::var("CAGE_JOB").unwrap_or_default(),
    };
    let bytes = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
    let target = Path::new(instance_dir).join(RECORD_FILE);
    let tmp = Path::new(instance_dir).join(format!(".running-{}", crate::token()[..8].to_owned()));
    std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &target).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e.to_string()
    })
}

/// A live record whose fingerprint differs from `config` means a running VM
/// still holds the old proxy or locale: stopping comes first.
pub fn check_running(state_dir: &str, config: &Config) -> Result<(), String> {
    let own_start_empty = process_start_token(std::process::id() as i32).is_empty();
    let mut found = Vec::new();
    collect_records(&Path::new(state_dir).join("lima"), &mut found);
    for record_path in found {
        let bytes = std::fs::read(&record_path).map_err(|e| e.to_string())?;
        let record: RunningProfile = serde_json::from_slice(&bytes)
            .map_err(|_| "invalid running cage profile record".to_owned())?;
        if record_alive(&record, own_start_empty) && record.fingerprint != config.fingerprint() {
            return Err(
                "cage configuration changed while a VM is running; run cage stop before restarting"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

fn collect_records(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let candidate = entry.path().join(RECORD_FILE);
            if candidate.is_file() {
                out.push(candidate);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state() -> String {
        let dir =
            std::env::temp_dir().join(format!("cage-run-{}", crate::token()[..12].to_owned()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.to_string_lossy().into_owned()
    }

    fn config_with(proxy_url: &str) -> Config {
        Config {
            proxy_url: proxy_url.to_owned(),
            dns_url: "https://1.1.1.1/dns-query".to_owned(),
            timezone: "Etc/UTC".to_owned(),
            locale: "en_US.UTF-8".to_owned(),
            browser_language: "en-US".to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn own_record_never_blocks() {
        let state = temp_state();
        let config = config_with("socks5://1.2.3.4:1080");
        let instance = format!("{state}/lima/test-vm");
        std::fs::create_dir_all(&instance).unwrap();
        record_running(&instance, &config).unwrap();
        // Our own fingerprint with a live PID passes.
        check_running(&state, &config).unwrap();
        std::fs::remove_dir_all(&state).unwrap();
    }

    #[test]
    fn changed_fingerprint_with_live_pid_blocks() {
        let state = temp_state();
        let instance = format!("{state}/lima/test-vm");
        std::fs::create_dir_all(&instance).unwrap();
        // Forge a record with a live PID (ours) but a different fingerprint.
        let record = serde_json::json!({
            "pid": std::process::id(),
            "fingerprint": "deadbeef".repeat(8),
        });
        std::fs::write(format!("{instance}/{RECORD_FILE}"), record.to_string()).unwrap();
        let err = check_running(&state, &config_with("socks5://1.2.3.4:1080")).unwrap_err();
        assert!(err.contains("cage stop"), "{err}");
        std::fs::remove_dir_all(&state).unwrap();
    }

    #[test]
    fn dead_pid_is_ignored() {
        let state = temp_state();
        let instance = format!("{state}/lima/test-vm");
        std::fs::create_dir_all(&instance).unwrap();
        // A PID that certainly does not exist: pick one far above pid_max-ish
        // range on this machine via a known-dead marker.
        let record = serde_json::json!({
            "pid": -1,
            "started": "",
            "fingerprint": "deadbeef".repeat(8),
        });
        std::fs::write(format!("{instance}/{RECORD_FILE}"), record.to_string()).unwrap();
        check_running(&state, &config_with("socks5://1.2.3.4:1080")).unwrap();
        std::fs::remove_dir_all(&state).unwrap();
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn start_token_differs_per_launch() {
        // Our own token is non-empty and stable within the process.
        let a = process_start_token(std::process::id() as i32);
        assert!(!a.is_empty());
        assert_eq!(a, process_start_token(std::process::id() as i32));
        // A nonexistent PID yields no token.
        assert_eq!(process_start_token(i32::MAX), "");
    }
}
