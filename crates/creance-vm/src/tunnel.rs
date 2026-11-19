//! The guest's single route out: an ssh reverse tunnel carrying the guest's
//! loopback proxy port to the host-side managed core.
//!
//! Lima's usernet NAT refuses RFC1918 destinations from the guest (a sound
//! default that also blocks reaching the host), and vz rejects reverse
//! portForwards — the standard mechanism that survives both is a plain
//! `ssh -R` from the host: the guest dials `127.0.0.1:<port>` and lands on
//! the core's loopback listener. Everything else in the guest is firewalled
//! off (see the provision script), making this tunnel the only wire out.

#![allow(unsafe_code)] // libc::kill orphan reaping — audited, pgrep-matched pids

use crate::paths;
use crate::pidfile;
use std::process::{Command, Stdio};

/// Brings the tunnel up for a running instance (idempotent): a pid file
/// proving a live ssh (start time included, FINDING-021) → reuse; otherwise
/// spawn a fresh `ssh -R`.
pub fn ensure(profile: &str, instance: &str, guest_port: u16) -> Result<(), String> {
    let pid_file = pidfile::proxy_pid_file(profile, "tunnel.pid");
    if pidfile::alive(&pid_file) {
        return Ok(());
    }
    let home = crate::vm::lima_home(profile);
    let out = Command::new("limactl")
        .env("LIMA_HOME", &home)
        .args(["list", "--json"])
        .output()
        .map_err(|e| format!("limactl list failed: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut ssh_port = None;
    for line in text.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if v["name"] == instance {
                ssh_port = v["sshLocalPort"].as_u64().map(|p| p as u16);
                break;
            }
        }
    }
    let Some(port) = ssh_port else {
        return Err(format!("instance {instance} is not running"));
    };
    // F-022: ssh in as the generated guest identity, never the host user
    // name lima would mirror by default.
    let user = crate::guestprofile::Profile::load_or_create(profile)
        .map_err(|e| format!("guest profile unavailable: {e}"))?
        .username;
    let child = Command::new("ssh")
        .arg("-i")
        .arg(paths::join(&home, "_config/user"))
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("StrictHostKeyChecking=yes")
        .arg("-o")
        .arg(format!(
            "UserKnownHostsFile={}",
            paths::join(&home, &format!("{instance}/ssh.known_hosts"))
        ))
        .arg("-o")
        .arg(format!("HostKeyAlias=lima-{instance}"))
        .arg("-o")
        .arg(format!("User={user}"))
        .arg("-o")
        .arg("ControlMaster=no")
        .arg("-o")
        .arg("ControlPath=none")
        .arg("-o")
        .arg("ExitOnForwardFailure=yes")
        .arg("-N")
        .arg("-R")
        .arg(format!("{guest_port}:127.0.0.1:{guest_port}"))
        .arg("-p")
        .arg(port.to_string())
        .arg("127.0.0.1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot spawn ssh tunnel: {e}"))?;
    pidfile::write(&pid_file, child.id() as i32)?;
    // Give the forward a moment to bind before callers probe it.
    std::thread::sleep(std::time::Duration::from_millis(500));
    Ok(())
}

/// Tears the tunnel down (VM stop companion). Never signals a process the
/// pid file cannot prove is ours (start time included, FINDING-021).
pub fn stop(profile: &str) -> Result<(), String> {
    pidfile::stop(&pidfile::proxy_pid_file(profile, "tunnel.pid"));
    Ok(())
}

/// Kills `ssh -R` forwards for `instance` that no pid file owns (F-026:
/// "closed = wire down" must not depend on one file's survival — a pid
/// write that failed, or a deleted file, would leave an orphan serving the
/// guest forever). The match is `HostKeyAlias=lima-<instance>`, a string
/// unique to this instance's tunnel command line, so it cannot hit an
/// unrelated process; the pid the file does own is spared.
pub fn reap_orphans(profile: &str, instance: &str) {
    let Ok(out) = Command::new("pgrep")
        .arg("-f")
        .arg(format!("HostKeyAlias=lima-{instance}"))
        .output()
    else {
        return;
    };
    let owned = pidfile::load(&pidfile::proxy_pid_file(profile, "tunnel.pid"))
        .map(|entry| entry.pid)
        .unwrap_or(-1);
    for pid in String::from_utf8_lossy(&out.stdout).split_whitespace() {
        if let Ok(pid) = pid.parse::<i32>() {
            if pid != owned && pid > 1 {
                unsafe { libc::kill(pid, libc::SIGTERM) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F-026 regression: an orphan carrying the instance signature dies, a
    /// process the pid file owns survives. `tail -f /dev/null <signature>`
    /// keeps the signature visible in its command line the way ssh -o
    /// args do, without needing a real forward.
    #[test]
    fn reap_kills_orphans_but_not_the_owned_tunnel() {
        let profile = std::env::temp_dir()
            .join(format!("creance-tun-{}", crate::token()[..10].to_owned()))
            .to_string_lossy()
            .into_owned();
        std::fs::create_dir_all(crate::proxy_dir(&profile)).unwrap();
        let instance = format!("test-inst-{}", crate::token()[..6].to_owned());
        let signature = format!("HostKeyAlias=lima-{instance}");

        let mut owned = Command::new("tail")
            .args(["-f", "/dev/null", &signature])
            .spawn()
            .unwrap();
        pidfile::write(
            &pidfile::proxy_pid_file(&profile, "tunnel.pid"),
            owned.id() as i32,
        )
        .unwrap();
        let mut orphan = Command::new("tail")
            .args(["-f", "/dev/null", &signature])
            .spawn()
            .unwrap();

        reap_orphans(&profile, &instance);
        std::thread::sleep(std::time::Duration::from_millis(300));

        let orphan_dead = orphan.try_wait().unwrap().is_some();
        let owned_alive = owned.try_wait().unwrap().is_none();
        let _ = owned.kill();
        let _ = owned.wait();
        let _ = orphan.wait();
        assert!(orphan_dead, "orphan must be reaped");
        assert!(owned_alive, "the owned tunnel must survive the sweep");
        std::fs::remove_dir_all(&profile).unwrap();
    }
}
