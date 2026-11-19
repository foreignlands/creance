//! The guest's single route out: an ssh reverse tunnel carrying the guest's
//! loopback proxy port to the host-side managed core.
//!
//! Lima's usernet NAT refuses RFC1918 destinations from the guest (a sound
//! default that also blocks reaching the host), and vz rejects reverse
//! portForwards — the standard mechanism that survives both is a plain
//! `ssh -R` from the host: the guest dials `127.0.0.1:<port>` and lands on
//! the core's loopback listener. Everything else in the guest is firewalled
//! off (see the provision script), making this tunnel the only wire out.

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
    let user = vsock_user();
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

/// The guest user lima provisions (host user name; lima mirrors it).
fn vsock_user() -> String {
    std::env::var("USER").unwrap_or_else(|_| "lima".to_owned())
}
