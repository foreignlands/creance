//! The guest's single route out: an ssh reverse tunnel carrying the guest's
//! loopback proxy port to the host-side managed core.
//!
//! Lima's usernet NAT refuses RFC1918 destinations from the guest (a sound
//! default that also blocks reaching the host), and vz rejects reverse
//! portForwards — the standard mechanism that survives both is a plain
//! `ssh -R` from the host: the guest dials `127.0.0.1:<port>` and lands on
//! the core's loopback listener. Everything else in the guest is firewalled
//! off (see the provision script), making this tunnel the only wire out.

#![allow(unsafe_code)] // libc::kill signal delivery — audited, pid from our own pid file

use crate::paths;
use std::process::{Command, Stdio};

/// Brings the tunnel up for a running instance (idempotent): alive pid →
/// probe → reuse; otherwise spawn a fresh `ssh -R`.
pub fn ensure(profile: &str, instance: &str, guest_port: u16) -> Result<(), String> {
    let pid_file = tunnel_pid_file(profile);
    if let Some(pid) = read_pid(&pid_file) {
        if alive(pid) {
            return Ok(());
        }
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
    std::fs::write(&pid_file, child.id().to_string()).map_err(|e| e.to_string())?;
    // Give the forward a moment to bind before callers probe it.
    std::thread::sleep(std::time::Duration::from_millis(500));
    Ok(())
}

/// Tears the tunnel down (VM stop companion).
pub fn stop(profile: &str) -> Result<(), String> {
    let pid_file = tunnel_pid_file(profile);
    if let Some(pid) = read_pid(&pid_file) {
        if alive(pid) {
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
        }
    }
    let _ = std::fs::remove_file(&pid_file);
    Ok(())
}

fn read_pid(pid_file: &str) -> Option<i32> {
    std::fs::read_to_string(pid_file)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
}

fn tunnel_pid_file(profile: &str) -> String {
    paths::join(&crate::proxy_dir(profile), "tunnel.pid")
}

fn alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    unsafe { libc::kill(pid, 0) == 0 }
}

/// The guest user lima provisions (host user name; lima mirrors it).
fn vsock_user() -> String {
    std::env::var("USER").unwrap_or_else(|_| "lima".to_owned())
}
