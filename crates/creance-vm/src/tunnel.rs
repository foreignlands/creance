//! The guest's single route out: an ssh reverse tunnel carrying the guest's
//! loopback proxy port to the host-side managed core.
//!
//! The host must reach the guest's sshd (Lima's usernet forward on macOS,
//! the hostfwd carve-out on QEMU), and the wire back is a plain `ssh -R`
//! from the host: the guest dials `127.0.0.1:<port>` and lands on the
//! core's loopback listener. Everything else in the guest is firewalled
//! off (see the provision script), making this tunnel the only wire out.

#![allow(unsafe_code)] // libc::kill orphan reaping — audited, pgrep-matched pids

use crate::pidfile;
use crate::vm;
use std::process::{Command, Stdio};

/// Brings the tunnel up for a running instance (idempotent): a pid file
/// proving a live ssh (start time included, FINDING-021) → reuse; otherwise
/// spawn a fresh `ssh -R`.
pub fn ensure(profile: &str, instance: &str, guest_port: u16) -> Result<(), String> {
    let pid_file = pidfile::proxy_pid_file(profile, "tunnel.pid");
    if pidfile::alive(&pid_file) {
        return Ok(());
    }
    // F-022: ssh in as the generated guest identity, never the host user
    // name a backend would mirror by default. The ssh coordinates (port,
    // key, pinned host key, user) come from the backend.
    let target = vm::ssh_target(profile, instance)?;
    let mut cmd = Command::new("ssh");
    vm::apply_ssh_options(&mut cmd, &target);
    let child = cmd
        .arg("-o")
        .arg("ExitOnForwardFailure=yes")
        .arg("-N")
        .arg("-R")
        .arg(format!("{guest_port}:127.0.0.1:{guest_port}"))
        .arg("127.0.0.1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot spawn ssh tunnel: {e}"))?;
    pidfile::write(&pid_file, child.id() as i32)?;
    // Give the forward a moment to bind before callers probe it.
    std::thread::sleep(std::time::Duration::from_millis(500));
    // F-027: an ssh that died inside the settle window (ExitOnForward-
    // Failure against a still-bound forward, a failed auth) must not read
    // as established — the zombie-aware liveness check makes the next
    // watchdog tick respawn instead of short-circuiting on a corpse.
    if !pidfile::alive(&pid_file) {
        return Err("tunnel ssh exited immediately".to_owned());
    }
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
/// guest forever). The match needs BOTH the instance's HostKeyAlias AND
/// the reverse-forward spec: the alias alone also appears in every
/// interactive `shell` ssh client (learned on the live machine — sessions
/// died mid-command until the sweep was narrowed), while `-R
/// <port>:127.0.0.1:<port>` is ours alone. The pid the file owns is spared.
pub fn reap_orphans(profile: &str, instance: &str, port: u16) {
    let alias = vm::host_key_alias(instance);
    let Ok(out) = Command::new("pgrep")
        .arg("-f")
        .arg(format!("HostKeyAlias={alias}.*-R {port}:127.0.0.1:{port}"))
        .output()
    else {
        return;
    };
    let pid_file = pidfile::proxy_pid_file(profile, "tunnel.pid");
    for pid in String::from_utf8_lossy(&out.stdout).split_whitespace() {
        if let Ok(pid) = pid.parse::<i32>() {
            // Re-read before every kill (F-027): an ensure() may have
            // claimed this pid between the pgrep snapshot and now, and the
            // snapshot's owned value would have us shoot our own fresh
            // tunnel in that race window.
            let owned = pidfile::load(&pid_file)
                .map(|entry| entry.pid)
                .unwrap_or(-1);
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
        let port: u16 = 18765;
        let alias = vm::host_key_alias(&instance);
        let signature = format!("HostKeyAlias={alias} -N -R {port}:127.0.0.1:{port}");

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
        // The interactive-shell shape: alias without the reverse-forward
        // spec. It must never match the sweep.
        let mut shell_client = Command::new("tail")
            .args(["-f", "/dev/null", &format!("HostKeyAlias={alias}")])
            .spawn()
            .unwrap();

        reap_orphans(&profile, &instance, port);
        std::thread::sleep(std::time::Duration::from_millis(300));

        let orphan_dead = orphan.try_wait().unwrap().is_some();
        let owned_alive = owned.try_wait().unwrap().is_none();
        let shell_alive = shell_client.try_wait().unwrap().is_none();
        let _ = owned.kill();
        let _ = owned.wait();
        let _ = orphan.wait();
        let _ = shell_client.kill();
        let _ = shell_client.wait();
        assert!(orphan_dead, "orphan must be reaped");
        assert!(owned_alive, "the owned tunnel must survive the sweep");
        assert!(shell_alive, "a shell-shaped client must never be reaped");
        std::fs::remove_dir_all(&profile).unwrap();
    }
}
