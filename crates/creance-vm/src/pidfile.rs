//! Pid files with start-time binding — "a PID alone is not proof of life".
//!
//! After a reboot or a crash the pid a file records can belong to an
//! unrelated process that reused the number; killing by that pid would hit
//! the wrong victim (FINDING-021). Records therefore carry the process's
//! start-time token, and liveness requires both. Bare-integer files written
//! by older builds keep pid-only semantics.

#![allow(unsafe_code)] // libc sysctl/kill — audited, pid from our own pid file

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct Entry {
    pub pid: i32,
    #[serde(default)]
    pub started: String,
}

/// The recorded process's start-time token: stable across a process's life,
/// different for every launch (even of a reused PID).
#[cfg(target_os = "macos")]
pub fn process_start_token(pid: i32) -> String {
    // kinfo_proc's first field is a union whose overlap member is the
    // process start timeval (tv_sec: i64, tv_usec: i32 on macOS), so the
    // raw sysctl buffer starts with exactly the two values we need.
    unsafe {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
        let mut buf = [0u8; 1024];
        let mut size = buf.len();
        if libc::sysctl(
            mib.as_mut_ptr(),
            4,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return String::new();
        }
        let sec = i64::from_ne_bytes(buf[0..8].try_into().expect("8 bytes"));
        let usec = i32::from_ne_bytes(buf[8..12].try_into().expect("4 bytes"));
        // Epoch zero (or a zero-sized answer) means the lookup found nothing.
        if sec == 0 || size < 12 {
            return String::new();
        }
        format!("{sec} {usec}")
    }
}

/// Linux: the start time is field 22 of `/proc/<pid>/stat` — clock ticks
/// since boot. Stable across a process's life, different for every launch,
/// which is all the guard needs (same contract as the macOS timeval token).
#[cfg(target_os = "linux")]
pub fn process_start_token(pid: i32) -> String {
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(s) => s,
        Err(_) => return String::new(), // no such pid, or hidden by hidepid
    };
    stat_starttime(&stat)
}

#[cfg(target_os = "linux")]
fn stat_starttime(stat: &str) -> String {
    // comm is parenthesized and may itself contain ')' or spaces, so the
    // numbered fields start after the LAST closing paren.
    let Some((_head, rest)) = stat.rsplit_once(')') else {
        return String::new();
    };
    // rest begins at field 3 (state): starttime, field 22, is index 19.
    // Zero means "no start time on record" — treat as unreadable.
    match rest
        .split_whitespace()
        .nth(19)
        .and_then(|t| t.parse::<u64>().ok())
    {
        Some(ticks @ 1..) => ticks.to_string(),
        _ => String::new(),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn process_start_token(_pid: i32) -> String {
    String::new()
}

fn signal_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // EPERM means the process exists but belongs to another user: alive.
    unsafe {
        libc::kill(pid, 0) == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

/// Whether `pid` is a child of the caller that has exited without being
/// waited on; the successful WNOHANG probe also reaps it. Non-children
/// return ECHILD and read as false, leaving the signal check in charge.
fn reaped_zombie(pid: i32) -> bool {
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) == pid }
}

/// Whether `entry` names a live process with the recorded start time.
/// Records without a start token (legacy bare-pid files) keep pid-only
/// semantics; an unreadable start time never fails against ourselves.
///
/// F-027: a zombie — an exited child the caller never waited on — passes
/// kill(pid,0) AND keeps its recorded start token, so both legacy checks
/// lie. The waitpid probe above catches and harvests exactly that case:
/// the gate daemon spawned the tunnel ssh and nobody else reaps it, so a
/// dead tunnel must fall through to "not alive" and let ensure() respawn.
pub fn entry_alive(entry: &Entry) -> bool {
    if reaped_zombie(entry.pid) {
        return false;
    }
    if !signal_alive(entry.pid) {
        return false;
    }
    if entry.started.is_empty() {
        return true;
    }
    let current = process_start_token(entry.pid);
    if current.is_empty() {
        return process_start_token(std::process::id() as i32).is_empty();
    }
    current == entry.started
}

/// Records `pid` and its start-time token in a JSON pid file. The parent
/// directory is created when missing (F-025: a virgin profile has no
/// proxy/ dir yet, and a missing directory must not read as daemon
/// failure).
pub fn write(path: &str, pid: i32) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let entry = Entry {
        pid,
        started: process_start_token(pid),
    };
    std::fs::write(path, serde_json::to_vec(&entry).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

/// Loads a pid file: a JSON entry, or the bare integer older builds wrote.
pub fn load(path: &str) -> Option<Entry> {
    let text = std::fs::read_to_string(path).ok()?;
    if let Ok(entry) = serde_json::from_str::<Entry>(&text) {
        return Some(entry);
    }
    text.trim().parse::<i32>().ok().map(|pid| Entry {
        pid,
        started: String::new(),
    })
}

/// Whether the pid file names a live process with the recorded start time.
pub fn alive(path: &str) -> bool {
    load(path).is_some_and(|e| entry_alive(&e))
}

/// Stops the recorded process (SIGTERM) when the file still proves it is
/// ours — start time included — then removes the file either way. A stale
/// or forged file never signals a victim (FINDING-021).
pub fn stop(path: &str) {
    if let Some(entry) = load(path) {
        if entry_alive(&entry) {
            unsafe {
                libc::kill(entry.pid, libc::SIGTERM);
            }
        }
    }
    let _ = std::fs::remove_file(path);
}

/// True when `path` records `pid` with a matching start time — the probe
/// callers use to decide whether to reuse or respawn.
pub fn owns(path: &str, pid: u32) -> bool {
    load(path).is_some_and(|e| e.pid == pid as i32 && entry_alive(&e))
}

/// The pid file for `name` in a profile's proxy directory.
pub fn proxy_pid_file(profile: &str, name: &str) -> String {
    crate::paths::join(&crate::proxy_dir(profile), name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_file(tag: &str) -> String {
        std::env::temp_dir()
            .join(format!(
                "creance-pid-{}-{}",
                tag,
                crate::token()[..8].to_owned()
            ))
            .to_string_lossy()
            .into_owned()
    }

    fn spawn_sleep() -> std::process::Child {
        std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("sleep available")
    }

    #[test]
    fn zombie_children_read_as_dead_and_get_reaped() {
        // F-027: an exited-but-unwaited child passes kill(pid,0) and keeps
        // its recorded start token — only the waitpid probe catches it,
        // which is what lets the gate daemon's watchdog respawn a dead
        // tunnel instead of short-circuiting on a corpse.
        let file = tmp_file("zomb");
        let mut child = spawn_sleep();
        write(&file, child.id() as i32).unwrap();
        child.kill().unwrap();
        // No wait yet: the kernel holds the exit status (zombie).
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(!alive(&file), "zombie must not read as alive");
        let _ = child.wait();
        assert!(!alive(&file), "reaped process stays dead");
        std::fs::remove_file(&file).unwrap();
    }

    #[test]
    fn roundtrip_alive_then_stop_kills_the_owner() {
        let file = tmp_file("rt");
        let mut victim = spawn_sleep();
        write(&file, victim.id() as i32).unwrap();
        assert!(alive(&file), "fresh entry must be alive");
        assert!(owns(&file, victim.id()));
        stop(&file);
        victim.wait().unwrap();
        assert!(!alive(&file), "stopped process and removed file");
    }

    #[test]
    fn forged_start_token_never_kills_a_victim() {
        // FINDING-021 regression: a pid file whose start token does not match
        // the current holder of that pid must never cause a signal.
        let file = tmp_file("forge");
        let mut victim = spawn_sleep();
        let forged = Entry {
            pid: victim.id() as i32,
            started: "0 0".to_owned(),
        };
        std::fs::write(&file, serde_json::to_vec(&forged).unwrap()).unwrap();
        assert!(!alive(&file), "stale start token must not count as alive");
        stop(&file);
        // The victim must survive and be reaped by us, not by stop().
        let status = victim
            .try_wait()
            .expect("victim queryable")
            .map(|s| s.to_string());
        assert!(status.is_none(), "victim was killed by a forged file");
        let _ = victim.kill();
        let _ = victim.wait();
    }

    #[test]
    fn legacy_bare_pid_files_load_pid_only() {
        let file = tmp_file("legacy");
        std::fs::write(&file, "12345\n").unwrap();
        let entry = load(&file).expect("legacy file loads");
        assert_eq!(entry.pid, 12345);
        assert_eq!(entry.started, "", "legacy entries carry no start token");
        assert!(!alive(&file), "no such process running");
        std::fs::remove_file(&file).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stat_starttime_survives_parens_and_spaces_in_comm() {
        // Field 22 (starttime) must come from after the LAST ')': comm can
        // contain both delimiters (prctl PR_SET_NAME is arbitrary bytes).
        let stat = "42 (weird )comm( na)me) S 1 0 0 0 -1 4194560 100 0 0 0 7 5 0 0 20 0 1 0 988172";
        assert_eq!(stat_starttime(stat), "988172");
        // A plain comm parses to the same field.
        let plain = "7 (sleep) S 1 0 0 0 -1 64 0 0 0 3 2 0 0 20 0 2 0 0 12345";
        assert_eq!(stat_starttime(plain), "12345");
        // Zero means "no start time on record" — treat as unreadable.
        let zero = "7 (sleep) R 1 0 0 0 -1 64 0 0 0 3 2 0 0 20 0 2 0 0 0";
        assert_eq!(stat_starttime(zero), "");
        // Malformed lines never guess.
        assert_eq!(stat_starttime("no parens at all"), "");
        assert_eq!(stat_starttime("1 (x) S"), "");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn own_start_token_is_real_and_stable() {
        // With /proc available the token must be non-empty (arming the
        // PID-reuse guard) and stable within the process's life.
        let pid = std::process::id() as i32;
        let a = process_start_token(pid);
        assert!(!a.is_empty(), "own /proc stat yields a start token");
        assert_eq!(a, process_start_token(pid));
        // A nonexistent pid yields none.
        assert_eq!(process_start_token(i32::MAX), "");
    }
}
