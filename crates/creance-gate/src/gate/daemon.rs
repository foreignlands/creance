use super::*;

/// Spawns the gate daemon detached from the calling CLI process: it holds
/// the GateHandle (socket, watchdog, tunnel coupling) for the environment's
/// lifetime. Fails cleanly when a daemon is already alive for this profile.
pub fn spawn_daemon(
    profile_dir: &str,
    instance: &str,
    config_path: &str,
    instance_dir: &str,
    proxy_port: u16,
) -> Result<(), String> {
    let pid_file = creance_vm::pidfile::proxy_pid_file(profile_dir, "gate.pid");
    // A record proves a daemon only while that daemon still serves its
    // socket (F-019: after SIGKILL or a reboot the record outlives the
    // process, and dedup-on-existence silently disabled every later `up`
    // while an orphan tunnel kept the wire open).
    if retire_stale_record(instance_dir) {
        // Stale: retire the leftovers — pid file and any orphan ssh -R the
        // dead watchdog can no longer cut — and raise a fresh daemon below.
        let _ = std::fs::remove_file(&pid_file);
        let _ = creance_vm::tunnel::stop(profile_dir);
        creance_vm::tunnel::reap_orphans(profile_dir, instance, proxy_port);
    } else if Path::new(&creance_vm::paths::join(instance_dir, "cage-gate.json")).exists() {
        // A record that survived the retire check has a serving daemon.
        return Ok(());
    } else if creance_vm::pidfile::alive(&pid_file) {
        // F-035: a live pid with no record means the daemon is either just
        // starting (its record is a rename away) or already dying (its
        // record was removed, the exit tick is pending). Deduping here
        // reported success while the end state had no daemon and no
        // record. Waiting one tick separates them: the fresh one publishes
        // its record, the dying one exits and its pid file dies with it.
        for _ in 0..3 {
            std::thread::sleep(Duration::from_millis(400));
            if Path::new(&creance_vm::paths::join(instance_dir, "cage-gate.json")).exists()
                && daemon_serving(instance_dir)
            {
                return Ok(());
            }
        }
        // Fall through to a fresh spawn; if the old daemon is somehow still
        // retiring, the run_id ownership handoff (F-028) sorts the overlap.
    }
    let exe = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .to_string_lossy()
        .into_owned();
    use std::process::{Command, Stdio};
    // F-025: a virgin profile has no proxy/ directory yet — create it
    // before touching the log or the pid file, or a healthy spawn reads
    // back as ENOENT failure.
    creance_vm::private::ensure_private_dir(&creance_vm::proxy_dir(profile_dir))
        .map_err(|e| e.to_string())?;
    let log = creance_vm::paths::join(&creance_vm::proxy_dir(profile_dir), "gate-daemon.log");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .ok();
    let mut cmd = Command::new(exe);
    cmd.arg("gate-daemon")
        .arg(profile_dir)
        .arg(instance)
        .arg(config_path)
        .arg(instance_dir)
        .arg(proxy_port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(match &log {
            Some(f) => Stdio::from(f.try_clone().map_err(|e| e.to_string())?),
            None => Stdio::null(),
        });
    // Same daemon discipline the proxy relay got: the daemon outlives the
    // CLI, so it inherits nothing of the caller's shell (hygiene) and sits
    // in its own process group (a terminal hangup must not reach it).
    creance_vm::vm::strip_env(&mut cmd);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }
    let child = cmd
        .spawn()
        .map_err(|e| format!("cannot spawn gate daemon: {e}"))?;
    creance_vm::pidfile::write(&pid_file, child.id() as i32)?;
    Ok(())
}

/// Whether the daemon a record names is still serving its socket, on
/// connect-level evidence only (F-029): a frozen, loaded, or slow daemon
/// still accepts connections and must never be retired — a status call
/// timing out says "slow", not "dead", and acting on it mutinied healthy
/// daemons (record deleted, live tunnel cut, replacement spawned). Only a
/// refused or vanished socket proves death; anything inconclusive counts
/// as alive.
pub(crate) fn daemon_serving(instance_dir: &str) -> bool {
    let record = creance_vm::paths::join(instance_dir, "cage-gate.json");
    let Ok(bytes) = std::fs::read(&record) else {
        return false; // no record: nothing serving
    };
    let socket = serde_json::from_slice::<GateRecord>(&bytes)
        .ok()
        .map(|r| r.socket)
        .unwrap_or_default();
    if socket.is_empty() {
        return false;
    }
    let Ok(addr) = std::os::unix::net::SocketAddr::from_pathname(&socket) else {
        return false;
    };
    // Local unix connects complete or refuse immediately (R4's filler kept
    // 200 connections queued against a healthy daemon and every connect
    // still returned), so connect_addr is the whole probe.
    match std::os::unix::net::UnixStream::connect_addr(&addr) {
        Ok(_) => true,
        // The socket file outlived its listener: refused or gone.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) =>
        {
            false
        }
        // Anything else inconclusive: do not mutiny.
        Err(_) => true,
    }
}

/// Removes a record whose daemon no longer serves it (F-019: SIGKILL and
/// reboots leave records behind; existence alone must never pass for a
/// working gate; F-029: only connect-level death counts). True when a
/// stale record was retired.
pub(crate) fn retire_stale_record(instance_dir: &str) -> bool {
    let record = creance_vm::paths::join(instance_dir, "cage-gate.json");
    if !Path::new(&record).exists() {
        return false;
    }
    if daemon_serving(instance_dir) {
        return false;
    }
    let _ = std::fs::remove_file(&record);
    true
}

/// The `creance gate-daemon` body: hold the gate until its record vanishes
/// (host-side close/removal — `close_and_remove` and `close_gates` both
/// remove it, which retires the daemon) or the process is signaled.
///
/// F-028: the loop also binds to the record's *identity*. Two daemons can
/// coexist for a moment (a spawn race, a concurrent `up`, or a direct
/// `gate-daemon` invocation); the record's rename is atomic, so the last
/// writer wins and every loser must notice that the record's run_id is no
/// longer theirs — and leave WITHOUT touching the wire, which the winner
/// now owns. Before this, a loser lived forever on "a record exists" while
/// its Closed-state watchdog murdered the winner's tunnel every 500ms:
pub fn run_daemon(
    profile_dir: &str,
    instance: &str,
    config_path: &str,
    instance_dir: &str,
    proxy_port: u16,
) -> i32 {
    let handle = match Gate::start(instance_dir, config_path, profile_dir, instance, proxy_port) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("gate daemon: {e}");
            return 1;
        }
    };
    let mine = handle.record.run_id.clone();
    let record = creance_vm::paths::join(instance_dir, "cage-gate.json");
    let mut replaced = false;
    loop {
        std::thread::sleep(Duration::from_millis(500));
        match std::fs::read(&record) {
            Ok(bytes) => {
                match serde_json::from_slice::<GateRecord>(&bytes) {
                    Ok(canonical) if canonical.run_id == mine => {}
                    // Someone else's record: we were renamed over. Retire
                    // quietly — no tunnel stop, no reap; the wire belongs
                    // to the canonical daemon now.
                    Ok(_) => {
                        replaced = true;
                        break;
                    }
                    // Unreadable for now: do not act on one bad read (a
                    // concurrent rename can be observed mid-flight).
                    Err(_) => continue,
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break, // retired
            Err(_) => continue, // transient — retry next tick
        }
    }
    let bridge_port = handle.record.tcp_port;
    handle.gate.shutdown();
    if replaced {
        // Leave the winner's record (and wire) standing: dropping a
        // disowned handle stops only this gate's own server and socket.
        handle.disown();
    }
    drop(handle);
    if replaced {
        return 0;
    }
    let _ = creance_vm::tunnel::stop(profile_dir);
    let _ = creance_vm::tunnel::stop_named(profile_dir, "gatebridge");
    creance_vm::tunnel::reap_orphans(profile_dir, instance, proxy_port);
    if bridge_port != 0 {
        creance_vm::tunnel::reap_orphans(profile_dir, instance, bridge_port);
    }
    0
}
