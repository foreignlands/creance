// R5 race probe — standalone rustc binary (workspace crates cannot be
// linked from outside the repo — the zombie-pidfile lesson). The spawn/
// retire/dedup decision logic and pidfile liveness checks are copied
// VERBATIM from crates/creance-gate/src/gate.rs and
// crates/creance-vm/src/pidfile.rs; the daemon under test is the REAL
// release `creance gate-daemon` subprocess, so everything downstream of
// the decision (Gate::start, watchdog, run_daemon loop, disown/drop) is
// production code.
//
// Rounds (fresh temp profile each):
//   r1  race: daemon alive → record removed (close_and_remove essence)
//       → spawn_daemon immediately. VIOLATION if it returns Ok while the
//       end state holds no daemon and no record (dedup hit a dying daemon).
//   r2  control: healthy dedup leaves exactly one daemon + record.
//   r3  control: fresh spawn raises exactly one daemon + record.
//   r4  corrupt record + live daemon: spawn_daemon must retire the corpse,
//       raise a successor, and the old daemon must retire within a tick
//       WITHOUT deleting the successor's record (F-028 disown machinery).
#![allow(unsafe_code, dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn sysctl(
        name: *mut i32,
        namelen: u32,
        oldp: *mut std::ffi::c_void,
        oldlenp: *mut usize,
        newp: *const std::ffi::c_void,
        newlen: usize,
    ) -> i32;
    fn __error() -> *const i32;
}
const CTL_KERN: i32 = 1;
const KERN_PROC: i32 = 14;
const KERN_PROC_PID: i32 = 1;
const EPERM: i32 = 1;
const SIGTERM: i32 = 15;
const WNOHANG: i32 = 1;

// ---- verbatim: pidfile.rs -------------------------------------------------

fn process_start_token(pid: i32) -> String {
    unsafe {
        let mut mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid];
        let mut buf = [0u8; 1024];
        let mut size = buf.len();
        if unsafe {
            sysctl(
                mib.as_mut_ptr(),
                4,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                &mut size,
                std::ptr::null(),
                0,
            )
        } != 0
        {
            return String::new();
        }
        let sec = i64::from_ne_bytes(buf[0..8].try_into().unwrap());
        let usec = i32::from_ne_bytes(buf[8..12].try_into().unwrap());
        if sec == 0 || size < 12 {
            return String::new();
        }
        format!("{sec} {usec}")
    }
}

fn signal_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    unsafe { kill(pid, 0) == 0 || *__error() == EPERM }
}

/// Verbatim: whether pid is the caller's exited-unwaited child. The probe
/// is the parent of the daemons it spawns (never waits mid-round) — the
/// same caller shape as the `up` CLI that just spawned a daemon.
fn reaped_zombie(pid: i32) -> bool {
    unsafe { waitpid(pid, std::ptr::null_mut(), WNOHANG) == pid }
}

fn entry_alive(pid: i32, started: &str) -> bool {
    if reaped_zombie(pid) {
        return false;
    }
    if !signal_alive(pid) {
        return false;
    }
    if started.is_empty() {
        return true;
    }
    let current = process_start_token(pid);
    if current.is_empty() {
        return process_start_token(std::process::id() as i32).is_empty();
    }
    current == started
}

/// pid file: flat {"pid":N,"started":"sec usec"} — parse pid + started.
fn load(path: &str) -> Option<(i32, String)> {
    let text = std::fs::read_to_string(path).ok()?;
    Some((json_num(&text, "pid")?, json_str(&text, "started")))
}

fn alive(path: &str) -> bool {
    load(path).is_some_and(|(pid, started)| entry_alive(pid, &started))
}

/// Minimal flat-JSON string field getter (records are flat, no escapes in
/// our own shapes).
fn json_str(text: &str, key: &str) -> String {
    let pat = format!("\"{key}\"");
    let Some(i) = text.find(&pat) else { return String::new() };
    let rest = &text[i + pat.len()..];
    let Some(c) = rest.find(':') else { return String::new() };
    let rest = rest[c + 1..].trim_start();
    if let Some(r) = rest.strip_prefix('"') {
        r.split('"').next().unwrap_or_default().to_owned()
    } else {
        rest.split(&[',', '}', '\n'][..])
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned()
    }
}

fn json_num(text: &str, key: &str) -> Option<i32> {
    json_str(text, key).trim().parse().ok()
}

// ---- verbatim: gate.rs (record + serving + retire + spawn) -----------------

/// GateRecord fields the probe needs (socket / run_id flat getters).
fn record_socket(text: &str) -> String {
    json_str(text, "socket")
}
fn record_is_gate(text: &str) -> bool {
    json_str(text, "run_id").len() == 32 && json_str(text, "token").len() == 48
}

fn daemon_serving(instance_dir: &str) -> bool {
    let record = Path::new(instance_dir).join("cage-gate.json");
    let Ok(bytes) = std::fs::read(&record) else {
        return false; // no record: nothing serving
    };
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let socket = record_socket(&text);
    if socket.is_empty() {
        return false;
    }
    let addr = match std::os::unix::net::SocketAddr::from_pathname(Path::new(&socket)) {
        Ok(a) => a,
        Err(_) => return false,
    };
    match std::os::unix::net::UnixStream::connect_addr(&addr) {
        Ok(_) => true,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) =>
        {
            false
        }
        Err(_) => true,
    }
}

fn retire_stale_record(instance_dir: &str) -> bool {
    let record = Path::new(instance_dir).join("cage-gate.json");
    if !Path::new(&record).exists() {
        return false;
    }
    if daemon_serving(instance_dir) {
        return false;
    }
    let _ = std::fs::remove_file(&record);
    true
}

fn spawn_daemon(
    exe: &str,
    profile_dir: &str,
    instance: &str,
    config_path: &str,
    instance_dir: &str,
    proxy_port: u16,
) -> Result<(), String> {
    let pid_file = format!("{profile_dir}/proxy/gate.pid");
    if retire_stale_record(instance_dir) {
        let _ = std::fs::remove_file(&pid_file);
    } else if Path::new(&format!("{instance_dir}/cage-gate.json")).exists()
        || alive(&pid_file)
    {
        return Ok(());
    }
    std::fs::create_dir_all(format!("{profile_dir}/proxy")).unwrap();
    let log_path = format!("{profile_dir}/proxy/gate-daemon.log");
    let log = std::fs::OpenOptions::new().create(true).append(true).open(&log_path).ok();
    let child = Command::new(exe)
        .arg("gate-daemon")
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
        })
        .spawn()
        .map_err(|e| format!("cannot spawn gate daemon: {e}"))?;
    std::fs::write(
        &pid_file,
        format!(
            r#"{{"pid":{},"started":"{}"}}"#,
            child.id() as i32,
            process_start_token(child.id() as i32)
        ),
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

// ---- probe harness --------------------------------------------------------

fn wait_record(instance_dir: &str, budget: Duration) -> bool {
    let record = Path::new(instance_dir).join("cage-gate.json");
    let start = Instant::now();
    while start.elapsed() < budget {
        if record.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

fn daemons_for(profile: &str) -> Vec<i32> {
    let out = Command::new("pgrep")
        .arg("-f")
        .arg(format!("gate-daemon {profile} "))
        .output()
        .expect("pgrep");
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .filter_map(|p| p.parse::<i32>().ok())
        .collect()
}

fn prep(profile: &Path) -> (String, String, String, String) {
    let inst_dir = profile.join("lima/inst");
    std::fs::create_dir_all(&inst_dir).unwrap();
    std::fs::create_dir_all(profile.join("proxy")).unwrap();
    std::fs::write(
        profile.join("config.json"),
        r#"{"proxy_url":"socks5://127.0.0.1:17896","dns_url":"https://1.1.1.1/dns-query","timezone":"Etc/UTC","locale":"en_US.UTF-8","browser_language":"en-US"}"#,
    )
    .unwrap();
    (
        profile.to_string_lossy().into_owned(),
        "inst".to_owned(),
        profile.join("config.json").to_string_lossy().into_owned(),
        inst_dir.to_string_lossy().into_owned(),
    )
}

fn cleanup(profile: &str) {
    for pid in daemons_for(profile) {
        unsafe { kill(pid, SIGTERM) };
    }
    std::thread::sleep(Duration::from_millis(700));
    let _ = std::fs::remove_dir_all(profile);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: r5-race-probe <path-to-release-creance>");
        std::process::exit(2);
    }
    let exe = args[1].clone();
    let base: PathBuf = std::env::temp_dir().join(format!("r5-race-{}", std::process::id()));
    let mut violations: Vec<String> = Vec::new();

    // --- r1: the race ------------------------------------------------------
    {
        let (profile, instance, config, inst_dir) = prep(&base.join("r1"));
        spawn_daemon(&exe, &profile, &instance, &config, &inst_dir, 17896).expect("r1 spawn");
        assert!(wait_record(&inst_dir, Duration::from_secs(3)), "r1: no record");
        std::fs::remove_file(format!("{inst_dir}/cage-gate.json")).expect("r1 rm");
        let verdict = spawn_daemon(&exe, &profile, &instance, &config, &inst_dir, 17896);
        println!("r1: spawn_daemon = {verdict:?}");
        std::thread::sleep(Duration::from_millis(1500));
        let record_left = Path::new(&format!("{inst_dir}/cage-gate.json")).exists();
        let daemons = daemons_for(&profile);
        println!("r1: end state record={record_left} daemons={daemons:?}");
        if verdict.is_ok() && !record_left && daemons.is_empty() {
            violations.push("r1: spawn_daemon returned Ok but nothing runs — up-reported success with no daemon (dedup on a dying daemon)".to_owned());
        }
        cleanup(&profile);
    }

    // --- r2: healthy dedup control ----------------------------------------
    {
        let (profile, instance, config, inst_dir) = prep(&base.join("r2"));
        spawn_daemon(&exe, &profile, &instance, &config, &inst_dir, 17896).expect("r2 spawn");
        assert!(wait_record(&inst_dir, Duration::from_secs(3)), "r2: no record");
        let verdict = spawn_daemon(&exe, &profile, &instance, &config, &inst_dir, 17896);
        std::thread::sleep(Duration::from_millis(1200));
        let daemons = daemons_for(&profile);
        println!("r2: spawn_daemon = {verdict:?} daemons={daemons:?}");
        if verdict.is_err() || daemons.len() != 1 {
            violations.push(format!("r2: healthy dedup misbehaved ({verdict:?}, daemons {daemons:?})"));
        }
        cleanup(&profile);
    }

    // --- r3: fresh spawn control ------------------------------------------
    {
        let (profile, instance, config, inst_dir) = prep(&base.join("r3"));
        let verdict = spawn_daemon(&exe, &profile, &instance, &config, &inst_dir, 17896);
        assert!(wait_record(&inst_dir, Duration::from_secs(3)), "r3: no record");
        let daemons = daemons_for(&profile);
        println!("r3: spawn_daemon = {verdict:?} daemons={daemons:?}");
        if verdict.is_err() || daemons.len() != 1 {
            violations.push(format!("r3: fresh spawn misbehaved ({verdict:?}, daemons {daemons:?})"));
        }
        cleanup(&profile);
    }

    // --- r4: corrupt record respawn + successor safety ---------------------
    {
        let (profile, instance, config, inst_dir) = prep(&base.join("r4"));
        spawn_daemon(&exe, &profile, &instance, &config, &inst_dir, 17896).expect("r4 spawn");
        assert!(wait_record(&inst_dir, Duration::from_secs(3)), "r4: no record");
        std::fs::write(format!("{inst_dir}/cage-gate.json"), b"PERSISTENT-GARBAGE\n").unwrap();
        let verdict = spawn_daemon(&exe, &profile, &instance, &config, &inst_dir, 17896);
        std::thread::sleep(Duration::from_millis(1500));
        let record_text = std::fs::read_to_string(format!("{inst_dir}/cage-gate.json")).unwrap_or_default();
        let successor_ok = record_is_gate(&record_text);
        let daemons = daemons_for(&profile);
        println!("r4: spawn_daemon = {verdict:?} daemons={daemons:?} successor_record_ok={successor_ok}");
        if verdict.is_err() || !successor_ok || daemons.len() != 1 {
            violations.push(format!(
                "r4: corrupt-record respawn misbehaved ({verdict:?}, daemons {daemons:?}, record ok {successor_ok})"
            ));
        }
        cleanup(&profile);
    }

    if violations.is_empty() {
        println!("PROBE RESULT: no violations (all invariants held)");
    } else {
        println!("PROBE RESULT: {} violation(s):", violations.len());
        for v in &violations {
            println!("  VIOLATION: {v}");
        }
    }
    let _ = std::fs::remove_dir_all(&base);
}
