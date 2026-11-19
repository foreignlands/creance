// R4 zombie-pidfile probe — logic copied verbatim from
// crates/creance-vm/src/pidfile.rs (signal_alive / process_start_token /
// entry_alive). Question: does an un-waited child that already exited
// (zombie) read as "alive" to the pid file, letting tunnel::ensure
// short-circuit forever?
#![allow(unsafe_code)]

// Minimal libc surface (avoiding a cargo project for a 60-line probe).
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn sysctl(
        name: *mut i32,
        namelen: u32,
        oldp: *mut std::ffi::c_void,
        oldlenp: *mut std::ffi::c_ulong,
        newp: *const std::ffi::c_void,
        newlen: std::ffi::c_ulong,
    ) -> i32;
}
const EPERM: i32 = 1;

fn signal_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    unsafe {
        let r = kill(pid, 0);
        r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(EPERM)
    }
}

// pidfile.rs process_start_token, verbatim (constants: CTL_KERN=1,
// KERN_PROC=14, KERN_PROC_PID=1 on darwin).
fn process_start_token(pid: i32) -> String {
    unsafe {
        let mut mib = [1i32, 14, 1, pid];
        let mut buf = [0u8; 1024];
        let mut size: std::ffi::c_ulong = buf.len() as std::ffi::c_ulong;
        if sysctl(
            mib.as_mut_ptr(),
            4,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            &mut size,
            std::ptr::null(),
            0,
        ) != 0
        {
            return String::new();
        }
        let sec = i64::from_ne_bytes(buf[0..8].try_into().expect("8 bytes"));
        let usec = i32::from_ne_bytes(buf[8..12].try_into().expect("4 bytes"));
        if sec == 0 || size < 12 {
            return String::new();
        }
        format!("{sec} {usec}")
    }
}

// pidfile.rs entry_alive, verbatim (started = what write() recorded at
// spawn time).
fn entry_alive(pid: i32, started: &str) -> bool {
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

fn main() {
    // 1. Spawn a child that exits immediately, NEVER wait() it — exactly the
    //    treatment tunnel::ensure gives its ssh child (tunnel.rs:82-84).
    let mut child = std::process::Command::new("true")
        .spawn()
        .expect("spawn true");
    let pid = child.id() as i32;
    // What pidfile::write would have recorded moments after spawn.
    let started_at_write = process_start_token(pid);
    println!("pid={pid} started_at_write={started_at_write:?}");

    // Give the child time to exit and become a zombie (parent never reaps).
    std::thread::sleep(std::time::Duration::from_millis(300));

    // 2. Inspect the zombie state.
    let alive = signal_alive(pid);
    let token_now = process_start_token(pid);
    let verdict = entry_alive(pid, &started_at_write);
    println!("after exit: signal_alive={alive} token_now={token_now:?}");
    println!("pidfile::alive equivalent = {verdict}");

    // 3. Cleanup (reap) — the production code never does this.
    let _ = child.wait();

    if verdict {
        println!(
            "VULN CONFIRMED: a zombie child of the caller reads as alive; \
             tunnel::ensure short-circuits on it forever (gate Open, wire dead)."
        );
        std::process::exit(42);
    }
    println!("not vulnerable: zombie judged dead");
}
