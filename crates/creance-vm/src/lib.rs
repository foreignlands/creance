//! creance-vm — host and guest orchestration.
//!
//! The profile (its `config.json` and directory layout), host path and
//! naming semantics, per-VM state markers, running records with PID-reuse
//! guards, host facts, the Lima-driven environment lifecycle on macOS and the native QEMU + cloud-init backend on Linux. Guest
//! fingerprint policy (exit anchoring) lives here too: it is profile data
//! the whole stack reads.

pub mod bundle;
pub mod config;
pub mod exit_policy;
pub mod gateprobe;
pub mod guestprofile;
pub mod host;
pub mod lima;
pub mod paths;
pub mod pidfile;
pub mod private;
pub mod provision;
#[cfg(target_os = "linux")]
pub mod qemu;
pub mod running;

// 平台矩阵是二元的：macOS（Lima/vz）与 Linux（QEMU/KVM）。其余 cfg 分支
// 一律按 `not(macos)` → Linux 后端书写——第三个系统在这里就地编译失败，
// 而不是在某个深处的 qemu 引用上炸出一条误导性错误。
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("creance-vm supports macOS and Linux only");
pub mod tunnel;
pub mod vm;
pub mod vmname;

/// The managed-proxy directory of a profile (tunnel pid lives there).
pub fn proxy_dir(profile: &str) -> String {
    paths::join(profile, "proxy")
}

/// A random hex token (48 hex digits) from the OS CSPRNG.
pub fn token() -> String {
    let mut b = [0u8; 24];
    rand::fill(&mut b);
    hex::encode(b)
}

/// Howard Hinnant's days-to-civil algorithm.
pub fn civil_from_days(days: u64) -> (i64, u32, u32) {
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The current instant in ISO-8601 UTC, civil-date conversion included.
pub fn iso8601_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, m, d) = civil_from_days(secs / 86_400);
    let rem = secs % 86_400;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// Atomically publishes a private file: temp file, fsync, rename.
pub fn write_private_atomic(path: &str, data: &[u8]) -> Result<(), String> {
    let parent = std::path::Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_owned());
    private::ensure_private_dir(&parent).map_err(|e| e.to_string())?;
    let (mut file, tmp) =
        private::create_private_temp(&parent, "cfg").map_err(|e| e.to_string())?;
    use std::io::Write;
    if let Err(e) = file.write_all(data).and_then(|_| file.sync_all()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.to_string());
    }
    drop(file);
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e.to_string()
    })
}
