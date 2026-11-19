//! Private host storage: directories and files only the current user may read.

use std::fs;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Creates host-only storage and removes inherited access.
pub fn ensure_private_dir(path: &str) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let info = symlink_metadata(path)?;
    if !info.is_dir() {
        return Err(io::Error::other("private storage must be a real directory"));
    }
    set_mode(path, 0o700)
}

/// Restricts an existing file or local socket to the current user.
pub fn protect_file(path: &str) -> io::Result<()> {
    set_mode(path, 0o600)
}

/// Rejects non-regular files and access by other local users.
pub fn check_private_file(path: &str) -> io::Result<()> {
    let info = symlink_metadata(path)?;
    if !info.is_file() {
        return Err(io::Error::other("private record must be a regular file"));
    }
    if info.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::other(
            "private record is accessible to other users",
        ));
    }
    Ok(())
}

/// Creates a file in `dir` that only the current user can read, returning its
/// path. The caller publishes it by rename.
pub fn create_private_temp(dir: &str, prefix: &str) -> io::Result<(fs::File, String)> {
    for attempt in 0.. {
        let name = Path::new(dir).join(format!(
            ".{prefix}-{}-{}",
            std::process::id(),
            hex_prefix(attempt as u64 ^ nanos())
        ));
        match fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&name)
        {
            Ok(f) => return Ok((f, name.to_string_lossy().into_owned())),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

fn set_mode(path: &str, mode: u32) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

fn symlink_metadata(path: &str) -> io::Result<fs::Metadata> {
    fs::symlink_metadata(path)
}

fn hex_prefix(v: u64) -> String {
    format!("{v:08x}")
}

fn nanos() -> u64 {
    // Test-temp names must be unique under parallel execution: subsec
    // nanos alone collide when two tests start in the same instant (an
    // intermittent AlreadyExists on macOS CI) — mix in a counter.
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    nanos ^ n.rotate_left(20)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_dir_and_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("cage-test-{}", nanos()));
        let dir_s = dir.to_string_lossy().into_owned();
        ensure_private_dir(&dir_s).unwrap();
        let (mut f, tmp) = create_private_temp(&dir_s, "probe").unwrap();
        use std::io::Write;
        f.write_all(b"x").unwrap();
        drop(f);
        protect_file(&tmp).unwrap();
        check_private_file(&tmp).unwrap();
        assert!(dir_s.starts_with("/tmp") || dir_s.contains("var/folders"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn check_rejects_group_readable() {
        let dir = std::env::temp_dir().join(format!("cage-test-{}", nanos()));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("f");
        std::fs::write(&file, b"x").unwrap();
        set_mode(file.to_str().unwrap(), 0o644).unwrap();
        let err = check_private_file(file.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("accessible to other users"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
