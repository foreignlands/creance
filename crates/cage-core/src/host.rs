//! Host facts the diagnostics need: free disk and total memory.

#[cfg(target_os = "macos")]
pub fn disk_free_bytes(path: &str) -> Result<u64, String> {
    use std::ffi::CString;
    let c = CString::new(path).map_err(|_| "invalid path".to_owned())?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(stat.f_bsize as u64 * stat.f_bavail as u64)
}

#[cfg(target_os = "linux")]
pub fn disk_free_bytes(path: &str) -> Result<u64, String> {
    use std::ffi::CString;
    let c = CString::new(path).map_err(|_| "invalid path".to_owned())?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(stat.f_bsize as u64 * stat.f_bavail as u64)
}

#[cfg(target_os = "macos")]
pub fn total_memory_bytes() -> Result<u64, String> {
    let mut size: u64 = 0;
    let mut len = std::mem::size_of::<u64>();
    let name = b"hw.memsize\0";
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            &mut size as *mut u64 as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(size)
}

#[cfg(target_os = "linux")]
pub fn total_memory_bytes() -> Result<u64, String> {
    for line in std::fs::read_to_string("/proc/meminfo")
        .map_err(|e| e.to_string())?
        .lines()
    {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest
                .trim()
                .trim_end_matches("kB")
                .trim()
                .parse()
                .map_err(|e| format!("meminfo: {e}"))?;
            return Ok(kb * 1024);
        }
    }
    Err("meminfo has no MemTotal".to_owned())
}

pub fn gib(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_and_memory_report_sane_values() {
        let free = disk_free_bytes("/tmp").unwrap();
        let total = total_memory_bytes().unwrap();
        assert!(free > 0, "tmp has free space");
        assert!(total > 1024 * 1024 * 1024, "host has more than 1 GiB");
        assert!(gib(total).ends_with("GiB"));
        #[cfg(target_os = "macos")]
        assert!(disk_free_bytes("/nonexistent-xyz").is_err());
    }
}
