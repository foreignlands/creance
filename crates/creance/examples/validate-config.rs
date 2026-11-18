//! Validates the generated mihomo config with the real bundled core:
//! `cargo run -p cage-core --example validate-config <profile-dir>`
//!
//! Requires `scripts/fetch-proxy-core.sh` to have installed the core at
//! `target/proxy-core/mihomo`. This exercises the same code path as
//! `proxy::service::validate` without touching launchd.

fn main() -> Result<(), String> {
    let profile = std::env::args()
        .nth(1)
        .ok_or("usage: validate-config <profile-dir>")?;
    let store = creance_proxy::load(&profile)?;
    let yaml = store.runtime_yaml(&profile)?;
    let path = std::env::temp_dir().join("cage-validate.yaml");
    std::fs::write(&path, &yaml).map_err(|e| e.to_string())?;
    let core = "target/proxy-core/mihomo";
    let out = std::process::Command::new(core)
        .args([
            "-t",
            "-d",
            &creance_proxy::dir(&profile),
            "-f",
            path.to_string_lossy().as_ref(),
        ])
        .output()
        .map_err(|e| format!("cannot run {core}: {e}"))?;
    println!(
        "mihomo -t exit={} \nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let _ = std::fs::remove_file(&path);
    if out.status.success() {
        Ok(())
    } else {
        Err("the bundled core rejected the generated configuration".to_owned())
    }
}
