//! Shared helpers for integration tests that need a prepared profile on
//! disk.

/// Creates a fresh temporary profile with a valid config.json; returns
/// (profile-dir, config-path).
pub fn fresh_profile() -> (String, String) {
    let profile = std::env::temp_dir()
        .join(format!(
            "cage-wb-{}",
            creance_proxy::token()[..12].to_owned()
        ))
        .to_string_lossy()
        .into_owned();
    std::fs::create_dir_all(&profile).unwrap();
    let config_path = std::path::Path::new(&profile).join("config.json");
    let config = creance_vm::config::default_config();
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    (profile, config_path.to_string_lossy().into_owned())
}
