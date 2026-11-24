use creance_vm::config;
use std::path::Path;

/// The default trace check target: a plain endpoint that reports the egress IP.
pub(crate) const CHECK_URL: &str = "https://1.1.1.1/cdn-cgi/trace";
pub(crate) const CHECK_BUDGET: std::time::Duration = std::time::Duration::from_secs(25);

mod identity;
mod plugin;
mod proxy;
mod vm;
pub(crate) use identity::*;
pub(crate) use plugin::*;
pub(crate) use proxy::*;
pub(crate) use vm::*;

pub(crate) fn profile() -> String {
    let path = config::config_path();
    Path::new(&path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_owned())
}

pub(crate) fn instance() -> String {
    let profile = profile();
    creance_vm::vm::instance_name(&profile, &creance_vm::vm::environment_dir(&profile))
}

pub(crate) fn fail(err: String) -> i32 {
    eprintln!("{err}");
    1
}

pub(crate) fn cmd_simple<F: FnOnce() -> Result<(), String>>(f: F) -> i32 {
    match f() {
        Ok(()) => 0,
        Err(e) => fail(e),
    }
}

pub(crate) fn gate_instance_dir() -> String {
    creance_vm::paths::join(&creance_vm::vm::instances_root(&profile()), &instance())
}
