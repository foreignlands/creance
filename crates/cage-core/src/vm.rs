//! VM orchestration through `limactl` with cage's environment hygiene.
//!
//! The Go build embeds Lima as a library; this rewrite drives the `limactl`
//! binary with the same per-profile state directories and the same instance
//! naming, so disks created by the Go build keep working. All proxy and
//! credential environment is stripped before any VM operation.

use crate::paths;
use sha2::{Digest, Sha256};
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;

/// The state directory of a profile: VM markers, Lima home, per-VM records.
pub fn state_dir(profile: &str) -> String {
    paths::join(profile, "state")
}

/// The per-profile Lima home: a short symlink in the temp dir pointing at
/// the real `state/lima`. Lima's instance sockets must fit UNIX_PATH_MAX,
/// and a profile stored in a deep temp path cannot, so — like the Go
/// build's managed storage link — every Lima path goes through the link.
pub fn lima_home(profile: &str) -> String {
    let real = paths::join(&state_dir(profile), "lima");
    let _ = std::fs::create_dir_all(&real);
    let digest = Sha256::digest(paths::clean(profile).as_bytes());
    let link = format!(
        "/tmp/cage-lima-{}-{}",
        users_uid(),
        hex::encode(&digest[..4])
    );
    // Re-create the link when missing or dangling (a cleared temp dir).
    match std::fs::read_link(&link) {
        Ok(_target) if Path::new(&link).exists() => {}
        _ => {
            let _ = std::fs::remove_file(&link);
            let _ = symlink(&real, &link);
        }
    }
    link
}

fn users_uid() -> u32 {
    unsafe { libc::getuid() }
}

/// The Lima instance name of `workspace` in this profile: the hashed folder
/// name cut to the home's socket budget, with recovery of instances created
/// under an earlier (smaller) budget.
pub fn instance_name(profile: &str, workspace: &str) -> String {
    let home = lima_home(profile);
    // The home is the short link: the budget is computed on its literal
    // spelling, which is what Lima's socket paths use.
    let limit = crate::vmname::Limit(crate::vmname::home_limit(&home, true).0);
    let expected = limit.name(workspace);
    if Path::new(&paths::join(&home, &format!("{expected}/lima.yaml"))).exists() {
        return expected;
    }
    // A profile restored from a different path can hold an instance made
    // under a previous socket limit. Only a unique, valid truncation of this
    // exact workspace's name, confirmed by a persistent Lima config, is
    // accepted.
    let suffix: String = expected
        .chars()
        .skip(expected.chars().count().saturating_sub(9))
        .collect();
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&home) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !entry.path().is_dir()
                || !name.ends_with(&suffix)
                || crate::vmname::Limit(name.len()).name(workspace) != name
            {
                continue;
            }
            if !Path::new(&paths::join(&home, &format!("{name}/lima.yaml"))).exists() {
                continue;
            }
            candidates.push(name);
        }
    }
    if candidates.len() == 1 {
        return candidates.pop().expect("one candidate");
    }
    expected
}

/// The single persistent environment of this profile: its transfer directory
/// and the VM instance inside it.
pub fn environment_dir(profile: &str) -> String {
    let saved = paths::join(profile, "environment.json");
    if let Ok(bytes) = std::fs::read_to_string(&saved) {
        #[derive(serde::Deserialize)]
        struct Record {
            directory: String,
        }
        if let Ok(record) = serde_json::from_str::<Record>(&bytes) {
            if Path::new(&record.directory).is_absolute() {
                return record.directory;
            }
        }
    }
    // Workbench-era records name the workspace directly.
    let workbench = paths::join(profile, "workbench.json");
    if let Ok(bytes) = std::fs::read_to_string(&workbench) {
        #[derive(serde::Deserialize)]
        struct Legacy {
            workspace: String,
        }
        if let Ok(legacy) = serde_json::from_str::<Legacy>(&bytes) {
            if Path::new(&legacy.workspace).is_absolute()
                && Path::new(&lima_yaml(profile, &legacy.workspace)).exists()
            {
                return legacy.workspace;
            }
        }
    }
    let previous = format!("{}-workspace", paths::clean(profile));
    if Path::new(&lima_yaml(profile, &previous)).exists() {
        return previous;
    }
    format!("{}-downloads", paths::clean(profile))
}

fn lima_yaml(profile: &str, workspace: &str) -> String {
    let name = crate::vmname::home_limit(&lima_home(profile), false).name(workspace);
    paths::join(&lima_home(profile), &format!("{name}/lima.yaml"))
}

/// The environment no VM operation may inherit: host proxies, credentials,
/// and cage's own state variables.
const STRIPPED: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "FTP_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "ftp_proxy",
    "no_proxy",
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CAGE_LIMA_CACHE_DIR",
    "CAGE_LOGICAL_LIMA_HOME",
    "AGENT_VM_STATE_DIR",
    "AGENT_VM_LIMA_HOME",
    "LIMA_HOME",
];

/// The child environment cage's checks see: everything but [STRIPPED], plus
/// `extra`. Documented and tested here; `limactl` applies the same filter
/// through `env_remove`.
pub fn sanitized_env(extra: &[(&str, String)]) -> Vec<(String, String)> {
    std::env::vars()
        .filter(|(k, _)| !STRIPPED.contains(&k.as_str()))
        .chain(extra.iter().map(|(k, v)| (k.to_string(), v.clone())))
        .collect()
}

fn limactl(profile: &str, args: &[std::ffi::OsString]) -> std::process::Command {
    let mut cmd = Command::new("limactl");
    cmd.env("LIMA_HOME", lima_home(profile));
    for name in STRIPPED {
        cmd.env_remove(name);
    }
    cmd.args(args);
    cmd
}

/// Runs `limactl <args>` in this terminal, inheriting stdio.
pub fn run_attached(profile: &str, args: &[&str]) -> i32 {
    let args: Vec<std::ffi::OsString> = args.iter().map(Into::into).collect();
    match limactl(profile, &args).status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => {
            eprintln!("cannot run limactl: {e}");
            1
        }
    }
}

/// Runs `limactl <args>` capturing output; used by management commands.
pub fn run_captured(profile: &str, args: &[&str]) -> Result<(bool, String), String> {
    let args: Vec<std::ffi::OsString> = args.iter().map(Into::into).collect();
    let out = limactl(profile, &args)
        .output()
        .map_err(|e| e.to_string())?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), text))
}

/// Lists this profile's VMs.
pub fn list(profile: &str) -> i32 {
    run_attached(profile, &["list"])
}

/// Stops the profile's environment VM if it is running.
pub fn stop_vm(profile: &str, instance: &str) -> i32 {
    run_attached(profile, &["stop", instance])
}

/// Opens a shell (or runs a command) inside the environment VM. lima 2.x
/// forwards everything after the instance to the guest; use `bash -c` for
/// flag-shaped arguments.
pub fn shell(profile: &str, instance: &str, command: &[&str]) -> i32 {
    let mut args = vec!["shell", instance];
    args.extend_from_slice(command);
    run_attached(profile, &args)
}

/// Starts the environment VM.
pub fn up(profile: &str, instance: &str) -> i32 {
    run_attached(profile, &["start", instance])
}

/// Creates (provisions) the environment VM's disk from its staged lima.yaml.
/// Lima derives the instance name from the file stem (`<instance>.yaml`).
pub fn create(profile: &str, instance: &str) -> i32 {
    let yaml = paths::join(
        &paths::join(&state_dir(profile), "setup"),
        &format!("{instance}.yaml"),
    );
    run_attached(profile, &["create", &yaml])
}

/// Prints instance diagnostics.
pub fn doctor(profile: &str, _instance: &str) -> i32 {
    match run_captured(profile, &["list", "--format", "json"]) {
        Ok((true, text)) => {
            print!("{text}");
            0
        }
        Ok((false, text)) => {
            eprint!("{text}");
            1
        }
        Err(e) => {
            eprintln!("cannot run limactl: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_strips_proxies_and_credentials() {
        // The test harness does not control the outer env; verify by
        // constructing the filter against injected values.
        std::env::set_var("HTTP_PROXY", "http://corp:3128");
        std::env::set_var("ANTHROPIC_API_KEY", "sk-ant-x");
        let env = sanitized_env(&[]);
        assert!(!env.iter().any(|(k, _)| k == "HTTP_PROXY"));
        assert!(!env.iter().any(|(k, _)| k == "ANTHROPIC_API_KEY"));
        std::env::remove_var("HTTP_PROXY");
        std::env::remove_var("ANTHROPIC_API_KEY");
        // Extra values pass through.
        let env = sanitized_env(&[("LIMA_HOME", "/tmp/lima".to_owned())]);
        assert!(env
            .iter()
            .any(|(k, v)| k == "LIMA_HOME" && v == "/tmp/lima"));
    }

    #[test]
    fn environment_dir_falls_back_to_downloads() {
        let dir = std::env::temp_dir().join(format!("cage-vm-{}", std::process::id()));
        let profile = dir.to_string_lossy().into_owned();
        std::fs::create_dir_all(&profile).unwrap();
        assert_eq!(environment_dir(&profile), format!("{profile}-downloads"));
        std::fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn lima_home_is_a_short_link() {
        let profile = std::env::temp_dir()
            .join(format!(
                "cage-link-{}",
                crate::proxy::token()[..12].to_owned()
            ))
            .to_string_lossy()
            .into_owned();
        let home = lima_home(&profile);
        // Short, hash-spaced link in the temp dir.
        assert!(home.starts_with("/tmp/cage-lima-"), "{home}");
        // It resolves to the real state/lima directory.
        let resolved = std::fs::read_link(&home)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(resolved.ends_with("state/lima"), "{resolved}");
        // Survives a dangling-link scenario (temp cleared, real dir back).
        std::fs::remove_dir_all(&profile).unwrap();
        std::fs::create_dir_all(&resolved).unwrap();
        std::fs::remove_file(&home).ok();
        let again = lima_home(&profile);
        assert!(std::path::Path::new(&again).exists(), "{again}");
        std::fs::remove_dir_all(&profile).unwrap();
        let _ = std::fs::remove_file(&home);
    }
}
