//! VM orchestration with cage's environment hygiene.
//!
//! macOS drives the `limactl` binary (Lima, vz) with the same per-profile
//! state directories and the same instance naming as the Go build; Linux
//! drives QEMU + cloud-init natively (see [`crate::qemu`]). This module
//! owns the shared spine both backends sit on: profile state layout,
//! instance naming, the stripped environment, and the platform dispatch.

#![allow(unsafe_code)] // FFI to libc: statfs/sysctl/signal — audited, no unchecked input
use crate::paths;
#[cfg(target_os = "macos")]
use sha2::{Digest, Sha256};
use std::path::Path;

/// The state directory of a profile: VM markers, instance home, per-VM records.
pub fn state_dir(profile: &str) -> String {
    paths::join(profile, "state")
}

/// What a fresh environment is built from — backend-neutral.
#[derive(Clone, Debug)]
pub struct SetupOptions {
    /// RAM in GiB.
    pub memory_gib: u32,
    pub cpus: u32,
    /// Disk in GiB.
    pub disk_gib: u32,
    /// Host folder mounted into the VM as the workspace.
    pub workspace: String,
    /// Guest fingerprint settings, taken from the profile config.
    pub timezone: String,
    pub locale: String,
    pub browser_language: String,
    /// Generated guest identity (hostname/username/session token).
    pub guest: crate::guestprofile::Profile,
}

impl Default for SetupOptions {
    fn default() -> Self {
        SetupOptions {
            memory_gib: 8,
            cpus: 4,
            disk_gib: 24,
            workspace: String::new(),
            timezone: "Etc/UTC".to_owned(),
            locale: "en_US.UTF-8".to_owned(),
            browser_language: "en-US".to_owned(),
            guest: crate::guestprofile::Profile::generate(),
        }
    }
}

/// Everything an ssh-based consumer (tunnel, escape probes, shell) needs to
/// reach the guest — the backend-neutral form of Lima's `sshLocalPort`,
/// `_config/user` key and per-instance known_hosts.
#[derive(Clone, Debug)]
pub struct SshTarget {
    /// Host-side port the guest's sshd answers on (hostfwd on QEMU, Lima's
    /// random local port on macOS).
    pub port: u16,
    /// The generated guest identity (never the host account's name).
    pub user: String,
    /// Private key path.
    pub key: String,
    /// Per-instance known_hosts pinning file.
    pub known_hosts: String,
    /// HostKeyAlias so pinning survives IP/port changes.
    pub host_key_alias: String,
}

/// The root every instance of this profile lives under — gate records,
/// running records and per-VM state sit beside the backend's own files.
pub fn instances_root(profile: &str) -> String {
    #[cfg(target_os = "macos")]
    {
        lima_home(profile)
    }
    #[cfg(not(target_os = "macos"))]
    {
        paths::join(&state_dir(profile), "qemu")
    }
}

/// The file whose existence proves an instance was set up by this profile.
pub fn instance_marker(profile: &str, instance: &str) -> String {
    #[cfg(target_os = "macos")]
    {
        paths::join(&lima_home(profile), &format!("{instance}/lima.yaml"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        paths::join(
            &instances_root(profile),
            &format!("{instance}/instance.json"),
        )
    }
}

/// The instance name of `workspace` in this profile: the hashed folder name
/// cut to the home's socket budget, with recovery of instances created under
/// an earlier (smaller) budget.
pub fn instance_name(profile: &str, workspace: &str) -> String {
    let home = instances_root(profile);
    // Instance names budget socket paths on the PHYSICAL home directory (the
    // macOS symlink is resolved by limactl; QEMU's unix sockets live under
    // the real path), so the limit derives from the canonical spelling.
    let physical = std::path::Path::new(&home)
        .canonicalize()
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_else(|_| home.clone());
    let limit = crate::vmname::Limit(crate::vmname::home_limit(&physical, true).0);
    let expected = limit.name(workspace);
    if Path::new(&instance_marker(profile, &expected)).exists() {
        return expected;
    }
    // A profile restored from a different path can hold an instance made
    // under a previous socket limit. Only a unique, valid truncation of this
    // exact workspace's name, confirmed by a persistent instance marker, is
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
            if !Path::new(&instance_marker(profile, &name)).exists() {
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
            let name =
                crate::vmname::home_limit(&instances_root(profile), false).name(&legacy.workspace);
            if Path::new(&legacy.workspace).is_absolute()
                && Path::new(&instance_marker(profile, &name)).exists()
            {
                return legacy.workspace;
            }
        }
    }
    let previous = format!("{}-workspace", paths::clean(profile));
    let name = crate::vmname::home_limit(&instances_root(profile), false).name(&previous);
    if Path::new(&instance_marker(profile, &name)).exists() {
        return previous;
    }
    format!("{}-downloads", paths::clean(profile))
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
/// through `env_remove`, and QEMU/ssh children get it applied by us.
pub fn sanitized_env(extra: &[(&str, String)]) -> Vec<(String, String)> {
    std::env::vars()
        .filter(|(k, _)| !STRIPPED.contains(&k.as_str()))
        .chain(extra.iter().map(|(k, v)| (k.to_string(), v.clone())))
        .collect()
}

/// Applies [STRIPPED] to a Command the way [`sanitized_env`] documents.
pub fn strip_env(cmd: &mut std::process::Command) {
    for name in STRIPPED {
        cmd.env_remove(name);
    }
}

// ---------------------------------------------------------------------------
// macOS: the Lima backend (drives `limactl`)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    /// The per-profile Lima home: a short symlink in the temp dir pointing at
    /// the real `state/lima`. Lima's instance sockets must fit UNIX_PATH_MAX,
    /// and a profile stored in a deep temp path cannot, so — like the Go
    /// build's managed storage link — every Lima path goes through the link.
    pub fn lima_home(profile: &str) -> String {
        let real = paths::join(&state_dir(profile), "lima");
        let _ = std::fs::create_dir_all(&real);
        let digest = Sha256::digest(paths::clean(profile).as_bytes());
        let link = format!("/tmp/vmhome-{}-{}", users_uid(), hex::encode(&digest[..4]));
        // Re-create the link when missing or dangling (a cleared temp dir).
        match std::fs::read_link(&link) {
            Ok(_target) if Path::new(&link).exists() => {}
            _ => {
                let _ = std::fs::remove_file(&link);
                let _ = std::os::unix::fs::symlink(&real, &link);
            }
        }
        link
    }

    fn users_uid() -> u32 {
        unsafe { libc::getuid() }
    }

    pub fn limactl(profile: &str, args: &[std::ffi::OsString]) -> std::process::Command {
        let mut cmd = std::process::Command::new("limactl");
        // Strip the inherited environment FIRST, then inject ours: env_remove
        // clears any earlier env() of the same name, and LIMA_HOME itself sits
        // in STRIPPED — setting it before the strip loop silently deleted it,
        // sending every VM operation to the global ~/.lima (FINDING-010).
        strip_env(&mut cmd);
        cmd.env("LIMA_HOME", lima_home(profile));
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
}

// The glob is the API surface: `lima_home` (and friends) were top-level
// `pub fn`s before the backend split, and lima.rs plus the harness
// regression tools still reach them as `vm::lima_home`. A private glob
// re-export is invisible across modules — macOS failed to compile while
// the Linux CI stayed green, blind to cfg'd-out code it never built.
#[cfg(target_os = "macos")]
pub use imp::*;

/// Lists this profile's VMs.
pub fn list(profile: &str) -> i32 {
    #[cfg(target_os = "macos")]
    {
        run_attached(profile, &["list"])
    }
    #[cfg(not(target_os = "macos"))]
    {
        crate::qemu::list(profile)
    }
}

/// Stops the profile's environment VM if it is running.
pub fn stop_vm(profile: &str, instance: &str) -> i32 {
    #[cfg(target_os = "macos")]
    {
        run_attached(profile, &["stop", instance])
    }
    #[cfg(not(target_os = "macos"))]
    {
        crate::qemu::stop_vm(profile, instance)
    }
}

/// Opens a shell (or runs a command) inside the environment VM.
pub fn shell(profile: &str, instance: &str, command: &[&str]) -> i32 {
    #[cfg(target_os = "macos")]
    {
        let mut args = vec!["shell", instance];
        args.extend_from_slice(command);
        run_attached(profile, &args)
    }
    #[cfg(not(target_os = "macos"))]
    {
        crate::qemu::shell(profile, instance, command)
    }
}

/// Runs `sh -s` inside the guest with `script` on stdin, capturing stdout —
/// the escape suite's transport. The child sees the stripped environment.
pub fn guest_script(profile: &str, instance: &str, script: &str) -> Result<String, String> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut cmd = Command::new("limactl");
        strip_env(&mut cmd);
        cmd.env("LIMA_HOME", lima_home(profile));
        cmd.args(["shell", instance, "sh", "-s"]);
        cmd
    };
    #[cfg(not(target_os = "macos"))]
    let mut cmd = {
        let target = ssh_target(profile, instance)?;
        let mut cmd = Command::new("ssh");
        apply_ssh_options(&mut cmd, &target);
        cmd.arg("-o")
            .arg("StrictHostKeyChecking=yes")
            .arg("127.0.0.1")
            .args(["sh", "-s"]);
        cmd
    };
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| format!("guest exec: {e}"))?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(script.as_bytes())
        .map_err(|e| format!("guest exec stdin: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("guest exec wait: {e}"))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Applies the cage ssh discipline to a Command: our key, pinned host key,
/// the generated identity, no control sockets, batch mode. The destination
/// (and any remote command) is appended by the caller.
pub fn apply_ssh_options(cmd: &mut std::process::Command, target: &SshTarget) {
    strip_env(cmd);
    cmd.arg("-p")
        .arg(target.port.to_string())
        .arg("-i")
        .arg(&target.key)
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", target.known_hosts))
        .arg("-o")
        .arg(format!("HostKeyAlias={}", target.host_key_alias))
        .arg("-o")
        .arg(format!("User={}", target.user))
        .arg("-o")
        .arg("ControlMaster=no")
        .arg("-o")
        .arg("ControlPath=none")
        .arg("-o")
        .arg("ConnectTimeout=10");
    // Deliberately NO StrictHostKeyChecking here: OpenSSH honors the FIRST
    // -o for a name, so a caller's later override would be silently dead.
    // The first-ever connect (runner::wait_ssh) passes accept-new to pin
    // the key; every later consumer passes yes.
}

/// The ssh host-key alias for an instance — pining identity, not address.
pub fn host_key_alias(instance: &str) -> String {
    #[cfg(target_os = "macos")]
    {
        format!("lima-{instance}")
    }
    #[cfg(not(target_os = "macos"))]
    {
        format!("creance-{instance}")
    }
}

/// The backend's ssh coordinates for this instance (tunnel, escape probes,
/// shell). Refuses when the instance is not running.
pub fn ssh_target(profile: &str, instance: &str) -> Result<SshTarget, String> {
    #[cfg(target_os = "macos")]
    {
        let home = lima_home(profile);
        // FINDING-010 discipline, same as the imp::limactl helper: strip
        // the inherited environment FIRST, then set LIMA_HOME — a user
        // shell exporting LIMA_HOME would otherwise send this query to
        // the global Lima home while every other operation used ours.
        let mut cmd = std::process::Command::new("limactl");
        strip_env(&mut cmd);
        let out = cmd
            .env("LIMA_HOME", &home)
            .args(["list", "--json"])
            .output()
            .map_err(|e| format!("limactl list failed: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let mut port = None;
        for line in text.lines() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if v["name"] == instance {
                    port = v["sshLocalPort"].as_u64().map(|p| p as u16);
                    break;
                }
            }
        }
        let Some(port) = port else {
            return Err(format!("instance {instance} is not running"));
        };
        let user = crate::guestprofile::Profile::load_or_create(profile)
            .map_err(|e| format!("guest profile unavailable: {e}"))?
            .username;
        Ok(SshTarget {
            port,
            user,
            key: paths::join(&home, "_config/user"),
            known_hosts: paths::join(&home, &format!("{instance}/ssh.known_hosts")),
            host_key_alias: host_key_alias(instance),
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        crate::qemu::ssh_target(profile, instance)
    }
}

/// Starts the environment VM.
pub fn up(profile: &str, instance: &str) -> i32 {
    #[cfg(target_os = "macos")]
    {
        run_attached(profile, &["start", instance])
    }
    #[cfg(not(target_os = "macos"))]
    {
        crate::qemu::up(profile, instance)
    }
}

/// Creates (provisions) the environment VM.
pub fn setup_instance(
    profile: &str,
    instance: &str,
    options: &SetupOptions,
) -> Result<i32, String> {
    #[cfg(target_os = "macos")]
    {
        crate::lima::setup_instance(profile, instance, options)?;
        let yaml = paths::join(
            &paths::join(&state_dir(profile), "setup"),
            &format!("{instance}.yaml"),
        );
        Ok(run_attached(profile, &["create", &yaml]))
    }
    #[cfg(not(target_os = "macos"))]
    {
        crate::qemu::setup_instance(profile, instance, options)
    }
}

/// Deletes the instance outright — the VM disk, not the host workspace.
/// F-051: re-running setup must actually rebuild the instance.
pub fn delete(profile: &str, instance: &str) -> i32 {
    #[cfg(target_os = "macos")]
    {
        run_attached(profile, &["delete", "-f", instance])
    }
    #[cfg(not(target_os = "macos"))]
    {
        crate::qemu::delete(profile, instance)
    }
}

/// Prints instance diagnostics.
pub fn doctor(profile: &str, _instance: &str) -> i32 {
    #[cfg(target_os = "macos")]
    {
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
    #[cfg(not(target_os = "macos"))]
    {
        crate::qemu::doctor(profile)
    }
}

/// Whether the named instance reports itself running.
pub fn instance_running(profile: &str, instance: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        // Same FINDING-010 discipline as every other limactl spawn.
        let mut cmd = std::process::Command::new("limactl");
        strip_env(&mut cmd);
        let out = cmd
            .env("LIMA_HOME", lima_home(profile))
            .args(["list", "--json"])
            .output();
        let Ok(out) = out else {
            return false;
        };
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        for line in text.lines() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if v["name"] == instance {
                    return v["status"] == "Running";
                }
            }
        }
        false
    }
    #[cfg(not(target_os = "macos"))]
    {
        crate::qemu::instance_running(profile, instance)
    }
}

/// How many workspace mounts this instance's config declares — the escape
/// probe's input (exactly one is contained; anything else, or anything the
/// parser cannot count, is an escape).
pub fn declared_mount_count(profile: &str, instance: &str) -> Result<usize, String> {
    #[cfg(target_os = "macos")]
    {
        count_declared_mounts(&instance_marker(profile, instance))
    }
    #[cfg(not(target_os = "macos"))]
    {
        crate::qemu::declared_mounts(profile, instance).map(|mounts| mounts.len())
    }
}

/// Counts `location` entries in a Lima instance YAML, fail-closing on
/// anything uncountable (merge keys, malformed structure — FINDING-016).
/// Pure parsing: compiled everywhere, exercised by tests on every host.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn count_declared_mounts(lima_yaml: &str) -> Result<usize, String> {
    let text =
        std::fs::read_to_string(lima_yaml).map_err(|e| format!("lima.yaml unreadable: {e}"))?;
    let root: serde_yaml::Value =
        serde_yaml::from_str(&text).map_err(|_| "lima.yaml is not valid YAML".to_owned())?;
    let mapping = root
        .as_mapping()
        .ok_or_else(|| "lima.yaml root is not a mapping".to_owned())?;
    if mapping.contains_key("<<") {
        return Err("lima.yaml uses merge keys; probe cannot count mounts".to_owned());
    }
    let Some(mounts) = mapping.get(serde_yaml::Value::String("mounts".into())) else {
        return Ok(0);
    };
    let entries = mounts
        .as_sequence()
        .ok_or_else(|| "mounts is not a sequence".to_owned())?;
    let mut count = 0;
    for entry in entries {
        let m = entry
            .as_mapping()
            .ok_or_else(|| "mounts entry is not a mapping".to_owned())?;
        if m.contains_key("<<") {
            return Err("mounts entry uses merge keys; probe cannot count".to_owned());
        }
        count += m
            .iter()
            .filter(|(k, _)| {
                k.as_str()
                    .map(|key| key.eq_ignore_ascii_case("location"))
                    .unwrap_or(false)
            })
            .count();
    }
    Ok(count)
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

    #[cfg(target_os = "macos")]
    #[test]
    fn limactl_carries_lima_home_despite_stripping() {
        // FINDING-010 regression: STRIPPED contains LIMA_HOME, so an env()
        // issued before the strip loop was silently deleted.
        let profile = std::env::temp_dir()
            .join(format!("cage-env-{}", crate::token()[..12].to_owned()))
            .to_string_lossy()
            .into_owned();
        let cmd = limactl(&profile, &[]);
        let seen: Vec<_> = cmd
            .get_envs()
            .filter(|(k, _)| k.to_string_lossy() == "LIMA_HOME")
            .collect();
        assert_eq!(seen.len(), 1, "LIMA_HOME must be set exactly once");
        let value = seen[0]
            .1
            .expect("set, not removed")
            .to_string_lossy()
            .into_owned();
        assert_eq!(value, lima_home(&profile));
        let _ = std::fs::remove_dir_all(&profile);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lima_home_is_a_short_link() {
        let profile = std::env::temp_dir()
            .join(format!("cage-link-{}", crate::token()[..12].to_owned()))
            .to_string_lossy()
            .into_owned();
        let home = lima_home(&profile);
        // Short, hash-spaced link in the temp dir.
        assert!(home.starts_with("/tmp/vmhome-"), "{home}");
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
