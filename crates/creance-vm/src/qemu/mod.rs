//! Native QEMU + cloud-init environment lifecycle for Linux hosts.
//!
//! No Lima, no vmnet, no root: one `qemu-system-x86_64` per instance on
//! KVM, slirp user networking whose ONLY opening is the hostfwd'd ssh port
//! (`restrict=on`: the guest cannot reach the host or the outside by
//! itself — a second, topology-level enforcement under the in-guest
//! firewall), a NoCloud seed on virtio-blk, and the single 9p workspace
//! share. All instance facts live in `instance.json`; the host-side ssh
//! keypair is ours, generated per instance at setup.

pub mod image;
pub mod provision;
pub mod runner;
pub mod seed;

use crate::paths;
use crate::pidfile;
use crate::vm::{self, SetupOptions, SshTarget};
use serde::{Deserialize, Serialize};

/// The QEMU backend runs native-arch Linux guests only (KVM is a hard
/// requirement; TCG's 8–12× slowdown is no sandbox an agent can work in).
pub const ARCH: &str = if cfg!(target_arch = "x86_64") {
    "amd64"
} else if cfg!(target_arch = "aarch64") {
    "arm64"
} else {
    "unsupported"
};

/// Every persistent fact about one instance. Written once by setup (with a
/// fresh `instance_id` — cloud-init's first-boot trigger on rebuilds) and
/// read by every later operation.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Instance {
    pub version: u32,
    pub name: String,
    /// cloud-init instance-id; rotates per setup.
    pub instance_id: String,
    /// Host-side port forwarded to the guest's sshd.
    pub ssh_local_port: u16,
    pub memory_gib: u32,
    pub cpus: u32,
    pub disk_gib: u32,
    /// Image arch spelling (amd64/arm64), matching Ubuntu cloud images.
    pub arch: String,
    /// The single 9p workspace mount (host path == guest path).
    pub workspace: String,
    pub created: String,
}

impl Instance {
    fn new(name: &str, options: &SetupOptions, port: u16) -> Self {
        Instance {
            version: 1,
            name: name.to_owned(),
            instance_id: format!("creance-{}-{}", name, crate::token()[..12].to_owned()),
            ssh_local_port: port,
            memory_gib: options.memory_gib,
            cpus: options.cpus,
            disk_gib: options.disk_gib,
            arch: ARCH.to_owned(),
            workspace: options.workspace.clone(),
            created: crate::iso8601_now(),
        }
    }
}

/// The directory of one instance under the profile's qemu root.
pub fn instance_dir(profile: &str, instance: &str) -> String {
    paths::join(&vm::instances_root(profile), instance)
}

fn instance_file(profile: &str, instance: &str) -> String {
    vm::instance_marker(profile, instance)
}

pub fn load_instance(profile: &str, instance: &str) -> Result<Instance, String> {
    let text = std::fs::read_to_string(instance_file(profile, instance)).map_err(|_| {
        format!("instance {instance} 不存在（未 setup 或已被删除）；请先 creance setup")
    })?;
    let inst: Instance =
        serde_json::from_str(&text).map_err(|e| format!("instance 记录损坏：{e}"))?;
    if inst.version != 1 {
        return Err(format!("instance 记录版本 {} 不受此构建支持", inst.version));
    }
    Ok(inst)
}

/// Creates the instance: base image (downloaded + verified once per
/// profile), ssh keypair, NoCloud seed, qcow2 overlay, and the
/// `instance.json` record. Nothing boots here.
pub fn setup_instance(
    profile: &str,
    instance: &str,
    options: &SetupOptions,
) -> Result<i32, String> {
    runner::require_tools()?;
    if ARCH == "unsupported" {
        return Err("QEMU 后端当前仅支持 x86_64 与 aarch64 Linux 主机".to_owned());
    }
    let dir = instance_dir(profile, instance);
    let state = vm::state_dir(profile);
    image::ensure_base_image(&state)?;

    // The 9p share is handed to qemu by path — a workspace that does not
    // exist yet (the fresh `environment.json`-less default) would make the
    // fsdev refuse to start.
    if options.workspace.is_empty() || !crate::paths::is_abs(&options.workspace) {
        return Err("workspace must be an absolute host directory".to_owned());
    }
    std::fs::create_dir_all(&options.workspace).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    crate::private::ensure_private_dir(&dir).map_err(|e| e.to_string())?;
    let key = runner::ensure_keypair(&dir)?;

    let port = runner::free_localhost_port()?;
    let inst = Instance::new(instance, options, port);
    let user_data = provision::user_data(options, &key)?;
    let meta_data = provision::meta_data(&inst.instance_id, &options.guest.hostname);
    seed::build(std::path::Path::new(&dir), &user_data, &meta_data)?;

    let base = image::base_image_path(&state, ARCH);
    let disk = image::overlay_path(&dir);
    image::create_overlay(&base, &disk, options.disk_gib)?;

    let bytes = serde_json::to_vec_pretty(&inst).map_err(|e| e.to_string())?;
    crate::write_private_atomic(&instance_file(profile, instance), &bytes)
        .map_err(|e| format!("cannot write instance record: {e}"))?;
    Ok(0)
}

/// Boots the instance and waits until ssh answers.
pub fn up(profile: &str, instance: &str) -> i32 {
    let inst = match load_instance(profile, instance) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    if let Err(e) = runner::start(
        &inst,
        &instance_dir(profile, instance),
        &vm::state_dir(profile),
    ) {
        eprintln!("{e}");
        return 1;
    }
    let target = match ssh_target(profile, instance) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    // First boots download nothing (image is pre-seeded) but cloud-init
    // still takes minutes; later boots answer in seconds.
    match runner::wait_ssh(&target, std::time::Duration::from_secs(600)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

/// Attaches an ssh session (or one command) to the guest.
pub fn shell(profile: &str, instance: &str, command: &[&str]) -> i32 {
    let target = match ssh_target(profile, instance) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let mut cmd = std::process::Command::new("ssh");
    vm::apply_ssh_options(&mut cmd, &target);
    cmd.arg("127.0.0.1").args(command);
    match cmd.status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => {
            eprintln!("cannot run ssh: {e}");
            1
        }
    }
}

/// Graceful stop: QMP system_powerdown (guest acpid), then SIGTERM, then a
/// token-proven SIGKILL — mirroring pidfile discipline.
pub fn stop_vm(profile: &str, instance: &str) -> i32 {
    let dir = instance_dir(profile, instance);
    match runner::stop(&dir) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

/// Deletes the instance outright — VM disk included, host workspace not.
pub fn delete(profile: &str, instance: &str) -> i32 {
    let dir = instance_dir(profile, instance);
    let _ = runner::stop(&dir);
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("cannot remove instance directory: {e}");
            1
        }
    }
}

/// Lists this profile's instances with their liveness.
pub fn list(profile: &str) -> i32 {
    let root = vm::instances_root(profile);
    let mut rows: Vec<(String, bool, u16)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&root) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Ok(inst) = load_instance(profile, &name) {
                let alive = qemu_alive(&root, &name);
                rows.push((name, alive, inst.ssh_local_port));
            }
        }
    }
    rows.sort();
    println!("STATE  SSH-PORT   NAME");
    for (name, alive, port) in rows {
        println!(
            "{:<6} {:<10} {}",
            if alive { "Running" } else { "Stopped" },
            port,
            name
        );
    }
    0
}

/// Prints instance diagnostics.
pub fn doctor(profile: &str) -> i32 {
    if let Err(e) = runner::require_tools() {
        eprintln!("{e}");
        return 1;
    }
    match runner::kvm_available() {
        Ok(()) => println!("kvm: /dev/kvm 可用"),
        Err(e) => println!("kvm: {e}"),
    }
    list(profile)
}

/// The ssh coordinates, reconstructed from the instance record.
pub fn ssh_target(profile: &str, instance: &str) -> Result<SshTarget, String> {
    let inst = load_instance(profile, instance)?;
    if !qemu_alive(&vm::instances_root(profile), instance) {
        return Err(format!("instance {instance} is not running"));
    }
    let dir = instance_dir(profile, instance);
    let guest = crate::guestprofile::Profile::load_or_create(profile)?;
    Ok(SshTarget {
        port: inst.ssh_local_port,
        user: guest.username,
        key: paths::join(&dir, "id_ed25519"),
        known_hosts: paths::join(&dir, "known_hosts"),
        host_key_alias: format!("creance-{instance}"),
    })
}

/// Whether the instance's qemu is alive (start-token bound).
pub fn instance_running(profile: &str, instance: &str) -> bool {
    qemu_alive(&vm::instances_root(profile), instance)
}

fn qemu_alive(root: &str, instance: &str) -> bool {
    let pid_file = paths::join(root, &format!("{instance}/qemu.pid"));
    pidfile::alive(&pid_file)
}

/// The declared mounts — the one 9p workspace, straight from the record.
pub fn declared_mounts(profile: &str, instance: &str) -> Result<Vec<String>, String> {
    let inst = load_instance(profile, instance)?;
    Ok(vec![inst.workspace])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> SetupOptions {
        SetupOptions {
            workspace: "/home/me/ws".to_owned(),
            guest: crate::guestprofile::Profile {
                version: 1,
                hostname: "cage-abc12345".to_owned(),
                username: "devabc12345".to_owned(),
                session_token: "ab".repeat(24),
            },
            ..Default::default()
        }
    }

    #[test]
    fn instance_record_round_trips() {
        let inst = Instance::new("ws-0123abcd", &options(), 40022);
        assert_eq!(inst.version, 1);
        assert_eq!(inst.arch, "amd64");
        assert!(inst.instance_id.starts_with("creance-ws-0123abcd-"));
        let text = serde_json::to_string(&inst).unwrap();
        let back: Instance = serde_json::from_str(&text).unwrap();
        assert_eq!(back.name, inst.name);
        assert_eq!(back.ssh_local_port, 40022);
        assert_eq!(back.workspace, "/home/me/ws");
        // Every setup mints a fresh cloud-init instance-id.
        let other = Instance::new("ws-0123abcd", &options(), 40022);
        assert_ne!(inst.instance_id, other.instance_id);
    }

    #[test]
    fn marker_is_instance_json_under_the_qemu_root() {
        let profile = std::env::temp_dir()
            .join(format!("creance-qemu-{}", crate::token()[..8].to_owned()))
            .to_string_lossy()
            .into_owned();
        let marker = vm::instance_marker(&profile, "ws-0123abcd");
        assert!(
            marker.ends_with("state/qemu/ws-0123abcd/instance.json"),
            "{marker}"
        );
    }
}
