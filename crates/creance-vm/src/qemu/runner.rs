//! The QEMU process itself: argument vector, spawn discipline, ssh wait,
//! and the QMP-driven stop ladder.

#![allow(unsafe_code)] // libc::kill on pids proven ours by start token — audited

use super::Instance;
use crate::paths;
use crate::pidfile;
use crate::vm::{self, SshTarget};
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

/// Poll cadence for boot waits; first boots take minutes (cloud-init).
const SSH_POLL: Duration = Duration::from_secs(3);
/// Grace window for an ACPI powerdown before escalation.
const POWERDOWN_BUDGET: Duration = Duration::from_secs(60);
const TERM_BUDGET: Duration = Duration::from_secs(10);

pub fn qemu_binary() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "qemu-system-x86_64"
    } else {
        "qemu-system-aarch64"
    }
}

/// The host tools the backend drives. Missing ones are setup-time fatals,
/// not runtime surprises.
pub fn require_tools() -> Result<(), String> {
    // pgrep too: the tunnel's orphan sweep (F-026) silently no-ops without
    // it, so its absence must be a setup-time fatal, not a live surprise.
    for tool in [
        qemu_binary(),
        "qemu-img",
        "ssh",
        "ssh-keygen",
        "curl",
        "pgrep",
    ] {
        let found = std::env::var_os("PATH")
            .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(tool).is_file()))
            .unwrap_or(false);
        if !found {
            return Err(format!(
                "缺少 {tool}（Ubuntu: sudo apt install qemu-system-x86 qemu-utils openssh-client procps curl）"
            ));
        }
    }
    Ok(())
}

/// KVM or no VM: TCG's 8–12× slowdown would make the sandbox unusable and
/// its silent enablement a support trap — refuse instead (quickemu's rule).
pub fn kvm_available() -> Result<(), String> {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
    {
        Ok(_) => Ok(()),
        Err(e) => Err(format!(
            "/dev/kvm 不可用（{e}）：请在 BIOS 打开虚拟化并确认当前用户在 kvm 组（`sudo usermod -aG kvm $USER` 后重新登录）"
        )),
    }
}

/// A free loopback port, reserved by binding and immediately released —
/// the same race Lima accepts.
pub fn free_localhost_port() -> Result<u16, String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    drop(listener);
    Ok(port)
}

/// The per-instance ed25519 keypair (id_ed25519[.pub] in the instance
/// directory); generated once at setup, private half never leaves the host.
pub fn ensure_keypair(dir: &str) -> Result<String, String> {
    let key = paths::join(dir, "id_ed25519");
    let pub_key = format!("{key}.pub");
    if Path::new(&key).is_file() && Path::new(&pub_key).is_file() {
        return std::fs::read_to_string(&pub_key).map_err(|e| e.to_string());
    }
    let out = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", "creance", "-f"])
        .arg(&key)
        .output()
        .map_err(|e| format!("cannot run ssh-keygen: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    std::fs::read_to_string(&pub_key).map_err(|e| e.to_string())
}

/// The full QEMU argument vector. Locked by unit tests: the topology
/// contract (exactly one hostfwd, one 9p share) lives here.
pub fn build_args(inst: &Instance, dir: &str, state: &str) -> Result<Vec<String>, String> {
    if super::ARCH == "unsupported" {
        return Err("QEMU 后端当前仅支持 x86_64 与 aarch64 Linux 主机".to_owned());
    }
    let machine = if cfg!(target_arch = "x86_64") {
        "q35,accel=kvm"
    } else {
        "virt,accel=kvm"
    };
    let cpu = "host";
    let base = super::image::base_image_path(state, &inst.arch);
    let disk = super::image::overlay_path(dir);
    let seed = paths::join(dir, "seed.img");
    let serial = paths::join(dir, "serial.log");
    let qmp = paths::join(dir, "qmp.sock");
    for required in [&base, &disk, &seed] {
        if !Path::new(required).is_file() {
            return Err(format!("缺少实例文件 {required}；请重新 creance setup"));
        }
    }
    let mut args: Vec<String> = vec![
        "-machine".into(),
        machine.into(),
        "-cpu".into(),
        cpu.into(),
        "-smp".into(),
        inst.cpus.to_string(),
        "-m".into(),
        format!("{}G", inst.memory_gib),
        // The boot disk: the instance's overlay of the verified base image.
        "-drive".into(),
        format!("file={disk},if=none,id=boot,format=qcow2,discard=on"),
        "-device".into(),
        "virtio-blk-pci,drive=boot,bootindex=1".into(),
        // The NoCloud seed on its own virtio disk.
        "-drive".into(),
        format!("file={seed},if=none,id=seed,format=raw,readonly=on"),
        "-device".into(),
        "virtio-blk-pci,drive=seed".into(),
        // slirp user networking: unprivileged NAT, same posture as the
        // macOS backend's usernet — the in-guest OUTPUT DROP firewall
        // (provision script) is the enforcement plane, so first-boot
        // provisioning (apt, node) still has a network until the lockdown
        // lands. slirp-level restrict=on would block that provisioning;
        // enabling it for already-provisioned instances is tracked as the
        // next hardening step (ROADMAP 0.6.x).
        "-netdev".into(),
        format!(
            "user,id=net0,hostfwd=tcp:127.0.0.1:{}-:22",
            inst.ssh_local_port
        ),
        "-device".into(),
        "virtio-net-pci,netdev=net0".into(),
        "-device".into(),
        "virtio-rng-pci".into(),
        // The single writable share: this workspace, 9p over virtio.
        "-fsdev".into(),
        format!(
            "local,id=host0,path={},security_model=mapped-xattr",
            inst.workspace
        ),
        "-device".into(),
        "virtio-9p-pci,fsdev=host0,mount_tag=creance".into(),
        // Headless: serial console to a log, no monitor, QMP for control.
        "-display".into(),
        "none".into(),
        "-serial".into(),
        format!("file:{serial}"),
        "-monitor".into(),
        "none".into(),
        "-qmp".into(),
        format!("unix:{qmp},server,nowait"),
        "-name".into(),
        format!("creance-{}", inst.name),
    ];
    // aarch64 boots the same image through UEFI firmware; x86_64 uses the
    // default SeaBIOS, which the Ubuntu cloud image's GPT layout supports.
    if cfg!(target_arch = "aarch64") {
        let fw = "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd";
        if !Path::new(fw).is_file() {
            return Err(format!(
                "缺少 aarch64 UEFI 固件（sudo apt install qemu-efi-aarch64 提供 {fw}）"
            ));
        }
        args.push("-bios".into());
        args.push(fw.into());
    }
    Ok(args)
}

/// Spawns the instance's qemu, detached in its own process group and pinned
/// by a start-token-bound pid file. Nothing is waited for here.
pub fn start(inst: &Instance, dir: &str, state: &str) -> Result<(), String> {
    kvm_available()?;
    let args = build_args(inst, dir, state)?;
    let mut cmd = Command::new(qemu_binary());
    vm::strip_env(&mut cmd);
    cmd.args(&args)
        .process_group(0)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let child = cmd.spawn().map_err(|e| format!("cannot start qemu: {e}"))?;
    let pid_file = paths::join(dir, "qemu.pid");
    if let Err(e) = pidfile::write(&pid_file, child.id() as i32) {
        unsafe {
            libc::kill(child.id() as i32, libc::SIGKILL);
        }
        let mut child = child;
        let _ = child.wait();
        return Err(format!("cannot pin the qemu process: {e}"));
    }
    std::mem::forget(child);
    Ok(())
}

/// Polls until an ssh `true` lands (or the budget dies). The first
/// successful connect pins the guest host key into the instance's
/// known_hosts — every later consumer uses StrictHostKeyChecking=yes.
/// A qemu that dies at any point aborts the wait immediately — a
/// hostfwd bind race kills the process at spawn, and nobody should
/// poll a corpse for ten minutes.
pub fn wait_ssh(target: &SshTarget, pid_file: &str, budget: Duration) -> Result<(), String> {
    let deadline = Instant::now() + budget;
    let mut last: String;
    loop {
        if !pidfile::alive(pid_file) {
            return Err(
                "qemu 进程已退出（hostfwd 端口被占用或启动即败）；请查看实例目录 serial.log"
                    .to_owned(),
            );
        }
        let mut cmd = Command::new("ssh");
        vm::apply_ssh_options(&mut cmd, target);
        cmd.arg("-o")
            .arg("StrictHostKeyChecking=accept-new")
            .arg("127.0.0.1")
            .arg("true");
        if let Ok(out) = cmd.output() {
            if out.status.success() {
                return Ok(());
            }
            last = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        } else {
            last = "cannot spawn ssh".to_owned();
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "guest ssh 未在预算内就绪（{last}）；请查看实例目录 serial.log"
            ));
        }
        std::thread::sleep(SSH_POLL);
    }
}

/// The stop ladder: QMP powerdown (guest acpid) → SIGTERM (token-proven) →
/// SIGKILL (token-proven). A dead instance is a no-op. Waits judge the
/// PROCESS (kill(pid,0)), never the pid file — pidfile::stop removes the
/// file, so a file-based wait would vacuously succeed on the first tick
/// and let delete() unlink a live instance directory.
pub fn stop(dir: &str) -> Result<(), String> {
    let pid_file = paths::join(dir, "qemu.pid");
    let entry = pidfile::load(&pid_file);
    let Some(entry) = entry else {
        return Ok(());
    };
    let alive = || pidfile::process_alive(entry.pid);
    if !alive() {
        let _ = std::fs::remove_file(&pid_file);
        return Ok(());
    }
    let qmp = paths::join(dir, "qmp.sock");
    let _ = qmp_powerdown(&qmp);
    if wait_until(|| !alive(), POWERDOWN_BUDGET, SSH_POLL) {
        let _ = std::fs::remove_file(&pid_file);
        return Ok(());
    }
    pidfile::stop(&pid_file);
    if wait_until(|| !alive(), TERM_BUDGET, SSH_POLL) {
        let _ = std::fs::remove_file(&pid_file);
        return Ok(());
    }
    if !entry.started.is_empty() && pidfile::process_start_token(entry.pid) == entry.started {
        unsafe {
            libc::kill(entry.pid, libc::SIGKILL);
        }
        if wait_until(|| !alive(), TERM_BUDGET, SSH_POLL) {
            let _ = std::fs::remove_file(&pid_file);
            return Ok(());
        }
        return Err("qemu 拒绝退出（SIGKILL 后仍存活）".to_owned());
    }
    Err("qemu 无法被安全停止（pid 复用防护拒绝发信号）".to_owned())
}

fn wait_until(mut cond: impl FnMut() -> bool, budget: Duration, step: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(step);
    }
    cond()
}

/// One QMP command exchange: greeting → capabilities → system_powerdown.
fn qmp_powerdown(sock: &str) -> Result<(), String> {
    let mut stream = std::os::unix::net::UnixStream::connect(sock)
        .map_err(|e| format!("qmp unreachable: {e}"))?;
    // A hung qemu must not wedge stop()/delete() here: the socket stays on
    // a short I/O deadline regardless of the outer powerdown budget.
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("qmp greeting: {e}"))?;
    for command in ["qmp_capabilities", "system_powerdown"] {
        let msg = format!("{{\"execute\":\"{command}\"}}\n");
        stream
            .write_all(msg.as_bytes())
            .map_err(|e| format!("qmp {command}: {e}"))?;
        stream.flush().map_err(|e| e.to_string())?;
        let mut reply = String::new();
        reader
            .read_line(&mut reply)
            .map_err(|e| format!("qmp {command} reply: {e}"))?;
        if reply.contains("\"error\"") {
            return Err(format!("qmp {command} refused: {reply}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inst() -> Instance {
        Instance {
            version: 1,
            name: "ws-0123abcd".to_owned(),
            instance_id: "creance-ws-0123abcd-0123456789ab".to_owned(),
            ssh_local_port: 40022,
            memory_gib: 8,
            cpus: 4,
            disk_gib: 24,
            arch: "amd64".to_owned(),
            workspace: "/home/me/ws".to_owned(),
            created: "2026-11-21T00:00:00Z".to_owned(),
        }
    }

    fn dir_with_files() -> String {
        let dir = std::env::temp_dir()
            .join(format!("creance-runner-{}", crate::token()[..8].to_owned()))
            .to_string_lossy()
            .into_owned();
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["seed.img", "disk.qcow2"] {
            std::fs::write(Path::new(&dir).join(name), b"x").unwrap();
        }
        dir
    }

    #[test]
    fn args_lock_the_topology_contract() {
        let dir = dir_with_files();
        let state = dir_with_files();
        let base = super::super::image::base_image_path(&state, "amd64");
        std::fs::create_dir_all(Path::new(&base).parent().unwrap()).unwrap();
        std::fs::write(&base, b"x").unwrap();
        let args = build_args(&inst(), &dir, &state).unwrap();
        let joined = args.join(" ");
        // KVM hard-required, never silent TCG.
        assert!(joined.contains("accel=kvm"), "{joined}");
        // slirp NAT, no restrict until provisioning completes (ROADMAP).
        // Exactly one netdev, one hostfwd: ssh to the guest, nothing else.
        assert_eq!(joined.matches("hostfwd=").count(), 1);
        assert_eq!(joined.matches("-netdev").count(), 1);
        assert!(joined.contains("hostfwd=tcp:127.0.0.1:40022-:22"));
        // The only share is the workspace, tagged creance, mapped-xattr.
        assert!(joined.contains("mount_tag=creance"));
        assert!(joined.contains("security_model=mapped-xattr"));
        assert!(joined.contains("path=/home/me/ws"));
        // Boot from the instance overlay of the verified base.
        assert!(joined.contains("file="));
        // Headless, serial logged, QMP present.
        assert!(joined.contains("-display none"));
        assert!(joined.contains("serial"));
        assert!(joined.contains("qmp.sock"));
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&state).unwrap();
    }

    #[test]
    fn missing_instance_files_refuse_to_boot() {
        let state = dir_with_files();
        let empty = std::env::temp_dir()
            .join(format!(
                "creance-runner-empty-{}",
                crate::token()[..8].to_owned()
            ))
            .to_string_lossy()
            .into_owned();
        std::fs::create_dir_all(&empty).unwrap();
        let err = build_args(&inst(), &empty, &state).unwrap_err();
        assert!(err.contains("缺少实例文件"), "{err}");
        std::fs::remove_dir_all(&empty).unwrap();
        std::fs::remove_dir_all(&state).unwrap();
    }
}
