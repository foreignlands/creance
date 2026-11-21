//! Base image acquisition and per-instance overlay disks.
//!
//! The Ubuntu LTS cloud image (qcow2) is downloaded once per profile into
//! `state/images/`, verified against cloud-images.ubuntu.com's SHA256SUMS,
//! and every instance boots a thin qcow2 overlay of it — reset = rebuild
//! the overlay, the cache stays.

use crate::provision::UBUNTU_RELEASE;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// `https://cloud-images.ubuntu.com/releases/<rel>/release/` — the same
/// source the Lima build points at.
fn release_dir() -> String {
    format!("https://cloud-images.ubuntu.com/releases/{UBUNTU_RELEASE}/release")
}

fn image_name(arch: &str) -> String {
    format!("ubuntu-{UBUNTU_RELEASE}-server-cloudimg-{arch}.img")
}

pub fn base_image_path(state: &str, arch: &str) -> String {
    paths_join(state, &format!("images/{}", image_name(arch)))
}

pub fn overlay_path(instance_dir: &str) -> String {
    paths_join(instance_dir, "disk.qcow2")
}

fn paths_join(a: &str, b: &str) -> String {
    Path::new(a).join(b).to_string_lossy().into_owned()
}

/// The cached base image, downloaded and hash-verified on first use.
pub fn ensure_base_image(state: &str) -> Result<PathBuf, String> {
    let arch = super::ARCH;
    let final_path = PathBuf::from(base_image_path(state, arch));
    if final_path.is_file() {
        return Ok(final_path);
    }
    let dir = state_images_dir(state);
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create image cache: {e}"))?;

    let name = image_name(arch);
    let base_url = release_dir();
    println!("downloading {name} (first setup only, ~600 MB)…");
    let tmp = dir.join(format!("{name}.part"));
    fetch(&format!("{base_url}/{name}"), &tmp)?;

    // Verify against the release's signed-by-construction checksum file
    // before the bytes are allowed to become a boot disk.
    let sums_tmp = dir.join("SHA256SUMS.part");
    fetch(&format!("{base_url}/SHA256SUMS"), &sums_tmp)?;
    let sums = std::fs::read_to_string(&sums_tmp).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&sums_tmp);
    let expected = parse_sum(&sums, &name)
        .ok_or_else(|| format!("{name} missing from SHA256SUMS — refusing unverified image"))?;
    let got = sha256_file(&tmp)?;
    if got != expected {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "镜像校验失败（期望 {expected}，得到 {got}）；已丢弃下载，请重试"
        ));
    }
    let final_tmp = dir.join(format!("{name}.final"));
    std::fs::rename(&tmp, &final_tmp).map_err(|e| e.to_string())?;
    std::fs::rename(&final_tmp, &final_path).map_err(|e| e.to_string())?;
    Ok(final_path)
}

fn state_images_dir(state: &str) -> PathBuf {
    Path::new(state).join("images")
}

fn parse_sum(sums: &str, name: &str) -> Option<String> {
    for line in sums.lines() {
        let mut fields = line.split_whitespace();
        let hash = fields.next()?;
        // cloud-images sums use GNU binary-mode spelling: `<hash> *<file>`.
        let file = fields.next()?.trim_start_matches('*');
        if file == name {
            return Some(hash.to_lowercase());
        }
    }
    None
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// One https fetch via curl, into `dst`, with the cage environment hygiene
/// (no inherited proxies: a fallback proxy is a fallback egress).
fn fetch(url: &str, dst: &Path) -> Result<(), String> {
    let mut cmd = std::process::Command::new("curl");
    crate::vm::strip_env(&mut cmd);
    let status = cmd
        .args([
            "-fsSL",
            "--retry",
            "3",
            "--connect-timeout",
            "20",
            "--max-time",
            "1800",
            "-o",
        ])
        .arg(dst)
        .arg(url)
        .status()
        .map_err(|e| format!("无法运行 curl（镜像下载需要它）：{e}"))?;
    if !status.success() {
        let _ = std::fs::remove_file(dst);
        return Err(format!("下载失败：{url}"));
    }
    Ok(())
}

/// A thin overlay of the verified base — the instance's own boot disk.
pub fn create_overlay(base: &str, dst: &str, disk_gib: u32) -> Result<(), String> {
    let _ = std::fs::remove_file(dst);
    let out = std::process::Command::new("qemu-img")
        .args([
            "create",
            "-f",
            "qcow2",
            "-o",
            &format!("backing_file={base},backing_fmt=qcow2"),
            dst,
            &format!("{disk_gib}G"),
        ])
        .output()
        .map_err(|e| format!("无法运行 qemu-img：{e}"))?;
    if !out.status.success() {
        return Err(format!(
            "qcow2 覆盖盘创建失败：{}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_parse_the_release_spelling() {
        // The real file uses GNU binary mode: `<hash> *<name>` (captured
        // from cloud-images.ubuntu.com/releases/24.04/release/SHA256SUMS).
        let sums = "04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94 *ubuntu-24.04-server-cloudimg-amd64.img\n\
                    1111111111111111111111111111111111111111111111111111111111111111 ubuntu-24.04-server-cloudimg-arm64.img\n";
        assert_eq!(
            parse_sum(sums, "ubuntu-24.04-server-cloudimg-amd64.img").as_deref(),
            Some("04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94")
        );
        // Text-mode (no asterisk) entries parse too.
        assert_eq!(
            parse_sum(sums, "ubuntu-24.04-server-cloudimg-arm64.img").as_deref(),
            Some("1111111111111111111111111111111111111111111111111111111111111111")
        );
        assert_eq!(
            parse_sum(sums, "ubuntu-24.04-server-cloudimg-s390x.img"),
            None
        );
    }

    #[test]
    fn paths_live_under_the_qemu_layout() {
        assert!(base_image_path("/state", "amd64")
            .ends_with("state/images/ubuntu-24.04-server-cloudimg-amd64.img"));
        assert!(overlay_path("/root/ws-0123abcd").ends_with("ws-0123abcd/disk.qcow2"));
    }
}
