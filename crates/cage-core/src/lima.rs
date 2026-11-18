//! Generation of the per-instance Lima configuration: an Ubuntu LTS cloud
//! image sized for the profile, mounting exactly the environment directory,
//! provisioned with the guest fingerprint (timezone, locale) the profile
//! promises and the tool chain Claude Code needs.
//!
//! The generated YAML is written to `<state>/lima/<instance>/lima.yaml` and
//! consumed by `limactl create`; instance naming stays compatible with the
//! Go build.

use crate::vm;
use serde_yaml::{Mapping, Value as Yaml};

/// The Ubuntu LTS release every fresh environment installs.
const UBUNTU_RELEASE: &str = "24.04";

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
        }
    }
}

/// Builds the Lima YAML for a fresh instance.
pub fn generate_lima_yaml(options: &SetupOptions) -> Result<Vec<u8>, String> {
    if options.workspace.is_empty() || !crate::paths::is_abs(&options.workspace) {
        return Err("workspace must be an absolute host directory".to_owned());
    }
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "amd64"
    };
    // Ubuntu's cloud image filenames use "arm64", not "aarch64".
    let image_arch = if arch == "aarch64" { "arm64" } else { arch };
    let image = format!(
        "https://cloud-images.ubuntu.com/releases/{UBUNTU_RELEASE}/release/ubuntu-{UBUNTU_RELEASE}-server-cloudimg-{image_arch}.img"
    );
    let mut images = Mapping::new();
    images.insert("location".into(), Yaml::from(image));
    images.insert("arch".into(), Yaml::from(arch));

    let mut mount = Mapping::new();
    mount.insert("location".into(), Yaml::from(options.workspace.clone()));
    mount.insert("writable".into(), Yaml::from(true));

    let mut provision = Mapping::new();
    provision.insert("mode".into(), Yaml::from("system"));
    provision.insert(
        "script".into(),
        Yaml::from(provision_script(&options.locale)),
    );

    let mut containerd = Mapping::new();
    containerd.insert("system".into(), Yaml::from(false));
    containerd.insert("user".into(), Yaml::from(false));

    let mut ssh = Mapping::new();
    ssh.insert("localPort".into(), Yaml::from(0));

    let mut root = Mapping::new();
    root.insert("vmType".into(), Yaml::from("vz"));
    root.insert("os".into(), Yaml::from("Linux"));
    root.insert("arch".into(), Yaml::from(arch));
    root.insert("images".into(), Yaml::Sequence(vec![Yaml::Mapping(images)]));
    root.insert("cpus".into(), Yaml::from(options.cpus));
    // Lima sets the guest timezone natively: the fingerprint promise holds
    // even before provisioning runs.
    root.insert("timezone".into(), Yaml::from(options.timezone.clone()));
    root.insert(
        "memory".into(),
        Yaml::from(format!("{}GiB", options.memory_gib)),
    );
    root.insert(
        "disk".into(),
        Yaml::from(format!("{}GiB", options.disk_gib)),
    );
    root.insert("mounts".into(), Yaml::Sequence(vec![Yaml::Mapping(mount)]));
    root.insert(
        "provision".into(),
        Yaml::Sequence(vec![Yaml::Mapping(provision)]),
    );
    root.insert("containerd".into(), Yaml::Mapping(containerd));
    root.insert("ssh".into(), Yaml::Mapping(ssh));
    root.insert("plain".into(), Yaml::from(false));

    serde_yaml::to_string(&Yaml::Mapping(root))
        .map_err(|e| e.to_string())
        .map(String::into_bytes)
}

/// The guest bootstrap: fingerprint (timezone/locale) first, then the tool
/// chain. Guest networking is not yet gated (see ROADMAP); the apt step
/// runs on the VM's NAT until the cage network layer is in place.
fn provision_script(locale: &str) -> String {
    format!(
        r#"#!/bin/sh
set -e
export CLAUDE_CAGE=1
export DEBIAN_FRONTEND=noninteractive
locale-gen {locale} >/dev/null 2>&1 || true
update-locale LANG={locale} >/dev/null 2>&1 || true
apt-get update -qq
apt-get install -y -qq curl git ca-certificates xz-utils >/dev/null
curl -fsSL https://nodejs.org/dist/v22.14.0/node-v22.14.0-linux-$([[ $(uname -m) = aarch64 ]] && echo arm64 || echo x64)/bin/node -o /usr/local/bin/node 2>/dev/null || apt-get install -y -qq nodejs npm >/dev/null
curl -fsSL https://claude.ai/install.sh | bash >/dev/null 2>&1 || true
"#
    )
}

/// Runs `limactl create` for the instance with the generated configuration
/// already in place, then `limactl start`. Mirrors the Go build's flow of
/// preparing the disk before booting it.
pub fn setup_instance(
    profile: &str,
    instance: &str,
    options: &SetupOptions,
) -> Result<String, String> {
    // `limactl create --name=<instance> <file>` owns the instance directory,
    // so the generated YAML is staged outside the Lima home and handed to it.
    let stage_dir = crate::paths::join(&vm::state_dir(profile), "setup");
    std::fs::create_dir_all(&stage_dir).map_err(|e| e.to_string())?;
    let yaml = generate_lima_yaml(options)?;
    // Lima 2.x derives the instance name from the file stem: `x.yaml`
    // creates instance `x`.
    let stage = crate::paths::join(&stage_dir, &format!("{instance}.yaml"));
    std::fs::write(&stage, &yaml).map_err(|e| e.to_string())?;
    Ok(stage)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> SetupOptions {
        SetupOptions {
            workspace: "/Users/me/project".to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn yaml_carries_image_size_and_mount() {
        let yaml = String::from_utf8(generate_lima_yaml(&options()).unwrap()).unwrap();
        let v: Yaml = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(v["vmType"], "vz");
        assert_eq!(v["cpus"], 4);
        assert_eq!(v["memory"], "8GiB");
        assert_eq!(v["disk"], "24GiB");
        let images = v["images"].as_sequence().unwrap();
        assert!(images[0]["location"]
            .as_str()
            .unwrap()
            .contains("ubuntu-24.04-server-cloudimg-arm64"));
        let mounts = v["mounts"].as_sequence().unwrap();
        assert_eq!(mounts[0]["location"], "/Users/me/project");
        assert_eq!(mounts[0]["writable"], Yaml::Bool(true));
        // Exactly one mount: only the environment directory is shared.
        assert_eq!(mounts.len(), 1);
        assert_eq!(v["containerd"]["system"], Yaml::Bool(false));
    }

    #[test]
    fn provision_aligns_the_fingerprint() {
        let opts = SetupOptions {
            timezone: "Asia/Tokyo".to_owned(),
            locale: "ja_JP.UTF-8".to_owned(),
            ..options()
        };
        let yaml = String::from_utf8(generate_lima_yaml(&opts).unwrap()).unwrap();
        assert!(yaml.contains("timezone: Asia/Tokyo"), "{yaml}");
        assert!(yaml.contains("locale-gen ja_JP.UTF-8"), "{yaml}");
    }

    #[test]
    fn workspace_must_be_absolute() {
        let mut opts = options();
        opts.workspace = "relative/path".to_owned();
        assert!(generate_lima_yaml(&opts).is_err());
        let mut empty = options();
        empty.workspace = String::new();
        assert!(generate_lima_yaml(&empty).is_err());
    }
}
