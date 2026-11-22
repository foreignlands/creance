//! Generation of the per-instance Lima configuration: an Ubuntu LTS cloud
//! image sized for the profile, mounting exactly the environment directory,
//! provisioned with the guest fingerprint (timezone, locale) the profile
//! promises and the tool chain Claude Code needs.
//!
//! The generated YAML is staged at `<state>/setup/<instance>.yaml` and handed
//! to `limactl create`, which owns the instance directory; instance naming
//! stays compatible with the Go build.

use crate::provision::{guest_bootstrap, UBUNTU_RELEASE};
use serde_yaml::{Mapping, Value as Yaml};

use crate::vm::SetupOptions;

/// Builds the Lima YAML for a fresh instance.
pub fn generate_lima_yaml(options: &SetupOptions) -> Result<Vec<u8>, String> {
    if options.workspace.is_empty() || !crate::paths::is_abs(&options.workspace) {
        return Err("workspace must be an absolute host directory".to_owned());
    }
    // The product targets Apple Silicon only — arm64 guests, always.
    let arch = "aarch64";
    // Ubuntu's cloud image filenames use "arm64", not "aarch64".
    let image_arch = "arm64";
    let image = format!(
        "https://cloud-images.ubuntu.com/releases/{UBUNTU_RELEASE}/release/ubuntu-{UBUNTU_RELEASE}-server-cloudimg-{image_arch}.img"
    );
    let mut images = Mapping::new();
    images.insert("location".into(), Yaml::from(image));
    // Supply chain: the image must match the recorded sha256 from
    // cloud-images.ubuntu.com/releases/24.04/release/SHA256SUMS — Lima
    // refuses a substituted download (parity with the QEMU backend,
    // which verifies against SHA256SUMS itself).
    images.insert(
        "digest".into(),
        Yaml::from("sha256:50e24e1fb79e89116e939d90aa7738f7af48c442fa1bc2510131e0b39c50348e"),
    );
    images.insert("arch".into(), Yaml::from(arch));

    let mut mount = Mapping::new();
    mount.insert("location".into(), Yaml::from(options.workspace.clone()));
    mount.insert("writable".into(), Yaml::from(true));

    let mut provision = Mapping::new();
    provision.insert("mode".into(), Yaml::from("system"));
    provision.insert(
        "script".into(),
        Yaml::from(guest_bootstrap(
            &options.locale,
            &options.timezone,
            &options.browser_language,
            &options.guest.session_token,
            &options.guest.hostname,
            &options.guest.username,
            // Lima usernet: gateway .2, internal DNS/DHCP .3 — /32 only
            // (F-073: a foreign backend's subnet is a live egress).
            &["192.168.5.2", "192.168.5.3"],
        )),
    );

    // F-020/F-022: the guest user is the generated identity, never a mirror
    // of the host account. `uid` stays unset ON PURPOSE: vz virtiofs mounts
    // pass uid numbers through unmapped, so lima's host-mirrored uid is what
    // keeps the writable workspace writable — a number leaks nothing; the
    // name and GECOS comment are the identity, and both are ours.
    // passwordlessSudo stays at lima's default: lima only allows false for
    // `plain` instances, and false anyway does NOT close the privilege path
    // (lima then parks a random password in the guest's ~/password). The
    // provision script strips the sudoers grant itself — that is the fix.
    let mut user = Mapping::new();
    user.insert("name".into(), Yaml::from(options.guest.username.clone()));
    user.insert("comment".into(), Yaml::from("creance guest"));

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
    root.insert("user".into(), Yaml::Mapping(user));
    root.insert("containerd".into(), Yaml::Mapping(containerd));
    root.insert("ssh".into(), Yaml::Mapping(ssh));
    root.insert("plain".into(), Yaml::from(false));

    serde_yaml::to_string(&Yaml::Mapping(root))
        .map_err(|e| e.to_string())
        .map(String::into_bytes)
}

/// Runs `limactl create` for the instance with the generated configuration
/// already in place, then `limactl start`. Mirrors the Go build's flow of
/// preparing the disk before booting it. (macOS backend only.)
#[cfg(target_os = "macos")]
pub fn setup_instance(
    profile: &str,
    instance: &str,
    options: &SetupOptions,
) -> Result<String, String> {
    // F-023: a physical Lima home too deep for the socket budget cannot
    // host an instance at all — say so here, before limactl's raw
    // UNIX_PATH_MAX fatal. The shortest meaningful name ("p-xxxxxxxx")
    // needs 10 bytes of budget.
    const MIN_NAME_BUDGET: isize = 10;
    let home = crate::vm::lima_home(profile);
    let budget = crate::vmname::socket_budget(&home, false);
    if budget < MIN_NAME_BUDGET {
        return Err(format!(
            "profile 路径过深：Lima home {home} 只剩 {budget} 字节套接字预算（至少需要 {MIN_NAME_BUDGET}）；请把 profile 移到更浅的目录（如 ~/creance/<名>）后重试"
        ));
    }
    // `limactl create --name=<instance> <file>` owns the instance directory,
    // so the generated YAML is staged outside the Lima home and handed to it.
    let stage_dir = crate::paths::join(&crate::vm::state_dir(profile), "setup");
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
            guest: crate::guestprofile::Profile {
                version: 1,
                hostname: "thinkpad-abc1".to_owned(),
                username: "devabc12345".to_owned(),
                session_token: "ab".repeat(24),
            },
            ..Default::default()
        }
    }

    #[test]
    fn yaml_carries_image_size_and_mount() {
        let yaml = String::from_utf8(generate_lima_yaml(&options()).unwrap()).unwrap();
        let v: Yaml = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(v["vmType"], "vz");
        // FINDING-024: lima rejects a `hostname` field — the identity lands
        // via provision's hostnamectl instead, so the field must stay absent.
        assert!(v["hostname"].is_null(), "{yaml}");
        // F-020/F-022: the guest user is the generated identity; uid stays
        // unset so the writable mount keeps working (vz virtiofs passes uid
        // numbers through unmapped), and the sudoers grant dies in provision.
        assert_eq!(v["user"]["name"], "devabc12345");
        assert_eq!(v["user"]["comment"], "creance guest");
        assert!(v["user"]["uid"].is_null(), "uid must stay host-mirrored");
        assert!(
            v["user"]["passwordlessSudo"].is_null(),
            "lima rejects false here; provision strips the grant instead"
        );
        let script = v["provision"][0]["script"].as_str().unwrap_or_default();
        assert!(
            script.contains("hostnamectl set-hostname thinkpad-"),
            "identity must land via provision"
        );
        // F-045: the guest-visible promise fields have a real supply path.
        // Brandless names (2026-11-21 de-clustering): the guest sees these.
        assert!(script.contains("export SESSION_TZ=Etc/UTC"), "{script}");
        assert!(script.contains("export SESSION_LOCALE=en_US.UTF-8"));
        assert!(script.contains("export SESSION_LANGUAGE=en-US"));
        assert!(!script.contains("cage"), "no brand strings reach the guest");
        // F-031: installation failures must not abort the script before the
        // lockdown and privilege retirement land.
        assert!(
            script.contains("apt-get update -qq >> /var/log/creance-toolchain.log 2>&1 || true"),
            "installs are best-effort, containment is mandatory"
        );
        // F-034: the node download is atomic — no partial corpse can shadow
        // the apt fallback.
        assert!(
            script.contains("/usr/local/bin/node.new")
                && script.contains("rm -f /usr/local/bin/node.new"),
            "downloads land on a temp name and clean up on failure"
        );
        // F-054: every network step is time-bounded and the toolchain leg
        // has a hard budget — a network blackhole must never eat the
        // containment contract. And no bashism under #!/bin/sh (dash).
        assert!(
            script.contains("TOOLCHAIN_BUDGET=300"),
            "hard budget on the toolchain leg"
        );
        assert!(script.contains("-m 120"), "curl carries its own deadline");
        assert!(!script.contains("[["), "dash has no [[ ]]");
        // F-055: ARCH is an INNER-script variable — the URL must expand it
        // inside the single-quoted block, never through a cross-quote
        // `'"$ARCH"'` (outer shell never defined it: empty URL segment).
        assert!(
            script.contains("linux-$ARCH/bin/node"),
            "the URL consumes the inner ARCH variable"
        );
        assert!(
            !script.contains(&format!("'\"{}", "$ARCH")),
            "no cross-quote expansion of inner variables"
        );
        assert!(
            script.contains("sed -i '\\#^devabc12345 #d'"),
            "the cloud-init sudoers grant must die in provision"
        );
        assert!(script.contains("passwd -l devabc12345"));
        assert!(
            script.contains("CREANCE_SESSION_TOKEN="),
            "credential handed off"
        );
        assert_eq!(v["cpus"], 4);
        assert_eq!(v["memory"], "8GiB");
        assert_eq!(v["disk"], "24GiB");
        let images = v["images"].as_sequence().unwrap();
        // Ubuntu cloud images spell the arch "arm64"; guests are arm64-only.
        let image_arch = "arm64";
        assert!(images[0]["location"]
            .as_str()
            .unwrap()
            .contains(&format!("ubuntu-24.04-server-cloudimg-{image_arch}")));
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
    fn lima_egress_table_holds_only_usernet_hosts() {
        // F-076/F-073: Lima's table must hold usernet's /32 hosts and
        // never slirp's — the two tables are rendered per backend.
        let yaml = String::from_utf8(generate_lima_yaml(&options()).unwrap()).unwrap();
        assert!(yaml.contains("-d 192.168.5.2/32 -j ACCEPT"), "{yaml}");
        assert!(yaml.contains("-d 192.168.5.3/32 -j ACCEPT"), "{yaml}");
        for foreign in ["192.168.5.0/24", "10.0.2."] {
            assert!(!yaml.contains(foreign), "leaked: {foreign}");
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn deep_profiles_fail_with_an_actionable_error() {
        // F-023: a home past the socket budget must fail here with advice,
        // not inside limactl with a raw UNIX_PATH_MAX fatal.
        let deep = format!(
            "{}/{}",
            std::env::temp_dir().to_string_lossy(),
            "d".repeat(70)
        );
        std::fs::create_dir_all(&deep).unwrap();
        let err = setup_instance(&deep, "t-deep", &options()).unwrap_err();
        assert!(err.contains("路径过深"), "{err}");
        assert!(err.contains("更浅"), "must say what to do: {err}");
        std::fs::remove_dir_all(&deep).unwrap();
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
