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
    pub browser_language: String,
    /// Host-side managed-core port; the guest loopback forwards back to it.
    pub proxy_port: u16,
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
            proxy_port: 17896,
            guest: crate::guestprofile::Profile::generate(),
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
        Yaml::from(provision_script(
            &options.locale,
            &options.timezone,
            &options.browser_language,
            &options.guest.session_token,
            &options.guest.hostname,
            &options.guest.username,
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

/// The guest bootstrap: fingerprint (timezone/locale) first, then the tool
/// chain. Guest networking is not yet gated (see ROADMAP); the apt step
/// runs on the VM's NAT until the cage network layer is in place.
fn provision_script(
    locale: &str,
    timezone: &str,
    browser_language: &str,
    session_token: &str,
    hostname: &str,
    username: &str,
) -> String {
    format!(
        r#"#!/bin/sh
set -e
export CLAUDE_CAGE=1
export CREANCE_SESSION_TOKEN={session_token}
hostnamectl set-hostname {hostname} 2>/dev/null || true
# F-045: the guest-visible fingerprint fields get a real supply path —
# the caged agent can perceive the promise (Go injects the same CAGE_*
# environment at guest start; without this, browser_language was a
# vacuous promise that still forced re-setups).
cat > /etc/profile.d/cage-env.sh <<'CAGEENV'
export CAGE_TZ={timezone}
export CAGE_LOCALE={locale}
export CAGE_LANGUAGE={browser_language}
CAGEENV
export DEBIAN_FRONTEND=noninteractive
locale-gen {locale} >/dev/null 2>&1 || true
update-locale LANG={locale} >/dev/null 2>&1 || true
# Toolchain installs are best-effort (F-031) AND time-bounded (F-054):
# `|| true` guards against failure, but a network BLACKHOLE neither
# fails nor succeeds — the provisioner's own timeout then killed the
# script mid-flight and the containment contract below never ran,
# shipping a VM with raw egress and passwordless sudo behind a green
# `up`. Every network step carries its own deadline, and the whole
# toolchain leg is wrapped in one hard budget so the contract section
# is always reached.
TOOLCHAIN_BUDGET=300
APT_OPTS="-o Acquire::http::Timeout=20 -o Acquire::Retries=1"
timeout "$TOOLCHAIN_BUDGET" sh -c '
  apt-get update -qq || true
  apt-get install '"$APT_OPTS"' -y -qq curl git ca-certificates xz-utils >/dev/null || true
  ARCH=$(case "$(uname -m)" in aarch64) echo arm64;; *) echo x64;; esac)
  # F-034: download atomically (tmp + mv) — a partial corpse in
  # /usr/local/bin shadows the apt fallback node.
  if curl -fsSL -m 120 https://nodejs.org/dist/v22.14.0/node-v22.14.0-linux-'"$ARCH"'/bin/node -o /usr/local/bin/node.new 2>/dev/null && mv /usr/local/bin/node.new /usr/local/bin/node 2>/dev/null; then
    chmod +x /usr/local/bin/node 2>/dev/null || true
  else
    rm -f /usr/local/bin/node.new
    apt-get install '"$APT_OPTS"' -y -qq nodejs npm >/dev/null || true
  fi
  curl -fsSL -m 120 https://claude.ai/install.sh | bash >/dev/null 2>&1 || true
' || true

# 0.3 TOPOLOGY LOCKDOWN — the guest's only wire out is the ssh -R tunnel to
# the host-side core on this machine's own loopback (managed from the host
# after boot). Everything else, including DNS and IPv6, is dropped.
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null
printf 'net.ipv6.conf.all.disable_ipv6=1\n' > /etc/sysctl.d/99-creance-noipv6.conf
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p udp --dport 67 -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT
iptables -P OUTPUT DROP
iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > /etc/iptables.up.rules

# 020 PRIVILEGE RETIREMENT — cloud-init unconditionally grants the guest
# user sudo (NOPASSWD, or a random password parked in ~/password when
# passwordlessSudo is false). The enforcement plane is only as strong as
# the weakest privilege path, so the grant dies here: without it the
# firewall above cannot be lifted from inside the guest.
SUDOERS=/etc/sudoers.d/90-cloud-init-users
[ -f "$SUDOERS" ] && sed -i '\#^{username} #d' "$SUDOERS" || true
passwd -l {username} 2>/dev/null || true
GUEST_HOME=$(getent passwd {username} | cut -d: -f6)
[ -n "$GUEST_HOME" ] && rm -f "$GUEST_HOME/password" || true
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
    // F-023: a physical Lima home too deep for the socket budget cannot
    // host an instance at all — say so here, before limactl's raw
    // UNIX_PATH_MAX fatal. The shortest meaningful name ("p-xxxxxxxx")
    // needs 10 bytes of budget.
    const MIN_NAME_BUDGET: isize = 10;
    let home = vm::lima_home(profile);
    let budget = crate::vmname::socket_budget(&home, false);
    if budget < MIN_NAME_BUDGET {
        return Err(format!(
            "profile 路径过深：Lima home {home} 只剩 {budget} 字节套接字预算（至少需要 {MIN_NAME_BUDGET}）；请把 profile 移到更浅的目录（如 ~/creance/<名>）后重试"
        ));
    }
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
            script.contains("hostnamectl set-hostname cage-"),
            "identity must land via provision"
        );
        // F-045: the guest-visible promise fields have a real supply path.
        assert!(script.contains("export CAGE_TZ=Etc/UTC"), "{script}");
        assert!(script.contains("export CAGE_LOCALE=en_US.UTF-8"));
        assert!(script.contains("export CAGE_LANGUAGE=en-US"));
        // F-031: installation failures must not abort the script before the
        // lockdown and privilege retirement land.
        assert!(
            script.contains("apt-get update -qq || true"),
            "installs are best-effort, containment is mandatory"
        );
        // F-034: the node download is atomic — no partial corpse can shadow
        // the apt fallback.
        assert!(
            script.contains("-o /usr/local/bin/node.new")
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
