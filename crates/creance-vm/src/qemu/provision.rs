//! cloud-init documents for the QEMU backend: a `#cloud-config` user-data
//! and the NoCloud meta-data, packed into the seed by [`super::seed`].
//!
//! The heavy lifting is the shared [`crate::provision::guest_bootstrap`]
//! script — identical contract to the Lima build. What differs here:
//! the user is declared without any sudo grant at all (Lima's cloud-init
//! grants one that provision then strips; our own user-data simply never
//! issues it), and the single 9p workspace mount is wired by runcmd
//! (Lima mounts before boot; QEMU mounts inside it).

use crate::provision::guest_bootstrap;
use crate::vm::SetupOptions;
use serde_yaml::{Mapping, Value as Yaml};

/// The `#cloud-config` user-data for a fresh instance.
pub fn user_data(options: &SetupOptions, ssh_pubkey: &str) -> Result<String, String> {
    let mut user = Mapping::new();
    user.insert("name".into(), Yaml::from(options.guest.username.clone()));
    user.insert("comment".into(), Yaml::from("creance guest"));
    user.insert("shell".into(), Yaml::from("/bin/bash"));
    user.insert("lock_passwd".into(), Yaml::from(true));
    user.insert("sudo".into(), Yaml::from(false));
    user.insert(
        "ssh_authorized_keys".into(),
        Yaml::Sequence(vec![Yaml::from(ssh_pubkey.trim())]),
    );

    let mut root = Mapping::new();
    // cloud-init sets both natively from user-data — the fingerprint promise
    // holds before runcmd runs (the bootstrap script re-asserts them too).
    root.insert(
        "hostname".into(),
        Yaml::from(options.guest.hostname.clone()),
    );
    root.insert("timezone".into(), Yaml::from(options.timezone.clone()));
    root.insert("users".into(), Yaml::Sequence(vec![Yaml::Mapping(user)]));
    let bootstrap = guest_bootstrap(
        &options.locale,
        &options.timezone,
        &options.browser_language,
        &options.guest.session_token,
        &options.guest.hostname,
        &options.guest.username,
    );
    root.insert(
        "runcmd".into(),
        Yaml::Sequence(vec![
            Yaml::Sequence(vec!["sh".into(), "-c".into(), Yaml::from(bootstrap)]),
            Yaml::Sequence(vec![
                "sh".into(),
                "-c".into(),
                Yaml::from(mount_script(&options.workspace, &options.guest.username)),
            ]),
        ]),
    );
    // serde_yaml does not emit the #cloud-config signature — cloud-init
    // refuses user-data without it, so it is prepended here.
    serde_yaml::to_string(&Yaml::Mapping(root))
        .map(|yaml| format!("#cloud-config\n{yaml}"))
        .map_err(|e| e.to_string())
}

/// The NoCloud meta-data: a fresh `instance-id` per setup forces first-boot
/// provisioning on rebuilt instances; `local-hostname` names the guest.
pub fn meta_data(instance_id: &str, hostname: &str) -> String {
    format!("instance-id: {instance_id}\nlocal-hostname: {hostname}\n")
}

/// Mounts the single 9p workspace share and hands it to the guest user.
/// `mapped-xattr` keeps ownership consistent across the boundary; the
/// chown makes the mount point writable by the generated identity.
fn mount_script(workspace: &str, username: &str) -> String {
    format!(
        r#"set -e
mkdir -p '{workspace}'
mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600 creance '{workspace}'
chown {username} '{workspace}'
chmod 750 '{workspace}'
grep -q 'creance {workspace}' /etc/fstab || printf 'creance %s 9p trans=virtio,version=9p2000.L,msize=104857600,_netdev,nofail 0 0\n' '{workspace}' >> /etc/fstab
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> SetupOptions {
        SetupOptions {
            workspace: "/home/me/ws".to_owned(),
            guest: crate::guestprofile::Profile {
                version: 1,
                hostname: "nitro-abc1".to_owned(),
                username: "devabc12345".to_owned(),
                session_token: "ab".repeat(24),
            },
            ..Default::default()
        }
    }

    #[test]
    fn user_data_is_cloud_config_with_no_privilege_grant() {
        let ud = user_data(&options(), "ssh-ed25519 AAAA test").unwrap();
        assert!(ud.starts_with("#cloud-config"), "{ud}");
        assert!(ud.contains("name: devabc12345"));
        // No sudo grant ever exists to strip — cleaner than Lima's path.
        assert!(ud.contains("sudo: false"));
        assert!(ud.contains("lock_passwd: true"));
        assert!(ud.contains("- ssh-ed25519 AAAA test"));
        // The shared bootstrap rides in runcmd, lockdown included.
        assert!(ud.contains("iptables-restore < /etc/iptables/rules.v4"));
        assert!(ud.contains("CREANCE_SESSION_TOKEN="));
        // 9p mount leg present, tagged, fstab-persisted.
        assert!(ud.contains("mount -t 9p"));
        assert!(ud.contains("chown devabc12345 '/home/me/ws'"));
        assert!(ud.contains(">> /etc/fstab"));
    }

    #[test]
    fn meta_data_carries_a_fresh_instance_id() {
        let md = meta_data("iid-123", "nitro-abc1");
        assert_eq!(md, "instance-id: iid-123\nlocal-hostname: nitro-abc1\n");
    }

    #[test]
    fn bootstrap_and_mount_split_across_two_runcmds() {
        // The bootstrap must be its own runcmd entry: it ends with the
        // containment lockdown, and a mount failure must not retroactively
        // skip provisioning that already succeeded (nor vice versa).
        let ud = user_data(&options(), "k").unwrap();
        let v: Yaml = serde_yaml::from_str(&ud).unwrap();
        let runcmd = v["runcmd"].as_sequence().unwrap();
        assert_eq!(runcmd.len(), 2);
        let first = runcmd[0][2].as_str().unwrap();
        let second = runcmd[1][2].as_str().unwrap();
        assert!(first.contains("iptables-restore < /etc/iptables/rules.v4"));
        assert!(second.contains("mount -t 9p"));
        assert!(!second.contains("iptables"));
    }
}
