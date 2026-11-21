//! The guest bootstrap script, shared by every environment backend.
//!
//! Lima delivers it through its `provision:` array; the QEMU backend packs
//! the same text into the cloud-init seed's `runcmd`. One script, one
//! contract: fingerprint supply first, best-effort toolchain second, and
//! the containment lockdown LAST — the section that must never be skipped.

/// The Ubuntu LTS release every fresh environment installs.
pub const UBUNTU_RELEASE: &str = "24.04";

/// The guest bootstrap: fingerprint (timezone/locale) first, then the tool
/// chain. Guest networking is not yet gated (see ROADMAP); the apt step
/// runs on the VM's NAT until the cage network layer is in place.
pub fn guest_bootstrap(
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
  ARCH=$(case "$(uname -m)" in aarch64) echo arm64;; *) echo x64;; esac)
  # node comes FIRST and with zero extra dependencies — python3 and
  # tar -z ship in the base cloud image — so a fast nodejs.org wins even
  # when the apt mirror crawls (a crawling mirror used to eat the whole
  # budget before the pinned download ever ran). nodejs.org/dist ships
  # whole tarballs; bin/node is lifted out of the official one.
  # F-034: land on a temp name and mv into place — a partial corpse in
  # /usr/local/bin would shadow the apt fallback node.
  python3 - <<PYEOF 2>/dev/null
import urllib.request
urllib.request.urlretrieve("https://nodejs.org/dist/v22.14.0/node-v22.14.0-linux-$ARCH.tar.gz", "/tmp/creance-node.tar.gz")
PYEOF
  tar -xzf /tmp/creance-node.tar.gz -C /tmp 2>/dev/null \
    && mv /tmp/node-v22.14.0-linux-$ARCH/bin/node /usr/local/bin/node.new 2>/dev/null \
    && mv /usr/local/bin/node.new /usr/local/bin/node 2>/dev/null \
    || rm -f /usr/local/bin/node.new /tmp/creance-node.tar.gz
  chmod +x /usr/local/bin/node 2>/dev/null || true
  apt-get update -qq || true
  apt-get install '"$APT_OPTS"' -y -qq curl git ca-certificates xz-utils >/dev/null || true
  # Fallback only when the pinned download did not land.
  [ -x /usr/local/bin/node ] || apt-get install '"$APT_OPTS"' -y -qq nodejs npm >/dev/null || true
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

#[cfg(test)]
mod tests {
    use super::*;

    fn script() -> String {
        guest_bootstrap(
            "en_US.UTF-8",
            "Asia/Shanghai",
            "en-US",
            "a".repeat(48).as_str(),
            "cage-0123abcd",
            "dev0123abcd",
        )
    }

    #[test]
    fn lockdown_leg_is_last_and_unskippable() {
        let s = script();
        let toolchain = s.find("TOOLCHAIN_BUDGET").expect("toolchain leg");
        let lockdown = s.find("iptables -P OUTPUT DROP").expect("lockdown leg");
        assert!(
            toolchain < lockdown,
            "the contract section must come after the tolerant toolchain leg"
        );
        // No `|| true` on the policy flip itself — it must land or fail loud.
        let flip = s.find("iptables -P OUTPUT DROP").unwrap();
        let rest = &s[flip..];
        let line_end = rest.find('\n').unwrap();
        assert!(!rest[..line_end].contains("|| true"));
    }

    #[test]
    fn qemu_inner_arch_variable_survives() {
        // F-055: ARCH is an INNER-script variable — the URL must expand it
        // inside the toolchain block (heredoc), never through a cross-quote
        // `'"$ARCH"'` (the outer shell never defined it: empty URL segment).
        let s = script();
        assert!(
            s.contains("linux-$ARCH.tar.gz"),
            "the tarball URL consumes the inner ARCH"
        );
        assert!(
            !s.contains(&format!("'\"{}", "$ARCH")),
            "no cross-quote expansion of inner variables"
        );
    }

    #[test]
    fn node_download_precedes_apt() {
        // The live-machine lesson: a slow apt mirror ate the whole toolchain
        // budget before the (fast) pinned node download ever ran. The
        // zero-dependency download now runs first, apt is the fallback.
        let s = script();
        let node = s.find("urlretrieve").expect("python download present");
        let apt = s.find("apt-get update").expect("apt leg present");
        assert!(node < apt, "node download must precede apt");
        assert!(
            s.contains("[ -x /usr/local/bin/node ] ||"),
            "apt node install is a fallback, not the primary"
        );
    }
}
