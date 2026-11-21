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
# The toolchain leg is best-effort, but never invisible: every step's
# outcome lands in /var/log/creance-toolchain.log so a missing binary is
# diagnosable after the lockdown makes the guest unreachable.
TLLOG=/var/log/creance-toolchain.log
: >"$TLLOG" 2>/dev/null || true
timeout "$TOOLCHAIN_BUDGET" sh -c '
  echo "toolchain start $(date -u +%FT%TZ)" >> /var/log/creance-toolchain.log
  ARCH=$(case "$(uname -m)" in aarch64) echo arm64;; *) echo x64;; esac)
  echo "arch=$ARCH" >> /var/log/creance-toolchain.log
  # node comes FIRST and with zero extra dependencies — curl and tar -z
  # ship in the base cloud image — so a fast nodejs.org wins even when the
  # apt mirror crawls (a crawling mirror used to eat the whole budget
  # before the pinned download ever ran). nodejs.org/dist ships whole
  # tarballs; bin/node is lifted out of the official one.
  # F-034: land on a temp name and mv into place — a partial corpse in
  # /usr/local/bin would shadow the apt fallback node.
  # curl ships in the base cloud image and its TLS stack survives
  # networks that fingerprint-filter python (live lesson: urllib died
  # with UNEXPECTED_EOF where curl sailed through).
  curl -fsSL -m 240 -o /tmp/creance-node.tar.gz https://nodejs.org/dist/v22.14.0/node-v22.14.0-linux-$ARCH.tar.gz >> /var/log/creance-toolchain.log 2>&1
  echo "node download rc=$?" >> /var/log/creance-toolchain.log
  tar -xzf /tmp/creance-node.tar.gz -C /tmp >> /var/log/creance-toolchain.log 2>&1 \
    && mv /tmp/node-v22.14.0-linux-$ARCH/bin/node /usr/local/bin/node.new 2>> /var/log/creance-toolchain.log \
    && mv /usr/local/bin/node.new /usr/local/bin/node 2>> /var/log/creance-toolchain.log \
    || rm -f /usr/local/bin/node.new /tmp/creance-node.tar.gz
  echo "node install rc=$? path=$(command -v /usr/local/bin/node 2>/dev/null || echo none)" >> /var/log/creance-toolchain.log
  chmod +x /usr/local/bin/node 2>/dev/null || true
  # The pinned download dies fast on MITM-intercepting networks; the
  # apt fallback must therefore run EARLY — the base extras (git, xz —
  # curl and ca-certificates already ship in the image) sink to the end
  # so they can never eat the budget the node fallback needs.
  apt-get update -qq >> /var/log/creance-toolchain.log 2>&1 || true
  echo "apt update rc=$?" >> /var/log/creance-toolchain.log
  [ -x /usr/local/bin/node ] || apt-get install '"$APT_OPTS"' -y -qq nodejs npm >> /var/log/creance-toolchain.log 2>&1 || true
  echo "node fallback rc=$? node=$(command -v node || echo missing)" >> /var/log/creance-toolchain.log
  curl -fsSL -m 120 https://claude.ai/install.sh | bash >> /var/log/creance-toolchain.log 2>&1 || true
  apt-get install '"$APT_OPTS"' -y -qq git xz-utils >> /var/log/creance-toolchain.log 2>&1 || true
  echo "toolchain end node=$(/usr/local/bin/node -v 2>/dev/null || command -v node || echo missing) claude=$(command -v claude || echo missing)" >> /var/log/creance-toolchain.log
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
    fn single_quotes_stay_paired_for_the_sh_c_wrapper() {
        // The bootstrap rides cloud-init as ["sh", "-c", script]: a lone
        // apostrophe inside a comment closed the wrapper early and dash
        // aborted the whole leg in one second (live lesson — the guest
        // came up toolchain-less behind a green cloud-init "done").
        // The deliberate cross-quoting pairs ("'"$VAR"'") are fine; a
        // stray unpaired quote is not. Parity must hold.
        let s = script();
        assert_eq!(
            s.matches('\'').count() % 2,
            0,
            "unpaired single quote would close the sh -c wrapper"
        );
    }

    #[test]
    fn node_download_precedes_apt() {
        // The live-machine lesson: a slow apt mirror ate the whole toolchain
        // budget before the (fast) pinned node download ever ran. The
        // zero-dependency download now runs first, apt is the fallback.
        let s = script();
        let node = s
            .find("node-v22.14.0-linux-$ARCH.tar.gz")
            .expect("pinned node download present");
        let apt = s.find("apt-get update").expect("apt leg present");
        assert!(node < apt, "node download must precede apt");
        assert!(
            s.contains("[ -x /usr/local/bin/node ] ||"),
            "apt node install is a fallback, not the primary"
        );
        let fallback = s.find("node fallback rc=").expect("fallback marker");
        let extras = s.find("git xz-utils").expect("base extras");
        assert!(
            fallback < extras,
            "the node fallback must precede the base extras"
        );
    }
}
