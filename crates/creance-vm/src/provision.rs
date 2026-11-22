//! The guest bootstrap script, shared by every environment backend.
//!
//! Lima delivers it through its `provision:` array; the QEMU backend packs
//! the same text into the cloud-init seed's `runcmd`. One script, one
//! contract: fingerprint supply first, best-effort toolchain second, and
//! the containment lockdown's runtime apply LAST — the section that must
//! never be skipped — while its persistence artifacts (rules file,
//! sysctl drop-in, boot unit) land before the toolchain leg so an
//! interrupted provision still converges to a contained guest next boot.

/// The Ubuntu LTS release every fresh environment installs.
pub const UBUNTU_RELEASE: &str = "24.04";

/// The guest bootstrap: fingerprint (timezone/locale) first, then the tool
/// chain. Guest networking is not yet gated (see ROADMAP); the apt step
/// runs on the VM's NAT until the cage network layer is in place.
/// `nat_allows` is the backend's own virtual hosts — the ONLY fixed
/// destinations the egress lockdown permits (DHCP/ICMP to the gateway).
/// Each backend passes its own: allowing a foreign backend's subnet lets
/// the VM NAT route it straight out the host NIC (F-073).
pub fn guest_bootstrap(
    locale: &str,
    timezone: &str,
    browser_language: &str,
    session_token: &str,
    hostname: &str,
    username: &str,
    nat_allows: &[&str],
) -> String {
    let mut nat_rules = String::new();
    for host in nat_allows {
        nat_rules.push_str(&format!(
            "-A OUTPUT -p udp --dport 67 -d {host}/32 -j ACCEPT\n-A OUTPUT -p icmp -d {host}/32 -j ACCEPT\n"
        ));
    }
    format!(
        r#"#!/bin/sh
set -e
export CREANCE_SESSION_TOKEN={session_token}
hostnamectl set-hostname {hostname} 2>/dev/null || true
# F-045: the guest-visible fingerprint fields get a real supply path —
# the confined agent can perceive the promise (Go injected CAGE_* at
# guest start; without this, browser_language was a vacuous promise that
# still forced re-setups). The names carry no product brand: guest
# processes see these, and a constant brand prefix is a fleet marker.
cat > /etc/profile.d/session-env.sh <<'SESSENV'
export SESSION_TZ={timezone}
export SESSION_LOCALE={locale}
export SESSION_LANGUAGE={browser_language}
SESSENV
export DEBIAN_FRONTEND=noninteractive
locale-gen {locale} >/dev/null 2>&1 || true
update-locale LANG={locale} >/dev/null 2>&1 || true
# 0.3a LOCKDOWN PERSISTENCE — the durable layer lands BEFORE the
# network-dependent toolchain leg. iptables state lives in kernel RAM
# (F-059), and a script killed mid-provision leaves nothing behind to
# replay: runcmd is per-instance on cloud-init, so an interrupted first
# boot used to mean the lockdown section below never ran AND never
# re-ran — the guest stayed wide open behind a "done" status while
# every later `up` refused it. With the ruleset, the no-IPv6 drop-in and
# the boot-replay unit already on disk+enabled at this point, any later
# boot restores DROP before the network is up: an interrupted provision
# degrades to a contained guest, never an open one. The RUNTIME
# application still comes last, after the toolchain leg — provisioning
# needs the open NAT (F-054 bounds that window).
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null
printf 'net.ipv6.conf.all.disable_ipv6=1\n' > /etc/sysctl.d/99-creance-noipv6.conf
mkdir -p /etc/iptables
# F-060/F-073: the DHCP and ICMP allowances exist for the virtual NAT
# gateway (lease renewal, path-MTU signals), scoped to the /32 hosts
# this backend itself owns plus DHCP broadcast — a subnet-wide allow
# is a live exfil channel on any backend whose NAT does not own that
# range. This file is the single source of truth: the boot unit restores it verbatim and the
# runtime apply below replays the same file (no second copy to drift).
cat > /etc/iptables/rules.v4 <<'EGRESSRULES'
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT DROP [0:0]
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -p udp --dport 67 -d 255.255.255.255 -j ACCEPT
{nat_rules}COMMIT
EGRESSRULES
# The boot replay: restore the ruleset before the network is up, so no
# boot window exists with an open egress. Neutral name — the unit list
# is guest-visible.
cat > /etc/systemd/system/egress-lock.service <<'LOCKUNIT'
[Unit]
Description=Network egress policy
DefaultDependencies=no
After=systemd-modules-load.service
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/iptables-restore /etc/iptables/rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
LOCKUNIT
systemctl daemon-reload
systemctl enable egress-lock.service >/dev/null
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
  # Supply chain: the pinned tarball must match the recorded sha256
  # (nodejs.org/dist/v22.14.0/SHASUMS256.txt). A substituted tarball is
  # refused, not unpacked — the apt fallback below stays the way out.
  case "$ARCH" in
    x64)   CREANCE_NODE_SHA256=9d942932535988091034dc94cc5f42b6dc8784d6366df3a36c4c9ccb3996f0c2 ;;
    arm64) CREANCE_NODE_SHA256=8cf30ff7250f9463b53c18f89c6c606dfda70378215b2c905d0a9a8b08bd45e0 ;;
    *)     CREANCE_NODE_SHA256= ;;
  esac
  if [ -n "$CREANCE_NODE_SHA256" ]; then
    echo "$CREANCE_NODE_SHA256  /tmp/creance-node.tar.gz" | sha256sum -c - >> /var/log/creance-toolchain.log 2>&1 || rm -f /tmp/creance-node.tar.gz
  fi
  [ -f /tmp/creance-node.tar.gz ] && tar -xzf /tmp/creance-node.tar.gz -C /tmp >> /var/log/creance-toolchain.log 2>&1 \
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

# 0.3b TOPOLOGY LOCKDOWN — runtime apply, LAST and unskippable: the
# guest's only wire out is the ssh -R tunnel to the host-side core on
# this machine's own loopback (managed from the host after boot).
# Everything else, including DNS and IPv6, is dropped. The ruleset comes
# from the file written above — the same bytes the boot unit replays —
# so the applied set and the persisted set cannot drift. Lima replays
# this script on every start and cloud-init runs it once; restore is
# idempotent either way. (`up` additionally verifies behaviorally; see
# main.rs.)
/usr/sbin/iptables-restore < /etc/iptables/rules.v4

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
            "nitro-012a",
            "dev0123abcd",
            &["10.0.2.2", "10.0.2.3"],
        )
    }

    #[test]
    fn lockdown_survives_reboots_and_scopes_its_allows() {
        // F-059: the lockdown must be an instance property — a boot-time
        // unit replays the saved rules, or a stop->up cycle hands back a
        // wide-open guest behind a green exit.
        let s = script();
        assert!(
            s.contains("iptables-restore /etc/iptables/rules.v4"),
            "a boot replay unit restores the rules"
        );
        assert!(
            s.contains("systemctl enable egress-lock.service"),
            "the replay unit is enabled"
        );
        // Unit semantics carry the ordering: Before=network-pre.target
        // makes the restore precede the network (textual order inside the
        // unit file is irrelevant — [Unit] precedes [Service] by format).
        assert!(
            s.contains("Before=network-pre.target"),
            "the restore unit orders itself before the network"
        );
        // F-060: DHCP and ICMP allows are destination-scoped to the NAT
        // subnets — no bare allowance may remain.
        for bare in ["-p udp --dport 67 -j ACCEPT", "-p icmp -j ACCEPT"] {
            assert!(!s.contains(bare), "bare allowance leaked: {bare}");
        }
        // F-073: only this backend's hosts, as /32 — never a foreign
        // backend's subnet.
        assert!(s.contains("-p icmp -d 10.0.2.2/32 -j ACCEPT"));
        assert!(s.contains("-p udp --dport 67 -d 10.0.2.3/32 -j ACCEPT"));
        for foreign in ["10.0.2.0/24", "192.168.5.0/24"] {
            assert!(
                !s.contains(foreign),
                "foreign/subnet allow leaked: {foreign}"
            );
        }
        // The persisted ruleset is the single source of truth: the same
        // file the boot unit restores is what the runtime apply replays —
        // no iptables-save capture (Lima's guestagent NAT used to leak
        // LIMADNS into rules.v4 that way), no second copy to drift.
        assert!(
            s.contains("cat > /etc/iptables/rules.v4"),
            "the ruleset is persisted to disk before the toolchain leg"
        );
        assert!(
            s.contains("iptables-restore < /etc/iptables/rules.v4"),
            "the runtime apply replays the persisted file verbatim"
        );
        // Restore replaces the whole table — idempotent under Lima's
        // every-boot replay and cloud-init's once-run alike.
        assert!(
            !s.contains("iptables-save"),
            "no capture-based persistence (LIMADNS contamination)"
        );
    }

    #[test]
    fn lockdown_leg_is_last_and_unskippable() {
        let s = script();
        let toolchain = s.find("TOOLCHAIN_BUDGET").expect("toolchain leg");
        let lockdown = s
            .find("iptables-restore < /etc/iptables/rules.v4")
            .expect("runtime lockdown apply");
        assert!(
            toolchain < lockdown,
            "the contract section must come after the tolerant toolchain leg"
        );
        // The persistence artifacts land BEFORE the toolchain leg — an
        // interrupted provision still converges to a contained guest.
        let persist = s.find("/etc/iptables/rules.v4").expect("rules file");
        assert!(
            persist < toolchain,
            "rules.v4 must be written before the network-dependent leg"
        );
        let enable = s
            .find("systemctl enable egress-lock.service")
            .expect("unit enable");
        assert!(
            enable < toolchain,
            "the boot-replay unit must be enabled before the toolchain leg"
        );
        // No `|| true` on the policy flip itself — it must land or fail loud.
        let flip = s.find("iptables-restore < /etc/iptables/rules.v4").unwrap();
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
