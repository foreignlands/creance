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
/// The exact bytes written to `/etc/iptables/rules.v4` — the SINGLE
/// source of truth for that file (F-094): the bootstrap heredoc embeds
/// this text and the up-gate probe (`escape::egress_probe_script`)
/// byte-compares the on-disk file against it, so no second renderer
/// can drift and no `-I`/whitespace/NUL/reordered spelling can read as
/// the canonical ruleset.
pub fn rules_v4_text(nat_allows: &[&str]) -> String {
    let mut out = String::from(
        "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT DROP [0:0]\n\
         -A OUTPUT -o lo -j ACCEPT\n\
         -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n\
         -A OUTPUT -p udp --dport 67 -d 255.255.255.255 -j ACCEPT\n",
    );
    for host in nat_allows {
        out.push_str(&format!(
            "-A OUTPUT -p udp --dport 67 -d {host}/32 -j ACCEPT\n-A OUTPUT -p icmp -d {host}/32 -j ACCEPT\n"
        ));
    }
    out.push_str("COMMIT\n");
    out
}

pub fn guest_bootstrap(
    locale: &str,
    timezone: &str,
    browser_language: &str,
    session_token: &str,
    hostname: &str,
    username: &str,
    nat_allows: &[&str],
) -> String {
    let rules_v4 = rules_v4_text(nat_allows);
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
{rules_v4}EGRESSRULES
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
# F-082: the up-gate runs unprivileged and cannot read netfilter — the
# unit stamps the LIVE OUTPUT section into a root-owned file under /run
# (tmpfs; the guest user cannot write /run, so it cannot be forged).
ExecStartPost=/bin/sh -c '/usr/sbin/iptables-save -t filter | /usr/bin/grep -E "^:OUTPUT|^-A OUTPUT" > /run/egress-armed'
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
# main.rs.) The unit is started rather than replaying the ruleset by
# hand so the armed stamp (F-082) is written by the same
# code path that will run at every later boot — one apply, one stamp.
# `restart`, not `start`: a RemainAfterExit oneshot already active is a
# no-op under start, but Lima replays this script and must re-apply
# + re-stamp.
systemctl restart egress-lock.service

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
        // F-079: the pinned node toolchain is verified — the recorded
        // sha256s and the `sha256sum -c` gate must stay in the script.
        let s2 = script();
        assert!(s2.contains("sha256sum -c -"), "{s2}");
        assert!(s2.contains("9d942932535988091034dc94cc5f42b6dc8784d6366df3a36c4c9ccb3996f0c2"));
        assert!(s2.contains("8cf30ff7250f9463b53c18f89c6c606dfda70378215b2c905d0a9a8b08bd45e0"));
        // The persisted ruleset is the single source of truth: the same
        // file the boot unit restores is what the runtime apply replays —
        // no iptables-save capture (Lima's guestagent NAT used to leak
        // LIMADNS into rules.v4 that way), no second copy to drift.
        assert!(
            s.contains("cat > /etc/iptables/rules.v4"),
            "the ruleset is persisted to disk before the toolchain leg"
        );
        assert!(
            s.contains("ExecStart=/usr/sbin/iptables-restore /etc/iptables/rules.v4"),
            "the unit replays the persisted file verbatim"
        );
        assert!(
            s.contains("systemctl restart egress-lock.service"),
            "the runtime apply goes through the unit (restore + stamp)"
        );
        // Restore replaces the whole table — idempotent under Lima's
        // every-boot replay and cloud-init's once-run alike. iptables-save
        // is allowed only in the read-only /run/egress-armed stamp — never
        // into rules.v4 (LIMADNS contamination).
        assert!(
            !s.contains("iptables-save > /etc"),
            "no capture-based persistence into rules.v4 (LIMADNS contamination)"
        );
        assert!(
            !s.contains("iptables-save -f"),
            "no capture-based persistence into rules.v4 (LIMADNS contamination)"
        );
    }

    #[test]
    fn lockdown_leg_is_last_and_unskippable() {
        let s = script();
        let toolchain = s.find("TOOLCHAIN_BUDGET").expect("toolchain leg");
        let lockdown = s
            .find("systemctl restart egress-lock.service")
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
        let flip = s.find("systemctl restart egress-lock.service").unwrap();
        let rest = &s[flip..];
        let line_end = rest.find('\n').unwrap();
        assert!(!rest[..line_end].contains("|| true"));
    }

    #[test]
    fn armed_stamp_is_root_written_from_live_rules() {
        // F-082/F-083/F-087: the unprivileged up-gate reads
        // /run/egress-armed; it must be produced by the unit (root)
        // from the LIVE ruleset — not by any path the guest user
        // controls. Exact line: a `;`/`|` append on ExecStartPost
        // (STAMPr) or a comment on the restart leg must fail these.
        let s = script();
        assert!(
            s.contains("ExecStartPost=/bin/sh -c '/usr/sbin/iptables-save -t filter | /usr/bin/grep -E \"^:OUTPUT|^-A OUTPUT\" > /run/egress-armed'\n"),
            "{s}"
        );
        // The apply leg goes through the unit, uncommented — the stamp
        // is written by the same code path that runs at every later boot.
        assert!(
            s.contains("\nsystemctl restart egress-lock.service\n"),
            "{s}"
        );
        // F-091/F-093/F-095: the ExecStartPost stamp write is the ONLY
        // occurrence of the stamp path in the whole script — a second,
        // forged write (`>`, `>>`, `>/run`, `| tee`, a smuggled line)
        // adds an occurrence and fails this regardless of spelling.
        // `egress-armed` alone (no /run/ prefix) catches an alternate
        // spelling of the SAME path (/run/./egress-armed, /run//…).
        assert_eq!(s.matches("/run/egress-armed").count(), 1, "{s}");
        assert_eq!(s.matches("egress-armed").count(), 1, "{s}");
        // F-095+F-097/NC-UNIT+ESPsp+STAMPq: exactly one ExecStartPost
        // under ANY spelling — systemd accepts `=` flanked by blanks
        // (`ExecStartPost = …` executes, verified on systemd 249) and
        // a forged stamp write can hide behind quote-splitted words
        // (`egress-"armed"`). The bare keyword count catches all of it:
        // a second post line, spaced or quoted, is count 2.
        assert_eq!(s.matches("ExecStartPost").count(), 1, "{s}");
        // F-114/F-115: heredoc spans — every `<<'TAG'` opener must
        // close at a bare TAG line; lines inside a span are heredoc
        // BODY, not executed shell. The cat/enable pins below must sit
        // OUTSIDE every span: a `: <<'X'` wrapper or an unterminated
        // heredoc swallows them while every count and `sh -n` stays
        // green.
        let mut spans: Vec<(usize, usize)> = Vec::new();
        for (li, l) in s.lines().enumerate() {
            if let Some(pos) = l.find("<<") {
                let tag: String = l[pos + 2..]
                    .trim_start_matches('\'')
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                assert!(!tag.is_empty(), "unparseable heredoc at line {li}: {l}");
                // F-120: POSIX `<<` accepts only a terminator line
                // byte-equal to the tag (no leading whitespace — `<<-`
                // strips tabs alone). A trimmed compare would close
                // the span on ` SKIPRULES` while dash keeps reading
                // to EOF, swallowing every pinned line after it.
                let end = s
                    .lines()
                    .enumerate()
                    .skip(li + 1)
                    .find(|(_, x)| *x == tag)
                    .map(|(i, _)| i)
                    .unwrap_or_else(|| panic!("unterminated heredoc {tag} at line {li}"));
                spans.push((li, end));
            }
        }
        let inside_span = |li: usize| spans.iter().any(|&(a, b)| li > a && li <= b);
        let line_idx = |needle: &str| {
            s.lines()
                .position(|l| l.trim() == needle)
                .unwrap_or_else(|| panic!("missing line: {needle}"))
        };
        // The three cat lines and the enable line are FULL-line literal
        // pins — quote-split paths (`system""d`, `cat >"…"`), trailing
        // args, comments or a `cd`-into-dir relative write all fail.
        for needle in [
            "cat > /etc/profile.d/session-env.sh <<'SESSENV'",
            "cat > /etc/iptables/rules.v4 <<'EGRESSRULES'",
            "cat > /etc/systemd/system/egress-lock.service <<'LOCKUNIT'",
            "systemctl enable egress-lock.service >/dev/null",
            "systemctl daemon-reload",
            "systemctl restart egress-lock.service",
        ] {
            let li = line_idx(needle);
            assert!(
                !inside_span(li),
                "{needle} is inside a heredoc — never executed"
            );
        }
        // F-121: all textual pins run on a QUOTE-MERGED copy — sh
        // concatenates adjacent quoted segments, so `system""d`,
        // `egress-""lock` and `cat >"…"` only differ on the surface.
        let norm: String = s.chars().filter(|c| *c != '\'' && *c != '"').collect();
        assert_eq!(norm.matches("cat >").count(), 3, "{s}");
        // Navigation/side-write verbs are banned outright: a `cd` into
        // the unit dir plus a relative `cat > x` writes a second unit
        // without touching the counts; `tee`/`dd` spellings bypass
        // `cat` counting the same way. F-120/F-121: `exec` replaces the
        // shell, `false` trips `set -e`, `&& exit`/`|| exit` terminate
        // early, and env/command prefixes or absolute paths dodge
        // line-start matching — all banned as tokens anywhere on a
        // non-span line.
        // The `sh -c '…'` toolchain block is an inner-shell span:
        // `exit`/`false` inside it aborts only the inner sh (caught by
        // `|| true`), and its lines legitimately use install/mv/apt.
        // Everything between the opener and the closing `' || true`
        // is exempt from the verb token ban below.
        let inner_open = s
            .lines()
            .position(|l| l.trim_end().ends_with("sh -c '"))
            .expect("toolchain inner block");
        let inner_close = s
            .lines()
            .enumerate()
            .skip(inner_open + 1)
            .find(|(_, l)| l.trim_start().starts_with('\''))
            .map(|(i, _)| i)
            .expect("inner block close");
        let banned_tokens = [
            "cd", "pushd", "popd", "builtin", "eval", "tee", "dd", "exit", "return", "exec",
            "false", "xargs", "install", "cp", "chroot", "setsid", "nohup", "sudo", "su", "source",
            "wait", "trap", "kill",
        ];
        for (li, l) in s.lines().enumerate() {
            if inside_span(li)
                || (li > inner_open && li < inner_close)
                || l.trim_start().starts_with('#')
            {
                continue;
            }
            let ln: String = l.chars().filter(|c| *c != '\'' && *c != '"').collect();
            assert!(
                !ln.trim_start().starts_with('/'),
                "absolute-path command: {l}"
            );
            for starter in ["env ", "command ", "nice ", "sudo "] {
                assert!(
                    !ln.trim_start().starts_with(starter),
                    "prefix-wrapped command: {l}"
                );
            }
            for tok in ln.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
                assert!(
                    !banned_tokens.contains(&tok),
                    "banned verb token in script line {li}: {l}"
                );
            }
        }
        // Every line MENTIONING `systemctl` or `egress-lock` (not just
        // line-start) must normalize to one of the literals — a
        // `/bin/systemctl disable` or an `env systemctl …` prefix and a
        // quote-split unit name all fail here.
        for l in s.lines().map(str::trim) {
            let ln: String = l.chars().filter(|c| *c != '\'' && *c != '"').collect();
            if ln.contains("systemctl") {
                assert!(
                    [
                        "systemctl daemon-reload",
                        "systemctl enable egress-lock.service >/dev/null",
                        "systemctl restart egress-lock.service"
                    ]
                    .contains(&ln.as_str()),
                    "unexpected systemctl line: {l}"
                );
            }
            if ln.contains("egress-lock") {
                assert!(
                    [
                        "cat > /etc/systemd/system/egress-lock.service <<LOCKUNIT",
                        "systemctl enable egress-lock.service >/dev/null",
                        "systemctl restart egress-lock.service"
                    ]
                    .contains(&ln.as_str()),
                    "unexpected egress-lock line: {l}"
                );
            }
        }
        assert_eq!(norm.matches("systemd/").count(), 1, "{s}");
        // F-096/F-098: the rules.v4 heredoc is checked STRUCTURALLY AND
        // EXECUTED. Structure: the `cat >` line is exactly the literal
        // (no `if`/`&&` prefix can mask it), exactly two lines mention
        // EGRESSRULES (open + bare terminator — a whitespace-prefixed
        // extra terminator line bumps the count), body byte-exact vs
        // rules_v4_text.
        let cat_line = s
            .lines()
            .find(|l| l.contains("cat > /etc/iptables/rules.v4"))
            .expect("rules.v4 cat line");
        assert_eq!(cat_line, "cat > /etc/iptables/rules.v4 <<'EGRESSRULES'");
        assert_eq!(
            s.lines().filter(|l| l.contains("EGRESSRULES")).count(),
            2,
            "{s}"
        );
        let open = s.find("<<'EGRESSRULES'\n").expect("heredoc open") + "<<'EGRESSRULES'\n".len();
        let term = s[open..]
            .find("\nEGRESSRULES\n")
            .expect("heredoc terminator");
        assert_eq!(
            &s[open..open + term + 1],
            &rules_v4_text(&["10.0.2.2", "10.0.2.3"]),
            "rules.v4 heredoc body must be the renderer's own bytes"
        );
        // Executed second line: run the segment — heredoc PLUS whatever
        // line follows the terminator — under `sh -e` in a temp dir.
        // A stray terminator-shaped line after `EGRESSRULES` (the
        // v0.6.18 brick, whitespace variants included) runs as a
        // command → RC=127; a wrapped `if false …`/`fi` tail breaks the
        // syntax. The byte-exact body assert covers CONTENT; this
        // covers the ENVELOPE.
        let seg_start = s.find("cat > /etc/iptables/rules.v4").unwrap();
        let term_end =
            seg_start + s[seg_start..].find("\nEGRESSRULES\n").unwrap() + "\nEGRESSRULES\n".len();
        let seg_end = s[term_end..]
            .find('\n')
            .map(|i| term_end + i + 1)
            .unwrap_or(s.len());
        // F-108: the cat line must also be TOP-LEVEL — a wrapper opened
        // before it (`if false; then`, `: <<'SKIPRULES'`) closes after
        // the segment and never enters the executed slice. `sh -n` on
        // the prefix+`exit 0` fails on any unclosed construct, and
        // `sh -n` on the whole script catches unbalanced `fi`/EOF.
        let prefix_ok = std::process::Command::new("sh")
            .arg("-nc")
            .arg(format!("{}\nexit 0\n", &s[..seg_start]))
            .status()
            .unwrap()
            .success();
        assert!(prefix_ok, "bootstrap prefix must be top-level shell");
        let whole_ok = std::process::Command::new("sh")
            .arg("-nc")
            .arg(&s)
            .status()
            .unwrap()
            .success();
        assert!(whole_ok, "rendered bootstrap must be balanced shell");
        let dir = std::env::temp_dir().join(format!("creance-heredoc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("rules.v4");
        let segment =
            s[seg_start..seg_end].replace("/etc/iptables/rules.v4", target.to_str().unwrap());
        let status = std::process::Command::new("sh")
            .arg("-ec")
            .arg(&segment)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "heredoc segment must execute clean: {segment}"
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            rules_v4_text(&["10.0.2.2", "10.0.2.3"]),
            "executed heredoc must write the renderer's bytes"
        );
        let _ = std::fs::remove_dir_all(&dir);
        // ...and the tail after the apply leg is byte-exact — any
        // injected netfilter touch (`iptables -P`, `nft flush`,
        // another stamp write) changes the bytes and fails this.
        let apply = s.find("systemctl restart egress-lock.service").unwrap();
        let expected_tail = concat!(
            "systemctl restart egress-lock.service\n",
            "\n",
            "# 020 PRIVILEGE RETIREMENT — cloud-init unconditionally grants the guest\n",
            "# user sudo (NOPASSWD, or a random password parked in ~/password when\n",
            "# passwordlessSudo is false). The enforcement plane is only as strong as\n",
            "# the weakest privilege path, so the grant dies here: without it the\n",
            "# firewall above cannot be lifted from inside the guest.\n",
            "SUDOERS=/etc/sudoers.d/90-cloud-init-users\n",
            "[ -f \"$SUDOERS\" ] && sed -i '\\#^dev0123abcd #d' \"$SUDOERS\" || true\n",
            "passwd -l dev0123abcd 2>/dev/null || true\n",
            "GUEST_HOME=$(getent passwd dev0123abcd | cut -d: -f6)\n",
            "[ -n \"$GUEST_HOME\" ] && rm -f \"$GUEST_HOME/password\" || true\n",
        );
        assert_eq!(&s[apply..], expected_tail, "{s}");
        // F-084/F-087/F-091: a bad node checksum must never be unpacked —
        // the conditional's full line (a `&& false` append breaks it),
        // the rm gate, exactly one nodejs.org download.
        assert!(
            s.contains("if [ -n \"$CREANCE_NODE_SHA256\" ]; then\n"),
            "{s}"
        );
        assert!(s.contains("sha256sum -c - >> /var/log/creance-toolchain.log 2>&1 || rm -f /tmp/creance-node.tar.gz"), "{s}");
        assert_eq!(
            s.matches("nodejs.org/dist/v22.14.0/node-v22.14.0-linux")
                .count(),
            1,
            "{s}"
        );
    }

    #[test]
    fn bootstrap_executes_the_lockdown_leg_for_real() {
        // F-120/F-121: no text pin can prove a line RUNS — `exec true`,
        // `exit`, a bare `false` under `set -e`, or a heredoc whose
        // terminator is whitespace-indented (POSIX `<<` wants a
        // byte-equal line) all kill the lockdown while every count
        // stays green. Execute the rendered script under real `sh -e`
        // in a stub root: absolute paths rewritten to a temp dir,
        // systemctl and friends stubbed behind it. The lockdown
        // artifacts and the systemctl call set are then asserted —
        // an early exit of ANY spelling leaves them unwritten.
        let s = script();
        let stub = std::env::temp_dir().join(format!("creance-bootexec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&stub);
        let root = stub.to_str().unwrap().to_string();
        // Stub commands live at $STUB/bin — the `/bin/` rewrite makes
        // absolute-path calls (`/bin/systemctl disable`) hit them too.
        for (name, body) in [
            (
                "systemctl",
                format!("echo \"$@\" >> {root}/systemctl.log\nexit 0\n"),
            ),
            ("hostnamectl", "exit 0\n".to_string()),
            ("locale-gen", "exit 0\n".to_string()),
            ("update-locale", "exit 0\n".to_string()),
            ("sysctl", "exit 0\n".to_string()),
            ("apt-get", "exit 0\n".to_string()),
            ("apt", "exit 0\n".to_string()),
            ("dpkg", "exit 0\n".to_string()),
            ("curl", "exit 22\n".to_string()),
            ("passwd", "exit 0\n".to_string()),
            ("iptables-restore", "exit 0\n".to_string()),
            ("ip", "exit 0\n".to_string()),
            ("mount", "exit 0\n".to_string()),
            (
                "getent",
                "echo \"$2:x:1000:1000::/nonexistent:/bin/sh\"\n".to_string(),
            ),
        ] {
            let p = stub.join("bin").join(name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, format!("#!/bin/sh\n{body}")).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        // /tmp/ first: replacement paths contain the stub root and must
        // not be re-rewritten by a later pass.
        let rewritten = s
            .replace("/tmp/", &format!("{root}/tmp/"))
            .replace("/etc/", &format!("{root}/etc/"))
            .replace("/var/", &format!("{root}/var/"))
            .replace("/run/", &format!("{root}/run/"))
            .replace("/usr/", &format!("{root}/usr/"))
            .replace("/home/", &format!("{root}/home/"))
            .replace("/bin/", &format!("{root}/bin/"))
            .replace("/sbin/", &format!("{root}/sbin/"));
        for d in [
            "etc/profile.d",
            "etc/sysctl.d",
            "etc/systemd/system",
            "var/log",
            "tmp",
            "usr/local/bin",
            "run",
            "home",
        ] {
            std::fs::create_dir_all(stub.join(d)).unwrap();
        }
        let script_path = stub.join("bootstrap.sh");
        std::fs::write(&script_path, &rewritten).unwrap();
        let out = std::process::Command::new("sh")
            .arg("-e")
            .arg(&script_path)
            .env(
                "PATH",
                format!("{}/bin:{}", root, std::env::var("PATH").unwrap()),
            )
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "bootstrap aborted under sh -e (rc={:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(stub.join("etc/iptables/rules.v4"))
                .expect("rules.v4 was never written — the script died before the cat"),
            rules_v4_text(&["10.0.2.2", "10.0.2.3"]),
        );
        let units: Vec<String> = std::fs::read_dir(stub.join("etc/systemd/system"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            units,
            ["egress-lock.service"],
            "unexpected units: {units:?}"
        );
        assert!(
            stub.join("etc/profile.d/session-env.sh").exists(),
            "session-env never written"
        );
        assert!(
            stub.join("etc/sysctl.d/99-creance-noipv6.conf").exists(),
            "no-ipv6 drop-in never written"
        );
        let calls = std::fs::read_to_string(stub.join("systemctl.log"))
            .expect("systemctl was never invoked");
        assert_eq!(
            calls.lines().collect::<Vec<_>>(),
            [
                "daemon-reload",
                "enable egress-lock.service",
                "restart egress-lock.service"
            ],
            "systemctl calls: {calls}"
        );
        let _ = std::fs::remove_dir_all(&stub);
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
