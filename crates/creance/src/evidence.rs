//! Exit-policy evidence: observe where traffic actually leaves, through
//! the configured proxy, and turn the observation into a grant's checks.
//!
//! The observation target is Cloudflare's trace endpoint: it answers with
//! the connecting IP and country (`ip=`, `loc=`) in a fixed text format.
//! Region/city have no honest source in this response (`colo` is a
//! Cloudflare datacenter, not the exit's region), so a region- or
//! city-scoped anchor evaluates Unknown — closed, with the reason —
//! rather than guessing.
//!
//! Trust boundary (F-038, stated honestly): this is a SINGLE-DESTINATION
//! sample. TLS (webpki-roots) proves the connection genuinely terminated
//! at Cloudflare, and the managed core's single-group config keeps the
//! evidence path and the wire on the same node — but nothing can prove
//! the NODE routes all destinations the same way. An exit that forwards
//! 1.1.1.1 through a US relay while sending everything else out a
//! mainland interface launders the anchor; the mandatory mainland deny
//! silently fails against such a subscription. The evidence keys below
//! are therefore a 1.1.1.1-path sample, not a whole-egress guarantee. A
//! second independent source narrows (cannot close) this; until then the
//! anchor's guarantee is: "the exit reaches Cloudflare from `<ip>` —
//! everything else rests on the subscription's routing honesty."

use creance_vm::config::Config;
use creance_vm::exit_policy::Location;
use std::time::Duration;
use std::time::Instant;

/// The exit-observation endpoint (shared with the gate watchdog's
/// periodic sampling — both fetch through `creance_net::trace`). Kept
/// as a const, not a re-export: `pub use` would erase the public API
/// item (semver-checks flags a missing const).
pub const TRACE_URL: &str = creance_net::trace::TRACE_URL;
/// The observation budget: a check window (180s) must survive it easily.
const TRACE_BUDGET: Duration = Duration::from_secs(25);

/// Observes the exit through the profile's configured proxy. `Err` means
/// no evidence at all — the caller must not grant on that.
pub fn observe(cfg: &Config) -> Result<Location, String> {
    observe_full(cfg).map(|(location, _)| location)
}

/// Like [`observe`] but also reports whether the second independent
/// source corroborated the country (F-038's narrowing).
pub fn observe_full(cfg: &Config) -> Result<(Location, bool), String> {
    let egress = creance_net::egress::Egress::new(&cfg.proxy_url, &cfg.dns_url)?;
    let (sample, corroborated) =
        creance_net::trace::sample_pair(&egress, Instant::now() + TRACE_BUDGET)?;
    Ok((sample_to_location(sample), corroborated))
}

/// Parses a `key=value` line format trace into a Location. Strict: an
/// IPv4 `ip` and a two-letter `loc` are required; unknown lines are
/// ignored, missing keys are errors (no evidence beats half evidence).
pub fn parse_trace(body: &str) -> Result<Location, String> {
    creance_net::trace::parse(body).map(sample_to_location)
}

fn sample_to_location(sample: creance_net::trace::ExitSample) -> Location {
    Location {
        ip: sample.ip,
        country_code: sample.country,
        region: String::new(),
        city: String::new(),
        country: String::new(),
        region_code: String::new(),
        timezone: String::new(),
    }
}

/// The checks a grant carries: the four structural self-checks (they
/// describe how the egress stack is built — one upstream, no direct
/// fallback, DNS over the same tunnel, IPv6 fenced — not runtime
/// observations) plus the exit-consistency verdict from live evidence,
/// with the observation itself recorded for the audit trail.
pub fn grant_checks(location: &Location) -> std::collections::BTreeMap<String, String> {
    grant_checks_with(location, false)
}

/// [`grant_checks`] plus the second-source corroboration flag, recorded
/// as an inert audit key so a later watchdog sample can see how strong
/// the baseline it compares against is.
pub fn grant_checks_with(
    location: &Location,
    corroborated: bool,
) -> std::collections::BTreeMap<String, String> {
    let mut checks = std::collections::BTreeMap::new();
    checks.insert("egress_policy".to_owned(), "passed".to_owned());
    checks.insert("fail_closed".to_owned(), "passed".to_owned());
    checks.insert("udp_policy".to_owned(), "passed".to_owned());
    checks.insert("ipv6_policy".to_owned(), "passed".to_owned());
    checks.insert("exit_consistency".to_owned(), "passed".to_owned());
    // Evidence keys are inert to the gate's REQUIRED set; they make the
    // observation itself part of the record. F-038: these describe the
    // 1.1.1.1 path sample, not the whole egress.
    checks.insert("exit_ip".to_owned(), location.ip.clone());
    checks.insert("exit_country".to_owned(), location.country_code.clone());
    checks.insert("exit_sample".to_owned(), "1.1.1.1-path".to_owned());
    checks.insert(
        "exit_corroborated".to_owned(),
        if corroborated { "yes" } else { "no" }.to_owned(),
    );
    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRACE: &str =
        "fl=abc\nh=1.1.1.1\nip=142.249.39.221\nts=...\nuag=curl\ncolo=LAX\nloc=us\ntls=TLSv1.3\n";

    #[test]
    fn trace_parses_to_a_location() {
        let loc = parse_trace(TRACE).unwrap();
        assert_eq!(loc.ip, "142.249.39.221");
        assert_eq!(loc.country_code, "US");
        assert_eq!(loc.region, "", "colo is not a region; it stays empty");
    }

    #[test]
    fn trace_without_evidence_is_an_error_not_a_guess() {
        assert!(parse_trace("fl=x\nloc=US\n").is_err(), "no ip");
        assert!(parse_trace("fl=x\nip=8.8.8.8\n").is_err(), "no loc");
        assert!(
            parse_trace("ip=2001:db8::1\nloc=US\n").is_err(),
            "v6 not parsed as v4"
        );
        assert!(
            parse_trace("ip=8.8.8.8\nloc=usa\n").is_err(),
            "country must be 2 letters"
        );
        assert!(parse_trace("").is_err(), "empty body");
    }

    #[test]
    fn grant_checks_carry_the_observation() {
        let loc = parse_trace(TRACE).unwrap();
        let checks = grant_checks(&loc);
        assert_eq!(
            checks.get("exit_consistency").map(String::as_str),
            Some("passed")
        );
        assert_eq!(
            checks.get("exit_ip").map(String::as_str),
            Some("142.249.39.221")
        );
        assert_eq!(checks.get("exit_country").map(String::as_str), Some("US"));
        for structural in ["egress_policy", "fail_closed", "udp_policy", "ipv6_policy"] {
            assert_eq!(checks.get(structural).map(String::as_str), Some("passed"));
        }
    }
}
