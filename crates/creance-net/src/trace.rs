//! Exit observation through the managed core: the Cloudflare trace
//! endpoint answers with the connecting IP and country (`ip=`, `loc=`)
//! in a fixed text format. Shared by the grant-time evidence path
//! (`creance::evidence`) and the gate watchdog's periodic sampling —
//! one implementation so both observations mean the same thing.
//!
//! Honest scope (same caveat as the grant path): this is a
//! single-destination 1.1.1.1-path sample, not a whole-egress guarantee.

use crate::egress::{self, Egress};
use std::time::Instant;

/// The exit-observation endpoint: reports the connecting IP and country.
pub const TRACE_URL: &str = "https://1.1.1.1/cdn-cgi/trace";
/// The corroborating endpoint (F-038's second source): independent
/// operator, JSON body — narrows (cannot close) the single-destination
/// laundering gap: an exit laundering Cloudflare alone now also has to
/// launder ipinfo consistently.
pub const IPINFO_URL: &str = "https://ipinfo.io/json";

/// One observed exit: where the trace connection actually left.
#[derive(Clone, Debug, PartialEq)]
pub struct ExitSample {
    pub ip: String,
    pub country: String,
}

/// Fetches the trace through `egress` and parses it. Kept for callers
/// that only need the observation; `sample_pair` adds the corroborating
/// source.
pub fn sample(egress: &Egress, deadline: Instant) -> Result<ExitSample, String> {
    Ok(sample_pair(egress, deadline)?.0)
}

/// `sample` plus the second-source verdict: the bool is true when
/// ipinfo.io answered AND agreed on the country (F-038's narrowing —
/// a failed second source degrades to false; it cannot convict on
/// silence). `Err` means no evidence at all — or two sources that
/// DISAGREE, which is evidence of laundering and worse than silence.
pub fn sample_pair(egress: &Egress, deadline: Instant) -> Result<(ExitSample, bool), String> {
    let response = egress::request(egress, "GET", TRACE_URL, None, &[], deadline)?;
    if response.status != 200 {
        return Err(format!("出口观测返回 HTTP {}", response.status));
    }
    let sample = parse(&String::from_utf8_lossy(&response.body))?;
    // Second source: corroborates on agreement, convicts on disagreement,
    // says nothing on failure.
    let mut corroborated = false;
    if let Ok(second) = egress::request(egress, "GET", IPINFO_URL, None, &[], deadline) {
        if second.status == 200 {
            corroborated = corroborate(&sample, &String::from_utf8_lossy(&second.body))?;
        }
    }
    Ok((sample, corroborated))
}

/// The dual-source verdict, pure for tests: agreement corroborates,
/// disagreement convicts (Err), an unreadable second body degrades to
/// uncorroborated — it narrows, it cannot convict on silence.
fn corroborate(sample: &ExitSample, second_body: &str) -> Result<bool, String> {
    match parse_ipinfo(second_body) {
        Ok(country) if country == sample.country => Ok(true),
        Ok(country) => Err(format!(
            "出口证据双源分歧：1.1.1.1={} vs ipinfo={}",
            sample.country, country
        )),
        Err(_) => Ok(false),
    }
}

/// ipinfo's JSON body — only `country` is needed (its `ip` echoes the
/// same path sample, country is the cross-check dimension).
fn parse_ipinfo(body: &str) -> Result<String, String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let c = v
        .get("country")
        .and_then(|c| c.as_str())
        .ok_or("ipinfo 缺少 country")?;
    if c.len() != 2 || !c.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(format!("ipinfo country 非法：{c:?}"));
    }
    Ok(c.to_owned())
}

/// Parses a `key=value` line format trace. Strict: an IPv4 `ip` and a
/// two-letter `loc` are required; unknown lines are ignored, missing
/// keys are errors (no evidence beats half evidence).
pub fn parse(body: &str) -> Result<ExitSample, String> {
    let mut ip = String::new();
    let mut loc = String::new();
    for line in body.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "ip" => ip = value.trim().to_owned(),
                "loc" => loc = value.trim().to_ascii_uppercase(),
                _ => {}
            }
        }
    }
    if ip.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(format!("出口观测缺少有效 IPv4（ip={ip:?}）"));
    }
    if loc.len() != 2 || !loc.bytes().all(|c| c.is_ascii_uppercase()) {
        return Err(format!("出口观测缺少国家或地区代码（loc={loc:?}）"));
    }
    Ok(ExitSample { ip, country: loc })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_trace_happy() {
        let s = parse("fl=1\nip=203.0.113.7\nloc=se\nts=1\n").unwrap();
        assert_eq!(s.ip, "203.0.113.7");
        assert_eq!(s.country, "SE");
    }

    #[test]
    fn parse_rejects_missing_or_malformed() {
        assert!(parse("loc=SE\n").is_err());
        assert!(parse("ip=203.0.113.7\n").is_err());
        assert!(parse("ip=not-an-ip\nloc=SE\n").is_err());
        assert!(parse("ip=203.0.113.7\nloc=se1\n").is_err());
    }

    #[test]
    fn ipinfo_happy_and_strict() {
        assert_eq!(parse_ipinfo(r#"{"country":"SE"}"#).unwrap(), "SE");
        // Lowercase, wrong length, missing key, non-JSON all fail.
        assert!(parse_ipinfo(r#"{"country":"se"}"#).is_err());
        assert!(parse_ipinfo(r#"{"country":"SWE"}"#).is_err());
        assert!(parse_ipinfo(r#"{"ip":"1.2.3.4"}"#).is_err());
        assert!(parse_ipinfo("not json").is_err());
    }

    #[test]
    fn sample_pair_wires_both_sources() {
        // The pure corroborate tests do not prove sample_pair CALLS it —
        // dropping the call survived the suite (M7, mutation-verified).
        let src = include_str!("trace.rs");
        let prod = &src[..src.find("#[cfg(test)]").unwrap()];
        let f = prod.find("pub fn sample_pair").unwrap();
        let body = &prod[f..];
        assert!(body.contains("TRACE_URL"), "first source fetch");
        assert!(body.contains("IPINFO_URL"), "second source fetch");
        assert!(
            body.contains("corroborate(&sample,"),
            "the verdict is wired into the fetch path"
        );
    }

    #[test]
    fn corroborate_three_states() {
        let s = parse("ip=203.0.113.7\nloc=SE\n").unwrap();
        // Agreement marks corroborated.
        assert!(corroborate(&s, r#"{"country":"SE"}"#).unwrap());
        // Disagreement convicts.
        assert!(corroborate(&s, r#"{"country":"DE"}"#).is_err());
        // An unreadable second source degrades silently.
        assert!(!corroborate(&s, "{}").unwrap());
    }
    #[test]
    fn reputation_parse_flags_and_verdicts() {
        let dc = parse_reputation(r#"{"is_datacenter":true,"ip":"1.2.3.4"}"#).unwrap();
        assert!(dc.datacenter && !dc.tor);
        assert!(dc.flagged());
        assert!(dc.verdict().contains("数据中心"));
        let clean = parse_reputation(r#"{"is_vpn":false,"ip":"5.6.7.8"}"#).unwrap();
        assert!(!clean.flagged());
        assert!(clean.verdict().contains("低风险"));
        let tor = parse_reputation(r#"{"is_tor":true}"#).unwrap();
        assert!(tor.verdict().contains("Tor"));
        // garbage convicts nothing — it is a parse error
        assert!(parse_reputation("not json").is_err());
    }
}

/// The reputation endpoint (B-class L3): ipapi.is answers datacenter/vpn/
/// proxy/tor flags without an API key at interactive volume. Reputation
/// is ADVISORY — it never convicts: a datacenter flag is a yellow card
/// the user needs to see, not a gate decision.
pub const IPAPI_URL: &str = "https://api.ipapi.is/";

/// The exit IP's risk-control reputation as platforms likely see it.
#[derive(Clone, Debug, PartialEq)]
pub struct Reputation {
    pub datacenter: bool,
    pub vpn: bool,
    pub proxy: bool,
    pub tor: bool,
}

impl Reputation {
    /// Human verdict: the worst applicable flag names itself.
    pub fn verdict(&self) -> &'static str {
        if self.tor {
            "Tor 出口——绝大多数平台直接拒绝"
        } else if self.datacenter {
            "数据中心 IP——平台风控高疑"
        } else if self.vpn || self.proxy {
            "VPN/代理标记——部分平台加强验证"
        } else {
            "住宅/未标记——低风险"
        }
    }

    /// Whether any platform-visible risk flag is raised.
    pub fn flagged(&self) -> bool {
        self.datacenter || self.vpn || self.proxy || self.tor
    }
}

/// Fetches the reputation of the exit's own IP through `egress`. `Err`
/// means no evidence — advisory data may never block anything.
pub fn reputation(egress: &Egress, deadline: Instant) -> Result<Reputation, String> {
    let response = egress::request(egress, "GET", IPAPI_URL, None, &[], deadline)?;
    if response.status != 200 {
        return Err(format!("信誉观测返回 HTTP {}", response.status));
    }
    parse_reputation(&String::from_utf8_lossy(&response.body))
}

/// Parses the ipapi.is JSON, pure for tests. Missing flags default to
/// false — a partial answer degrades to less warning, never to conviction.
pub fn parse_reputation(body: &str) -> Result<Reputation, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("信誉响应解析失败：{e}"))?;
    let flag = |key: &str| v[key].as_bool().unwrap_or(false);
    Ok(Reputation {
        datacenter: flag("is_datacenter"),
        vpn: flag("is_vpn"),
        proxy: flag("is_proxy"),
        tor: flag("is_tor"),
    })
}
