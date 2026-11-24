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

/// One observed exit: where the trace connection actually left.
#[derive(Clone, Debug, PartialEq)]
pub struct ExitSample {
    pub ip: String,
    pub country: String,
}

/// Fetches the trace through `egress` and parses it. `Err` means no
/// evidence at all — callers must not treat it as a verdict either way.
pub fn sample(egress: &Egress, deadline: Instant) -> Result<ExitSample, String> {
    let response = egress::request(egress, "GET", TRACE_URL, None, &[], deadline)?;
    if response.status != 200 {
        return Err(format!("出口观测返回 HTTP {}", response.status));
    }
    parse(&String::from_utf8_lossy(&response.body))
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
