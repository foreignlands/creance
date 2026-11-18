//! Exit policy: the user-configured anchor for where guest traffic may leave,
//! plus the mandatory mainland-IPv4 deny list checked on every evaluation.
//!
//! Observations never silently replace a configured address or region; the
//! policy's anchor survives checks and restarts.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::OnceLock;

/// The bundled mainland prefix list, from the same source the Go build embeds.
static MAINLAND_TXT: &str = include_str!("data/mainland-ipv4.txt");

/// User configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub mode: String,
    pub scope: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub country_code: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub region: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub city: String,
}

/// One observation of where traffic actually left.
#[derive(Clone, Debug, Default)]
pub struct Location {
    pub ip: String,
    pub country_code: String,
    pub region: String,
    pub city: String,
    /// Full country name; unused by evaluation, kept for reporting parity.
    pub country: String,
    pub region_code: String,
    pub timezone: String,
}

/// The verdict of one evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Passed,
    Failed,
    Unknown,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Passed => "passed",
            State::Failed => "failed",
            State::Unknown => "unknown",
        }
    }
}

impl Policy {
    /// Fills unset fields with their defaults and normalizes spacing.
    pub fn normalized(&self) -> Policy {
        let mut p = self.clone();
        if p.mode.is_empty() {
            p.mode = "dynamic".to_owned();
        }
        if p.scope.is_empty() {
            p.scope = "country".to_owned();
        }
        p.ip = p.ip.trim().to_owned();
        p.country_code = p.country_code.trim().to_uppercase();
        p.region = collapse_spaces(&p.region);
        p.city = collapse_spaces(&p.city);
        p
    }

    /// `Err(message)` when user-entered values are invalid.
    pub fn validate(&self) -> Result<(), String> {
        let p = self.normalized();
        if p.mode != "static" && p.mode != "dynamic" {
            return Err("请选择静态或动态 IP".to_owned());
        }
        if !matches!(p.scope.as_str(), "any" | "country" | "region" | "city") {
            return Err("请选择动态 IP 的允许范围".to_owned());
        }
        if !p.ip.is_empty() {
            match p.ip.parse::<Ipv4Addr>() {
                Ok(ip) if is_global_unicast(&ip) && !is_private(&ip) => {}
                _ => return Err("固定出口应填写公网 IPv4 地址".to_owned()),
            }
        }
        if !p.country_code.is_empty()
            && (p.country_code.len() != 2
                || !p.country_code.bytes().all(|c| c.is_ascii_uppercase()))
        {
            return Err("国家或地区代码应为两个字母，例如 US".to_owned());
        }
        if p.region.len() > 120 || p.city.len() > 120 {
            return Err("地区名称过长".to_owned());
        }
        Ok(())
    }

    /// Whether evaluation still awaits a binding the user must confirm.
    pub fn needs_binding(&self) -> bool {
        let p = self.normalized();
        if p.mode == "static" {
            return p.ip.is_empty();
        }
        p.scope != "any"
            && (p.country_code.is_empty()
                || (p.scope == "region" || p.scope == "city") && p.region.is_empty()
                || p.scope == "city" && p.city.is_empty())
    }

    /// Binds only previously unset anchor fields, and only when the
    /// observation itself passes the mandatory country check.
    pub fn bind_missing(&self, location: &Location) -> Policy {
        let mut p = self.normalized();
        if check_exit_country(&location.ip, Some(location)).0 != State::Passed {
            return p;
        }
        if p.mode == "static" && p.ip.is_empty() {
            p.ip = location.ip.clone();
        }
        if p.mode == "dynamic" && p.scope != "any" {
            if p.country_code.is_empty() {
                p.country_code = location.country_code.clone();
            }
            if (p.scope == "region" || p.scope == "city")
                && p.country_code.eq_ignore_ascii_case(&location.country_code)
            {
                if p.region.is_empty() {
                    p.region = location.region.clone();
                }
                if p.scope == "city" && p.city.is_empty() {
                    p.city = location.city.clone();
                }
            }
        }
        p.normalized()
    }

    /// Evaluates an observed exit IP against this policy.
    pub fn evaluate(&self, ip: &str, location: Option<&Location>) -> (State, String) {
        let p = self.normalized();
        if let Err(message) = p.validate() {
            return (State::Unknown, message);
        }
        let (state, message) = check_exit_country(ip, location);
        if state != State::Passed {
            return (state, message);
        }
        let Some(location) = location else {
            return (
                State::Unknown,
                "无法确认出口国家或地区，外网保持关闭".to_owned(),
            );
        };
        if p.needs_binding() {
            if p.mode == "dynamic" && p.country_code.is_empty() {
                return (
                    State::Unknown,
                    "动态 IP 的允许国家或地区尚未绑定，外网保持关闭。请在网络与代理设置中确认出口地区".to_owned(),
                );
            }
            return (
                State::Unknown,
                "尚未绑定出口规则，请在设置中确认检测到的 IP 或地区".to_owned(),
            );
        }
        if p.mode == "static" {
            return if p.ip == ip {
                (State::Passed, "检测出口与绑定的静态 IP 一致".to_owned())
            } else {
                (State::Failed, "检测出口已偏离绑定的静态 IP".to_owned())
            };
        }
        if p.scope == "any" {
            return (
                State::Passed,
                "动态 IP 可在非中国大陆地区变化，流量仍须经指定代理".to_owned(),
            );
        }
        if !p.country_code.eq_ignore_ascii_case(&location.country_code) {
            return (State::Failed, "检测出口超出允许的国家或地区".to_owned());
        }
        if p.scope == "country" {
            return (State::Passed, "检测出口位于允许的国家或地区".to_owned());
        }
        if location.region.is_empty() {
            return (
                State::Unknown,
                "当前位置缺少州或省，不能确认允许范围".to_owned(),
            );
        }
        if !p
            .region
            .eq_ignore_ascii_case(&collapse_spaces(&location.region))
        {
            return (State::Failed, "检测出口超出允许的州或省范围".to_owned());
        }
        if p.scope == "region" {
            return (State::Passed, "检测出口位于允许的州或省".to_owned());
        }
        if location.city.is_empty() {
            return (
                State::Unknown,
                "当前位置缺少州、省或城市，不能确认城市范围".to_owned(),
            );
        }
        if !p
            .city
            .eq_ignore_ascii_case(&collapse_spaces(&location.city))
        {
            return (State::Failed, "检测出口超出允许的城市范围".to_owned());
        }
        (
            State::Passed,
            "检测出口位于允许的城市及其所属州、省".to_owned(),
        )
    }
}

/// Mandatory regardless of the user-selected rule: a mainland list match is
/// enough to deny; absence from the list cannot prove a non-mainland exit and
/// still requires matching country evidence.
pub fn check_exit_country(ip: &str, location: Option<&Location>) -> (State, String) {
    let Ok(address) = ip.parse::<Ipv4Addr>() else {
        return (State::Unknown, "尚未取得有效的检测出口".to_owned());
    };
    if !is_global_unicast(&address) || is_private(&address) {
        return (State::Unknown, "尚未取得有效的检测出口".to_owned());
    }
    let Some(prefixes) = mainland_prefixes() else {
        return (
            State::Unknown,
            "大陆出口网段库不可用，外网保持关闭".to_owned(),
        );
    };
    if prefixes
        .iter()
        .any(|(net, bits)| masked(address, *bits) == *net)
    {
        return (
            State::Failed,
            "检测出口命中中国大陆 IP 网段，Cage 禁止使用大陆出口，外网保持关闭".to_owned(),
        );
    }
    let Some(location) = location else {
        return (
            State::Unknown,
            "无法确认出口国家或地区，外网保持关闭".to_owned(),
        );
    };
    if location.ip != address.to_string() {
        return (
            State::Unknown,
            "无法确认出口国家或地区，外网保持关闭".to_owned(),
        );
    }
    let country = location.country_code.trim().to_uppercase();
    let ok = country.len() == 2
        && country.bytes().all(|c| c.is_ascii_uppercase())
        && country != "ZZ"
        && country != "XX";
    if !ok {
        return (
            State::Unknown,
            "无法确认出口国家或地区，外网保持关闭".to_owned(),
        );
    }
    if country == "CN" {
        return (
            State::Failed,
            "检测出口位于中国大陆，Cage 禁止使用大陆出口，外网保持关闭".to_owned(),
        );
    }
    (
        State::Passed,
        "检测出口未命中大陆网段，国家或地区信息符合非大陆出口要求".to_owned(),
    )
}

/// RFC 1918 private ranges.
fn is_private(ip: &Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a == 10 || (a == 172 && (0x10..=0x1f).contains(&b)) || (a == 192 && b == 168)
}

/// Unicast, excluding unspecified, loopback, link-local and multicast —
/// Go's `netip.Addr.IsGlobalUnicast` for IPv4.
fn is_global_unicast(ip: &Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_broadcast()
        && !ip.is_multicast()
}

fn collapse_spaces(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Parses the embedded list once; a malformed file yields `None` and fails
/// closed. Entries are normalized to their masked form; anything below a /8
/// is rejected.
fn mainland_prefixes() -> Option<&'static [(Ipv4Addr, u8)]> {
    static PREFIXES: OnceLock<Vec<(Ipv4Addr, u8)>> = OnceLock::new();
    let prefixes = PREFIXES.get_or_init(|| {
        let mut out = Vec::new();
        for line in MAINLAND_TXT.split_whitespace() {
            let Some((addr, bits)) = line.split_once('/') else {
                return Vec::new();
            };
            let (Ok(addr), Ok(bits)) = (addr.parse::<Ipv4Addr>(), bits.parse::<u8>()) else {
                return Vec::new();
            };
            if bits < 8 {
                return Vec::new();
            }
            out.push((masked(addr, bits), bits));
        }
        out
    });
    (!prefixes.is_empty()).then_some(prefixes.as_slice())
}

fn masked(addr: Ipv4Addr, bits: u8) -> Ipv4Addr {
    let v = u32::from(addr) & if bits == 0 { 0 } else { !0u32 << (32 - bits) };
    Ipv4Addr::from(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dynamic(scope: &str, country: &str) -> Policy {
        Policy {
            mode: "dynamic".to_owned(),
            scope: scope.to_owned(),
            country_code: country.to_owned(),
            ..Default::default()
        }
    }

    fn location(ip: &str, country: &str) -> Location {
        Location {
            ip: ip.to_owned(),
            country_code: country.to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn mainland_list_is_strict() {
        // Well-known mainland and non-mainland addresses.
        assert_eq!(check_exit_country("114.114.114.114", None).0, State::Failed);
        assert_eq!(check_exit_country("8.8.8.8", None).0, State::Unknown);
        assert_eq!(check_exit_country("192.168.1.1", None).0, State::Unknown);
        assert_eq!(check_exit_country("not-an-ip", None).0, State::Unknown);
        // CN evidence itself is a denial.
        let loc = location("8.8.8.8", "CN");
        assert_eq!(check_exit_country("8.8.8.8", Some(&loc)).0, State::Failed);
    }

    #[test]
    fn mainland_file_is_valid_and_masked() {
        let prefixes = mainland_prefixes().expect("bundled list must parse");
        assert!(prefixes.len() > 1000);
        // 1.3.0.0/16 contains 1.3.255.255.
        let covered: Ipv4Addr = "1.3.255.255".parse().unwrap();
        assert!(prefixes
            .iter()
            .any(|(net, bits)| masked(covered, *bits) == *net));
    }

    #[test]
    fn validate_rejects_bad_anchors() {
        assert!(dynamic("country", "US").validate().is_ok());
        assert!(dynamic("galaxy", "US").validate().is_err());
        assert!(dynamic("country", "usa").validate().is_err());
        let mut p = Policy {
            mode: "static".to_owned(),
            ..Default::default()
        };
        p.ip = "10.0.0.1".to_owned();
        assert!(
            p.validate().is_err(),
            "private IP is not a valid static exit"
        );
        p.ip = "1.2.3.4".to_owned();
        assert!(p.validate().is_ok());
    }

    #[test]
    fn evaluate_static_ip() {
        let mut p = Policy {
            mode: "static".to_owned(),
            ..Default::default()
        };
        p.ip = "8.8.4.4".to_owned();
        let loc = location("8.8.4.4", "US");
        assert_eq!(p.evaluate("8.8.4.4", Some(&loc)).0, State::Passed);
        // The observation must name the evaluated IP, or the country evidence
        // does not apply. A static policy evaluating a different exit fails.
        let loc8 = location("8.8.8.8", "US");
        assert_eq!(p.evaluate("8.8.8.8", Some(&loc8)).0, State::Failed);
        assert_eq!(p.evaluate("8.8.8.8", Some(&loc)).0, State::Unknown);
        assert_eq!(p.evaluate("8.8.4.4", Some(&loc8)).0, State::Unknown);
        // Before binding, evaluation stays unknown.
        assert_eq!(
            Policy {
                mode: "static".to_owned(),
                ..Default::default()
            }
            .evaluate("8.8.4.4", Some(&loc))
            .0,
            State::Unknown
        );
    }

    #[test]
    fn evaluate_dynamic_country() {
        let p = dynamic("country", "US");
        let loc = location("8.8.4.4", "US");
        assert_eq!(p.evaluate("8.8.4.4", Some(&loc)).0, State::Passed);
        let jp = location("8.8.4.4", "JP");
        assert_eq!(p.evaluate("8.8.4.4", Some(&jp)).0, State::Failed);
        assert_eq!(p.evaluate("114.114.114.114", Some(&loc)).0, State::Failed);
    }

    #[test]
    fn evaluate_dynamic_region_and_city() {
        let mut p = dynamic("region", "US");
        p.region = "California".to_owned();
        let mut loc = location("8.8.4.4", "US");
        loc.region = "California".to_owned();
        assert_eq!(p.evaluate("8.8.4.4", Some(&loc)).0, State::Passed);
        loc.region = "Oregon".to_owned();
        assert_eq!(p.evaluate("8.8.4.4", Some(&loc)).0, State::Failed);
        // Region spelling is collapsed before comparison.
        loc.region = "california".to_owned();
        assert_eq!(p.evaluate("8.8.4.4", Some(&loc)).0, State::Passed);
        // City scope without city evidence stays unknown, not failed.
        let mut city_policy = dynamic("city", "US");
        city_policy.region = "California".to_owned();
        let mut city_loc = location("8.8.4.4", "US");
        city_loc.region = "California".to_owned();
        assert_eq!(
            city_policy.evaluate("8.8.4.4", Some(&city_loc)).0,
            State::Unknown
        );
        city_loc.city = "Mountain View".to_owned();
        city_policy.city = "Mountain  View".to_owned();
        assert_eq!(
            city_policy.evaluate("8.8.4.4", Some(&city_loc)).0,
            State::Passed
        );
    }

    #[test]
    fn normalized_collapse_and_trim() {
        let p = Policy {
            country_code: " us ".to_owned(),
            region: "  California   coast ".to_owned(),
            ..Default::default()
        };
        let n = p.normalized();
        assert_eq!(n.country_code, "US");
        assert_eq!(n.region, "California coast");
        assert_eq!(n.mode, "dynamic");
        assert_eq!(n.scope, "country");
    }

    #[test]
    fn bind_missing_fills_only_blanks() {
        let p = Policy::default().bind_missing(&location("8.8.4.4", "US"));
        assert_eq!(p.country_code, "US");
        // A configured anchor is never overwritten.
        let p2 = dynamic("country", "JP").bind_missing(&location("8.8.4.4", "US"));
        assert_eq!(p2.country_code, "JP");
    }
}
