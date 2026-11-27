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

/// Fingerprint-quadruple plausibility (0.7.0): exit country ↔ VM timezone ↔
/// Accept-Language ↔ locale. The table answers "would a real user in this
/// country plausibly carry this fingerprint?" — the "US IP + 东八区 + 中文
/// 语言" giveaway the roadmap's exit-standard names.
///
/// Country → (IANA timezone prefixes, plausible language subtags). `en`
/// appears in every row: it is the world's default UI language, so only a
/// NON-English mismatch is a signal. `Etc/UTC` is treated as neutral
/// (server default, weak signal) — the hard fail is a timezone that
/// belongs to a DIFFERENT region.
const COUNTRY_PROFILE: &[(&str, &[&str], &[&str])] = &[
    ("US", &["America/", "US/"], &["en", "es"]),
    ("CA", &["America/", "Canada/"], &["en", "fr"]),
    (
        "MX",
        &["America/Mexico", "America/Cancun", "America/Tijuana"],
        &["es", "en"],
    ),
    (
        "BR",
        &[
            "America/Sao_Paulo",
            "America/Manaus",
            "America/Fortaleza",
            "Brazil/",
        ],
        &["pt", "en"],
    ),
    ("GB", &["Europe/London"], &["en"]),
    ("IE", &["Europe/Dublin"], &["en"]),
    ("DE", &["Europe/Berlin"], &["de", "en"]),
    ("FR", &["Europe/Paris"], &["fr", "en"]),
    ("NL", &["Europe/Amsterdam"], &["nl", "en"]),
    ("BE", &["Europe/Brussels"], &["nl", "fr", "en"]),
    ("CH", &["Europe/Zurich"], &["de", "fr", "it", "en"]),
    ("AT", &["Europe/Vienna"], &["de", "en"]),
    ("IT", &["Europe/Rome"], &["it", "en"]),
    ("ES", &["Europe/Madrid"], &["es", "en"]),
    ("PT", &["Europe/Lisbon"], &["pt", "en"]),
    ("SE", &["Europe/Stockholm"], &["sv", "en"]),
    ("NO", &["Europe/Oslo"], &["no", "nb", "en"]),
    ("DK", &["Europe/Copenhagen"], &["da", "en"]),
    ("FI", &["Europe/Helsinki"], &["fi", "en"]),
    ("PL", &["Europe/Warsaw"], &["pl", "en"]),
    ("CZ", &["Europe/Prague"], &["cs", "en"]),
    (
        "RU",
        &[
            "Europe/Moscow",
            "Asia/Yekaterinburg",
            "Asia/Novosibirsk",
            "Asia/Vladivostok",
        ],
        &["ru", "en"],
    ),
    (
        "TR",
        &["Europe/Istanbul", "Asia/Istanbul", "Turkey"],
        &["tr", "en"],
    ),
    ("JP", &["Asia/Tokyo"], &["ja", "en"]),
    ("KR", &["Asia/Seoul"], &["ko", "en"]),
    (
        "CN",
        &["Asia/Shanghai", "Asia/Urumqi", "PRC"],
        &["zh", "en"],
    ),
    ("HK", &["Asia/Hong_Kong", "Hongkong"], &["zh", "en"]),
    ("TW", &["Asia/Taipei"], &["zh", "en"]),
    (
        "SG",
        &["Asia/Singapore", "Singapore"],
        &["en", "zh", "ms", "ta"],
    ),
    ("IN", &["Asia/Kolkata", "Asia/Calcutta"], &["en", "hi"]),
    ("TH", &["Asia/Bangkok"], &["th", "en"]),
    ("VN", &["Asia/Ho_Chi_Minh", "Asia/Saigon"], &["vi", "en"]),
    (
        "ID",
        &["Asia/Jakarta", "Asia/Makassar", "Asia/Jayapura"],
        &["id", "en"],
    ),
    (
        "MY",
        &["Asia/Kuala_Lumpur", "Asia/Kuching"],
        &["ms", "en", "zh"],
    ),
    ("PH", &["Asia/Manila"], &["en", "fil", "tl"]),
    ("AU", &["Australia/"], &["en"]),
    ("NZ", &["Pacific/Auckland"], &["en"]),
    ("AE", &["Asia/Dubai"], &["ar", "en"]),
    ("IL", &["Asia/Jerusalem", "Israel"], &["he", "en", "ar"]),
    ("ZA", &["Africa/Johannesburg"], &["en", "af", "zu"]),
    (
        "AR",
        &["America/Argentina/", "America/Buenos_Aires"],
        &["es", "en"],
    ),
    ("CL", &["America/Santiago", "Chile/"], &["es", "en"]),
    ("CO", &["America/Bogota"], &["es", "en"]),
];

/// The primary language subtag of a BCP-47 tag or a POSIX locale
/// (`en-US`, `en_US.UTF-8`, `zh_CN` → `en`/`zh`). `None` on shapes the
/// validator already rejects — the caller fails closed on its own.
fn lang_subtag(tag: &str) -> Option<String> {
    let head = tag.split(['-', '_', '.']).next()?;
    if head.len() >= 2 && head.bytes().all(|c| c.is_ascii_lowercase()) {
        Some(head.to_owned())
    } else {
        None
    }
}

/// The concrete canonical IANA zone a timezone-following persona lands on
/// for each tabulated country (the profile's zone entries are match
/// prefixes like `America/`, not names a guest can boot with).
const CANONICAL_TZ: &[(&str, &str)] = &[
    ("US", "America/New_York"),
    ("CA", "America/Toronto"),
    ("MX", "America/Mexico_City"),
    ("BR", "America/Sao_Paulo"),
    ("GB", "Europe/London"),
    ("IE", "Europe/Dublin"),
    ("DE", "Europe/Berlin"),
    ("FR", "Europe/Paris"),
    ("NL", "Europe/Amsterdam"),
    ("BE", "Europe/Brussels"),
    ("CH", "Europe/Zurich"),
    ("AT", "Europe/Vienna"),
    ("IT", "Europe/Rome"),
    ("ES", "Europe/Madrid"),
    ("PT", "Europe/Lisbon"),
    ("SE", "Europe/Stockholm"),
    ("NO", "Europe/Oslo"),
    ("DK", "Europe/Copenhagen"),
    ("FI", "Europe/Helsinki"),
    ("PL", "Europe/Warsaw"),
    ("CZ", "Europe/Prague"),
    ("RU", "Europe/Moscow"),
    ("TR", "Europe/Istanbul"),
    ("CN", "Asia/Shanghai"),
    ("JP", "Asia/Tokyo"),
    ("KR", "Asia/Seoul"),
    ("HK", "Asia/Hong_Kong"),
    ("TW", "Asia/Taipei"),
    ("SG", "Asia/Singapore"),
    ("IN", "Asia/Kolkata"),
    ("TH", "Asia/Bangkok"),
    ("VN", "Asia/Ho_Chi_Minh"),
    ("ID", "Asia/Jakarta"),
    ("MY", "Asia/Kuala_Lumpur"),
    ("PH", "Asia/Manila"),
    ("AU", "Australia/Sydney"),
    ("NZ", "Pacific/Auckland"),
    ("AE", "Asia/Dubai"),
    ("IL", "Asia/Jerusalem"),
    ("ZA", "Africa/Johannesburg"),
    ("AR", "America/Argentina/Buenos_Aires"),
    ("CL", "America/Santiago"),
    ("CO", "America/Bogota"),
];

/// The canonical IANA zone for a tabulated country — what `timezone:
/// "auto"` writes into the guest. `None` for countries outside the table.
pub fn canonical_timezone(country_code: &str) -> Option<&'static str> {
    let cc = country_code.to_ascii_uppercase();
    CANONICAL_TZ.iter().find(|(c, _)| *c == cc).map(|(_, z)| *z)
}

/// Judges one fingerprint triple against an observed exit country.
///
/// `None` — the country has no table row (unknown exits never convict).
/// `Some(Ok(()))` — consistent. `Some(Err(reason))` — a 穿帮组合:
/// timezone outside the country's zones (and not Etc/UTC), a browser
/// language nobody there speaks, or a locale language nobody there speaks.
/// The locale's REGION is deliberately not checked — `en_US.UTF-8` is the
/// universal baseline locale and convicting it would fail every non-US
/// profile's default config.
pub fn fingerprint_verdict(
    country_code: &str,
    timezone: &str,
    locale: &str,
    browser_language: &str,
) -> Option<Result<(), String>> {
    let cc = country_code.to_ascii_uppercase();
    let (_, zones, langs) = COUNTRY_PROFILE.iter().find(|(c, _, _)| *c == cc)?;
    let tz = timezone.trim();
    // "auto" follows the observed exit — consistent by construction.
    if tz != "auto" && tz != "Etc/UTC" && tz != "UTC" && !zones.iter().any(|z| tz.starts_with(z)) {
        return Some(Err(format!(
            "时区 {tz} 与出口国别 {cc} 不一致（该地区的时区候选：{}）",
            zones.join("、")
        )));
    }
    let bl = lang_subtag(browser_language).unwrap_or_default();
    if !bl.is_empty() && !langs.iter().any(|l| *l == bl) {
        return Some(Err(format!(
            "浏览器语言 {browser_language} 与出口国别 {cc} 不一致"
        )));
    }
    let ll = lang_subtag(locale).unwrap_or_default();
    if !ll.is_empty() && !langs.iter().any(|l| *l == ll) {
        return Some(Err(format!("locale {locale} 的语言与出口国别 {cc} 不一致")));
    }
    Some(Ok(()))
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
        assert!(
            prefixes
                .iter()
                .any(|(net, bits)| masked(covered, *bits) == *net)
        );
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

    #[test]
    fn fingerprint_verdict_convicts_the_giveaway_combo() {
        // The roadmap's named case: US exit + 东八区 + 中文语言.
        let v = fingerprint_verdict("US", "Asia/Shanghai", "zh_CN.UTF-8", "zh-CN");
        assert!(matches!(v, Some(Err(_))), "US+Shanghai+zh must convict");
        // Timezone is the first convicted leg.
        let v = fingerprint_verdict("US", "Asia/Shanghai", "en_US.UTF-8", "en-US");
        assert!(matches!(v, Some(Err(ref m)) if m.contains("时区")));
        // Language leg: zh browser language on a US exit convicts even
        // with a plausible timezone.
        let v = fingerprint_verdict("US", "America/New_York", "en_US.UTF-8", "zh-CN");
        assert!(matches!(v, Some(Err(ref m)) if m.contains("浏览器语言")));
        // Locale language leg.
        let v = fingerprint_verdict("JP", "Asia/Tokyo", "zh_CN.UTF-8", "ja-JP");
        assert!(matches!(v, Some(Err(ref m)) if m.contains("locale")));
    }

    #[test]
    fn fingerprint_verdict_passes_consistent_and_neutral() {
        // Fully consistent persona.
        assert_eq!(
            fingerprint_verdict("JP", "Asia/Tokyo", "ja_JP.UTF-8", "ja-JP"),
            Some(Ok(()))
        );
        // Universal baseline: en_US locale + en-US language + UTC pass on
        // any tabulated exit (default config must stay green).
        assert_eq!(
            fingerprint_verdict("DE", "Etc/UTC", "en_US.UTF-8", "en-US"),
            Some(Ok(()))
        );
        assert_eq!(
            fingerprint_verdict("SG", "Etc/UTC", "en_US.UTF-8", "en-US"),
            Some(Ok(()))
        );
        // Multi-language countries accept each listed language.
        assert_eq!(
            fingerprint_verdict("SG", "Asia/Singapore", "zh_SG.UTF-8", "zh-CN"),
            Some(Ok(()))
        );
        // Country with no row: no conviction either way.
        assert_eq!(
            fingerprint_verdict("XX", "Asia/Shanghai", "zh_CN.UTF-8", "zh-CN"),
            None
        );
        // Case-insensitive country code.
        assert!(matches!(
            fingerprint_verdict("us", "Asia/Shanghai", "en_US.UTF-8", "en-US"),
            Some(Err(_))
        ));
        // 时区跟随："auto" lands wherever the exit is — consistent on
        // every tabulated country.
        assert_eq!(
            fingerprint_verdict("US", "auto", "en_US.UTF-8", "en-US"),
            Some(Ok(()))
        );
        assert_eq!(
            fingerprint_verdict("JP", "auto", "en_US.UTF-8", "en-US"),
            Some(Ok(()))
        );
        // Canonical zone lookup feeds the ~/.creance-tz write.
        assert_eq!(canonical_timezone("US"), Some("America/New_York"));
        assert_eq!(canonical_timezone("jp"), Some("Asia/Tokyo"));
        assert_eq!(canonical_timezone("XX"), None);
        // Every tabulated country must have a canonical zone — a row
        // added without one would silently skip the follow-write.
        for (cc, _, _) in COUNTRY_PROFILE {
            assert!(
                canonical_timezone(cc).is_some(),
                "{cc} lacks canonical zone"
            );
        }
    }
}
