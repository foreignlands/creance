//! The cage profile configuration and its strict validation.
//!
//! Every profile is one directory; its `config.json` fully determines the
//! isolation boundary: the proxy endpoint, the DoH resolver, the guest
//! fingerprint (timezone, locale, browser language) and the exit policy.

use crate::exit_policy::Policy as ExitPolicy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;

/// Names the profile's config file; the file's directory is the profile.
/// `CREANCE_CONFIG` wins; the legacy `CLAUDE_CAGE_CONFIG` still works.
pub const CONFIG_ENV: &str = "CLAUDE_CAGE_CONFIG";
pub const CONFIG_ENV_NEW: &str = "CREANCE_CONFIG";

/// The default limit for reading a configuration file.
const MAX_CONFIG_SIZE: u64 = 64 << 10;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The single upstream every guest connection goes through. Never a DNS
    /// name: the proxy bootstrap itself must not need a resolver.
    #[serde(default)]
    pub proxy_url: String,
    /// Set when the applied node is recorded; mismatched revisions close the gate.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proxy_revision: String,
    #[serde(default)]
    pub dns_url: String,
    #[serde(default)]
    pub timezone: String,
    #[serde(default)]
    pub locale: String,
    #[serde(default)]
    pub browser_language: String,
    #[serde(default)]
    pub exit_policy: ExitPolicy,
    /// 手机审批通道（Telegram Bot）：敏感操作要求手机回执。空=未启用。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub approval_bot_token: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub approval_chat_id: String,
}

/// The configuration a fresh profile starts with.
pub fn default_config() -> Config {
    Config {
        proxy_url: "socks5://127.0.0.1:17896".to_owned(),
        dns_url: "https://1.1.1.1/dns-query".to_owned(),
        timezone: "Etc/UTC".to_owned(),
        locale: "en_US.UTF-8".to_owned(),
        browser_language: "en-US".to_owned(),
        ..Default::default()
    }
}

/// Resolves the config path this process operates on.
pub fn config_path() -> String {
    for var in [CONFIG_ENV_NEW, CONFIG_ENV] {
        if let Ok(p) = std::env::var(var)
            && !p.is_empty()
        {
            return p;
        }
    }
    let home = crate::paths::home();
    // Prefer the creance home; fall back to the legacy cage profile so an
    // existing environment keeps working untouched.
    let modern = crate::paths::join(&home, ".creance/config.json");
    if std::path::Path::new(&modern).exists() {
        return modern;
    }
    let legacy = crate::paths::join(&home, ".claude-cage/config.json");
    if std::path::Path::new(&legacy).exists() {
        return legacy;
    }
    modern
}

/// Loads and validates the profile at `path`. The exit policy is normalized
/// before validation, matching what a later fingerprint sees.
pub fn load(path: &str) -> Result<Config, String> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("cannot read cage configuration: {e}"))?;
    let mut buf = Vec::new();
    (&file)
        .take(MAX_CONFIG_SIZE + 1)
        .read_to_end(&mut buf)
        .map_err(|_| "invalid cage JSON configuration".to_owned())?;
    if buf.len() as u64 > MAX_CONFIG_SIZE {
        return Err("invalid cage JSON configuration".to_owned());
    }
    let text = String::from_utf8(buf).map_err(|_| "invalid cage JSON configuration".to_owned())?;
    let mut config: Config =
        serde_json::from_str(&text).map_err(|_| "invalid cage JSON configuration".to_owned())?;
    config.exit_policy = config.exit_policy.normalized();
    // 首次配置友好（0.8.3 实测发现）：缺省字段用语义默认值补齐而
    // 非报错死路——空 timezone=auto（跟随出口，本就是设计语义），
    // 空 locale/language 用中立默认。用户显式写错仍然报错。
    if config.timezone.is_empty() {
        config.timezone = "auto".to_owned();
    }
    if config.locale.is_empty() {
        config.locale = "en_US.UTF-8".to_owned();
    }
    if config.browser_language.is_empty() {
        config.browser_language = "en-US".to_owned();
    }
    config.validate()?;
    Ok(config)
}

impl Config {
    /// The full validation of the isolation boundary.
    pub fn validate(&self) -> Result<(), String> {
        // A `keychain:` reference is opaque by design — the shape check
        // runs when the resolved value is used, not here.
        if !crate::secret::is_reference(&self.proxy_url) {
            creance_net::egress::validate_proxy_url(&self.proxy_url)?;
        }
        creance_net::egress::validate_dns_url(&self.dns_url)?;
        validate_timezone(&self.timezone)?;
        if !is_locale(&self.locale) {
            return Err("locale must have the form en_US.UTF-8".to_owned());
        }
        if !is_language_tag(&self.browser_language) {
            return Err("invalid browser language tag".to_owned());
        }
        validate_approval(&self.approval_bot_token, &self.approval_chat_id)?;
        self.exit_policy.validate()
    }

    /// The proxy endpoint with any `keychain:` reference resolved — use
    /// sites that OPEN connections need this; comparisons and persistence
    /// keep using the raw (reference-form) field.
    pub fn resolved_proxy_url(&self) -> Result<String, String> {
        crate::secret::resolve(&self.proxy_url)
    }

    /// The approval bot token with any `keychain:` reference resolved.
    pub fn resolved_approval_bot_token(&self) -> Result<String, String> {
        crate::secret::resolve(&self.approval_bot_token)
    }

    /// The identity of this configuration as far as running environments are
    /// concerned: any change requires a stop first.
    pub fn fingerprint(&self) -> String {
        let mut normalized = self.clone();
        normalized.exit_policy = normalized.exit_policy.normalized();
        let b = serde_json::to_vec(&normalized).expect("config serializes");
        hex::encode(Sha256::digest(&b))
    }

    /// The fields the GUEST can perceive — the actual provisioning promise
    /// a setup stamp records (F-040). Host-only concerns (which proxy
    /// endpoint, which revision, which exit anchor) are deliberately
    /// excluded: a routine proxy-select or anchor tune must not turn the
    /// escape probe permanently red; the full fingerprint still guards
    /// the running-record lock at `up`.
    pub fn guest_fingerprint(&self) -> String {
        let promise = (
            self.timezone.clone(),
            self.locale.clone(),
            self.browser_language.clone(),
        );
        let b = serde_json::to_vec(&promise).expect("promise serializes");
        hex::encode(Sha256::digest(&b))
    }
}

/// Atomically writes a validated configuration as a private file.
pub fn write_private_config(path: &str, config: &Config) -> Result<(), String> {
    config.validate()?;
    let mut bytes = serde_json::to_vec_pretty(config).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    crate::write_private_atomic(path, &bytes)
}

/// 审批通道凭据必须成对出现；token 形如 `123456:ABC…`（BotFather 发放），
/// chat_id 允许数字或 @name。
fn validate_approval(token: &str, chat: &str) -> Result<(), String> {
    if token.is_empty() && chat.is_empty() {
        return Ok(());
    }
    if token.is_empty() || chat.is_empty() {
        return Err("approval_bot_token 与 approval_chat_id 须成对配置".to_owned());
    }
    if crate::secret::is_reference(token) {
        return Ok(());
    }
    let mut parts = token.splitn(2, ':');
    let id_ok = parts
        .next()
        .is_some_and(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    let secret_ok = parts.next().is_some_and(|p| p.len() >= 30);
    if !id_ok || !secret_ok {
        return Err("approval_bot_token 形如 <bot_id>:<secret>".to_owned());
    }
    let chat_ok = chat
        .trim_start_matches('-')
        .chars()
        .all(|c| c.is_ascii_digit())
        || (chat.starts_with('@') && chat.len() > 1);
    if !chat_ok {
        return Err("approval_chat_id 须为数字或 @name".to_owned());
    }
    Ok(())
}

/// Rejects "Local" and unknown zones; the system zoneinfo database is the
/// authority when present, a structural `Area/Location` check otherwise.
fn validate_timezone(tz: &str) -> Result<(), String> {
    // "auto" = timezone follows the observed exit (0.7.x): the gate-open
    // path writes the exit country's canonical zone into the guest.
    if tz == "auto" {
        return Ok(());
    }
    if tz.is_empty() || tz == "Local" {
        return Err("timezone must be an explicit IANA name, e.g. Etc/UTC".to_owned());
    }
    if tz.split('/').any(|c| c.is_empty() || c == "." || c == "..") || tz.contains('\\') {
        return Err("unknown cage timezone".to_owned());
    }
    let db = std::path::Path::new("/usr/share/zoneinfo").join(tz);
    // Go's time.LoadLocation reads the file's contents, so a directory name
    // ("Etc", "posix", "right") is not a timezone there either (FINDING-004).
    if std::fs::metadata(&db).map(|m| m.is_file()).unwrap_or(false) {
        return Ok(());
    }
    if std::path::Path::new("/usr/share/zoneinfo").is_dir() {
        return Err("unknown cage timezone".to_owned());
    }
    let mut parts = tz.split('/');
    if parts.clone().count() != 2
        || !parts.all(|p| {
            p.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        })
    {
        return Err("unknown cage timezone".to_owned());
    }
    Ok(())
}

/// `^[A-Za-z]{2,3}_[A-Za-z]{2,3}\.UTF-8$`
fn is_locale(s: &str) -> bool {
    let Some((lang, rest)) = s.split_once('_') else {
        return false;
    };
    let Some(encoding) = rest.strip_suffix(".UTF-8") else {
        return false;
    };
    is_alpha_group(lang) && is_alpha_group(encoding)
}

/// `^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$`
fn is_language_tag(s: &str) -> bool {
    let mut groups = s.split('-');
    match groups.next() {
        Some(g) if is_alpha_group(g) => {}
        _ => return false,
    }
    groups.all(|g| (2..=8).contains(&g.len()) && g.bytes().all(|c| c.is_ascii_alphanumeric()))
}

fn is_alpha_group(s: &str) -> bool {
    (2..=3).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> Config {
        default_config()
    }

    #[test]
    fn default_config_validates() {
        assert!(good().validate().is_ok());
    }

    #[test]
    fn approval_credentials_must_pair_up() {
        let good_token = "123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        for (t, c, ok) in [
            (good_token, "555", true),
            (good_token, "-100123456789", true),
            (good_token, "@me", true),
            (good_token, "", false),     // 半配置
            ("", "555", false),          // 半配置
            ("notatoken", "555", false), // 无冒号
            ("123:short", "555", false), // secret 太短
            (good_token, "!", false),    // chat 形非法
        ] {
            let mut cfg = good();
            cfg.approval_bot_token = t.to_owned();
            cfg.approval_chat_id = c.to_owned();
            assert_eq!(cfg.validate().is_ok(), ok, "{t}|{c}");
        }
    }

    #[test]
    fn proxy_rules() {
        let mut c = good();
        for bad in [
            "socks5://proxy.example.com:1080", // DNS bootstrap
            "socks5://1.2.3.4",                // no port
            "socks5://1.2.3.4:0",              // port 0
            "socks4://1.2.3.4:1080",           // scheme
            "socks5://1.2.3.4:1080/path",      // path
            "socks5://1.2.3.4:1080/",          // trailing slash is still a path (FINDING-004)
        ] {
            c.proxy_url = bad.to_owned();
            assert!(c.validate().is_err(), "{bad} must be rejected");
        }
        c.proxy_url = "http://10.0.0.1:8080".to_owned();
        assert!(c.validate().is_ok());
        c.proxy_url = "socks5://user:pw@1.2.3.4:1080".to_owned();
        assert!(c.validate().is_ok());
        // Bracketed IPv6 literals are numeric endpoints too (FINDING-004).
        c.proxy_url = "socks5://[::1]:1080".to_owned();
        assert!(c.validate().is_ok(), "[::1] must parse as an IP literal");
        c.proxy_url = "socks5://user:pw@[::1]:1080".to_owned();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn dns_rules() {
        let mut c = good();
        c.dns_url = "http://1.1.1.1/dns-query".to_owned();
        assert!(c.validate().is_err());
        c.dns_url = "https://user@1.1.1.1/dns-query".to_owned();
        assert!(c.validate().is_err());
        c.dns_url = "https://223.5.5.5/dns-query".to_owned();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn timezone_locale_language_rules() {
        let mut c = good();
        c.timezone = "Local".to_owned();
        assert!(c.validate().is_err());
        c.timezone = "Asia/Shanghai".to_owned();
        assert!(c.validate().is_ok());
        c.timezone = "Not/AZone/../..".to_owned();
        assert!(c.validate().is_err());
        // A zoneinfo *directory* name is not a timezone (FINDING-004):
        // Go's time.LoadLocation fails on it, so must we.
        if std::path::Path::new("/usr/share/zoneinfo").is_dir() {
            c.timezone = "Etc".to_owned();
            assert!(c.validate().is_err(), "directory name Etc must be rejected");
        }
        c.timezone = "Etc/UTC".to_owned();
        c.locale = "en_US".to_owned();
        assert!(c.validate().is_err());
        c.locale = "en_US.UTF-8".to_owned();
        assert!(c.validate().is_ok());
        c.browser_language = "zh_CN".to_owned();
        assert!(c.validate().is_err());
        c.browser_language = "zh-CN-1234".to_owned();
        assert!(c.validate().is_ok());
        c.browser_language = "zh-CN-x".to_owned();
        assert!(c.validate().is_err(), "one-letter subtag is invalid");
    }

    #[test]
    fn load_is_strict() {
        let dir = std::env::temp_dir().join(format!("cage-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        // Unknown fields are denied.
        std::fs::write(
            &path,
            r#"{"proxy_url":"socks5://1.2.3.4:1080","surprise":1}"#,
        )
        .unwrap();
        assert!(load(path.to_str().unwrap()).is_err());
        // A valid profile loads and normalizes its exit policy.
        std::fs::write(&path, r#"{"proxy_url":"socks5://1.2.3.4:1080","dns_url":"https://1.1.1.1/dns-query","timezone":"Etc/UTC","locale":"en_US.UTF-8","browser_language":"en-US"}"#).unwrap();
        let cfg = load(path.to_str().unwrap()).unwrap();
        assert_eq!(cfg.exit_policy.normalized().mode, "dynamic");
        // Fingerprint changes when the exit policy changes.
        let mut changed = cfg.clone();
        changed.exit_policy.country_code = "US".to_owned();
        assert_ne!(cfg.fingerprint(), changed.fingerprint());
        // Fingerprint is stable across a load round-trip.
        std::fs::write(&path, serde_json::to_vec_pretty(&changed).unwrap()).unwrap();
        assert_eq!(
            changed.fingerprint(),
            load(path.to_str().unwrap()).unwrap().fingerprint()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn keychain_reference_forms_validate() {
        // A reference-shaped proxy_url skips the shape check (opaque by
        // design); a reference-shaped token pairs fine with a chat id.
        let mut c = default_config();
        c.proxy_url = "keychain:proxy_url".to_owned();
        c.approval_bot_token = "keychain:approval_bot_token".to_owned();
        c.approval_chat_id = "123456".to_owned();
        assert!(c.validate().is_ok(), "{:?}", c.validate());
        // pairing rule still applies to references
        let mut unpaired = c.clone();
        unpaired.approval_chat_id = String::new();
        assert!(unpaired.validate().is_err());
        // malformed reference spellings fall back to the ordinary rules —
        // `keychain:` alone is not a reference and fails proxy validation
        let mut bad = default_config();
        bad.proxy_url = "keychain:".to_owned();
        assert!(bad.validate().is_err());
    }
}
