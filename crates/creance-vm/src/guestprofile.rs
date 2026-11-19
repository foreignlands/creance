//! Guest profiles and per-session credentials — "escaped, but nothing to
//! steal": the guest identity is generated (never copied from the host) and
//! every credential the workload holds is a cage-issued, revocable session
//! token, not the user's own.

use serde::{Deserialize, Serialize};

pub const FILENAME: &str = "guest-profile.json";

/// Creation-time guest preferences. Empty fields request generated values.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    pub version: u32,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub session_token: String,
}

impl Profile {
    /// Generates a fresh profile: a natural-ish hostname, a non-reserved
    /// username, and a 48-hex session token.
    pub fn generate() -> Profile {
        let suffix = &crate::token()[..8];
        Profile {
            version: 1,
            hostname: format!("cage-{suffix}"),
            username: format!("dev{suffix}"),
            session_token: crate::token(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err("客机配置版本无效".to_owned());
        }
        let host_ok = !self.hostname.is_empty()
            && self.hostname.len() <= 15
            && self
                .hostname
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            && self.hostname.as_bytes()[0].is_ascii_alphabetic();
        if !host_ok {
            return Err("主机名须为 1–15 位 ASCII 字母/数字/连字符，字母开头".to_owned());
        }
        const RESERVED: &[&str] = &[
            "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp",
            "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody",
        ];
        if RESERVED.contains(&self.username.as_str()) {
            return Err("用户名不能使用系统保留账户".to_owned());
        }
        let user_ok = !self.username.is_empty()
            && self.username.len() <= 24
            && self
                .username
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
            && self.username.as_bytes()[0].is_ascii_lowercase();
        if !user_ok {
            return Err("用户名须为小写字母开头，仅含小写字母/数字/下划线".to_owned());
        }
        if self.session_token.len() != 48
            || !self.session_token.bytes().all(|c| c.is_ascii_hexdigit())
        {
            return Err("会话令牌无效".to_owned());
        }
        Ok(())
    }

    /// Loads the profile of a profile directory; generates and persists one
    /// when absent (never overwrites — a failed install keeps its identity).
    pub fn load_or_create(profile_dir: &str) -> Result<Profile, String> {
        let path = crate::paths::join(profile_dir, FILENAME);
        if let Ok(bytes) = std::fs::read(&path) {
            let p: Profile =
                serde_json::from_slice(&bytes).map_err(|_| "客机配置格式无效".to_owned())?;
            p.validate()?;
            return Ok(p);
        }
        let fresh = Profile::generate();
        fresh.validate()?;
        crate::write_private_atomic(&path, &serde_json::to_vec_pretty(&fresh).unwrap())?;
        Ok(fresh)
    }

    /// Rotates the session token (revocation): the old token dies with the
    /// store's auth rotation on the next `proxy-select`.
    pub fn rotate_token(profile_dir: &str) -> Result<Profile, String> {
        let mut p = Profile::load_or_create(profile_dir)?;
        p.session_token = crate::token();
        let path = crate::paths::join(profile_dir, FILENAME);
        crate::write_private_atomic(&path, &serde_json::to_vec_pretty(&p).unwrap())?;
        Ok(p)
    }
}

/// The credential handoff the guest receives: exactly one cage-issued
/// session token, delivered through the tunnel at provision time. The
/// host's own credentials (API keys, OAuth tokens) never enter the VM.
pub fn credential_env(guest: &Profile) -> Vec<(String, String)> {
    vec![(
        "CREANCE_SESSION_TOKEN".to_owned(),
        guest.session_token.clone(),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_profiles_validate() {
        let p = Profile::generate();
        assert_eq!(p.validate(), Ok(()));
        assert!(p.hostname.starts_with("cage-"));
        assert!(p.username.starts_with("dev"));
        assert_eq!(p.session_token.len(), 48);
    }

    #[test]
    fn load_or_create_is_stable_and_private() {
        let dir = std::env::temp_dir()
            .join(format!("creance-gp-{}", crate::token()[..12].to_owned()))
            .to_string_lossy()
            .into_owned();
        std::fs::create_dir_all(&dir).unwrap();
        let first = Profile::load_or_create(&dir).unwrap();
        let second = Profile::load_or_create(&dir).unwrap();
        assert_eq!(first, second, "identity is created once");
        let rotated = Profile::rotate_token(&dir).unwrap();
        assert_ne!(rotated.session_token, first.session_token);
        assert_eq!(rotated.hostname, first.hostname);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn validation_rejects_host_identity_shapes() {
        let mut p = Profile::generate();
        p.username = "root".to_owned();
        assert!(p.validate().is_err(), "reserved-ish names refused");
        p = Profile::generate();
        p.hostname = "way-too-long-hostname-name".to_owned();
        assert!(p.validate().is_err());
        p = Profile::generate();
        p.session_token = "short".to_owned();
        assert!(p.validate().is_err());
    }
}
