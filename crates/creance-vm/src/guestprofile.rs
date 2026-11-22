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
    /// Generates a fresh profile: a real-machine-style hostname, a
    /// non-reserved username, and a 48-hex session token.
    ///
    /// The hostname matters beyond aesthetics: it lands in shell prompts
    /// and any telemetry that reports `os.hostname()`, where a constant
    /// product prefix (`cage-…`) clusters every installation into one
    /// identifiable fleet — the exact batch-detection upstream Cage
    /// suffered (issue #173). A consumer-OEM model name with a short hex
    /// suffix reads like a real machine while staying unique per profile.
    pub fn generate() -> Profile {
        const BASES: &[&str] = &[
            "thinkpad", "ideapad", "inspiron", "vivobook", "latitude", "pavilion", "zenbook",
            "yoga", "swift", "nitro",
        ];
        // One token feeds both picks; hex digits are uniform enough entropy
        // for a cosmetic base choice.
        let token = crate::token();
        let base = BASES[token.as_bytes()[0] as usize % BASES.len()];
        let suffix = &token[..8];
        Profile {
            version: 1,
            hostname: format!("{base}-{}", &suffix[..4]),
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
    /// when absent. Never overwrites: a file that exists but cannot be read
    /// or parsed (F-022) is an error, not a reason to reset the identity.
    pub fn load_or_create(profile_dir: &str) -> Result<Profile, String> {
        let path = crate::paths::join(profile_dir, FILENAME);
        match std::fs::read(&path) {
            Ok(bytes) => {
                let p: Profile =
                    serde_json::from_slice(&bytes).map_err(|_| "客机配置格式无效".to_owned())?;
                p.validate()?;
                Ok(p)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let fresh = Profile::generate();
                fresh.validate()?;
                crate::write_private_atomic(&path, &serde_json::to_vec_pretty(&fresh).unwrap())?;
                Ok(fresh)
            }
            Err(e) => Err(format!(
                "客机配置不可读（{e}），拒绝重置身份；请修复权限或手动轮换"
            )),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_profiles_validate() {
        let p = Profile::generate();
        assert_eq!(p.validate(), Ok(()));
        // Real-machine style: one of the OEM bases, never a product brand
        // — a constant prefix here clusters every install into a fleet.
        const BASES: &[&str] = &[
            "thinkpad", "ideapad", "inspiron", "vivobook", "latitude", "pavilion", "zenbook",
            "yoga", "swift", "nitro",
        ];
        assert!(BASES.iter().any(|b| p.hostname.starts_with(b)));
        assert!(!p.hostname.contains("cage"));
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
    fn unreadable_profile_refuses_to_reset_identity() {
        // F-022: a read failure must never fall through to regeneration —
        // a directory in the slot is unreadable on every platform, root
        // included, and must stay untouched.
        let dir = std::env::temp_dir()
            .join(format!("creance-gp-{}", crate::token()[..12].to_owned()))
            .to_string_lossy()
            .into_owned();
        std::fs::create_dir_all(&dir).unwrap();
        let slot = crate::paths::join(&dir, FILENAME);
        std::fs::create_dir(&slot).unwrap();
        let err = Profile::load_or_create(&dir).expect_err("must refuse");
        assert!(err.contains("拒绝重置身份"), "{err}");
        assert!(std::path::Path::new(&slot).is_dir(), "slot untouched");
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
