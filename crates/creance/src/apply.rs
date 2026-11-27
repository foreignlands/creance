//! 声明式重建（配置即数据 ③）：一个声明文件完整描述一套 persona——
//! 身份种子、config、订阅来源——`creance apply` 在空白机器上从零重建
//! 到「setup 即可用」的状态。换机/重装从“打包带走”变成“声明重建”。
//!
//! 声明文件（JSON）：
//! ```json
//! {
//!   "version": 1,
//!   "identity_seed": "keychain:identity_seed",
//!   "config": { "proxy_url": "keychain:proxy_url", "timezone": "auto", ... },
//!   "sources": [{"name": "main", "url": "https://…"}]
//! }
//! ```
//!
//! 安全纪律：seed 是根秘密（泄露=身份可克隆）——允许 `keychain:` 引用，
//! 明文直写也行但会警告。seed 只用于派生，绝不写进任何持久化文件。

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Declaration {
    pub version: u32,
    pub identity_seed: String,
    #[serde(default)]
    pub config: Option<creance_vm::config::Config>,
    #[serde(default)]
    pub sources: Vec<DeclSource>,
}

#[derive(Deserialize)]
pub struct DeclSource {
    pub name: String,
    pub url: String,
}

pub fn load_declaration(path: &str) -> Result<Declaration, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("声明文件读取失败：{e}"))?;
    if text.len() > 256 * 1024 {
        return Err("声明文件过大".to_owned());
    }
    let decl: Declaration =
        serde_json::from_str(&text).map_err(|e| format!("声明文件解析失败：{e}"))?;
    if decl.version != 1 {
        return Err("声明文件 version 须为 1".to_owned());
    }
    if decl.identity_seed.len() < 16 && !creance_vm::secret::is_reference(&decl.identity_seed) {
        return Err("identity_seed 太短（<16）——弱种子的身份可被枚举".to_owned());
    }
    Ok(decl)
}

/// Applies the declaration to `profile`: derives the guest identity from
/// the seed, writes config + guest-profile. Returns human-readable notes.
/// Does NOT touch a running instance — the caller enforces stopped-state.
pub fn apply(profile: &str, decl: &Declaration) -> Result<Vec<String>, String> {
    let mut notes = Vec::new();
    let seed = creance_vm::secret::resolve(&decl.identity_seed)?;
    if !creance_vm::secret::is_reference(&decl.identity_seed) {
        notes.push("警告：identity_seed 明文写在声明文件里——建议挪入 keychain 改用引用".to_owned());
    }
    // Identity：种子派生——同种子同身份，跨机稳定。
    let guest = creance_vm::guestprofile::Profile::derive(&seed);
    guest.validate()?;
    let guest_path = creance_vm::paths::join(profile, creance_vm::guestprofile::FILENAME);
    let bytes = serde_json::to_vec_pretty(&guest).map_err(|e| e.to_string())?;
    creance_vm::write_private_atomic(&guest_path, &bytes)?;
    notes.push(format!(
        "身份派生：{} / {}（session token 已轮换）",
        guest.hostname, guest.username
    ));
    // Config：声明里的 config 全量覆盖；缺席则保留现有（首次则报错）。
    if let Some(cfg) = &decl.config {
        cfg.validate()?;
        creance_vm::config::write_private_config(
            &creance_vm::paths::join(profile, "config.json"),
            cfg,
        )?;
        notes.push("config.json 已按声明写入".to_owned());
    }
    // Sources：声明的订阅直接进 store（fetch 留给 proxy-refresh——
    // apply 不碰网络，重建必须是可离线审计的纯落盘）。
    if !decl.sources.is_empty() {
        let mut store = creance_proxy::load(profile).unwrap_or_default();
        for s in &decl.sources {
            store.declare_source(&s.name, &s.url)?;
            notes.push(format!("订阅已登记：{}（proxy-refresh 后可用）", s.name));
        }
        creance_proxy::save(profile, &store)?;
    }
    Ok(notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declaration_validation_rejects_weak_seeds_and_bad_versions() {
        let dir = std::env::temp_dir().join(format!("creance-decl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("d.json");
        std::fs::write(&file, r#"{"version":1,"identity_seed":"short"}"#).unwrap();
        assert!(load_declaration(file.to_str().unwrap()).is_err());
        std::fs::write(
            &file,
            r#"{"version":2,"identity_seed":"long-enough-seed-value"}"#,
        )
        .unwrap();
        assert!(load_declaration(file.to_str().unwrap()).is_err());
        std::fs::write(
            &file,
            r#"{"version":1,"identity_seed":"long-enough-seed-value"}"#,
        )
        .unwrap();
        assert!(load_declaration(file.to_str().unwrap()).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_derives_identity_and_is_deterministic() {
        let dir = std::env::temp_dir().join(format!("creance-apply-{}", std::process::id()));
        let profile = dir.to_string_lossy().into_owned();
        std::fs::create_dir_all(&dir).unwrap();
        let decl = Declaration {
            version: 1,
            identity_seed: "test-seed-deterministic-16+".to_owned(),
            config: None,
            sources: Vec::new(),
        };
        apply(&profile, &decl).unwrap();
        let text = std::fs::read_to_string(creance_vm::paths::join(
            &profile,
            creance_vm::guestprofile::FILENAME,
        ))
        .unwrap();
        let first: serde_json::Value = serde_json::from_str(&text).unwrap();
        // second apply: same hostname/username (seed-stable)
        apply(&profile, &decl).unwrap();
        let text2 = std::fs::read_to_string(creance_vm::paths::join(
            &profile,
            creance_vm::guestprofile::FILENAME,
        ))
        .unwrap();
        let second: serde_json::Value = serde_json::from_str(&text2).unwrap();
        assert_eq!(first["hostname"], second["hostname"]);
        assert_eq!(first["username"], second["username"]);
        // and the derived values match a direct derive
        let direct = creance_vm::guestprofile::Profile::derive("test-seed-deterministic-16+");
        assert_eq!(first["hostname"].as_str().unwrap(), direct.hostname);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
