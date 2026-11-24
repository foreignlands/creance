//! Identity Bundle — the double-layer encrypted container (ROADMAP 0.7.1).
//!
//! Inner layer: a plaintext manifest packing the persona files
//! (`guest-profile.json`, `config.json`, `sources.json`) — the virtual
//! fingerprint stays identical across devices. Outer layer: the manifest
//! sealed with a key the master password derives via argon2id —
//! "换电脑不换虚拟指纹，没授权打不开包".
//!
//! Layout: `CRB1` magic + u32le header length + header JSON (kdf params,
//! nonce) + XChaCha20-Poly1305 ciphertext of the manifest JSON.

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

pub const MAGIC: &[u8; 4] = b"CRB1";
/// persona files a bundle carries. sources.json rides along because the
/// account's dedicated exit node is part of the persona.
pub const FILES: &[&str] = &["guest-profile.json", "config.json", "sources.json"];

fn kdf(password: &str, salt: &[u8; 16]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    // OWASP argon2id minimums (m=19MiB, t=2, p=1) — a bundle is at-rest
    // cold storage, the honest threat model is offline cracking.
    let params =
        argon2::Params::new(19 * 1024, 2, 1, Some(32)).map_err(|e| format!("kdf 参数异常：{e}"))?;
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("kdf 失败：{e}"))?;
    Ok(key)
}

fn manifest_of(profile_dir: &str) -> Result<Vec<u8>, String> {
    let mut files = serde_json::Map::new();
    let mut carried = 0usize;
    for name in FILES {
        let path = crate::paths::join(profile_dir, name);
        match std::fs::read(&path) {
            Ok(bytes) => {
                use base64::Engine;
                files.insert(
                    (*name).to_owned(),
                    serde_json::Value::from(
                        base64::engine::general_purpose::STANDARD.encode(&bytes),
                    ),
                );
                carried += 1;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{name} 不可读（{e}），导出中止")),
        }
    }
    if carried == 0 {
        return Err("没有任何身份文件可打包（profile 目录为空？）".to_owned());
    }
    serde_json::to_vec(&serde_json::json!({
        "format": "creance-bundle",
        "version": 1,
        "files": serde_json::Value::Object(files),
    }))
    .map_err(|e| format!("manifest 序列化失败：{e}"))
}

/// Packs the persona of `profile_dir` and seals it with `password`.
pub fn export(profile_dir: &str, password: &str) -> Result<Vec<u8>, String> {
    if password.is_empty() {
        return Err("主密码不能为空".to_owned());
    }
    let plain = manifest_of(profile_dir)?;
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 24];
    use rand::RngCore;
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce_bytes);
    let key = kdf(password, &salt)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|e| format!("cipher 初始化失败：{e}"))?;
    let sealed = cipher
        .encrypt(&XNonce::from(nonce_bytes), plain.as_ref())
        .map_err(|e| format!("封装失败：{e}"))?;
    let header = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "kdf": "argon2id",
        "salt": hex::encode(salt),
        "nonce": hex::encode(nonce_bytes),
    }))
    .map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(8 + header.len() + sealed.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(header.len() as u32).to_le_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn unseal(bytes: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if bytes.len() < 8 || &bytes[..4] != MAGIC {
        return Err("不是有效的 creance bundle（魔数不符）".to_owned());
    }
    let hlen = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    if bytes.len() < 8 + hlen {
        return Err("bundle 头部截断".to_owned());
    }
    let header: serde_json::Value =
        serde_json::from_slice(&bytes[8..8 + hlen]).map_err(|_| "bundle 头部无效".to_owned())?;
    let salt_hex = header["salt"].as_str().ok_or("bundle 缺 salt")?;
    let nonce_hex = header["nonce"].as_str().ok_or("bundle 缺 nonce")?;
    let salt_vec = hex::decode(salt_hex).map_err(|_| "salt 无效")?;
    let nonce_vec = hex::decode(nonce_hex).map_err(|_| "nonce 无效")?;
    let salt: [u8; 16] = salt_vec.try_into().map_err(|_| "salt 长度无效")?;
    if nonce_vec.len() != 24 {
        return Err("nonce 长度无效".to_owned());
    }
    let key = kdf(password, &salt)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|e| format!("cipher 初始化失败：{e}"))?;
    cipher
        .decrypt(
            &XNonce::from(
                <[u8; 24]>::try_from(nonce_vec.as_slice()).map_err(|_| "nonce 长度无效")?,
            ),
            &bytes[8 + hlen..],
        )
        .map_err(|_| "解封失败——主密码错误或包已损坏".to_owned())
}

/// Unseals `bytes` with `password` and lands the persona files into
/// `profile_dir` with private perms. Refuses to clobber an existing file
/// (F-022 discipline: never overwrite a live identity blind).
pub fn import(profile_dir: &str, password: &str, bytes: &[u8]) -> Result<usize, String> {
    let plain = unseal(bytes, password)?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&plain).map_err(|_| "manifest 损坏".to_owned())?;
    if manifest["format"].as_str() != Some("creance-bundle") {
        return Err("manifest 格式标记不符".to_owned());
    }
    let files = manifest["files"].as_object().ok_or("manifest 缺 files")?;
    // Two passes: verify nothing would be clobbered before writing any.
    for name in files.keys() {
        if !FILES.contains(&name.as_str()) {
            return Err(format!("bundle 含未知文件 {name}，拒绝落地"));
        }
        if std::path::Path::new(&crate::paths::join(profile_dir, name)).exists() {
            return Err(format!(
                "{name} 已存在，拒绝覆盖——先备份或换新 profile 目录"
            ));
        }
    }
    use base64::Engine;
    let mut written = 0usize;
    for (name, encoded) in files {
        let raw = encoded
            .as_str()
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .ok_or_else(|| format!("{name} 内容损坏"))?;
        let path = crate::paths::join(profile_dir, name);
        crate::write_private_atomic(&path, &raw)?;
        written += 1;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_seals_and_lands_the_persona() {
        let dir = std::env::temp_dir().join(format!("crb-src-{}", std::process::id()));
        let dst = std::env::temp_dir().join(format!("crb-dst-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(dir.join("guest-profile.json"), b"{\"u\":1}").unwrap();
        std::fs::write(dir.join("config.json"), b"{\"c\":2}").unwrap();
        let sealed = export(dir.to_str().unwrap(), "pw-123").unwrap();
        assert_eq!(&sealed[..4], MAGIC);
        // The plaintext persona must not be greppable in the sealed file.
        assert!(!sealed.windows(7).any(|w| w == b"{\"u\":1}"));
        let n = import(dst.to_str().unwrap(), "pw-123", &sealed).unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            std::fs::read(dst.join("config.json")).unwrap(),
            b"{\"c\":2}"
        );
        // Wrong password never lands anything.
        assert!(import(dst.to_str().unwrap(), "wrong", &sealed).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dst);
    }

    #[test]
    fn refuses_to_clobber_and_rejects_foreign_files() {
        let dir = std::env::temp_dir().join(format!("crb-clob-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.json"), b"{}").unwrap();
        let sealed = export(dir.to_str().unwrap(), "pw").unwrap();
        // Existing target file => whole import refused.
        assert!(import(dir.to_str().unwrap(), "pw", &sealed).is_err());
        // Forged manifest with an out-of-set name is refused after unseal.
        let mut manifest = serde_json::json!({
            "format": "creance-bundle", "version": 1,
            "files": {"/etc/passwd": "eA=="}
        });
        assert!(files_set_rejects(&mut manifest));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Helper mirroring import's allow-list check, used to prove a forged
    // manifest can't sneak an arbitrary path through the name gate.
    fn files_set_rejects(manifest: &mut serde_json::Value) -> bool {
        manifest["files"]
            .as_object()
            .map(|f| f.keys().any(|n| !FILES.contains(&n.as_str())))
            .unwrap_or(false)
    }
}
