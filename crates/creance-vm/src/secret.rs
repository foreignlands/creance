//! Keychain 引用（0.7.x 评审项②）：配置文件里任何敏感串都可以写成
//! `keychain:<entry>` 引用形，真值活在操作系统钥匙串（macOS Keychain /
//! Linux secret-service）里，永不落盘。引用在 `load` 后**保持引用形**——
//! 身份比较、持久化、fingerprints 全在引用上走；只有真正要用秘密的
//! 使用点（建 egress、调 Bot API）才经 `resolve` 还原。
//!
//! 安全不变量：creance 任何代码路径都不得把 resolve 的返回值写进
//! 文件或日志。store/write-back 路径（store.rs 应用节点回写）在引用形
//! 字段上更新钥匙串本身，而不是把真值回填进 config。

pub const SERVICE: &str = "creance";
pub const PREFIX: &str = "keychain:";

/// A reference is `keychain:` plus a non-empty entry name. Entry names are
/// restricted so a typo'd reference cannot smuggle odd control bytes into
/// backend-specific key paths.
pub fn is_reference(value: &str) -> bool {
    value
        .strip_prefix(PREFIX)
        .is_some_and(|e| !e.is_empty() && entry_name_ok(e))
}

fn entry_name_ok(entry: &str) -> bool {
    entry.len() <= 128
        && entry
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
}

/// Resolves a value: plaintext passes through untouched; a `keychain:`
/// reference is read from the OS keychain. Errors are explicit — a missing
/// entry or an unavailable backend must never silently degrade to empty.
pub fn resolve(value: &str) -> Result<String, String> {
    if !is_reference(value) {
        return Ok(value.to_owned());
    }
    let entry = &value[PREFIX.len()..];
    let handle =
        keyring::Entry::new(SERVICE, entry).map_err(|e| format!("keychain 后端不可用：{e}"))?;
    handle
        .get_password()
        .map_err(|e| format!("keychain 条目 {entry} 读取失败：{e}"))
}

/// Writes `value` under `entry` in the OS keychain.
pub fn store(entry: &str, value: &str) -> Result<(), String> {
    if !entry_name_ok(entry) {
        return Err(format!("keychain 条目名非法：{entry}"));
    }
    let handle =
        keyring::Entry::new(SERVICE, entry).map_err(|e| format!("keychain 后端不可用：{e}"))?;
    handle
        .set_password(value)
        .map_err(|e| format!("keychain 条目 {entry} 写入失败：{e}"))
}

/// Deletes an entry; a missing entry is not an error.
pub fn delete(entry: &str) -> Result<(), String> {
    let handle =
        keyring::Entry::new(SERVICE, entry).map_err(|e| format!("keychain 后端不可用：{e}"))?;
    match handle.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("keychain 条目 {entry} 删除失败：{e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_shape() {
        assert!(is_reference("keychain:proxy"));
        assert!(is_reference("keychain:prod/proxy-eu"));
        assert!(!is_reference("keychain:"));
        assert!(!is_reference("socks5://127.0.0.1:1080"));
        assert!(!is_reference("keychain:bad entry"));
        assert!(!is_reference("keychain:bad\nentry"));
    }

    #[test]
    fn plaintext_passes_through_untouched() {
        // The non-keychain path must never so much as look at a backend —
        // headless hosts without secret-service keep working exactly as before.
        assert_eq!(
            resolve("socks5://u:p@10.0.0.1:1080").unwrap(),
            "socks5://u:p@10.0.0.1:1080"
        );
        assert_eq!(resolve("").unwrap(), "");
    }

    #[test]
    fn missing_entry_is_an_explicit_error() {
        // Whether the backend is absent (headless CI) or present without the
        // entry, resolution must fail loudly — never degrade to empty.
        let err = resolve("keychain:creance-test-nonexistent-entry-zz").unwrap_err();
        assert!(!err.is_empty());
    }
}
