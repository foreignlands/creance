//! 插件协议（0.7 规格：MCP 宿主受控执行）——每次宿主调用都是一次
//! 微型 gate-open：插件名必须登记在 `<profile>/plugins.json` 白名单
//! 内，`approval` 标项还须持手机批条；argv 固定绝对路径、spawn 不经
//! shell、参数透传由 `allow_args` 显式放开。
//!
//! ```json
//! [{"name": "disk-usage", "argv": ["/usr/bin/df", "-h"], "approval": false, "allow_args": false}]
//! ```

use std::process::Command;

use serde::Deserialize;
use sha2::Digest;

const OUTPUT_CAP: usize = 64 * 1024;

#[derive(Deserialize)]
struct Entry {
    name: String,
    argv: Vec<String>,
    #[serde(default)]
    approval: bool,
    #[serde(default)]
    allow_args: bool,
}

fn grant_valid(profile: &str, action: &str) -> bool {
    let key = hex::encode(sha2::Sha256::digest(action.as_bytes()));
    let path = creance_vm::paths::join(&format!("{profile}/.approvals"), &key[..16]);
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(expiry) = text.trim().parse::<u64>() else {
        return false;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX);
    now < expiry
}

fn capped(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(OUTPUT_CAP)]).into_owned()
}

/// Executes allowlisted plugin `name` with `args`; returns the JSON result
/// body. `approval_configured` mirrors the profile's approval channel: an
/// approval-flagged plugin refuses outright when the channel is off —
/// there is no way to grant it (fail-closed).
pub fn call(
    profile: &str,
    approval_configured: bool,
    name: &str,
    args: &[String],
) -> Result<serde_json::Value, String> {
    let path = creance_vm::paths::join(profile, "plugins.json");
    let text =
        std::fs::read_to_string(&path).map_err(|_| "无插件注册表 plugins.json".to_owned())?;
    if text.len() > 256 * 1024 {
        return Err("plugins.json 过大".to_owned());
    }
    let entries: Vec<Entry> =
        serde_json::from_str(&text).map_err(|e| format!("plugins.json 解析失败：{e}"))?;
    let entry = entries
        .iter()
        .find(|e| e.name == name)
        .ok_or_else(|| format!("插件未注册：{name}"))?;
    if entry.argv.is_empty() || !std::path::Path::new(&entry.argv[0]).is_absolute() {
        return Err(format!("插件 {name} 的 argv[0] 须为绝对路径"));
    }
    if !entry.allow_args && !args.is_empty() {
        return Err(format!("插件 {name} 不接受参数"));
    }
    if entry.approval {
        if !approval_configured {
            return Err(format!("插件 {name} 要求审批通道，但通道未配置"));
        }
        if !grant_valid(profile, &format!("plugin-{name}")) {
            return Err(format!(
                "插件 {name} 须持批条：creance approve plugin-{name}"
            ));
        }
    }
    let out = Command::new(&entry.argv[0])
        .args(&entry.argv[1..])
        .args(args)
        .output()
        .map_err(|e| format!("插件 {name} 启动失败：{e}"))?;
    Ok(serde_json::json!({
        "plugin": name,
        "exit": out.status.code().unwrap_or(-1),
        "stdout": capped(&out.stdout),
        "stderr": capped(&out.stderr),
    }))
}
