//! 手机审批通道（0.7 规格：复用成熟通道 + 端到端签名回执）。
//!
//! 通道=Telegram Bot：`approve <action>` 给本人 chat 发一条含随机回执码
//! 的请求，轮询 getUpdates 等本人回复该码；回执命中即在
//! `<profile>/.approvals/` 落一张限时批条（0600）。敏感操作经
//! `has_grant` 查批条——批条不在或过期即拒。

use std::time::{Duration, Instant};

use creance_net::egress::{self, Egress};
use creance_vm::config::Config;

const GRANT_TTL_SECS: u64 = 600;
const POLL_BUDGET: Duration = Duration::from_secs(600);

fn api(eg: &Egress, token: &str, method: &str, body: &[u8]) -> Result<String, String> {
    let r = egress::request(
        eg,
        "POST",
        &format!("https://api.telegram.org/bot{token}/{method}"),
        Some("application/json"),
        body,
        Instant::now() + Duration::from_secs(30),
    )?;
    if r.status != 200 {
        return Err(format!("telegram {method} 返回 {}", r.status));
    }
    Ok(String::from_utf8_lossy(&r.body).into_owned())
}

/// 发送审批请求并等待手机回执；确认后落批条。
pub fn request_approval(profile: &str, cfg: &Config, action: &str) -> Result<(), String> {
    if cfg.approval_bot_token.is_empty() || cfg.approval_chat_id.is_empty() {
        return Err(
            "审批通道未配置（config.json 需 approval_bot_token + approval_chat_id）".to_owned(),
        );
    }
    let eg = Egress::new(&cfg.resolved_proxy_url()?, &cfg.dns_url)?;
    let token = cfg.resolved_approval_bot_token()?;
    let nonce = &creance_vm::token()[..12];
    let text = format!(
        "creance 审批请求：{action}\n回执码：{nonce}\n在本对话直接回复该回执码即批准（10 分钟有效）"
    );
    api(
        &eg,
        &token,
        "sendMessage",
        serde_json::json!({"chat_id": cfg.approval_chat_id, "text": text})
            .to_string()
            .as_bytes(),
    )?;
    eprintln!("审批请求已发出（回执码 {nonce}），等待手机回执……");
    let deadline = Instant::now() + POLL_BUDGET;
    let mut offset: i64 = -1; // -1 = 只看新消息
    while Instant::now() < deadline {
        let url_body =
            serde_json::json!({"timeout": 25, "offset": offset, "allowed_updates": ["message"]});
        let resp = api(&eg, &token, "getUpdates", url_body.to_string().as_bytes());
        let Ok(resp) = resp else { continue };
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap_or_default();
        let Some(updates) = v["result"].as_array() else {
            continue;
        };
        for u in updates {
            if let Some(id) = u["update_id"].as_i64() {
                offset = id + 1;
            }
            let msg = &u["message"];
            let chat = msg["chat"]["id"].to_string();
            let chat = chat.trim_matches('"');
            if chat != cfg.approval_chat_id.trim_matches('"') {
                continue;
            }
            let text = msg["text"].as_str().unwrap_or_default();
            if text.contains(nonce) {
                write_grant(profile, action)?;
                return Ok(());
            }
        }
    }
    Err("审批超时（10 分钟无回执），操作未执行".to_owned())
}

fn grant_path(profile: &str, action: &str) -> String {
    use sha2::Digest;
    let key = hex::encode(sha2::Sha256::digest(action.as_bytes()));
    creance_vm::paths::join(&format!("{profile}/.approvals"), &key[..16])
}

fn write_grant(profile: &str, action: &str) -> Result<(), String> {
    let dir = format!("{profile}/.approvals");
    creance_vm::private::ensure_private_dir(&dir).map_err(|e| e.to_string())?;
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() + GRANT_TTL_SECS)
        .unwrap_or(0);
    creance_vm::write_private_atomic(&grant_path(profile, action), expiry.to_string().as_bytes())
}

/// 该操作是否持有效批条（未配置审批通道时默认放行——通道是加固项，
/// 不是必须项；配置了才强制）。
pub fn has_grant(profile: &str, cfg: &Config, action: &str) -> bool {
    if cfg.approval_bot_token.is_empty() && cfg.approval_chat_id.is_empty() {
        return true;
    }
    prune_expired(profile);
    let Ok(text) = std::fs::read_to_string(grant_path(profile, action)) else {
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

/// 清理过期批条，防止 .approvals/ 无限累积。
fn prune_expired(profile: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let Ok(entries) = std::fs::read_dir(format!("{profile}/.approvals")) else {
        return;
    };
    for e in entries.flatten() {
        let expired = std::fs::read_to_string(e.path())
            .ok()
            .and_then(|t| t.trim().parse::<u64>().ok())
            .is_some_and(|exp| now >= exp);
        if expired {
            let _ = std::fs::remove_file(e.path());
        }
    }
}
