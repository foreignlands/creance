//! `creance serve` — the lean workbench: a loopback-only HTTP service with a
//! single-page UI for the control plane (status, subscriptions, node
//! selection, core lifecycle, transport check).
//!
//! Security posture: binds `127.0.0.1` only, refuses cross-origin POSTs, and
//! every action goes through the same cage-core paths the CLI uses, so the
//! no-direct-fallback and applied-revision contracts hold.

use creance_proxy::{self};
use creance_vm::config::{self, Config};
use creance_vm::vm;
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

/// Concurrent connection ceiling for the loopback workbench.
const MAX_CONNECTIONS: usize = 64;

const CHECK_URL: &str = "https://1.1.1.1/cdn-cgi/trace";
const CHECK_BUDGET: Duration = Duration::from_secs(25);
/// The UI, embedded at build time.
const WORKBENCH_HTML: &str = include_str!("workbench.html");

/// Serves the workbench on `127.0.0.1:port` until the process is stopped.
pub fn serve(profile: &str, config_path: &str, port: u16) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    eprintln!("creance workbench on http://127.0.0.1:{port} (profile {profile})");
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    let live = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for stream in listener.incoming().flatten() {
        // A local process must not be able to thread-flood the workbench.
        if live.load(std::sync::atomic::Ordering::Relaxed) >= MAX_CONNECTIONS {
            let mut stream = stream;
            let _ = stream.write_all(b"HTTP/1.1 503 Busy\r\nContent-Length: 0\r\n\r\n");
            continue;
        }
        live.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let live = live.clone();
        let ctx = ServeCtx {
            profile: profile.to_owned(),
            config_path: config_path.to_owned(),
        };
        std::thread::spawn(move || {
            handle(stream, port, ctx);
            live.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });
    }
    Ok(())
}

struct ServeCtx {
    profile: String,
    config_path: String,
}

fn handle(mut stream: std::net::TcpStream, port: u16, ctx: ServeCtx) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let (head, mut stream) = match creance_net::wire::read_header_block(&mut stream, 16 << 10) {
        Ok((h, r)) if !h.is_empty() => (h, r),
        _ => return,
    };
    let (request_line, fields) = creance_net::wire::parse_header_block(&head);
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_uppercase();
    let path = parts.next().unwrap_or_default().to_owned();
    // FINDING-006: invalid or repeated Content-Length is an ambiguity
    // smuggling vector — reject it outright.
    let body_len = match creance_net::wire::strict_content_length(&fields) {
        Ok(Some(n)) => n,
        Ok(None) => 0,
        Err(_) => return reply(&mut stream, 400, "invalid content-length"),
    };
    let mut origin = String::new();
    for (k, v) in &fields {
        if k.eq_ignore_ascii_case("transfer-encoding") {
            return reply(&mut stream, 400, "chunked bodies are not supported");
        } else if k.eq_ignore_ascii_case("origin") && !v.is_empty() {
            origin = v.clone();
        }
    }
    if body_len > 1 << 20 {
        return reply(&mut stream, 400, "body too large");
    }
    let mut body = vec![0u8; body_len];
    if body_len > 0 && stream.read_exact(&mut body).is_err() {
        return;
    }
    // Mutations must come from the same origin (the workbench itself) or
    // from no Origin at all (curl/CLI); a foreign Origin is a CSRF.
    if method == "POST" && !origin.is_empty() {
        let allowed = format!("http://127.0.0.1:{port}");
        if origin != allowed {
            return reply(&mut stream, 403, "cross-origin mutation refused");
        }
    }
    let (status, content_type, payload) = route(&ctx, &method, &path, &body);
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            status,
            reason(status),
            payload.len()
        )
        .as_bytes(),
    );
    let _ = stream.write_all(&payload);
}

/// 扫描本机常见 Clash 系配置（0.8.3 迁移引导）：Verge/Mihomo/Clash
/// 的 profiles 目录，返回可导入的 YAML 路径清单。只读不拷贝——
/// 用户在 UI 确认后才经 import-paste 路径入库。
fn scan_local_configs() -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let Some(home) = std::env::var_os("HOME") else {
        return out;
    };
    let home = std::path::Path::new(&home);
    let candidates: Vec<std::path::PathBuf> = [
        ".config/clash-verge/profiles",
        ".config/clash-verge-rev/profiles",
        ".config/mihomo/profiles",
        ".config/clash/profiles",
        ".config/clash",
        "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/profiles",
        "Library/Application Support/clash-verge/profiles",
    ]
    .iter()
    .map(|c| home.join(c))
    .collect();
    for dir in candidates {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let path = ent.path();
            let is_yaml = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "yaml" || e == "yml");
            if !is_yaml {
                continue;
            }
            // 小文件头嗅探：必须含 proxies 或订阅链接特征，避免扫进无关 yaml
            let Ok(head) =
                std::fs::read(&path).map(|b| b.iter().take(4096).copied().collect::<Vec<u8>>())
            else {
                continue;
            };
            let text = String::from_utf8_lossy(&head);
            if !(text.contains("proxies:") || text.contains("proxy-providers")) {
                continue;
            }
            out.push(json!({
                "path": path.display().to_string(),
                "size": ent.metadata().map(|m| m.len()).unwrap_or(0),
            }));
        }
    }
    out
}

fn route(ctx: &ServeCtx, method: &str, path: &str, body: &[u8]) -> (u16, &'static str, Vec<u8>) {
    match (method, path) {
        ("GET", "/") => (
            200,
            "text/html; charset=utf-8",
            WORKBENCH_HTML.as_bytes().to_vec(),
        ),
        ("GET", "/api/status") => (
            200,
            "application/json",
            status_json(ctx).to_string().into_bytes(),
        ),
        ("GET", "/api/nodes") => (
            200,
            "application/json",
            nodes_json(ctx).to_string().into_bytes(),
        ),
        ("POST", "/api/proxy/import") => json_action(ctx, body, |ctx, v| {
            let name = v["name"].as_str().unwrap_or_default();
            let url = v["url"].as_str().unwrap_or_default();
            if name.is_empty() || url.is_empty() {
                return (400, json!({"error": "name and url required"}));
            }
            let cfg = match config::load(&ctx.config_path) {
                Ok(c) => c,
                Err(e) => return (409, json!({"error": e})),
            };
            let host_download = v["host_download"].as_bool().unwrap_or(false);
            let data = match if host_download {
                creance_proxy::fetch::fetch_subscription_host(url)
            } else {
                creance_proxy::fetch::fetch_subscription(&cfg, url)
            } {
                Ok(d) => d,
                Err(e) => return (502, json!({"error": e})),
            };
            let saved = creance_proxy::with_store_lock(&ctx.profile, || {
                let mut store = creance_proxy::load(&ctx.profile)?;
                store.import(name, url, &data, "", 0, "workbench")?;
                let count = store.count();
                creance_proxy::save(&ctx.profile, &store)?;
                Ok(count)
            });
            match saved {
                Ok(count) => (200, json!({"ok": true, "nodes": count})),
                Err(e) => (409, json!({"error": e})),
            }
        }),
        ("POST", "/api/proxy/import-paste") => json_action(ctx, body, |ctx, v| {
            let name = v["name"].as_str().unwrap_or_default();
            let content = v["content"].as_str().unwrap_or_default();
            if name.is_empty() || content.is_empty() {
                return (400, json!({"error": "name and content required"}));
            }
            if content.len() > creance_proxy::MAX_IMPORT {
                return (400, json!({"error": "配置超过 8 MiB 上限"}));
            }
            let saved = creance_proxy::with_store_lock(&ctx.profile, || {
                let mut store = creance_proxy::load(&ctx.profile)?;
                store.import(name, "", content.as_bytes(), "", 0, "workbench-paste")?;
                let count = store.count();
                creance_proxy::save(&ctx.profile, &store)?;
                Ok(count)
            });
            match saved {
                Ok(count) => (200, json!({"ok": true, "nodes": count})),
                Err(e) => (409, json!({"error": e})),
            }
        }),
        ("POST", "/api/proxy/import-local") => json_action(ctx, body, |ctx, v| {
            let path = v["path"].as_str().unwrap_or_default();
            let name = v["name"].as_str().unwrap_or_default();
            if path.is_empty() || name.is_empty() {
                return (400, json!({"error": "path and name required"}));
            }
            // 只允许导入 scan-local 刚扫描出的路径——这个端点不是通用文件读取器。
            let allowed = scan_local_configs();
            if !allowed.iter().any(|f| f["path"].as_str() == Some(path)) {
                return (403, json!({"error": "路径不在本机配置扫描结果内"}));
            }
            let data = match std::fs::read(path) {
                Ok(d) if d.len() <= creance_proxy::MAX_IMPORT => d,
                Ok(_) => return (400, json!({"error": "配置超过 8 MiB 上限"})),
                Err(e) => return (409, json!({"error": format!("读取失败：{e}")})),
            };
            let saved = creance_proxy::with_store_lock(&ctx.profile, || {
                let mut store = creance_proxy::load(&ctx.profile)?;
                store.import(name, "", &data, "", 0, "workbench-local")?;
                let count = store.count();
                creance_proxy::save(&ctx.profile, &store)?;
                Ok(count)
            });
            match saved {
                Ok(count) => (200, json!({"ok": true, "nodes": count})),
                Err(e) => (409, json!({"error": e})),
            }
        }),
        ("GET", "/api/proxy/scan-local") => {
            let found = scan_local_configs();
            (
                200,
                "application/json",
                json!({"found": found}).to_string().into_bytes(),
            )
        }
        ("POST", "/api/proxy/select") => json_action(ctx, body, |ctx, v| {
            let node = v["node"].as_str().unwrap_or_default();
            // F-043/F-047: revoke first, fatally — the CLI's transactional
            // order (close fails → the selection never lands).
            match creance_gate::gate::close_gates(&ctx.profile) {
                Ok(()) => {
                    match creance_proxy::select_and_apply(&ctx.profile, &ctx.config_path, node) {
                        Ok(_) => (200, json!({"ok": true})),
                        Err(e) => (409, json!({"error": e})),
                    }
                }
                Err(e) => (409, json!({"error": e})),
            }
        }),
        ("POST", "/api/proxy/start") => cmd_action(ctx, || {
            // F-036: gates learn about the (possibly changed) exit BEFORE
            // the core restarts — same ordering as the CLI's proxy-start,
            // no open-gate-with-swapped-exit window, and no silently
            // skipped sync either (the workbench used to skip it entirely).
            if let Ok(client) =
                creance_gate::gate::GateClient::open(&gate_instance_dir(&ctx.profile))
            {
                let _ = client.sync_proxy_revision();
            }
            creance_proxy::start_managed(&ctx.profile, &ctx.config_path)
        }),
        ("POST", "/api/proxy/stop") => cmd_action(ctx, || {
            let _ = creance_gate::gate::close_gates(&ctx.profile);
            creance_proxy::service::stop(&ctx.profile)
        }),
        ("POST", "/api/check") => cmd_action(ctx, || {
            let cfg = config::load(&ctx.config_path)?;
            let egress =
                creance_net::egress::Egress::new(&cfg.resolved_proxy_url()?, &cfg.dns_url)?;
            let response = creance_net::egress::request(
                &egress,
                "GET",
                CHECK_URL,
                None,
                &[],
                Instant::now() + CHECK_BUDGET,
            )?;
            if response.status == 200 {
                Ok(())
            } else {
                Err(format!("proxy check returned HTTP {}", response.status))
            }
        }),
        _ => (
            404,
            "application/json",
            json!({"error": "not found"}).to_string().into_bytes(),
        ),
    }
}

fn json_action(
    ctx: &ServeCtx,
    body: &[u8],
    action: impl Fn(&ServeCtx, &serde_json::Value) -> (u16, serde_json::Value),
) -> (u16, &'static str, Vec<u8>) {
    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return (
                400,
                "application/json",
                json!({"error": format!("invalid body: {e}")})
                    .to_string()
                    .into_bytes(),
            );
        }
    };
    let (status, reply) = action(ctx, &value);
    (status, "application/json", reply.to_string().into_bytes())
}

fn cmd_action(
    _ctx: &ServeCtx,
    action: impl FnOnce() -> Result<(), String>,
) -> (u16, &'static str, Vec<u8>) {
    match action() {
        Ok(()) => (
            200,
            "application/json",
            json!({"ok": true}).to_string().into_bytes(),
        ),
        Err(e) => (
            409,
            "application/json",
            json!({"error": e}).to_string().into_bytes(),
        ),
    }
}

fn status_json(ctx: &ServeCtx) -> serde_json::Value {
    let cfg: Result<Config, String> = config::load(&ctx.config_path);
    let store = creance_proxy::load(&ctx.profile).unwrap_or_default();
    let instance = vm::instance_name(&ctx.profile, &vm::environment_dir(&ctx.profile));
    let mut value = json!({
        "instance": instance,
        "sources": store.sources.len(),
        "nodes": store.count(),
        "selected": store.selected,
        "core_running": false,
        "applied": false,
    });
    if let Ok(cfg) = cfg {
        let applied = cfg
            .resolved_proxy_url()
            .and_then(|u| creance_proxy::applied(&ctx.profile, &u, &cfg.proxy_revision));
        value["applied"] = json!(applied.is_ok());
        value["timezone"] = json!(cfg.timezone);
        value["locale"] = json!(cfg.locale);
        if let Ok(applied) = applied {
            value["route"] = json!(applied.route().unwrap_or_default());
            value["core_running"] = json!(creance_proxy::service::running(&ctx.profile, &applied));
        }
    }
    value
}

fn nodes_json(ctx: &ServeCtx) -> serde_json::Value {
    let store = creance_proxy::load(&ctx.profile).unwrap_or_default();
    json!(
        store
            .sources
            .iter()
            .flat_map(|s| s
                .nodes
                .iter()
                .map(|n| json!({
                    "id": n.id,
                    "name": n.name,
                    "type": n.node_type,
                    "source": s.name,
                }))
                .collect::<Vec<_>>())
            .collect::<Vec<_>>()
    )
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        500 => "Internal Server Error",
        503 => "Busy",
        _ => "Status",
    }
}

fn reply<W: std::io::Write>(stream: &mut W, status: u16, message: &str) {
    let payload = json!({"error": message}).to_string();
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            reason(status),
            payload.len()
        )
        .as_bytes(),
    );
}

/// The instance dir of the profile's gate record, for the status panel.
pub fn gate_instance_dir(profile: &str) -> String {
    creance_vm::paths::join(
        &vm::instances_root(profile),
        &vm::instance_name(profile, &vm::environment_dir(profile)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn roundtrip(request: &str) -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let ctx = ServeCtx {
            profile: "t".into(),
            config_path: "/nonexistent".into(),
        };
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle(stream, port, ctx);
        });
        let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.write_all(request.as_bytes()).unwrap();
        let _ = c.shutdown(std::net::Shutdown::Write);
        let mut buf = String::new();
        let _ = c.read_to_string(&mut buf);
        buf
    }

    #[test]
    fn workbench_calls_only_real_routes() {
        // Every /api path the embedded UI calls must resolve through the
        // router — a dead endpoint is a silent broken button (the old
        // /api/proxy/refresh-x call was exactly that). The pin is STATIC:
        // each UI path must appear verbatim in a router match arm. The
        // first cut of this test executed `route()` live — but POST arms
        // are real mutations (close_gates, select_and_apply, service
        // spawns), and the test was only safe because every handler
        // happened to fail fast on the bogus config. A handler that ever
        // acts before reading config would mutate real host state from a
        // test run; the router is a plain match, so a verbatim source pin
        // is exactly as strong and has zero side effects.
        let source = include_str!("serve.rs");
        let mut paths: Vec<&str> = Vec::new();
        for needle in ["'/api/", "\"/api/"] {
            for m in WORKBENCH_HTML.match_indices(needle) {
                let rest = &WORKBENCH_HTML[m.0 + 1..];
                let end = rest.find(['\'', '"', '<', ' ']).unwrap_or(rest.len());
                paths.push(&rest[..end]);
            }
        }
        paths.sort();
        paths.dedup();
        assert!(!paths.is_empty(), "UI must call at least one endpoint");
        for path in paths {
            let hit = ["GET", "POST"]
                .iter()
                .any(|m| source.contains(&format!("(\"{m}\", \"{path}\")")));
            assert!(hit, "UI calls {path} but the router does not serve it");
        }
        // All fetches must stay loopback-relative — an absolute URL in
        // the UI would be an off-origin call (and a CSRF the Origin
        // check is built to refuse).
        for m in WORKBENCH_HTML.match_indices("fetch(") {
            let rest = &WORKBENCH_HTML[m.0 + 6..m.0 + 6 + 24.min(WORKBENCH_HTML.len() - m.0 - 6)];
            assert!(
                !rest.trim_start().starts_with("h") && !rest.contains("http"),
                "absolute fetch target near offset {}: {rest}",
                m.0
            );
        }
    }

    #[test]
    fn workbench_escapes_subscription_controlled_fields() {
        // Node name/type/source/id arrive from subscription data — an
        // attacker-controlled string. Every emission into innerHTML must
        // go through esc(); raw `${n.field}` in a rendered position is
        // stored XSS in the workbench.
        assert!(WORKBENCH_HTML.contains("const esc ="), "esc helper missing");
        for f in ["id", "name", "type", "source"] {
            assert!(
                WORKBENCH_HTML.contains(&format!("esc(n.{f})")),
                "n.{f} emitted without esc()"
            );
        }
        for f in ["name", "type", "source"] {
            assert!(
                !WORKBENCH_HTML.contains(&format!("${{n.{f}}}")),
                "raw interpolation of n.{f}"
            );
        }
        // Status fields likewise render as text, never parsed markup.
        for f in ["instance", "timezone", "locale", "route", "nodes"] {
            assert!(
                !WORKBENCH_HTML.contains(&format!("innerHTML = s.{f}")),
                "status field {f} rendered via innerHTML"
            );
        }
    }

    #[test]
    fn transfer_encoding_is_rejected() {
        // F-079/F-084: TE must stay a hard 400 — removing the check lets
        // a chunked body desync the parser (request smuggling).
        assert!(
            roundtrip("POST /api/x HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
                .starts_with("HTTP/1.1 400"),
            "TE request must be refused"
        );
        assert!(
            roundtrip("POST /api/x HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}")
                .starts_with("HTTP/1.1 400"),
            "duplicated Content-Length must be refused"
        );
    }
}
