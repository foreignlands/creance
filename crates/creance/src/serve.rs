//! `cage serve` — the lean workbench: a loopback-only HTTP service with a
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
use std::path::Path;
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
            live: live.clone(),
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
    /// Keeps the connection slot owned by this handler's spawn scope alive.
    #[allow(dead_code)]
    live: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

fn handle(mut stream: std::net::TcpStream, port: u16, ctx: ServeCtx) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let (head, mut stream) = match creance_net::wire::read_header_block(&mut stream, 16 << 10) {
        Ok((h, r)) if !h.is_empty() => (h, r),
        _ => return,
    };
    let text = String::from_utf8_lossy(&head).into_owned();
    let request_line = text.lines().next().unwrap_or_default().to_owned();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_uppercase();
    let path = parts.next().unwrap_or_default().to_owned();
    let mut body_len = 0usize;
    let mut origin = String::new();
    for line in text.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            if k.eq_ignore_ascii_case("content-length") {
                body_len = v.parse().unwrap_or(0);
            } else if k.eq_ignore_ascii_case("origin") && !v.is_empty() {
                origin = v.to_owned();
            }
        }
    }
    if body_len > 1 << 20 {
        return reply(&mut stream, 400, "body too large");
    }
    if text
        .lines()
        .any(|l| l.eq_ignore_ascii_case("transfer-encoding: chunked"))
    {
        return reply(&mut stream, 400, "chunked bodies are not supported");
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
            "HTTP/1.1 {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            status,
            payload.len()
        )
        .as_bytes(),
    );
    let _ = stream.write_all(&payload);
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
            let data = match creance_proxy::fetch::fetch_subscription(&cfg, url) {
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
            let egress = creance_net::egress::Egress::new(&cfg.proxy_url, &cfg.dns_url)?;
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
            )
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
        let applied = creance_proxy::applied(&ctx.profile, &cfg.proxy_url, &cfg.proxy_revision);
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
    json!(store
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
        .collect::<Vec<_>>())
}

fn reply<W: std::io::Write>(stream: &mut W, status: u16, message: &str) {
    let payload = json!({"error": message}).to_string();
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        )
        .as_bytes(),
    );
}

/// The instance dir of the profile's gate record, for the status panel.
pub fn gate_instance_dir(profile: &str) -> String {
    creance_vm::paths::join(
        &vm::lima_home(profile),
        &vm::instance_name(profile, &vm::environment_dir(profile)),
    )
}

/// Whether a gate record exists and its state, for the workbench panel.
pub fn gate_state(profile: &str) -> Option<String> {
    let client = creance_gate::gate::GateClient::open(&gate_instance_dir(profile)).ok()?;
    let status = client.status().ok()?;
    Some(format!("{:?}", status.state).trim_matches('"').to_owned())
}

/// Path helper re-exported for the workbench HTML host.
pub fn config_parent(config_path: &str) -> String {
    Path::new(config_path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}
