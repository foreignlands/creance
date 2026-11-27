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
const XTERM_JS: &str = include_str!("static/xterm.js");
const XTERM_CSS: &str = include_str!("static/xterm.css");
const XTERM_FIT: &str = include_str!("static/xterm-addon-fit.js");

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
    // WS 终端通道升级时需要原始 TcpStream（read_header_block 之后
    // 只剩 PrefacedReader）。升级请求不携带管道化字节，克隆是安全的。
    let ws_clone = stream.try_clone().ok();
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
    // WebSocket 终端通道：升级握手在 route 之前接管连接。
    // 浏览器 WebSocket() 不能设自定义头——参数全走 query：
    // /api/term?agent=<id>&cols=<n>&rows=<n>
    if path.starts_with("/api/term") && method == "GET" {
        // CSRF：跨站 WebSocket 不受同源策略限制，浏览器会带 Origin——
        // 非本工作台来源的升级请求一律拒。无 Origin=curl/CLI 放行
        // （与 POST 突变同纪律）。
        let foreign = fields.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("origin")
                && !v.is_empty()
                && v != &format!("http://127.0.0.1:{port}")
        });
        if foreign {
            return;
        }
        if let Some(key) = crate::term::handshake_key(&fields) {
            let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
            let get = |name: &str| {
                qs.split('&').find_map(|p| {
                    p.split_once('=')
                        .filter(|(k, _)| *k == name)
                        .map(|(_, v)| v.to_owned())
                })
            };
            if let Some(agent) = get("agent").and_then(|id| crate::agents::find(&id)) {
                let num = |name: &str, def: u16, max: u16| {
                    get(name)
                        .and_then(|v| v.parse().ok())
                        .filter(|&n: &u16| n > 0 && n <= max)
                        .unwrap_or(def)
                };
                let params = crate::term::TermParams {
                    launch: agent.launch.to_owned(),
                    cols: num("cols", 80, 500),
                    rows: num("rows", 24, 200),
                };
                if let Some(raw) = ws_clone {
                    let _ = crate::term::run(raw, &key, &ctx.profile, params);
                }
            }
        }
        return;
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

/// 经 ssh 在 guest 内执行脚本（agent 检测/安装的唯一通道——
/// 永远不在 host 执行）。输出 capped 防内存炸弹。
fn guest_exec(ctx: &ServeCtx, script: &str) -> Result<std::process::Output, String> {
    let instance = running_instance(&ctx.profile)?;
    let target = creance_vm::vm::ssh_target(&ctx.profile, &instance)?;
    let mut cmd = std::process::Command::new("ssh");
    creance_vm::vm::apply_ssh_options(&mut cmd, &target);
    cmd.arg("-o")
        .arg("StrictHostKeyChecking=yes")
        .arg("127.0.0.1")
        // bash 而非 sh：安装命令含管道，pipefail 是 bash 特性——
        // `curl|bash` 中 curl 失败必须使整体失败（dash 无 pipefail，
        // 空输入的 bash 返回 0 造成"假成功"，0.8.5 实测踩中）。
        .args(["bash", "-s"]);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        // stderr 必须保留——DNS/网络错误全在那里，丢弃=错误无痕
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("guest 通道失败：{e}"))?;
    use std::io::Write as _;
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(script.as_bytes())
        .map_err(|e| format!("guest 写入失败：{e}"))?;
    child
        .wait_with_output()
        .map_err(|e| format!("guest 执行失败：{e}"))
}

/// desktop 通道（0.8.8）：serve 进程级单例——ssh -L 转发到 guest
/// noVNC + creance-oauth 的 Xvnc/openbox 栈。open 幂等（已开则复用
/// 端口）；close 杀转发+guest stop；serve 退出即子进程孤死（ssh 本身
/// 随父退出，无清理债务）。
static DESKTOP: std::sync::Mutex<Option<(u16, std::process::Child)>> = std::sync::Mutex::new(None);

fn desktop_port() -> Option<u16> {
    DESKTOP.lock().ok()?.as_ref().map(|(p, _)| *p)
}

fn desktop_open(ctx: &ServeCtx) -> Result<u16, String> {
    // 已开且转发进程活着→直接复用
    if let Ok(mut guard) = DESKTOP.lock()
        && let Some((port, child)) = guard.as_mut()
    {
        // try_wait 顺带收割僵尸——活着则复用，死了则清空重开
        match child.try_wait() {
            Ok(None) => return Ok(*port),
            _ => {
                *guard = None;
            }
        }
    }
    let instance = running_instance(&ctx.profile)?;
    let target = creance_vm::vm::ssh_target(&ctx.profile, &instance)?;
    let local_port = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .and_then(|l| l.local_addr())
        .map_err(|e| format!("无法分配本地端口：{e}"))?
        .port();
    let mut fwd = std::process::Command::new("ssh");
    creance_vm::vm::apply_ssh_options(&mut fwd, &target);
    let mut child = fwd
        .arg("-o")
        .arg("StrictHostKeyChecking=yes")
        .arg("-o")
        .arg("ExitOnForwardFailure=yes")
        .arg("-N")
        .arg("-L")
        .arg(format!("127.0.0.1:{local_port}:127.0.0.1:6080"))
        .arg("127.0.0.1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("ssh 转发失败：{e}"))?;
    std::thread::sleep(std::time::Duration::from_millis(600));
    if let Ok(Some(_)) = child.try_wait() {
        return Err("ssh 转发立即退出——环境在运行吗？".to_owned());
    }
    // guest 侧 X 栈拉起（幂等——已开直接返回）
    creance_vm::vm::guest_script(
        &ctx.profile,
        &instance,
        "sh /usr/local/bin/creance-oauth start",
    )?;
    if let Ok(mut guard) = DESKTOP.lock() {
        *guard = Some((local_port, child));
    }
    Ok(local_port)
}

fn desktop_close(ctx: &ServeCtx) {
    if let Ok(mut guard) = DESKTOP.lock()
        && let Some((_, mut child)) = guard.take()
    {
        let _ = child.kill();
        let _ = child.wait();
    }
    if let Ok(instance) = running_instance(&ctx.profile) {
        let _ = creance_vm::vm::guest_script(
            &ctx.profile,
            &instance,
            "sh /usr/local/bin/creance-oauth stop",
        );
    }
}

pub(crate) fn running_instance(profile: &str) -> Result<String, String> {
    // 实例名是确定性派生；ssh_target 在实例未运行时自己拒绝，
    // 错误文案在那里统一。
    Ok(creance_vm::vm::instance_name(
        profile,
        &creance_vm::vm::environment_dir(profile),
    ))
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
        ("GET", "/static/xterm.js") => {
            (200, "application/javascript", XTERM_JS.as_bytes().to_vec())
        }
        ("GET", "/static/xterm.css") => (200, "text/css", XTERM_CSS.as_bytes().to_vec()),
        ("GET", "/static/xterm-addon-fit.js") => {
            (200, "application/javascript", XTERM_FIT.as_bytes().to_vec())
        }
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
        ("POST", "/api/desktop/open") => {
            json_action(ctx, body, |ctx, _v| match desktop_open(ctx) {
                Ok(port) => (200, json!({"ok": true, "port": port})),
                Err(e) => (409, json!({"error": e})),
            })
        }
        ("POST", "/api/agents/launch-desktop") => json_action(ctx, body, |ctx, v| {
            let id = v["id"].as_str().unwrap_or_default();
            let Some(agent) = crate::agents::find(id) else {
                return (404, json!({"error": "unknown agent"}));
            };
            // launch 模板是注册表常量；setsid 脱离 ssh 会话存活，DISPLAY 与
            // creance-oauth 栈同值
            let script = format!(
                "setsid env DISPLAY=:99 {} >/dev/null 2>&1 & echo launched",
                agent.launch
            );
            match guest_exec(ctx, &script) {
                Ok(out) if out.status.success() => (200, json!({"ok": true})),
                Ok(_) => (409, json!({"error": "启动失败——应用已安装吗？"})),
                Err(e) => (409, json!({"error": e})),
            }
        }),
        ("POST", "/api/desktop/close") => json_action(ctx, body, |ctx, _v| {
            desktop_close(ctx);
            (200, json!({"ok": true}))
        }),
        ("GET", "/api/desktop/status") => {
            let port = desktop_port();
            (
                200,
                "application/json",
                json!({"open": port.is_some(), "port": port})
                    .to_string()
                    .into_bytes(),
            )
        }
        ("GET", "/api/agents") => (
            200,
            "application/json",
            crate::agents::registry_json().to_string().into_bytes(),
        ),
        ("POST", "/api/agents/detect") => json_action(ctx, body, |ctx, v| {
            let id = v["id"].as_str().unwrap_or_default();
            let Some(agent) = crate::agents::find(id) else {
                return (404, json!({"error": "unknown agent"}));
            };
            match guest_exec(ctx, agent.detect) {
                Ok(out) => (200, json!({"installed": out.status.success()})),
                Err(e) => (409, json!({"error": e})),
            }
        }),
        ("POST", "/api/agents/install") => json_action(ctx, body, |ctx, v| {
            let id = v["id"].as_str().unwrap_or_default();
            let Some(agent) = crate::agents::find(id) else {
                return (404, json!({"error": "unknown agent"}));
            };
            if agent.install.is_empty() {
                return (
                    409,
                    json!({"error": format!("{} 需要手工安装——{}", agent.name, agent.note)}),
                );
            }
            match guest_exec(ctx, &format!("set -eo pipefail; {}", agent.install)) {
                Ok(out) if out.status.success() => (200, json!({"ok": true})),
                Ok(out) => {
                    let err_tail = String::from_utf8_lossy(&out.stderr);
                    let out_tail = String::from_utf8_lossy(&out.stdout);
                    let pick = if err_tail.trim().is_empty() {
                        out_tail
                    } else {
                        err_tail
                    };
                    let tail = pick
                        .lines()
                        .rfind(|l| !l.trim().is_empty())
                        .unwrap_or("未知原因")
                        .chars()
                        .take(140)
                        .collect::<String>();
                    (
                        409,
                        json!({"error": format!("安装失败：{tail} → 检查 guest 出口连通性（节点是否已应用并启动核心）")}),
                    )
                }
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
