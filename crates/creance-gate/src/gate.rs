//! The cage gate: the host-side control service guarding every environment's
//! external networking.
//!
//! One gate per running instance, identified by a `cage-gate.json` record in
//! the instance directory (the private unix socket path, a bearer token, and
//! this run's id). The control protocol is HTTP over that socket:
//!
//! - `GET /status` → the current [`GateStatus`]
//! - `POST /control` → one [`GateCommand`], authenticated with
//!   `Authorization: Bearer <token>` and `Host: cage`; anything else is 403
//!
//! Actions `check`/`fault`/`grant`/`renew` open or probe the gate only while
//! the applied proxy configuration still validates; `close` tears it down
//! with a reason; `proxy-revision` adopts a changed exit after verifying the
//! rest of the configuration survived (or only the exit-policy binding was
//! completed), otherwise 409.
//!
//! The enforcement plane (per-connection allow/deny and guest DNS) is wired
//! to the VM's network layer; see ROADMAP. This module owns the control
//! plane, the state machine, and the records, all of which stand alone.

use creance_vm::config::{self, Config};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The safety contract every status carries.
pub const POLICY: &str = "cage-safety/3";

/// How long an opened gate may stay open without a renewal.
const OPEN_LEASE: Duration = Duration::from_secs(90);
/// How long a check window may run before the gate closes itself.
const CHECK_LEASE: Duration = Duration::from_secs(180);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateRecord {
    pub socket: String,
    pub token: String,
    pub run_id: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateState {
    Closed,
    Checking,
    Open,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateStatus {
    pub state: GateState,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    pub run_id: String,
    pub policy: String,
    pub epoch: u64,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub counts: std::collections::BTreeMap<String, u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateCommand {
    pub action: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub report_id: String,
    #[serde(default)]
    pub report: Option<SafetyReport>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SafetyReport {
    pub report_id: String,
    #[serde(default)]
    pub checks: std::collections::BTreeMap<String, String>,
}

impl SafetyReport {
    /// The checks the gate requires before opening: every critical one must
    /// have passed, mirroring the Go gate's authorization set.
    const REQUIRED: &'static [&'static str] = &[
        "egress_policy",
        "fail_closed",
        "udp_policy",
        "ipv6_policy",
        "exit_consistency",
    ];

    fn authorizes(&self) -> bool {
        Self::REQUIRED
            .iter()
            .all(|c| self.checks.get(*c).map(String::as_str) == Some("passed"))
    }
}

struct GateInner {
    state: GateState,
    reason: String,
    epoch: u64,
    opened_at: Option<Instant>,
    lease: Duration,
    report: Option<SafetyReport>,
    counts: std::collections::BTreeMap<String, u64>,
    /// The configuration snapshot this gate started with; `proxy-revision`
    /// compares the freshly loaded config against it.
    recorded: Option<Config>,
}

impl GateInner {
    fn status(&self, run_id: &str) -> GateStatus {
        GateStatus {
            state: self.state.clone(),
            reason: self.reason.clone(),
            run_id: run_id.to_owned(),
            policy: POLICY.to_owned(),
            epoch: self.epoch,
            counts: self.counts.clone(),
        }
    }

    fn close(&mut self, reason: &str) {
        self.state = GateState::Closed;
        self.reason = truncate_utf8(reason, 200).to_owned();
        self.epoch += 1;
        self.opened_at = None;
        self.report = None;
        *self.counts.entry("closed".to_owned()).or_default() += 1;
    }
}

fn truncate_utf8(s: &str, max: usize) -> &str {
    match s
        .char_indices()
        .nth_back(s.chars().count().saturating_sub(max))
    {
        Some((i, _)) if s.len() > max => &s[..i.min(s.len())],
        _ if s.len() <= max => s,
        _ => s,
    }
}

/// The gate's shared core, served on its private socket.
pub struct Gate {
    run_id: String,
    inner: Mutex<GateInner>,
    shutdown: AtomicBool,
    config_path: String,
    record_path: String,
    socket_path: String,
    listener: Mutex<Option<UnixListener>>,
}

/// The owner of one running gate: keeps the server alive while held, stops
/// it and removes its record and socket directory on drop.
pub struct GateHandle {
    gate: Arc<Gate>,
    pub record: GateRecord,
    instance_dir: String,
}

impl Drop for GateHandle {
    fn drop(&mut self) {
        self.gate.shutdown();
        let record = Path::new(&self.instance_dir).join("cage-gate.json");
        let _ = std::fs::remove_file(record);
    }
}

/// Locks a gate mutex, recovering from a poisoned lock (a panicked handler
/// must not cascade into every later call).
fn lock_or_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Gate {
    /// Starts a gate: creates the record in `instance_dir` (socket path,
    /// token, run id) and spawns the control server. The returned handle
    /// owns the gate's lifetime — dropping it stops the server and removes
    /// the socket directory.
    pub fn start(instance_dir: &str, config_path: &str) -> Result<GateHandle, String> {
        let token = creance_proxy::token();
        let run_id = creance_proxy::token()[..32].to_owned();
        let sock_dir = std::env::temp_dir().join(format!(
            "cage-gate-{}",
            creance_proxy::token()[..8].to_owned()
        ));
        creance_vm::private::ensure_private_dir(sock_dir.to_string_lossy().as_ref())
            .map_err(|e| e.to_string())?;
        let socket = sock_dir.join("control.sock").to_string_lossy().into_owned();
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).map_err(|e| e.to_string())?;
        creance_vm::private::protect_file(&socket).map_err(|e| e.to_string())?;

        let record = GateRecord {
            socket: socket.clone(),
            token,
            run_id: run_id.clone(),
        };
        // Publish the record atomically; readers check it is private.
        let bytes = serde_json::to_vec_pretty(&record).map_err(|e| e.to_string())?;
        let record_path = Path::new(instance_dir).join("cage-gate.json");
        let tmp = Path::new(instance_dir)
            .join(format!(".gate-{}", creance_proxy::token()[..8].to_owned()));
        std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
        creance_vm::private::protect_file(tmp.to_string_lossy().as_ref())
            .map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &record_path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            e.to_string()
        })?;

        let gate = Arc::new(Gate {
            run_id,
            inner: Mutex::new(GateInner {
                state: GateState::Closed,
                reason: String::new(),
                epoch: 0,
                opened_at: None,
                lease: CHECK_LEASE,
                report: None,
                counts: std::collections::BTreeMap::new(),
                recorded: config::load(config_path).ok(),
            }),
            shutdown: AtomicBool::new(false),
            config_path: config_path.to_owned(),
            record_path: record_path.to_string_lossy().into_owned(),
            socket_path: socket.clone(),
            listener: Mutex::new(Some(listener)),
        });

        // The lease watchdog: a gate left open (or checking) without renewal
        // closes itself with a fixed reason. It holds only a Weak reference
        // so a dropped handle fully retires the gate.
        let watchdog = Arc::downgrade(&gate);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(500));
            let Some(watchdog) = watchdog.upgrade() else {
                return;
            };
            if watchdog.shutdown.load(Ordering::Relaxed) {
                return;
            }
            let mut inner = lock_or_recover(&watchdog.inner);
            if let (Some(opened), lease) = (inner.opened_at, inner.lease) {
                if opened.elapsed() > lease {
                    inner.close("检测租期到期，等待重新检查");
                }
            }
        });

        // The accept loop also holds only a Weak: it exits when the gate is
        // dropped or shut down, and owns the socket-file cleanup.
        let accept_sock = socket.clone();
        let accept_dir = sock_dir.to_string_lossy().into_owned();
        let server = Arc::downgrade(&gate);
        std::thread::spawn(move || {
            loop {
                let Some(server) = server.upgrade() else {
                    break;
                };
                if server.shutdown.load(Ordering::Relaxed) {
                    break;
                }
                // Accept on the listener the Gate still owns; taking it in
                // shutdown() drops the fd and unblocks us with an error.
                let accepted = {
                    let guard = lock_or_recover(&server.listener);
                    match guard.as_ref() {
                        Some(listener) => listener.accept().map(|(s, _)| s),
                        None => Err(std::io::Error::other("gate closed")),
                    }
                };
                match accepted {
                    Ok(stream) => {
                        let server = server.clone();
                        std::thread::spawn(move || server.handle(stream));
                    }
                    Err(_) => {
                        if server.shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                        // Transient accept errors (EMFILE, ECONNABORTED):
                        // back off instead of spinning.
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
                drop(server);
            }
            let _ = std::fs::remove_file(&accept_sock);
            let _ = std::fs::remove_dir(&accept_dir);
        });
        Ok(GateHandle {
            gate,
            record,
            instance_dir: instance_dir.to_owned(),
        })
    }

    /// Stops the server loop and closes the listening socket. The accept
    /// thread removes the socket directory on its way out.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Dropping our listener fd alone leaves the accept thread's view
        // open (fds are references); a self-connect wakes it so it observes
        // the flag and exits.
        if let Ok(mut guard) = self.listener.try_lock() {
            *guard = None;
        }
        let _ = std::os::unix::net::UnixStream::connect(&self.socket_path);
    }

    /// The current status snapshot.
    pub fn status(&self) -> GateStatus {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .status(&self.run_id)
    }

    fn handle(&self, mut stream: std::os::unix::net::UnixStream) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let (head, mut stream) = match creance_net::wire::read_header_block(&mut stream, 16 << 10) {
            Ok((h, r)) if !h.is_empty() => (h, r),
            _ => return,
        };
        let text = String::from_utf8_lossy(&head).into_owned();
        let mut lines = text.lines();
        let request_line = lines.next().unwrap_or_default().to_owned();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_owned();
        let path = parts.next().unwrap_or_default().to_owned();
        let mut body_len = 0usize;
        let mut bearer = String::new();
        let mut host = String::new();
        let mut origin_present = false;
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                let (k, v) = (k.trim(), v.trim());
                if k.eq_ignore_ascii_case("content-length") {
                    body_len = v.parse().unwrap_or(0);
                } else if k.eq_ignore_ascii_case("authorization") {
                    bearer = v.strip_prefix("Bearer ").unwrap_or_default().to_owned();
                } else if k.eq_ignore_ascii_case("host") {
                    host = v.to_owned();
                } else if k.eq_ignore_ascii_case("origin") {
                    origin_present = true;
                }
            }
        }
        // Host must be the private name, Origin must be absent, and the
        // bearer must match the record's token.
        if host != "cage" || origin_present || bearer != self.record_token() {
            let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
            return;
        }
        if body_len > 64 << 10 {
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            return;
        }
        let mut body = vec![0u8; body_len];
        if body_len > 0 && stream.read_exact(&mut body).is_err() {
            return;
        }
        let response = match (method.as_str(), path.as_str()) {
            ("GET", "/status") => {
                let status = serde_json::to_vec(&self.status()).expect("status serializes");
                (200, status)
            }
            ("POST", "/control") => self.control(&body),
            _ => (404, error_json("not found")),
        };
        let _ = stream.write_all(
            format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.0,
                response.1.len()
            )
            .as_bytes(),
        );
        let _ = stream.write_all(&response.1);
    }

    fn record_token(&self) -> String {
        std::fs::read_to_string(self.record_path())
            .ok()
            .and_then(|s| serde_json::from_str::<GateRecord>(&s).ok())
            .map(|r| r.token)
            .unwrap_or_default()
    }

    fn record_path(&self) -> PathBuf {
        PathBuf::from(&self.record_path)
    }

    fn control(&self, body: &[u8]) -> (u16, Vec<u8>) {
        let command: GateCommand = match serde_json::from_slice(body) {
            Ok(c) => c,
            Err(e) => return (400, error_json(&format!("invalid command: {e}"))),
        };
        // Every mutating action first re-validates the applied proxy.
        let config = match config::load(&self.config_path) {
            Ok(c) => c,
            Err(_) => {
                self.inner
                    .lock()
                    .expect("gate lock")
                    .close("配置读取失败，外网保持关闭");
                return (409, error_json("配置读取失败，外网保持关闭"));
            }
        };
        if let Err(e) = creance_proxy::applied(
            Path::new(&self.config_path)
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
                .as_str(),
            &config.proxy_url,
            &config.proxy_revision,
        ) {
            self.inner
                .lock()
                .expect("gate lock")
                .close(&format!("代理节点未应用：{e}"));
            return (409, error_json(&format!("代理节点未应用：{e}")));
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.status(&self.run_id); // keep the counts shape warm
        match command.action.as_str() {
            "check" => {
                inner.state = GateState::Checking;
                inner.reason.clear();
                inner.opened_at = Some(Instant::now());
                inner.lease = CHECK_LEASE;
                let _ = &command;
                (
                    200,
                    serde_json::to_vec(&inner.status(&self.run_id)).expect("status"),
                )
            }
            "fault" => {
                // Fault injection only stands during checking; it closes the gate.
                inner.close("注入故障演练，外网保持关闭");
                (
                    200,
                    serde_json::to_vec(&inner.status(&self.run_id)).expect("status"),
                )
            }
            "grant" => match command.report {
                Some(report) if report.authorizes() => {
                    inner.state = GateState::Open;
                    inner.reason.clear();
                    inner.opened_at = Some(Instant::now());
                    inner.lease = OPEN_LEASE;
                    inner.report = Some(report);
                    (
                        200,
                        serde_json::to_vec(&inner.status(&self.run_id)).expect("status"),
                    )
                }
                _ => (409, error_json("安全报告缺失必需的通过项，外网保持关闭")),
            },
            "renew" => {
                let matches_report = inner
                    .report
                    .as_ref()
                    .map(|r| r.report_id == command.report_id)
                    .unwrap_or(false);
                if inner.state == GateState::Open && matches_report {
                    inner.opened_at = Some(Instant::now());
                    (
                        200,
                        serde_json::to_vec(&inner.status(&self.run_id)).expect("status"),
                    )
                } else {
                    inner.close("续期与当前检测不匹配，外网保持关闭");
                    (409, error_json("续期与当前检测不匹配"))
                }
            }
            "close" => {
                inner.close(if command.reason.is_empty() {
                    "收到关闭指令，外网保持关闭"
                } else {
                    &command.reason
                });
                (
                    200,
                    serde_json::to_vec(&inner.status(&self.run_id)).expect("status"),
                )
            }
            "proxy-revision" => match self.sync_proxy_revision_with(&mut inner) {
                Ok(()) => {
                    inner.close("代理节点已变更，等待重新检查");
                    (
                        200,
                        serde_json::to_vec(&inner.status(&self.run_id)).expect("status"),
                    )
                }
                Err(message) => {
                    inner.close(&message);
                    (409, error_json(&message))
                }
            },
            _ => (400, error_json("unknown action")),
        }
    }

    /// Adopts a changed exit, comparing the freshly loaded config against
    /// the snapshot this gate started with. A pure revision change — or a
    /// first-time completion of the exit-policy binding under the same mode
    /// and scope — is accepted and recorded; anything else requires a
    /// restart. No change is an idempotent success.
    fn sync_proxy_revision_with(&self, inner: &mut GateInner) -> Result<(), String> {
        let new_config = config::load(&self.config_path)?;
        let old_config = inner
            .recorded
            .clone()
            .ok_or("出口地址或环境设置变化需要重启环境")?;
        let revision_changed = new_config.proxy_revision != old_config.proxy_revision
            || new_config.proxy_url != old_config.proxy_url;
        let binding_completed = old_config.exit_policy.needs_binding()
            && new_config.exit_policy.normalized().mode == old_config.exit_policy.normalized().mode
            && new_config.exit_policy.normalized().scope
                == old_config.exit_policy.normalized().scope
            && !new_config.exit_policy.needs_binding();
        if !revision_changed && !binding_completed {
            // Nothing to adopt: the gate keeps its state.
            if strip_config(&old_config) == strip_config(&new_config) {
                return Ok(());
            }
            return Err("出口地址或环境设置变化需要重启环境".to_owned());
        }
        if strip_config(&old_config) != strip_config(&new_config) {
            return Err("出口地址或环境设置变化需要重启环境".to_owned());
        }
        if new_config.proxy_revision.is_empty() {
            return Err("出口地址或环境设置变化需要重启环境".to_owned());
        }
        inner.recorded = Some(new_config.clone());
        Ok(())
    }
}

/// The fields a revision change may move: the exit endpoint/revision and the
/// exit-policy binding. Everything else must match for a sync to be adopted.
fn strip_config(c: &Config) -> Config {
    let mut c = c.clone();
    c.exit_policy = Default::default();
    c.proxy_url = String::new();
    c.proxy_revision = String::new();
    c
}

fn error_json(message: &str) -> Vec<u8> {
    serde_json::json!({ "error": message })
        .to_string()
        .into_bytes()
}

/// A host-side client for one gate record: the calls `cage proxy-stop` and
/// the workbench make against every running instance's gate.
pub struct GateClient {
    pub record: GateRecord,
}

impl GateClient {
    /// Loads the newest record in `instance_dir`, if any.
    pub fn open(instance_dir: &str) -> Result<GateClient, String> {
        let path = Path::new(instance_dir).join("cage-gate.json");
        creance_vm::private::check_private_file(path.to_string_lossy().as_ref())
            .map_err(|e| e.to_string())?;
        if std::fs::metadata(&path)
            .map(|m| m.len() > 4096)
            .unwrap_or(true)
        {
            return Err("gate record too large".to_owned());
        }
        let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
        let record: GateRecord = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        Ok(GateClient { record })
    }

    fn call(&self, method: &str, path: &str, body: Option<&str>) -> Result<GateStatus, String> {
        use std::os::unix::net::UnixStream;
        let mut stream = UnixStream::connect(&self.record.socket)
            .map_err(|_| "gate control socket unreachable".to_owned())?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: cage\r\nAuthorization: Bearer {}\r\nConnection: close\r\n",
            self.record.token
        );
        if let Some(body) = body {
            request.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
        } else {
            request.push_str("\r\n");
        }
        stream
            .write_all(request.as_bytes())
            .map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).map_err(|e| e.to_string())?;
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("invalid gate response")?;
        let head = String::from_utf8_lossy(&raw[..split]).into_owned();
        let status: u16 = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .ok_or("invalid gate response")?;
        if !(200..300).contains(&status) {
            return Err(format!("gate returned HTTP {status}"));
        }
        serde_json::from_slice(&raw[split + 4..]).map_err(|e| e.to_string())
    }

    pub fn status(&self) -> Result<GateStatus, String> {
        self.call("GET", "/status", None)
    }

    pub fn begin_check(&self) -> Result<GateStatus, String> {
        self.call("POST", "/control", Some(r#"{"action":"check"}"#))
    }

    pub fn close(&self, reason: &str) -> Result<GateStatus, String> {
        let body = serde_json::json!({ "action": "close", "reason": reason });
        self.call("POST", "/control", Some(&body.to_string()))
    }

    pub fn sync_proxy_revision(&self) -> Result<GateStatus, String> {
        self.call("POST", "/control", Some(r#"{"action":"proxy-revision"}"#))
    }
}

/// Closes every gate recorded under `state_dir`'s Lima instances — the
/// `cage proxy-stop` companion so VMs drop their networking the moment the
/// core goes away.
pub fn close_gates(profile: &str) -> Result<(), String> {
    let lima = creance_vm::vm::lima_home(profile);
    let mut last = None;
    if let Ok(entries) = std::fs::read_dir(&lima) {
        for entry in entries.flatten() {
            let instance_dir = entry.path().to_string_lossy().into_owned();
            if Path::new(&instance_dir).join("cage-gate.json").exists() {
                if let Ok(client) = GateClient::open(&instance_dir) {
                    if let Err(e) = client.close("代理核心停止或重启，等待重新检测")
                    {
                        last = Some(e);
                    }
                }
            }
        }
    }
    last.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn prepare_profile() -> (String, String) {
        let profile = std::env::temp_dir()
            .join(format!(
                "cage-gate-{}",
                creance_proxy::token()[..12].to_owned()
            ))
            .to_string_lossy()
            .into_owned();
        let config_path = creance_vm::paths::join(&profile, "config.json");
        fs::create_dir_all(&profile).unwrap();
        fs::create_dir_all(creance_vm::paths::join(&profile, "proxy")).unwrap();
        let mut store = creance_proxy::load(&profile).unwrap();
        store.sources.push(creance_proxy::Source {
            id: "src".to_owned(),
            name: "s".to_owned(),
            url: String::new(),
            interval_hours: 0,
            updated_at: String::new(),
            attempted_at: String::new(),
            error: String::new(),
            usage: String::new(),
            nodes: vec![creance_proxy::Node {
                id: "node-1".to_owned(),
                name: "exit".to_owned(),
                node_type: "ss".to_owned(),
                config: {
                    let mut m = serde_json::Map::new();
                    m.insert("server".to_owned(), serde_json::json!("192.0.2.1"));
                    m.insert("port".to_owned(), serde_json::json!(8388));
                    m.insert("cipher".to_owned(), serde_json::json!("aes-128-gcm"));
                    m.insert("password".to_owned(), serde_json::json!("x"));
                    m
                },
            }],
            skipped: Vec::new(),
        });
        store.selected = "node-1".to_owned();
        store.revision = creance_proxy::token();
        creance_proxy::save(&profile, &store).unwrap();
        let mut config = config::default_config();
        config.proxy_url = store.endpoint();
        config.proxy_revision = store.revision.clone();
        config::write_private_config(&config_path, &config).unwrap();
        (profile, config_path)
    }

    #[test]
    fn gate_lifecycle_over_the_private_socket() {
        let (profile, config_path) = prepare_profile();
        let instance_dir = creance_vm::paths::join(&profile, "lima/test-vm");
        fs::create_dir_all(&instance_dir).unwrap();
        let handle = Gate::start(&instance_dir, &config_path).unwrap();
        let record = handle.record.clone();
        let client = GateClient::open(&instance_dir).unwrap();

        // Starts closed with the safety contract attached.
        let status = client.status().unwrap();
        assert_eq!(status.state, GateState::Closed);
        assert_eq!(status.policy, POLICY);
        assert_eq!(status.run_id, record.run_id);

        // Checking opens the check window.
        let status = client.begin_check().unwrap();
        assert_eq!(status.state, GateState::Checking);

        // Grant without the required checks is refused and closes.
        let bad = serde_json::json!({"action": "grant", "report_id": "r1"});
        let raw = call_raw(&record, &bad.to_string()).unwrap();
        assert!(raw.0.starts_with("409"), "{raw:?}");

        // With every required check passed, the gate opens.
        let mut checks = std::collections::BTreeMap::new();
        for c in SafetyReport::REQUIRED {
            checks.insert((*c).to_owned(), "passed".to_owned());
        }
        let good = serde_json::json!({
            "action": "grant",
            "report_id": "r2",
            "report": {"report_id": "r2", "checks": checks},
        });
        let raw = call_raw(&record, &good.to_string()).unwrap();
        assert!(raw.0.starts_with("200"), "{raw:?}");
        assert!(serde_json::to_string(&raw.1).unwrap().contains("open"));

        // Close is honored with its reason.
        let status = client.close("测试关闭").unwrap();
        assert_eq!(status.state, GateState::Closed);
        assert_eq!(status.reason, "测试关闭");
        fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn gate_rejects_missing_auth_and_bad_hosts() {
        let (profile, config_path) = prepare_profile();
        let instance_dir = creance_vm::paths::join(&profile, "lima/test-vm");
        fs::create_dir_all(&instance_dir).unwrap();
        let handle = Gate::start(&instance_dir, &config_path).unwrap();
        let record = handle.record.clone();
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        let _raw_full = |request: &str| -> String {
            let mut stream = UnixStream::connect(&record.socket).unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            let mut raw = Vec::new();
            stream.read_to_end(&mut raw).unwrap();
            String::from_utf8_lossy(&raw)
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned()
        };
        let raw_no_auth = |request: &str| -> String {
            let mut stream = UnixStream::connect(&record.socket).unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            let mut raw = Vec::new();
            stream.read_to_end(&mut raw).unwrap();
            String::from_utf8_lossy(&raw)
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned()
        };
        assert!(
            raw_no_auth("POST /control HTTP/1.1\r\nHost: cage\r\nContent-Length: 2\r\n\r\n{}")
                .starts_with("403")
        );
        assert!(raw_no_auth(&format!("POST /control HTTP/1.1\r\nHost: evil\r\nAuthorization: Bearer {}\r\nContent-Length: 2\r\n\r\n{{}}", record.token)).starts_with("403"));
        // Valid command with the right token goes through.
        let body = r#"{"action":"check"}"#;
        let got = raw_no_auth(&format!(
            "POST /control HTTP/1.1\r\nHost: cage\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n{}",
            record.token,
            body.len(),
            body
        ));
        assert!(got.starts_with("200"));
        fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn sync_proxy_revision_accepts_revision_change_only() {
        let (profile, config_path) = prepare_profile();
        let instance_dir = creance_vm::paths::join(&profile, "lima/test-vm");
        fs::create_dir_all(&instance_dir).unwrap();
        let handle = Gate::start(&instance_dir, &config_path).unwrap();
        let _record = handle.record.clone();
        let client = GateClient::open(&instance_dir).unwrap();

        // Rotate the store revision and re-apply into config.json the way
        // `cage proxy-select` does; sync then adopts it and closes.
        let mut store = creance_proxy::load(&profile).unwrap();
        store.revision = creance_proxy::token();
        creance_proxy::save(&profile, &store).unwrap();
        let mut new_config = config::load(&config_path).unwrap();
        new_config.proxy_url = store.endpoint();
        new_config.proxy_revision = store.revision.clone();
        config::write_private_config(&config_path, &new_config).unwrap();
        match client.sync_proxy_revision() {
            Ok(status) => {
                assert_eq!(status.state, GateState::Closed);
                assert_eq!(
                    config::load(&config_path).unwrap().proxy_revision,
                    new_config.proxy_revision
                );
            }
            Err(e) => panic!("SYNC-DEBUG err: {e}"),
        }
        let _ = store;
        fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn sync_proxy_revision_rejects_other_changes() {
        let (profile, config_path) = prepare_profile();
        let instance_dir = creance_vm::paths::join(&profile, "lima/test-vm");
        fs::create_dir_all(&instance_dir).unwrap();
        let handle = Gate::start(&instance_dir, &config_path).unwrap();
        let _record = handle.record.clone();
        let client = GateClient::open(&instance_dir).unwrap();

        // A timezone change is not a revision change: refused.
        let mut changed = config::load(&config_path).unwrap();
        changed.timezone = "Asia/Tokyo".to_owned();
        config::write_private_config(&config_path, &changed).unwrap();
        let err = client.sync_proxy_revision().unwrap_err();
        assert!(
            err.contains("需要重启环境") || err.contains("HTTP 409"),
            "{err}"
        );
        fs::remove_dir_all(&profile).unwrap();
    }

    fn call_raw(record: &GateRecord, body: &str) -> Result<(String, serde_json::Value), String> {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        let mut stream = UnixStream::connect(&record.socket).map_err(|e| e.to_string())?;
        let request = format!(
            "POST /control HTTP/1.1\r\nHost: cage\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            record.token,
            body.len(),
            body
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).map_err(|e| e.to_string())?;
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("bad response")?;
        let status = String::from_utf8_lossy(&raw[..split])
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        let value: serde_json::Value =
            serde_json::from_slice(&raw[split + 4..]).map_err(|e| e.to_string())?;
        Ok((status, value))
    }
}
