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
use std::path::Path;
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
    /// Identifies the open check window; a grant must carry it back.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub check_id: String,
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
    /// Binding dimensions (F-036, first slice of the Go contract): the
    /// gate's run the report was produced for, and when. A report minted
    /// for another gate (or another lifetime of this one) must not open
    /// this gate; stale reports die with the check window. The Go
    /// contract's configuration-fingerprint binding lands with the 0.6
    /// authorization-set alignment.
    #[serde(default)]
    pub run_id: String,
    /// Unix epoch seconds; 0 = absent (refused by the grant check).
    #[serde(default)]
    pub created_at: u64,
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
    check_id: String,
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
            check_id: self.check_id.clone(),
            counts: self.counts.clone(),
        }
    }

    fn close(&mut self, reason: &str) {
        self.state = GateState::Closed;
        self.reason = truncate_utf8(reason, 200).to_owned();
        self.epoch += 1;
        self.opened_at = None;
        self.report = None;
        self.check_id.clear();
        *self.counts.entry("closed".to_owned()).or_default() += 1;
    }
}

/// The longest prefix of `s` that is at most `max` BYTES and ends on a
/// char boundary. FINDING-008: the previous implementation measured in
/// chars, so multi-byte text barely truncated at all.
/// Length-safe constant-time equality for secret comparisons (FINDING-008;
/// Go uses subtle.ConstantTimeCompare).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = 0;
    for (i, ch) in s.char_indices() {
        if i + ch.len_utf8() > max {
            break;
        }
        end = i + ch.len_utf8();
    }
    &s[..end]
}

/// The gate's shared core, served on its private socket.
pub struct Gate {
    profile_dir: String,
    instance: String,
    proxy_port: u16,
    run_id: String,
    /// The control-plane bearer, read into memory at start (F-037: the
    /// per-request re-read of the record file degraded to an empty token
    /// whenever the file was unreadable — chmod 000, or the removal window
    /// during close — and `constant_time_eq("", "")` let a credential-less
    /// process drive check→grant→open). Holding our own token also means a
    /// renamed-over loser never accepts the winner's.
    token: String,
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
    /// Cleared by `disown`: a handle renamed over by a successor must not
    /// delete the successor's record on drop (F-028's last twist — the
    /// loser's parting shot used to erase the winner, cascading into a
    /// full gate collapse).
    owns_record: AtomicBool,
}

impl GateHandle {
    /// Declares the published record no longer ours (a successor renamed
    /// over it): drop will still stop this gate's server and socket, but
    /// leaves the winner's record — and with it the wire — untouched.
    pub fn disown(&self) {
        self.owns_record.store(false, Ordering::Relaxed);
    }
}

impl Drop for GateHandle {
    fn drop(&mut self) {
        self.gate.shutdown();
        if self.owns_record.load(Ordering::Relaxed) {
            let record = Path::new(&self.instance_dir).join("cage-gate.json");
            let _ = std::fs::remove_file(record);
        }
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
    pub fn start(
        instance_dir: &str,
        config_path: &str,
        profile_dir: &str,
        instance: &str,
        proxy_port: u16,
    ) -> Result<GateHandle, String> {
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
            token: token.clone(),
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
            profile_dir: profile_dir.to_owned(),
            instance: instance.to_owned(),
            proxy_port,
            run_id,
            token,
            inner: Mutex::new(GateInner {
                state: GateState::Closed,
                reason: String::new(),
                epoch: 0,
                opened_at: None,
                lease: CHECK_LEASE,
                report: None,
                check_id: String::new(),
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
            // 0.4: the VM's wire follows the gate. Closed gate → the ssh -R
            // tunnel must be down; Open/Checking → it must be up. Healing is
            // one-way (we cut, we do not silently re-raise). Reaping backs
            // the stop with a signature sweep so the cut holds even when the
            // pid file was lost (F-026). Only the canonical daemon moves the
            // wire (F-028): a renamed-over loser must neither cut nor raise
            // what the winner owns — its main loop retires it within a tick.
            let closed = inner.state == GateState::Closed;
            drop(inner);
            if !watchdog.still_owner() {
                continue;
            }
            if closed {
                let _ = creance_vm::tunnel::stop(&watchdog.profile_dir);
                creance_vm::tunnel::reap_orphans(
                    &watchdog.profile_dir,
                    &watchdog.instance,
                    watchdog.proxy_port,
                );
            } else {
                let _ = creance_vm::tunnel::ensure(
                    &watchdog.profile_dir,
                    &watchdog.instance,
                    watchdog.proxy_port,
                );
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
            owns_record: AtomicBool::new(true),
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

    /// Whether the published record still names THIS gate (F-028). A daemon
    /// renamed over by a successor must not touch the wire; when in doubt
    /// (unreadable record), it also holds back — the main loop decides.
    fn still_owner(&self) -> bool {
        std::fs::read(&self.record_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<GateRecord>(&bytes).ok())
            .is_some_and(|record| record.run_id == self.run_id)
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
        if host != "cage"
            || origin_present
            || !constant_time_eq(bearer.as_bytes(), self.token.as_bytes())
        {
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

    fn control(&self, body: &[u8]) -> (u16, Vec<u8>) {
        let mut command: GateCommand = match serde_json::from_slice(body) {
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
                // FINDING-008: the check window gets an id; a grant must
                // carry it back, tying the report to this window (Go's
                // CheckID binding).
                inner.check_id = creance_vm::token()[..16].to_owned();
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
            "grant" => {
                // FINDING-008: Go only grants from the Checking state with
                // the report bound to the open check window. F-036 adds
                // the run binding: the report must name THIS gate's run
                // and be minted inside the check window, and the inner
                // report id must match the outer one (they used to be
                // checked asymmetrically).
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let window = CHECK_LEASE.as_secs();
                let bound = |report: &SafetyReport| {
                    report.run_id == self.run_id
                        && report.created_at <= now
                        && now - report.created_at <= window
                };
                if inner.state != GateState::Checking {
                    (409, error_json("仅在检测进行中可以授权开放，外网保持关闭"))
                } else if command.report_id != inner.check_id || inner.check_id.is_empty() {
                    inner.close("授权与当前检测窗口不匹配，外网保持关闭");
                    (409, error_json("授权与当前检测窗口不匹配，外网保持关闭"))
                } else {
                    match command.report.take() {
                        Some(report)
                            if report.authorizes()
                                && report.report_id == command.report_id
                                && bound(&report) =>
                        {
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
                    }
                }
            }
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
                // F-036: only an ADOPTED change (or a rejected sync) closes
                // the gate — an idempotent no-change sync keeps the state,
                // so a routine `proxy-start` on an unchanged config no
                // longer force-retires an open gate.
                Ok(SyncOutcome::Adopted) => {
                    inner.close("代理节点已变更，等待重新检查");
                    (
                        200,
                        serde_json::to_vec(&inner.status(&self.run_id)).expect("status"),
                    )
                }
                Ok(SyncOutcome::Unchanged) => (
                    200,
                    serde_json::to_vec(&inner.status(&self.run_id)).expect("status"),
                ),
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
    fn sync_proxy_revision_with(&self, inner: &mut GateInner) -> Result<SyncOutcome, String> {
        let new_config = config::load(&self.config_path)?;
        let old_config = inner
            .recorded
            .clone()
            .ok_or("出口地址或环境设置变化需要重启环境".to_owned())?;
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
                return Ok(SyncOutcome::Unchanged);
            }
            return Err("出口地址或环境设置变化需要重启环境".to_owned());
        }
        if strip_config(&old_config) != strip_config(&new_config) {
            return Err("出口地址或环境设置变化需要重启环境".to_owned());
        }
        // FINDING-008: the exit policy may only be *completed*, never
        // modified — Go's SyncProxyRevision allows each field to change
        // only from unbound to a value. Any other change demands a restart.
        if !exit_policy_only_completed(&old_config.exit_policy, &new_config.exit_policy) {
            return Err("出口地址或环境设置变化需要重启环境".to_owned());
        }
        if new_config.proxy_revision.is_empty() {
            return Err("出口地址或环境设置变化需要重启环境".to_owned());
        }
        inner.recorded = Some(new_config.clone());
        // Go refreshes the environment's running record so its fingerprint
        // matches the adopted configuration.
        let instance_dir = Path::new(&self.record_path)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let _ = creance_vm::running::record_running(&instance_dir, &new_config);
        Ok(SyncOutcome::Adopted)
    }
}

/// What a proxy-revision sync decided (F-036): an adopted change closes
/// the gate for re-checking; an idempotent no-change keeps the state.
enum SyncOutcome {
    Adopted,
    Unchanged,
}

/// True when `new` only fills fields `old` left empty (same mode/scope);
/// any bound value that changed means the anchor moved — a restart.
fn exit_policy_only_completed(
    old: &crate::exit_policy::Policy,
    new: &crate::exit_policy::Policy,
) -> bool {
    let old = old.normalized();
    let new = new.normalized();
    if old.mode != new.mode || old.scope != new.scope {
        return false;
    }
    let completed = |o: &str, n: &str| o.is_empty() || o == n;
    completed(&old.ip, &new.ip)
        && completed(&old.country_code, &new.country_code)
        && completed(&old.region, &new.region)
        && completed(&old.city, &new.city)
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

/// Spawns the gate daemon detached from the calling CLI process: it holds
/// the GateHandle (socket, watchdog, tunnel coupling) for the environment's
/// lifetime. Fails cleanly when a daemon is already alive for this profile.
pub fn spawn_daemon(
    profile_dir: &str,
    instance: &str,
    config_path: &str,
    instance_dir: &str,
    proxy_port: u16,
) -> Result<(), String> {
    let pid_file = creance_vm::pidfile::proxy_pid_file(profile_dir, "gate.pid");
    // A record proves a daemon only while that daemon still serves its
    // socket (F-019: after SIGKILL or a reboot the record outlives the
    // process, and dedup-on-existence silently disabled every later `up`
    // while an orphan tunnel kept the wire open).
    if retire_stale_record(instance_dir) {
        // Stale: retire the leftovers — pid file and any orphan ssh -R the
        // dead watchdog can no longer cut — and raise a fresh daemon below.
        let _ = std::fs::remove_file(&pid_file);
        let _ = creance_vm::tunnel::stop(profile_dir);
        creance_vm::tunnel::reap_orphans(profile_dir, instance, proxy_port);
    } else if Path::new(&creance_vm::paths::join(instance_dir, "cage-gate.json")).exists() {
        // A record that survived the retire check has a serving daemon.
        return Ok(());
    } else if creance_vm::pidfile::alive(&pid_file) {
        // F-035: a live pid with no record means the daemon is either just
        // starting (its record is a rename away) or already dying (its
        // record was removed, the exit tick is pending). Deduping here
        // reported success while the end state had no daemon and no
        // record. Waiting one tick separates them: the fresh one publishes
        // its record, the dying one exits and its pid file dies with it.
        for _ in 0..3 {
            std::thread::sleep(Duration::from_millis(400));
            if Path::new(&creance_vm::paths::join(instance_dir, "cage-gate.json")).exists()
                && daemon_serving(instance_dir)
            {
                return Ok(());
            }
        }
        // Fall through to a fresh spawn; if the old daemon is somehow still
        // retiring, the run_id ownership handoff (F-028) sorts the overlap.
    }
    let exe = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .to_string_lossy()
        .into_owned();
    use std::process::{Command, Stdio};
    // F-025: a virgin profile has no proxy/ directory yet — create it
    // before touching the log or the pid file, or a healthy spawn reads
    // back as ENOENT failure.
    creance_vm::private::ensure_private_dir(&creance_vm::proxy_dir(profile_dir))
        .map_err(|e| e.to_string())?;
    let log = creance_vm::paths::join(&creance_vm::proxy_dir(profile_dir), "gate-daemon.log");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .ok();
    let child = Command::new(exe)
        .arg("gate-daemon")
        .arg(profile_dir)
        .arg(instance)
        .arg(config_path)
        .arg(instance_dir)
        .arg(proxy_port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(match &log {
            Some(f) => Stdio::from(f.try_clone().map_err(|e| e.to_string())?),
            None => Stdio::null(),
        })
        .spawn()
        .map_err(|e| format!("cannot spawn gate daemon: {e}"))?;
    creance_vm::pidfile::write(&pid_file, child.id() as i32)?;
    Ok(())
}

/// Whether the daemon a record names is still serving its socket, on
/// connect-level evidence only (F-029): a frozen, loaded, or slow daemon
/// still accepts connections and must never be retired — a status call
/// timing out says "slow", not "dead", and acting on it mutinied healthy
/// daemons (record deleted, live tunnel cut, replacement spawned). Only a
/// refused or vanished socket proves death; anything inconclusive counts
/// as alive.
fn daemon_serving(instance_dir: &str) -> bool {
    let record = creance_vm::paths::join(instance_dir, "cage-gate.json");
    let Ok(bytes) = std::fs::read(&record) else {
        return false; // no record: nothing serving
    };
    let socket = serde_json::from_slice::<GateRecord>(&bytes)
        .ok()
        .map(|r| r.socket)
        .unwrap_or_default();
    if socket.is_empty() {
        return false;
    }
    let Ok(addr) = std::os::unix::net::SocketAddr::from_pathname(&socket) else {
        return false;
    };
    // Local unix connects complete or refuse immediately (R4's filler kept
    // 200 connections queued against a healthy daemon and every connect
    // still returned), so connect_addr is the whole probe.
    match std::os::unix::net::UnixStream::connect_addr(&addr) {
        Ok(_) => true,
        // The socket file outlived its listener: refused or gone.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) =>
        {
            false
        }
        // Anything else inconclusive: do not mutiny.
        Err(_) => true,
    }
}

/// Removes a record whose daemon no longer serves it (F-019: SIGKILL and
/// reboots leave records behind; existence alone must never pass for a
/// working gate; F-029: only connect-level death counts). True when a
/// stale record was retired.
fn retire_stale_record(instance_dir: &str) -> bool {
    let record = creance_vm::paths::join(instance_dir, "cage-gate.json");
    if !Path::new(&record).exists() {
        return false;
    }
    if daemon_serving(instance_dir) {
        return false;
    }
    let _ = std::fs::remove_file(&record);
    true
}

/// The `creance gate-daemon` body: hold the gate until its record vanishes
/// (host-side close/removal — `close_and_remove` and `close_gates` both
/// remove it, which retires the daemon) or the process is signaled.
///
/// F-028: the loop also binds to the record's *identity*. Two daemons can
/// coexist for a moment (a spawn race, a concurrent `up`, or a direct
/// `gate-daemon` invocation); the record's rename is atomic, so the last
/// writer wins and every loser must notice that the record's run_id is no
/// longer theirs — and leave WITHOUT touching the wire, which the winner
/// now owns. Before this, a loser lived forever on "a record exists" while
/// its Closed-state watchdog murdered the winner's tunnel every 500ms:
/// gate=closed with an intermittently live wire, forever.
pub fn run_daemon(
    profile_dir: &str,
    instance: &str,
    config_path: &str,
    instance_dir: &str,
    proxy_port: u16,
) -> i32 {
    let handle = match Gate::start(instance_dir, config_path, profile_dir, instance, proxy_port) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("gate daemon: {e}");
            return 1;
        }
    };
    let mine = handle.record.run_id.clone();
    let record = creance_vm::paths::join(instance_dir, "cage-gate.json");
    let mut replaced = false;
    loop {
        std::thread::sleep(Duration::from_millis(500));
        match std::fs::read(&record) {
            Ok(bytes) => {
                match serde_json::from_slice::<GateRecord>(&bytes) {
                    Ok(canonical) if canonical.run_id == mine => {}
                    // Someone else's record: we were renamed over. Retire
                    // quietly — no tunnel stop, no reap; the wire belongs
                    // to the canonical daemon now.
                    Ok(_) => {
                        replaced = true;
                        break;
                    }
                    // Unreadable for now: do not act on one bad read (a
                    // concurrent rename can be observed mid-flight).
                    Err(_) => continue,
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break, // retired
            Err(_) => continue, // transient — retry next tick
        }
    }
    handle.gate.shutdown();
    if replaced {
        // Leave the winner's record (and wire) standing: dropping a
        // disowned handle stops only this gate's own server and socket.
        handle.disown();
    }
    drop(handle);
    if replaced {
        return 0;
    }
    let _ = creance_vm::tunnel::stop(profile_dir);
    creance_vm::tunnel::reap_orphans(profile_dir, instance, proxy_port);
    0
}

/// Convenience: opens the gate (check window + grant) over the record.
/// The caller supplies the checks — structural self-checks plus the
/// exit-consistency verdict from live evidence (see creance's evidence
/// module). The daemon still enforces its REQUIRED set on arrival; a
/// grant missing any critical check is refused there.
pub fn open(
    instance_dir: &str,
    checks: &std::collections::BTreeMap<String, String>,
) -> Result<GateStatus, String> {
    let client = GateClient::open(instance_dir)?;
    client.begin_check()?;
    let status = client.status()?;
    // F-036: the binding fields are minted here — bound to the record's
    // run and the current instant — so callers cannot omit them and a
    // report from another gate's lifetime never opens this one.
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let body = serde_json::json!({
        "action": "grant",
        "report_id": status.check_id,
        "report": {
            "report_id": status.check_id,
            "run_id": client.record.run_id,
            "created_at": created_at,
            "checks": checks,
        },
    });
    client.raw_control(&body.to_string())
}

/// Convenience: closes the gate and removes its record (the daemon then
/// retires on its own), and cuts the tunnel right away — the closed wire
/// must not depend on a daemon that may already be gone (F-019), nor on
/// the pid file's survival (F-026's signature reaping).
pub fn close_and_remove(profile: &str, instance_dir: &str, port: u16) -> Result<(), String> {
    if let Ok(client) = GateClient::open(instance_dir) {
        let _ = client.close("宿主请求关闭");
    }
    let _ = std::fs::remove_file(creance_vm::paths::join(instance_dir, "cage-gate.json"));
    let _ = creance_vm::tunnel::stop(profile);
    let instance = Path::new(instance_dir)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    creance_vm::tunnel::reap_orphans(profile, &instance, port);
    Ok(())
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

    fn raw_control(&self, body: &str) -> Result<GateStatus, String> {
        self.call("POST", "/control", Some(body))
    }
}

/// Closes every gate recorded under the profile's Lima instances — the
/// `creance proxy-stop` companion so VMs drop their networking the moment
/// the core goes away. A record whose socket no longer answers is stale
/// (F-019): its daemon is gone, so the record goes too — nothing else
/// would clean it, and a live-looking corpse would mask a missing gate.
pub fn close_gates(profile: &str) -> Result<(), String> {
    let lima = creance_vm::vm::lima_home(profile);
    let mut last = None;
    if let Ok(entries) = std::fs::read_dir(&lima) {
        for entry in entries.flatten() {
            let instance_dir = entry.path().to_string_lossy().into_owned();
            let record = Path::new(&instance_dir).join("cage-gate.json");
            if record.exists() {
                // F-029: the same connect-level evidence everywhere — a
                // dead daemon's record is cleaned here, a serving (or
                // merely slow) one gets its close command and errors count.
                if daemon_serving(&instance_dir) {
                    if let Err(e) = GateClient::open(&instance_dir)
                        .and_then(|c| c.close("代理核心停止或重启，等待重新检测").map(|_| ()))
                    {
                        last = Some(e);
                    }
                } else {
                    let _ = std::fs::remove_file(&record);
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
        let handle = Gate::start(
            &instance_dir,
            &config_path,
            &profile,
            "gate-test-inst",
            17896,
        )
        .unwrap();
        let record = handle.record.clone();
        let client = GateClient::open(&instance_dir).unwrap();

        // Starts closed with the safety contract attached.
        let status = client.status().unwrap();
        assert_eq!(status.state, GateState::Closed);
        assert_eq!(status.policy, POLICY);
        assert_eq!(status.run_id, record.run_id);

        // Checking opens the check window and issues its id.
        let status = client.begin_check().unwrap();
        assert_eq!(status.state, GateState::Checking);
        let check_id = status.check_id.clone();
        assert!(!check_id.is_empty());

        // A grant bound to this window but missing required checks: refused
        // WITHOUT closing (the report can be completed and resubmitted).
        let bad = serde_json::json!({
            "action": "grant",
            "report_id": check_id,
            "report": {"report_id": check_id, "checks": {}},
        });
        let raw = call_raw(&record, &bad.to_string()).unwrap();
        assert!(raw.0.starts_with("409"), "{raw:?}");
        assert_eq!(client.status().unwrap().state, GateState::Checking);

        // With every required check passed, the window id carried, and the
        // F-036 run/time binding present, open.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut checks = std::collections::BTreeMap::new();
        for c in SafetyReport::REQUIRED {
            checks.insert((*c).to_owned(), "passed".to_owned());
        }
        let good = serde_json::json!({
            "action": "grant",
            "report_id": check_id,
            "report": {"report_id": check_id, "run_id": record.run_id, "created_at": now, "checks": checks},
        });
        let raw = call_raw(&record, &good.to_string()).unwrap();
        assert!(raw.0.starts_with("200"), "{raw:?}");
        assert!(serde_json::to_string(&raw.1).unwrap().contains("open"));

        // F-036 regressions: binding failures refuse without opening.
        client.begin_check().unwrap();
        let check_id2 = client.status().unwrap().check_id;
        let wrong_run = serde_json::json!({
            "action": "grant",
            "report_id": check_id2,
            "report": {"report_id": check_id2, "run_id": "some-other-gate", "created_at": now, "checks": checks},
        });
        let raw = call_raw(&record, &wrong_run.to_string()).unwrap();
        assert!(
            raw.0.starts_with("409"),
            "a report for another run must not open: {raw:?}"
        );
        let stale_report = serde_json::json!({
            "action": "grant",
            "report_id": check_id2,
            "report": {"report_id": check_id2, "run_id": record.run_id, "created_at": now - 3600, "checks": checks},
        });
        let raw = call_raw(&record, &stale_report.to_string()).unwrap();
        assert!(
            raw.0.starts_with("409"),
            "a stale report must not open: {raw:?}"
        );
        client.close("F-036 回归收尾").unwrap();

        // Close is honored with its reason.
        let status = client.close("测试关闭").unwrap();
        assert_eq!(status.state, GateState::Closed);
        assert_eq!(status.reason, "测试关闭");

        // FINDING-008 regressions ------------------------------------
        // A grant while Closed is refused outright (Go: Checking-only).
        let mut checks = std::collections::BTreeMap::new();
        for c in SafetyReport::REQUIRED {
            checks.insert((*c).to_owned(), "passed".to_owned());
        }
        let closed_grant = serde_json::json!({
            "action": "grant",
            "report_id": "whatever",
            "report": {"report_id": "whatever", "checks": checks.clone()},
        });
        let raw = call_raw(&record, &closed_grant.to_string()).unwrap();
        assert!(raw.0.starts_with("409"), "{raw:?}");

        // A grant with a stale window id closes the gate (mis-bound report).
        client.begin_check().unwrap();
        let stale = serde_json::json!({
            "action": "grant",
            "report_id": "stale-id",
            "report": {"report_id": "stale-id", "checks": checks},
        });
        let raw = call_raw(&record, &stale.to_string()).unwrap();
        assert!(raw.0.starts_with("409"), "{raw:?}");
        assert_eq!(client.status().unwrap().state, GateState::Closed);
        fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn stale_records_retire_but_served_ones_stay() {
        // F-019 regression: a record whose socket no longer answers must be
        // removed, never treated as a working gate; a served record survives.
        let (profile, config_path) = prepare_profile();
        let instance_dir = creance_vm::paths::join(&profile, "lima/test-vm");
        fs::create_dir_all(&instance_dir).unwrap();

        // Stale: a valid, private record pointing at a socket nobody serves.
        let record_path = creance_vm::paths::join(&instance_dir, "cage-gate.json");
        let stale = serde_json::json!({
            "socket": creance_vm::paths::join(&profile, "no-such-sock.sock"),
            "token": creance_proxy::token(),
            "run_id": creance_proxy::token()[..32].to_owned(),
        });
        fs::write(&record_path, serde_json::to_vec(&stale).unwrap()).unwrap();
        creance_vm::private::protect_file(&record_path).unwrap();
        assert!(retire_stale_record(&instance_dir), "dead record retires");
        assert!(!Path::new(&record_path).exists(), "record removed");

        // Live: a started gate keeps its record.
        let handle = Gate::start(
            &instance_dir,
            &config_path,
            &profile,
            "gate-test-inst",
            17896,
        )
        .unwrap();
        assert!(!retire_stale_record(&instance_dir), "served record stays");
        assert!(Path::new(&record_path).exists());
        drop(handle);
        fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn still_owner_flips_when_the_record_is_renamed_over() {
        // F-028 regression: a daemon renamed over by a successor must see
        // itself as disowned and never touch the winner's wire.
        let (profile, config_path) = prepare_profile();
        let instance_dir = creance_vm::paths::join(&profile, "lima/test-vm");
        fs::create_dir_all(&instance_dir).unwrap();
        let handle = Gate::start(
            &instance_dir,
            &config_path,
            &profile,
            "gate-test-inst",
            17896,
        )
        .unwrap();
        assert!(handle.gate.still_owner(), "fresh gate owns its record");

        // A successor's record: same shape, different run_id.
        let successor = serde_json::json!({
            "socket": handle.record.socket,
            "token": handle.record.token,
            "run_id": creance_proxy::token()[..32].to_owned(),
        });
        let record_path = creance_vm::paths::join(&instance_dir, "cage-gate.json");
        fs::write(&record_path, serde_json::to_vec(&successor).unwrap()).unwrap();
        assert!(!handle.gate.still_owner(), "renamed-over gate is disowned");

        // And an unreadable record also means "do not touch the wire".
        fs::write(&record_path, b"not json").unwrap();
        assert!(!handle.gate.still_owner(), "garbage record: hold back");
        drop(handle);
        fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn daemon_serving_distinguishes_slow_from_dead() {
        // F-029 regression: only connect-level death retires a record.
        let (profile, config_path) = prepare_profile();
        let instance_dir = creance_vm::paths::join(&profile, "lima/test-vm");
        fs::create_dir_all(&instance_dir).unwrap();
        let record_path = creance_vm::paths::join(&instance_dir, "cage-gate.json");
        let write_record = |socket: &str| {
            let record = serde_json::json!({
                "socket": socket,
                "token": creance_proxy::token(),
                "run_id": creance_proxy::token()[..32].to_owned(),
            });
            fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
        };

        // A gate that serves: alive.
        let handle = Gate::start(
            &instance_dir,
            &config_path,
            &profile,
            "gate-test-inst",
            17896,
        )
        .unwrap();
        assert!(daemon_serving(&instance_dir), "serving gate is alive");
        drop(handle);

        // The frozen-daemon shape: a listener that never accepts or reads
        // still completes connects — it must count as ALIVE, not stale.
        let frozen_dir = std::env::temp_dir().join(format!(
            "cage-gate-frozen-{}",
            creance_proxy::token()[..8].to_owned()
        ));
        fs::create_dir_all(&frozen_dir).unwrap();
        let frozen_sock = frozen_dir.join("control.sock");
        let listener = std::os::unix::net::UnixListener::bind(&frozen_sock).unwrap();
        write_record(frozen_sock.to_string_lossy().as_ref());
        assert!(
            daemon_serving(&instance_dir),
            "frozen-but-bound daemon must not be retired"
        );

        // The dead shape: the listener is gone, its socket file remains
        // (exactly what a SIGKILLed daemon leaves behind).
        drop(listener);
        assert!(!daemon_serving(&instance_dir), "refused socket is dead");
        fs::remove_dir_all(&frozen_dir).unwrap();
        fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn disowned_handle_drop_leaves_the_successors_record() {
        // F-028's last twist: a renamed-over loser dropping its handle used
        // to delete whatever record was live — the winner's — cascading
        // into a full gate collapse (verified on the live machine).
        let (profile, config_path) = prepare_profile();
        let instance_dir = creance_vm::paths::join(&profile, "lima/test-vm");
        fs::create_dir_all(&instance_dir).unwrap();
        let record_path = creance_vm::paths::join(&instance_dir, "cage-gate.json");
        let loser = Gate::start(
            &instance_dir,
            &config_path,
            &profile,
            "gate-test-inst",
            17896,
        )
        .unwrap();

        // A successor renames over the record; the loser notices and disowns.
        let successor = serde_json::json!({
            "socket": loser.record.socket,
            "token": loser.record.token,
            "run_id": creance_proxy::token()[..32].to_owned(),
        });
        fs::write(&record_path, serde_json::to_vec(&successor).unwrap()).unwrap();
        assert!(!loser.gate.still_owner());
        loser.disown();
        drop(loser);

        assert!(
            Path::new(&record_path).exists(),
            "a disowned drop must not delete the winner's record"
        );
        fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn spawn_daemon_waits_out_a_pid_without_a_record() {
        // F-035: a live pid file whose daemon owns no record must not be
        // deduped on — spawn_daemon waits the window out (fresh daemons
        // publish a record; dying ones exit) and then spawns regardless.
        // The test binary standing in as the daemon exits immediately;
        // what matters is the wait happened and the call did not
        // short-circuit into a success with nothing running.
        let (profile, config_path) = prepare_profile();
        let instance_dir = creance_vm::paths::join(&profile, "lima/test-vm");
        fs::create_dir_all(&instance_dir).unwrap();
        fs::create_dir_all(creance_vm::proxy_dir(&profile)).unwrap();
        let mut bystander = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        // Legacy bare-pid shape: alive semantics without a record.
        fs::write(
            creance_vm::pidfile::proxy_pid_file(&profile, "gate.pid"),
            format!("{}\n", bystander.id()),
        )
        .unwrap();

        let started = std::time::Instant::now();
        spawn_daemon(
            &profile,
            "gate-test-inst",
            &config_path,
            &instance_dir,
            17896,
        )
        .unwrap();
        assert!(
            started.elapsed() >= Duration::from_millis(1100),
            "the in-flight/dying window must be waited out"
        );
        assert!(
            !Path::new(&creance_vm::paths::join(&instance_dir, "cage-gate.json")).exists(),
            "no record appeared (nothing serves) — spawn proceeded"
        );
        let _ = std::fs::remove_file(creance_vm::pidfile::proxy_pid_file(&profile, "gate.pid"));
        let _ = bystander.kill();
        let _ = bystander.wait();
        fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn unreadable_record_never_degrades_the_bearer_check() {
        // F-037 regression: the token lives in memory — an unreadable
        // record file (chmod 000, or the removal window during close)
        // must not turn the check into `constant_time_eq("", "")`, which
        // let a credential-less process drive check→grant→open.
        let (profile, config_path) = prepare_profile();
        let instance_dir = creance_vm::paths::join(&profile, "lima/test-vm");
        fs::create_dir_all(&instance_dir).unwrap();
        let handle = Gate::start(
            &instance_dir,
            &config_path,
            &profile,
            "gate-test-inst",
            17896,
        )
        .unwrap();
        let record = handle.record.clone();

        let status = |bearer: &str| -> String {
            use std::io::{Read, Write};
            use std::os::unix::net::UnixStream;
            let mut stream = UnixStream::connect(&record.socket).unwrap();
            let auth = if bearer.is_empty() {
                String::new()
            } else {
                format!("Authorization: Bearer {bearer}\r\n")
            };
            stream
                .write_all(format!("GET /status HTTP/1.1\r\nHost: cage\r\n{auth}\r\n").as_bytes())
                .unwrap();
            let mut raw = Vec::new();
            stream.read_to_end(&mut raw).unwrap();
            String::from_utf8_lossy(&raw)
                .lines()
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned()
        };

        // Baseline: right token works, empty bearer is refused.
        assert_eq!(status(&record.token), "200");
        assert_eq!(status(""), "403");

        // The record unreadable: the in-memory token keeps serving the
        // legitimate holder and still refuses the credential-less.
        let record_path = creance_vm::paths::join(&instance_dir, "cage-gate.json");
        let mut perms = fs::metadata(&record_path).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o000);
        fs::set_permissions(&record_path, perms).unwrap();
        assert_eq!(status(""), "403", "no credential stays refused");
        assert_eq!(status(&record.token), "200", "holder unaffected");
        drop(handle);
        fs::remove_dir_all(&profile).unwrap();
    }

    #[test]
    fn truncate_reason_enforces_the_byte_budget() {
        // FINDING-008: multi-byte text must actually hit the 200-byte cap.
        let cjk = "好".repeat(150); // 450 bytes
        let truncated = truncate_utf8(&cjk, 200);
        assert!(truncated.len() <= 200, "{}", truncated.len());
        assert!(truncated.chars().all(|c| c == '好'));
        assert_eq!(truncate_utf8("abc", 200), "abc");
        assert_eq!(truncate_utf8(&"a".repeat(300), 200).len(), 200);
    }

    #[test]
    fn gate_rejects_missing_auth_and_bad_hosts() {
        let (profile, config_path) = prepare_profile();
        let instance_dir = creance_vm::paths::join(&profile, "lima/test-vm");
        fs::create_dir_all(&instance_dir).unwrap();
        let handle = Gate::start(
            &instance_dir,
            &config_path,
            &profile,
            "gate-test-inst",
            17896,
        )
        .unwrap();
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
        let handle = Gate::start(
            &instance_dir,
            &config_path,
            &profile,
            "gate-test-inst",
            17896,
        )
        .unwrap();
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
        let handle = Gate::start(
            &instance_dir,
            &config_path,
            &profile,
            "gate-test-inst",
            17896,
        )
        .unwrap();
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
