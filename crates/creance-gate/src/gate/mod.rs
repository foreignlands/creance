//! The cage gate: the host-side control service guarding every environment's
//! external networking.
//!
//! One gate per running instance, identified by a `cage-gate.json` record in
//! the instance directory (the private unix socket path, a bearer token, and
//! this run's id). The control protocol is HTTP over that socket:
//!
//! - `GET /status` → the current [`GateStatus`]
//! - `POST /control` → one [`GateCommand`], authenticated with
//!   `Authorization: Bearer <token>` and `Host: gate`; anything else is 403
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
pub const POLICY: &str = "session-safety/3";

/// How long an opened gate may stay open without a renewal.
const OPEN_LEASE: Duration = Duration::from_secs(90);
/// How long a check window may run before the gate closes itself.
const CHECK_LEASE: Duration = Duration::from_secs(180);
mod client;
mod core;
mod daemon;
pub mod plugin;
#[cfg(test)]
mod tests;
pub use client::*;
pub use daemon::*;

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
    #[serde(default)]
    pub plugin: String,
    #[serde(default)]
    pub args: Vec<String>,
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

/// RFC 9112 status lines carry a reason phrase; strict parsers reject a
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        _ => "Status",
    }
}

/// Locks a gate mutex, recovering from a poisoned lock (a panicked handler
/// must not cascade into every later call).
fn lock_or_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}
fn error_json(message: &str) -> Vec<u8> {
    serde_json::json!({ "error": message })
        .to_string()
        .into_bytes()
}
