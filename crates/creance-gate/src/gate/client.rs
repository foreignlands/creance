use super::*;

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

/// A host-side client for one gate record: the calls `creance proxy-stop` and
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

    fn call_raw(&self, method: &str, path: &str, body: Option<&str>) -> Result<Vec<u8>, String> {
        use std::os::unix::net::UnixStream;
        let mut stream = UnixStream::connect(&self.record.socket)
            .map_err(|_| "gate control socket unreachable".to_owned())?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: gate\r\nAuthorization: Bearer {}\r\nConnection: close\r\n",
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
        let body_bytes = raw[split + 4..].to_vec();
        if !(200..300).contains(&status) {
            let detail = String::from_utf8_lossy(&body_bytes).into_owned();
            return Err(format!("gate returned HTTP {status}: {detail}"));
        }
        Ok(body_bytes)
    }

    fn call(&self, method: &str, path: &str, body: Option<&str>) -> Result<GateStatus, String> {
        serde_json::from_slice(&self.call_raw(method, path, body)?).map_err(|e| e.to_string())
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

    /// 插件调用（action=plugin）：返回插件 JSON 结果体，非 2xx 时把
    /// gate 的拒绝原因带进 Err。
    pub fn plugin_call(&self, name: &str, args: &[String]) -> Result<serde_json::Value, String> {
        let body =
            serde_json::json!({ "action": "plugin", "plugin": name, "args": args }).to_string();
        let raw = self.call_raw("POST", "/control", Some(&body))?;
        serde_json::from_slice(&raw).map_err(|e| e.to_string())
    }
}

/// Closes every gate recorded under the profile's instance root (per backend) — the
/// `creance proxy-stop` companion so VMs drop their networking the moment
/// the core goes away. A record whose socket no longer answers is stale
/// (F-019): its daemon is gone, so the record goes too — nothing else
/// would clean it, and a live-looking corpse would mask a missing gate.
pub fn close_gates(profile: &str) -> Result<(), String> {
    let lima = creance_vm::vm::instances_root(profile);
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
