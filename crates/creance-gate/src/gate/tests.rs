use super::client::*;
use super::daemon::*;
use super::*;
use std::fs;

fn prepare_profile() -> (String, String) {
    let profile = std::env::temp_dir()
        .join(format!("gate-{}", creance_proxy::token()[..12].to_owned()))
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
        "gate-frozen-{}",
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
    // (exactly what a SIGKILLed daemon leaves behind). A connect that
    // raced into the backlog before the close can still succeed for a
    // beat — poll to refused instead of asserting the instant state
    // (the R12-known flake, finally given a deterministic shape).
    drop(listener);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if !daemon_serving(&instance_dir) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "refused socket is dead"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
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
            .write_all(format!("GET /status HTTP/1.1\r\nHost: gate\r\n{auth}\r\n").as_bytes())
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
        raw_no_auth("POST /control HTTP/1.1\r\nHost: gate\r\nContent-Length: 2\r\n\r\n{}")
            .starts_with("403")
    );
    assert!(raw_no_auth(&format!("POST /control HTTP/1.1\r\nHost: evil\r\nAuthorization: Bearer {}\r\nContent-Length: 2\r\n\r\n{{}}", record.token)).starts_with("403"));
    // F-079/FINDING-006: a duplicated Content-Length — even two
    // identical values — is an ambiguity smuggling vector (400,
    // before any auth check).
    assert!(raw_no_auth(
        "POST /control HTTP/1.1\r\nHost: gate\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}"
    )
    .starts_with("400"));
    // Valid command with the right token goes through.
    let body = r#"{"action":"check"}"#;
    let got = raw_no_auth(&format!(
            "POST /control HTTP/1.1\r\nHost: gate\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n{}",
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
fn unchanged_sync_is_blind_to_nothing_anchor_drift_closes() {
    // F-041 regression: an anchor change with an unmoved revision used
    // to take the idempotent Unchanged path (strip_config removes
    // exit_policy) and the OPEN gate survived against the old anchor's
    // evidence. Both drift shapes must now demand a restart.
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
    let client = GateClient::open(&instance_dir).unwrap();

    // bound→bound anchor swap, revision untouched.
    let mut changed = config::load(&config_path).unwrap();
    changed.exit_policy = crate::exit_policy::Policy {
        mode: "static".to_owned(),
        scope: "country".to_owned(),
        ip: "203.0.113.7".to_owned(),
        ..Default::default()
    };
    config::write_private_config(&config_path, &changed).unwrap();
    let err = client.sync_proxy_revision().unwrap_err();
    assert!(
        err.contains("需要重启") || err.contains("HTTP 409"),
        "anchor swap: {err}"
    );

    // mode migration (dynamic/any → static), revision untouched.
    let mut changed = config::load(&config_path).unwrap();
    changed.exit_policy = crate::exit_policy::Policy {
        mode: "static".to_owned(),
        scope: "any".to_owned(),
        ip: "198.51.100.9".to_owned(),
        ..Default::default()
    };
    config::write_private_config(&config_path, &changed).unwrap();
    let err = client.sync_proxy_revision().unwrap_err();
    assert!(
        err.contains("需要重启") || err.contains("HTTP 409"),
        "mode migration: {err}"
    );

    // And the truly unchanged config (the one the gate recorded at
    // start) still syncs clean through the idempotent path.
    let original = config::load(&config_path).unwrap();
    let mut restored = original.clone();
    restored.exit_policy = Default::default();
    config::write_private_config(&config_path, &restored).unwrap();
    client.sync_proxy_revision().unwrap();
    drop(handle);
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

#[test]
fn watchdog_fuses_open_gate_when_core_unreachable() {
    // 0.6.x 常驻巡检/自动熔断：Open 态闸连续 3 tick（≈1.5s）探不
    // 到托管核心的 loopback 监听 → 熔断关闸；监听存活则不熔断。
    let (profile, config_path) = prepare_profile();
    let instance_dir = creance_vm::paths::join(&profile, "qemu/fuse-vm");
    fs::create_dir_all(&instance_dir).unwrap();
    // A port nothing listens on: bind :0 once, learn the port, drop.
    let dead_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let handle = Gate::start(
        &instance_dir,
        &config_path,
        &profile,
        "fuse-inst-dead",
        dead_port,
    )
    .unwrap();
    {
        let mut inner = lock_or_recover(&handle.gate.inner);
        inner.state = GateState::Open;
        inner.opened_at = Some(Instant::now());
        inner.lease = Duration::from_secs(600);
    }
    // F-102/NC-WDthr8: the fuse must fire within ~2s — a widened
    // threshold (>=8 ticks ≈ 4s) would still pass a bare "closes
    // eventually" check. Measure the latency, don't just poll for
    // the end state.
    let t0 = Instant::now();
    // Lower bound too (F-110): at ~1.3s only two dead ticks have
    // sampled (500ms loop) — fusing that early means the threshold
    // shrank below 3.
    std::thread::sleep(Duration::from_millis(1300));
    {
        let inner = lock_or_recover(&handle.gate.inner);
        assert_eq!(
            inner.state,
            GateState::Open,
            "two dead ticks must not fuse — threshold is 3"
        );
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        std::thread::sleep(Duration::from_millis(50));
        let inner = lock_or_recover(&handle.gate.inner);
        if inner.state == GateState::Closed || Instant::now() > deadline {
            break inner.status(&handle.gate.run_id);
        }
    };
    assert_eq!(status.state, GateState::Closed, "{status:?}");
    assert!(status.reason.contains("熔断"), "{status:?}");
    assert!(
        t0.elapsed() <= Duration::from_millis(3000),
        "fuse must land inside ~3 ticks: {:?}",
        t0.elapsed()
    );

    // Live listener → no fuse.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let live_port = listener.local_addr().unwrap().port();
    let handle = Gate::start(
        &instance_dir,
        &config_path,
        &profile,
        "fuse-inst-live",
        live_port,
    )
    .unwrap();
    {
        let mut inner = lock_or_recover(&handle.gate.inner);
        inner.state = GateState::Open;
        inner.opened_at = Some(Instant::now());
        inner.lease = Duration::from_secs(600);
    }
    std::thread::sleep(Duration::from_millis(2500));
    let inner = lock_or_recover(&handle.gate.inner);
    assert_eq!(inner.state, GateState::Open, "live core must not fuse");
    drop(inner);
    drop(handle);
    drop(listener);
    fs::remove_dir_all(&profile).unwrap();
}

#[test]
fn watchdog_does_not_fuse_during_checking() {
    // F-102/NC-WDany: a dead core during the Checking window must
    // NOT fuse — Checking has its own lease and fusing it would
    // kill a gate mid-startup. Only Open ticks the counter.
    let (profile, config_path) = prepare_profile();
    let instance_dir = creance_vm::paths::join(&profile, "qemu/check-vm");
    fs::create_dir_all(&instance_dir).unwrap();
    let dead_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let handle = Gate::start(
        &instance_dir,
        &config_path,
        &profile,
        "fuse-inst-checking",
        dead_port,
    )
    .unwrap();
    {
        let mut inner = lock_or_recover(&handle.gate.inner);
        inner.state = GateState::Checking;
        inner.opened_at = Some(Instant::now());
        inner.lease = Duration::from_secs(600);
    }
    std::thread::sleep(Duration::from_millis(2500));
    let inner = lock_or_recover(&handle.gate.inner);
    assert_eq!(
        inner.state,
        GateState::Checking,
        "dead core during Checking must not fuse"
    );
    drop(inner);
    drop(handle);
    fs::remove_dir_all(&profile).unwrap();
}

#[test]
fn watchdog_fused_gate_cuts_the_wire() {
    // F-102/NC-WDnocut: after the fuse closes the gate, the very
    // next tick's closed branch must kill the wire — observable as
    // the tunnel pidfile's process dying, not just state=Closed.
    // A `sleep` child stands in for the tunnel: only `tunnel::stop`
    // (pidfile-owned pid) kills it — `reap_orphans` skips the pid
    // the file owns.
    let (profile, config_path) = prepare_profile();
    let instance_dir = creance_vm::paths::join(&profile, "qemu/cut-vm");
    fs::create_dir_all(&instance_dir).unwrap();
    let dead_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut wire = std::process::Command::new("sleep")
        .arg("300")
        .spawn()
        .unwrap();
    creance_vm::pidfile::write(
        &creance_vm::pidfile::proxy_pid_file(&profile, "tunnel.pid"),
        wire.id() as i32,
    )
    .unwrap();
    let handle = Gate::start(
        &instance_dir,
        &config_path,
        &profile,
        "fuse-inst-wire",
        dead_port,
    )
    .unwrap();
    {
        let mut inner = lock_or_recover(&handle.gate.inner);
        inner.state = GateState::Open;
        inner.opened_at = Some(Instant::now());
        inner.lease = Duration::from_secs(600);
    }
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut dead = false;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        if wire.try_wait().unwrap().is_some() {
            dead = true;
            break;
        }
    }
    assert!(dead, "fused gate must kill the wire process");
    drop(handle);
    let _ = wire.kill();
    let _ = wire.wait();
    fs::remove_dir_all(&profile).unwrap();
}

#[test]
fn watchdog_fuse_source_pins() {
    // F-102: textual pins on the watchdog loop's own region —
    // behavioural tests cover the endpoints, these pin the
    // semantics in between that a mutation preserves: the 250ms
    // sample timeout (a 30s timeout starves every tick), the >=3
    // threshold, BOTH counter resets (on success and after fusing),
    // Open-only counting, and the closed branch cutting the wire.
    // gate.rs was split into gate/{mod,core,daemon,client}.rs —
    // the prod region is the concatenation of all four (no test
    // module lives in any of them).
    let prod = concat!(
        include_str!("mod.rs"),
        include_str!("core.rs"),
        include_str!("daemon.rs"),
        include_str!("client.rs")
    );
    // Global prod-region counts: pinning the loop's region by brace
    // matching is brittle, and a duplicated counter elsewhere is a
    // finding anyway — the whole prod file is the honest region.
    // F-110: needles are shape-exact — `from_millis(250),` carries
    // the trailing comma so a `.max(...)` chain breaks it; the
    // threshold line is asserted verbatim so `&& is_multiple_of(4)`
    // fails; shadow declarations (`let _core_down_ticks`) and
    // rebinds are banned so a reset can't become a dead write.
    assert_eq!(prod.matches("from_millis(250),").count(), 1);
    assert_eq!(
        prod.lines()
            .filter(|l| l.trim() == "if core_down_ticks >= 3 {")
            .count(),
        1
    );
    assert_eq!(prod.matches("core_down_ticks += 1").count(), 1);
    assert!(!prod.contains("let _core_down_ticks"), "shadowed reset");
    assert_eq!(
        prod.matches("let mut core_down_ticks").count(),
        1,
        "the counter is declared exactly once"
    );
    // F-116: bare-name count — decl(1) + increment(1) + threshold(1)
    // + two resets(2) = 5. A `grace` counter or a second increment
    // site bumps it; a renamed counter breaks the decl/inc/threshold
    // pins anyway.
    assert_eq!(prod.matches("core_down_ticks").count(), 5, "{prod}");
    assert!(!prod.contains("grace"), "a grace counter softens the fuse");
    // The 500ms sampling period: exactly two `from_millis(500)` in
    // prod — the watchdog tick and the record-replace loop. A third
    // (a widened tick) bumps the count. F-122: the sleep lines are
    // verbatim — `from_millis(500) + from_millis(300)` keeps the
    // literal but widens the period, so the WHOLE trimmed line is
    // pinned; same for the increment (`+= 1 - u32::from(take(&w))`
    // keeps the `+= 1` substring while softening the fuse).
    assert_eq!(prod.matches("from_millis(500)").count(), 2, "{prod}");
    assert_eq!(
        prod.lines()
            .filter(|l| l.trim() == "std::thread::sleep(Duration::from_millis(500));")
            .count(),
        2,
        "tick + record-replace sleep lines are verbatim"
    );
    assert_eq!(
        prod.lines()
            .filter(|l| l.trim() == "core_down_ticks += 1;")
            .count(),
        1,
        "the increment line is verbatim — arithmetic suffixes are refused"
    );
    // F-122: the fuse region (counter decl → the `>= 3` block's
    // second reset) may hold no new mutable state and no `bool` —
    // but a `let mut warm = true;` declared just BEFORE the counter
    // lands outside the region, so the writable-state helpers are
    // pinned prod-wide instead: `let mut` == 18, `= true;` == 2,
    // `= false;` == 2, and `mem::take`/`u32::from` do not exist in
    // prod at all. Any warmup flag — wherever it's declared —
    // bumps one of those counts.
    let fuse_start = prod.find("let mut core_down_ticks").unwrap();
    let fuse_end = prod.rfind("core_down_ticks = 0;").unwrap();
    let fuse = &prod[fuse_start..fuse_end];
    assert_eq!(fuse.matches("let mut").count(), 2, "{fuse}");
    assert!(
        !fuse.contains("bool"),
        "fuse softener in watchdog region: bool"
    );
    assert_eq!(prod.matches("let mut").count(), 18, "{prod}");
    assert_eq!(prod.matches("= true;").count(), 2, "{prod}");
    assert_eq!(prod.matches("= false;").count(), 2, "{prod}");
    for needle in ["mem::take", "u32::from"] {
        assert!(!prod.contains(needle), "fuse softener in prod: {needle}");
    }
    assert_eq!(
        prod.matches("core_down_ticks = 0;").count(),
        2,
        "success reset + post-fuse reset both required (the `= 0u32;` declaration doesn't match)"
    );
    assert!(prod.contains("let open = inner.state == GateState::Open"));
    // `let core_up = !open || probe` — the `||` sits on the next
    // line after fmt, so the needle stops at `!open`. Both shapes
    // matter: `!open` exempts non-Open states from sampling, the
    // connect probe is the only other input.
    assert!(prod.contains("let core_up = !open"));
    assert_eq!(
        prod.matches("tunnel::stop(&watchdog.profile_dir)").count(),
        1,
        "the watchdog's own closed-branch cut must exist"
    );
    assert_eq!(
        prod.matches("tunnel::ensure(").count(),
        1,
        "the open-path ensure leg must exist"
    );
    assert!(prod.contains("代理核心不可达，自动熔断"));
}

fn call_raw(record: &GateRecord, body: &str) -> Result<(String, serde_json::Value), String> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(&record.socket).map_err(|e| e.to_string())?;
    let request = format!(
            "POST /control HTTP/1.1\r\nHost: gate\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
