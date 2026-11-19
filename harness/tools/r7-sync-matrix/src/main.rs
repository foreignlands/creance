//! R7 探针主程序：四个假设各一组断言。全部走真实库函数（Gate::start /
//! GateClient / config::write_private_config），不做逻辑复刻。
//! 退出码：0 = 全部观测与预测一致；非 0 = 存在偏离（无论方向都记录）。

use creance_gate::gate::{Gate, GateClient, GateRecord};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

static FAILURES: AtomicUsize = AtomicUsize::new(0);

fn check(label: &str, ok: bool, detail: &str) {
    if ok {
        println!("  PASS  {label}");
    } else {
        println!("  FAIL  {label}  ({detail})");
        FAILURES.fetch_add(1, Ordering::Relaxed);
    }
}

fn finished() -> i32 {
    let n = FAILURES.load(Ordering::Relaxed);
    if n == 0 {
        println!("probe: all observations matched predictions");
        0
    } else {
        println!("probe: {n} deviation(s)");
        1
    }
}

/// gate-daemon 兜底：spawn_daemon 若未去重会以当前 exe 重入；探针必须
/// 能扮演守护而不是递归自身。
fn maybe_daemon() -> bool {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && args[1] == "gate-daemon" {
        let code = creance_gate::gate::run_daemon(
            &args[2], &args[3], &args[4], &args[5], args[6].parse().unwrap_or(17896),
        );
        std::process::exit(code);
    }
    false
}

struct Rig {
    profile: String,
    config_path: String,
    instance_dir: String,
    handle: Option<creance_gate::gate::GateHandle>,
}

fn prepare(name: &str) -> Rig {
    let profile = std::env::temp_dir()
        .join(format!("r7-{name}-{}", creance_proxy::token()[..12].to_owned()))
        .to_string_lossy()
        .into_owned();
    let config_path = creance_vm::paths::join(&profile, "config.json");
    std::fs::create_dir_all(&profile).unwrap();
    std::fs::create_dir_all(creance_vm::paths::join(&profile, "proxy")).unwrap();
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
    let mut config = creance_vm::config::default_config();
    config.proxy_url = store.endpoint();
    config.proxy_revision = store.revision.clone();
    // H1 的起点锚点：static + ip（bound，needs_binding=false）。
    config.exit_policy = creance_vm::exit_policy::Policy {
        mode: "static".to_owned(),
        scope: "any".to_owned(),
        ip: "203.0.113.7".to_owned(),
        country_code: String::new(),
        region: String::new(),
        city: String::new(),
    };
    creance_vm::config::write_private_config(&config_path, &config).unwrap();
    let instance_dir = creance_vm::paths::join(&creance_vm::vm::lima_home(&profile), "test-vm");
    std::fs::create_dir_all(&instance_dir).unwrap();
    let handle = Gate::start(&instance_dir, &config_path, &profile, "r7-probe", 17896).unwrap();
    Rig { profile, config_path, instance_dir, handle: Some(handle) }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.handle = None; // drop handle: stop server, remove record
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}

fn open_gate(rig: &Rig, record: &GateRecord) {
    let client = GateClient::open(&rig.instance_dir).unwrap();
    client.begin_check().unwrap();
    let status = client.status().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut checks = std::collections::BTreeMap::new();
    for c in ["egress_policy", "fail_closed", "udp_policy", "ipv6_policy", "exit_consistency"] {
        checks.insert(c.to_owned(), "passed".to_owned());
    }
    let body = serde_json::json!({
        "action": "grant",
        "report_id": status.check_id,
        "report": {
            "report_id": status.check_id,
            "run_id": record.run_id,
            "created_at": now,
            "checks": checks,
        },
    });
    let (code, _) = call_raw(record, &body.to_string()).unwrap();
    assert!(code.starts_with("200"), "open_gate grant: {code}");
}

fn call_raw(record: &GateRecord, body: &str) -> Result<(String, serde_json::Value), String> {
    let mut stream = UnixStream::connect(&record.socket).map_err(|e| e.to_string())?;
    let request = format!(
        "POST /control HTTP/1.1\r\nHost: cage\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        record.token,
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("bad response")?;
    let status = String::from_utf8_lossy(&raw[..split])
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let value: serde_json::Value = serde_json::from_slice(&raw[split + 4..]).map_err(|e| e.to_string())?;
    Ok((status, value))
}

fn get_status(record: &GateRecord) -> Result<(String, serde_json::Value), String> {
    let mut stream = UnixStream::connect(&record.socket).map_err(|e| e.to_string())?;
    let request = format!(
        "GET /status HTTP/1.1\r\nHost: cage\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        record.token
    );
    stream.write_all(request.as_bytes()).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("bad response")?;
    let status = String::from_utf8_lossy(&raw[..split])
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let body = &raw[split + 4..];
    let value = if body.is_empty() {
        serde_json::json!({}) // 403/400 响应无 body
    } else {
        serde_json::from_slice(body).map_err(|e| e.to_string())?
    };
    Ok((status, value))
}

fn write_config(rig: &Rig, policy: Option<creance_vm::exit_policy::Policy>, bump_revision: bool) {
    let mut config = creance_vm::config::load(&rig.config_path).unwrap();
    if let Some(p) = policy {
        config.exit_policy = p;
    }
    if bump_revision {
        // 真实形态：select_and_apply 同时落 store 与 config（revision 成对）。
        let mut store = creance_proxy::load(&rig.profile).unwrap();
        store.revision = creance_proxy::token();
        creance_proxy::save(&rig.profile, &store).unwrap();
        config.proxy_revision = store.revision.clone();
    }
    creance_vm::config::write_private_config(&rig.config_path, &config).unwrap();
}

// ---------------------------------------------------------------- H1/H2

fn h1_h2_sync_anchor_matrix() {
    println!("H1/H2 sync 幂等矩阵：锚点变化 × revision 不动/变化（真实 Gate + GateClient）");

    // ---- 矩阵 1：bound→bound 换 ip，revision 不动。
    let rig = prepare("anchor-ip");
    {
        let record = rig.handle.as_ref().unwrap().record.clone();
        open_gate(&rig, &record);
        let (_, st) = get_status(&record).unwrap();
        check("m1 前置：gate 已 Open", st["state"] == "open", &st.to_string());

        write_config(
            &rig,
            Some(creance_vm::exit_policy::Policy {
                mode: "static".to_owned(),
                scope: "any".to_owned(),
                ip: "198.51.100.9".to_owned(),
                country_code: String::new(),
                region: String::new(),
                city: String::new(),
            }),
            false,
        );
        let client = GateClient::open(&rig.instance_dir).unwrap();
        let sync = client.sync_proxy_revision();
        let (_, st) = get_status(&record).unwrap();
        match &sync {
            Ok(_) => {
                println!("        sync → 200（Unchanged 路径）");
                check(
                    "m1 预测=洞成立：锚点漂移+revision 不动 → Unchanged 且 gate 保持 Open",
                    st["state"] == "open",
                    &st.to_string(),
                );
            }
            Err(e) => {
                println!("        sync → Err: {e}");
                check(
                    "m1 预测被证伪：gate 已 fail-closed 关闭（洞不成立）",
                    st["state"] == "closed",
                    &st.to_string(),
                );
            }
        }
    }

    // ---- 矩阵 2：同锚点变化 + revision 变化 → Adopted 路径 only_completed 应拒。
    let rig = prepare("anchor-ip-bump");
    {
        let record = rig.handle.as_ref().unwrap().record.clone();
        open_gate(&rig, &record);
        write_config(
            &rig,
            Some(creance_vm::exit_policy::Policy {
                mode: "static".to_owned(),
                scope: "any".to_owned(),
                ip: "198.51.100.9".to_owned(),
                country_code: String::new(),
                region: String::new(),
                city: String::new(),
            }),
            true, // revision bump（store+config 成对）
        );
        let client = GateClient::open(&rig.instance_dir).unwrap();
        let sync = client.sync_proxy_revision();
        let (_, st) = get_status(&record).unwrap();
        check(
            "m2 锚点漂移+revision 变化 → 拒绝/关闭（only_completed）",
            sync.is_err() && st["state"] == "closed",
            &format!("{sync:?} / {}", st),
        );
    }

    // ---- 矩阵 3：mode dynamic/any → static/ip 填充，revision 不动
    //      （binding_completed 要求 mode 相同 → false；Unchanged 路径）。
    let mut rig = prepare("mode-move");
    {
        let record = rig.handle.as_ref().unwrap().record.clone();
        // 起点换 dynamic/any（needs_binding=false）。
        write_config(
            &rig,
            Some(creance_vm::exit_policy::Policy {
                mode: "dynamic".to_owned(),
                scope: "any".to_owned(),
                ip: String::new(),
                country_code: String::new(),
                region: String::new(),
                city: String::new(),
            }),
            false,
        );
        // 重开 gate 使 recorded 吸收新起点。
        rig.handle = None;
        std::fs::create_dir_all(&rig.instance_dir).unwrap();
        rig.handle = Some(
            Gate::start(&rig.instance_dir, &rig.config_path, &rig.profile, "r7-probe", 17896)
                .unwrap(),
        );
        let record = rig.handle.as_ref().unwrap().record.clone();
        open_gate(&rig, &record);

        write_config(
            &rig,
            Some(creance_vm::exit_policy::Policy {
                mode: "static".to_owned(),
                scope: "any".to_owned(),
                ip: "203.0.113.7".to_owned(),
                country_code: String::new(),
                region: String::new(),
                city: String::new(),
            }),
            false,
        );
        let client = GateClient::open(&rig.instance_dir).unwrap();
        let sync = client.sync_proxy_revision();
        let (_, st) = get_status(&record).unwrap();
        match &sync {
            Ok(_) => check(
                "m3 预测=洞成立：mode 迁移+revision 不动 → Unchanged 且 gate 保持 Open",
                st["state"] == "open",
                &st.to_string(),
            ),
            Err(_) => check(
                "m3 预测被证伪：gate 已 fail-closed 关闭",
                st["state"] == "closed",
                &st.to_string(),
            ),
        }
    }

    // ---- 矩阵 4：干净幂等（什么都不变）→ Unchanged 且 Open 保持（修复的意图）。
    let rig = prepare("clean-unchanged");
    {
        let record = rig.handle.as_ref().unwrap().record.clone();
        open_gate(&rig, &record);
        let client = GateClient::open(&rig.instance_dir).unwrap();
        let sync = client.sync_proxy_revision();
        let (_, st) = get_status(&record).unwrap();
        check(
            "m4 干净幂等 → 200 且 Open 保持（修复意图成立）",
            sync.is_ok() && st["state"] == "open",
            &format!("{sync:?} / {}", st),
        );
    }

    // ---- 矩阵 5：非锚点变化（timezone）+ revision 不动 → Err → close。
    let rig = prepare("tz-change");
    {
        let record = rig.handle.as_ref().unwrap().record.clone();
        open_gate(&rig, &record);
        let mut config = creance_vm::config::load(&rig.config_path).unwrap();
        config.timezone = "Asia/Tokyo".to_owned();
        creance_vm::config::write_private_config(&rig.config_path, &config).unwrap();
        let client = GateClient::open(&rig.instance_dir).unwrap();
        let sync = client.sync_proxy_revision();
        let (_, st) = get_status(&record).unwrap();
        check(
            "m5 timezone 变化 → Err → close（其余字段受 strip 比较）",
            sync.is_err() && st["state"] == "closed",
            &format!("{sync:?} / {}", st),
        );
    }
}

// ---------------------------------------------------------------- H3

fn h3_grant_time_matrix() {
    println!("H3 grant 绑定时间源可达边界（真实 gate）");
    let rig = prepare("time-matrix");
    let record = rig.handle.as_ref().unwrap().record.clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut checks = std::collections::BTreeMap::new();
    for c in ["egress_policy", "fail_closed", "udp_policy", "ipv6_policy", "exit_consistency"] {
        checks.insert(c.to_owned(), "passed".to_owned());
    }
    let grant = |created_at: serde_json::Value, include_field: bool, run: &str| -> String {
        let client = GateClient::open(&rig.instance_dir).unwrap();
        client.begin_check().unwrap();
        let status = client.status().unwrap();
        let mut report = serde_json::json!({
            "report_id": status.check_id,
            "run_id": run,
            "checks": checks,
        });
        if include_field {
            report["created_at"] = created_at;
        }
        let body = serde_json::json!({
            "action": "grant",
            "report_id": status.check_id,
            "report": report,
        });
        call_raw(&record, &body.to_string()).unwrap().0
    };

    check("t1 created_at 未来（+3600）→ 拒", grant(serde_json::json!(now + 3600), true, &record.run_id).starts_with("409"), "");
    check("t2 created_at 过期（-3600）→ 拒", grant(serde_json::json!(now - 3600), true, &record.run_id).starts_with("409"), "");
    check("t3 created_at=0 → 拒（now 远大于窗口）", grant(serde_json::json!(0), true, &record.run_id).starts_with("409"), "");
    check("t4 created_at 字段缺省 → 拒", grant(serde_json::Value::Null, false, &record.run_id).starts_with("409"), "");
    check("t5 created_at 刚好窗口+1（-181）→ 拒", grant(serde_json::json!(now.saturating_sub(181)), true, &record.run_id).starts_with("409"), "");
    check("t6 created_at 窗口内（-60）→ 收", grant(serde_json::json!(now - 60), true, &record.run_id).starts_with("200"), "");
    // run_id 绑定：错的 run 即便时间新鲜也拒。
    check("t7 run_id 错 → 拒", grant(serde_json::json!(now), true, "some-other-gate").starts_with("409"), "");
}

// ---------------------------------------------------------------- H4

fn h4_record_token_rewrite() {
    println!("H4 record token 字段外部改写：403 死锁与自愈面（真实 gate）");
    let rig = prepare("token-rewrite");
    let handle = rig.handle.as_ref().unwrap();
    let record_path = Path::new(&rig.instance_dir).join("cage-gate.json");

    // 外部改写：同 run_id 同 socket，只换 token。
    let mut evil = handle.record.clone();
    evil.token = creance_proxy::token();
    let bytes = serde_json::to_vec(&evil).unwrap();
    std::fs::write(&record_path, &bytes).unwrap();

    let (code, _) = get_status(&evil).unwrap();
    check("r1 改写后新 token → 403（服务端认内存旧 token）", code == "403", &code);
    let (code2, _) = get_status(&handle.record).unwrap();
    check("r2 原 token（客户端侧已不可见）此刻仍 200", code2 == "200", &code2);

    // 自愈面 1：spawn_daemon 的 up 去重——record 存在且 serving → 直接 Ok，
    // 不重生守护，死锁不修。
    let deduped = creance_gate::gate::spawn_daemon(
        &rig.profile, "r7-probe", &rig.config_path, &rig.instance_dir, 17896,
    );
    check("r3 up 去重放行（spawn_daemon=Ok，死锁不修）", deduped.is_ok(), &format!("{deduped:?}"));
    let (code3, _) = get_status(&evil).unwrap();
    check("r4 up 后仍 403（无自愈）", code3 == "403", &code3);

    // 自愈面 2：stop 的 close_and_remove 删 record → 守护退场（无守护战争）。
    let _ = creance_gate::gate::close_and_remove(&rig.profile, &rig.instance_dir, 17896);
    let gone = !record_path.exists();
    check("r5 stop 路径删 record（唯一自愈门）", gone, "");
}

fn main() {
    maybe_daemon();
    h1_h2_sync_anchor_matrix();
    h3_grant_time_matrix();
    h4_record_token_rewrite();
    std::process::exit(finished());
}
