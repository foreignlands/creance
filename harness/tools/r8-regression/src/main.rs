//! R8 探针主程序：四个假设各一组断言。全部走真实库函数（Gate::start /
//! GateClient / escape::host_probes / refresh_fingerprint_stamp /
//! service::check_running），不做逻辑复刻。
//! 退出码：0 = 全部观测与预测一致；非 0 = 存在偏离（无论方向都记录）。

use creance_gate::gate::{Gate, GateClient, GateRecord};
use creance_vm::exit_policy::Policy;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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

/// gate-daemon 兜底（同 r7）：探针若被 spawn_daemon 重入则扮演守护。
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
        .join(format!("r8-{name}-{}", creance_proxy::token()[..12].to_owned()))
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
    // 默认起点锚点：dynamic/country/cc=US（bound，needs_binding=false）。
    config.exit_policy = Policy {
        mode: "dynamic".to_owned(),
        scope: "country".to_owned(),
        ip: String::new(),
        country_code: "US".to_owned(),
        region: String::new(),
        city: String::new(),
    };
    creance_vm::config::write_private_config(&config_path, &config).unwrap();
    let instance_dir = creance_vm::paths::join(&creance_vm::vm::lima_home(&profile), "test-vm");
    std::fs::create_dir_all(&instance_dir).unwrap();
    let handle = Gate::start(&instance_dir, &config_path, &profile, "r8-probe", 17896).unwrap();
    Rig { profile, config_path, instance_dir, handle: Some(handle) }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.handle = None; // drop handle: stop server, remove record
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}

fn restart_gate(rig: &mut Rig) -> GateRecord {
    rig.handle = None;
    std::fs::create_dir_all(&rig.instance_dir).unwrap();
    let handle =
        Gate::start(&rig.instance_dir, &rig.config_path, &rig.profile, "r8-probe", 17896).unwrap();
    let record = handle.record.clone();
    rig.handle = Some(handle);
    record
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
    let value: serde_json::Value =
        serde_json::from_slice(&raw[split + 4..]).map_err(|e| e.to_string())?;
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

fn write_config(rig: &Rig, policy: Option<Policy>, bump_revision: bool) {
    let mut config = creance_vm::config::load(&rig.config_path).unwrap();
    if let Some(p) = policy {
        config.exit_policy = p;
    }
    if bump_revision {
        let mut store = creance_proxy::load(&rig.profile).unwrap();
        store.revision = creance_proxy::token();
        creance_proxy::save(&rig.profile, &store).unwrap();
        config.proxy_revision = store.revision.clone();
    }
    creance_vm::config::write_private_config(&rig.config_path, &config).unwrap();
}

fn sync_and_report(
    rig: &Rig,
    record: &GateRecord,
    label: &str,
    expect_closed: bool,
) {
    let client = GateClient::open(&rig.instance_dir).unwrap();
    let sync = client.sync_proxy_revision();
    let (_, st) = get_status(record).unwrap();
    match &sync {
        Ok(_) => check(
            &format!("{label}: sync=200, gate 状态={}", if expect_closed { "closed（Adopted）" } else { "open（Unchanged）" }),
            st["state"] == if expect_closed { "closed" } else { "open" },
            &st.to_string(),
        ),
        Err(e) => check(
            &format!("{label}: sync=Err, gate 已关闭"),
            expect_closed && st["state"] == "closed",
            &format!("{e} / {st}"),
        ),
    }
}

// ---------------------------------------------------------------- H1

fn h1_f041_matrix() {
    println!("H1 F-041 修复面：Unchanged 路径全矩阵（真实 Gate + GateClient，基线 985a5a2）");

    // r1 = r7 的 m1 回归：bound→bound 换锚 + revision 不动。修复后预测：Err → closed。
    let rig = prepare("r1-bound-swap");
    {
        let record = rig.handle.as_ref().unwrap().record.clone();
        open_gate(&rig, &record);
        write_config(
            &rig,
            Some(Policy {
                mode: "dynamic".to_owned(),
                scope: "country".to_owned(),
                ip: String::new(),
                country_code: "JP".to_owned(),
                region: String::new(),
                city: String::new(),
            }),
            false,
        );
        sync_and_report(&rig, &record, "r1 bound→bound 换锚+revision 不动（预测 fail-closed）", true);
    }

    // r2 = m4 回归：干净幂等 → Unchanged，Open 保持（修复意图）。
    let rig = prepare("r2-clean");
    {
        let record = rig.handle.as_ref().unwrap().record.clone();
        open_gate(&rig, &record);
        sync_and_report(&rig, &record, "r2 干净幂等（预测 Unchanged，Open 保持）", false);
    }

    // r3 部分绑定·幂等：起点=needs_binding（dynamic/region/cc 空），原样重写。
    // 预测：Unchanged，Open 保持（branch 1，normalized 相等）。
    let mut rig = prepare("r3-partial-idem");
    {
        write_config(
            &rig,
            Some(Policy {
                mode: "dynamic".to_owned(),
                scope: "region".to_owned(),
                ip: String::new(),
                country_code: String::new(),
                region: String::new(),
                city: String::new(),
            }),
            false,
        );
        let record = restart_gate(&mut rig);
        open_gate(&rig, &record);
        write_config(
            &rig,
            Some(Policy {
                mode: "dynamic".to_owned(),
                scope: "region".to_owned(),
                ip: String::new(),
                country_code: String::new(),
                region: String::new(),
                city: String::new(),
            }),
            false,
        );
        sync_and_report(&rig, &record, "r3 部分绑定·原样重写（预测 Unchanged，Open 保持）", false);
    }

    // r4 部分绑定·填一格仍欠：cc 空→US，region 仍空（仍 needs_binding）。
    // 预测：branch 1，normalized 不同 → Err → closed。
    let mut rig = prepare("r4-partial-fill");
    {
        write_config(
            &rig,
            Some(Policy {
                mode: "dynamic".to_owned(),
                scope: "region".to_owned(),
                ip: String::new(),
                country_code: String::new(),
                region: String::new(),
                city: String::new(),
            }),
            false,
        );
        let record = restart_gate(&mut rig);
        open_gate(&rig, &record);
        write_config(
            &rig,
            Some(Policy {
                mode: "dynamic".to_owned(),
                scope: "region".to_owned(),
                ip: String::new(),
                country_code: "US".to_owned(),
                region: String::new(),
                city: String::new(),
            }),
            false,
        );
        sync_and_report(&rig, &record, "r4 部分绑定·填 cc 仍欠 region（预测 Err→closed）", true);
    }

    // r5 绑定完成：dynamic/country cc 空→US（needs_binding→bound，mode/scope 同）。
    // 预测：binding_completed → Adopted → closed。
    let mut rig = prepare("r5-bind-complete");
    {
        write_config(
            &rig,
            Some(Policy {
                mode: "dynamic".to_owned(),
                scope: "country".to_owned(),
                ip: String::new(),
                country_code: String::new(),
                region: String::new(),
                city: String::new(),
            }),
            false,
        );
        let record = restart_gate(&mut rig);
        open_gate(&rig, &record);
        write_config(
            &rig,
            Some(Policy {
                mode: "dynamic".to_owned(),
                scope: "country".to_owned(),
                ip: String::new(),
                country_code: "US".to_owned(),
                region: String::new(),
                city: String::new(),
            }),
            false,
        );
        sync_and_report(&rig, &record, "r5 绑定完成 cc 空→US（预测 Adopted→closed）", true);
    }

    // r6 等价锚：bound cc=US → raw cc="us"（write_private_config 不 normalize，
    // load 时归一为 US）。预测：normalized 全等 → Unchanged，Open 保持。
    let rig = prepare("r6-equiv-anchor");
    {
        let record = rig.handle.as_ref().unwrap().record.clone();
        open_gate(&rig, &record);
        // 直接写 JSON（绕开 write_private_config 的校验也无妨——load 才是归一点），
        // 但保持文件合法：手写 serde_json。
        let mut config = creance_vm::config::load(&rig.config_path).unwrap();
        config.exit_policy.country_code = "us".to_owned();
        let bytes = serde_json::to_vec_pretty(&config).unwrap();
        std::fs::write(&rig.config_path, bytes).unwrap();
        sync_and_report(&rig, &record, "r6 等价锚 raw=us（预测归一后 Unchanged，Open 保持）", false);
    }

    // r7 un-bind：bound cc=US → cc 清空。预测：branch 1，normalized 不同 → Err → closed。
    let rig = prepare("r7-unbind");
    {
        let record = rig.handle.as_ref().unwrap().record.clone();
        open_gate(&rig, &record);
        write_config(
            &rig,
            Some(Policy {
                mode: "dynamic".to_owned(),
                scope: "country".to_owned(),
                ip: String::new(),
                country_code: String::new(),
                region: String::new(),
                city: String::new(),
            }),
            false,
        );
        sync_and_report(&rig, &record, "r7 un-bind（预测 Err→closed，不许解绑）", true);
    }
}

// ---------------------------------------------------------------- H2

fn fingerprint_outcome(profile: &str, config_path: &str) -> String {
    let probes = creance::escape::host_probes(profile, config_path);
    probes
        .into_iter()
        .find(|p| p.id == "fingerprint-consistent")
        .map(|p| match p.outcome {
            creance::escape::Outcome::Contained => "Contained".to_owned(),
            creance::escape::Outcome::Escaped(e) => format!("Escaped({e})"),
            creance::escape::Outcome::NotEnforced => "NotEnforced".to_owned(),
        })
        .unwrap_or_else(|| "MISSING".to_owned())
}

fn h2_f040_stamp() {
    println!("H2 F-040 修复面：guest_fingerprint 承诺面 + up 刷戳的假绿面（纯 host 侧）");
    let profile = std::env::temp_dir()
        .join(format!("r8-stamp-{}", creance_proxy::token()[..12].to_owned()))
        .to_string_lossy()
        .into_owned();
    let config_path = creance_vm::paths::join(&profile, "config.json");
    std::fs::create_dir_all(&profile).unwrap();
    let mut config = creance_vm::config::default_config();
    config.proxy_url = "socks5://127.0.0.1:17896".to_owned();
    creance_vm::config::write_private_config(&config_path, &config).unwrap();

    // 模拟 setup：写 setup 戳 = 当时的 guest fingerprint。
    let stamp = creance_vm::paths::join(&creance_vm::vm::state_dir(&profile), "fingerprint.txt");
    std::fs::create_dir_all(creance_vm::vm::state_dir(&profile)).unwrap();
    std::fs::write(&stamp, config.guest_fingerprint()).unwrap();
    check(
        "h2.0 setup 后探针=Contained（承诺一致）",
        fingerprint_outcome(&profile, &config_path) == "Contained",
        &fingerprint_outcome(&profile, &config_path),
    );

    // 对照 1：host 侧字段变化（revision/proxy_url/exit_policy）→ 探针保持绿（修复意图）。
    let mut cfg = creance_vm::config::load(&config_path).unwrap();
    cfg.proxy_revision = "rev-2".to_owned();
    cfg.exit_policy.country_code = "JP".to_owned();
    creance_vm::config::write_private_config(&config_path, &cfg).unwrap();
    check(
        "h2.1 host 侧变化（revision+锚点）→ 探针保持绿（F-040 修复意图）",
        fingerprint_outcome(&profile, &config_path) == "Contained",
        &fingerprint_outcome(&profile, &config_path),
    );

    // guest 侧字段变化 → 探针红（诚实）。
    let mut cfg = creance_vm::config::load(&config_path).unwrap();
    cfg.timezone = "Asia/Tokyo".to_owned();
    creance_vm::config::write_private_config(&config_path, &cfg).unwrap();
    let honest = fingerprint_outcome(&profile, &config_path);
    check("h2.2 guest 侧变化（timezone）→ 探针红（诚实）", honest.starts_with("Escaped"), &honest);

    // 模拟 up 的无条件刷新（refresh_fingerprint_stamp）→ 再观测。
    // guest 从未重供给（本探针无 VM，与真实 stop→edit→up 的语义一致：limactl start
    // 不重跑 provision）。若观测=Contained → 假绿实证（F-044 成立）。
    let cfg = creance_vm::config::load(&config_path).unwrap();
    creance::escape::refresh_fingerprint_stamp(&profile, &cfg).unwrap();
    let after = fingerprint_outcome(&profile, &config_path);
    println!("        up 刷戳后探针 = {after}");
    check(
        "h2.3 预测：刷戳后探针红（诚实——guest 未重供给）；若绿=F-044 假绿成立",
        after.starts_with("Escaped"),
        &after,
    );

    let _ = std::fs::remove_dir_all(&profile);
}

// ---------------------------------------------------------------- H3

fn h3_f043_close() {
    println!("H3 F-043 修复面：close_gates 对在服 gate 撤销 + 死记录清理（真实 gate）");
    let mut rig = prepare("h3-close");
    {
        let record = rig.handle.as_ref().unwrap().record.clone();
        open_gate(&rig, &record);
        let (_, st) = get_status(&record).unwrap();
        check("h3.0 前置：gate Open", st["state"] == "open", &st.to_string());
        // 模拟 cmd_proxy_select / workbench select 的同步撤销。
        let result = creance_gate::gate::close_gates(&rig.profile);
        let (_, st) = get_status(&record).unwrap();
        check(
            "h3.1 select 后 close_gates → Ok 且 gate closed",
            result.is_ok() && st["state"] == "closed",
            &format!("{result:?} / {st}"),
        );
    }
    // 死记录：无守护的 cage-gate.json → close_gates 清理并 Ok。
    rig.handle = None;
    std::fs::create_dir_all(&rig.instance_dir).unwrap();
    std::fs::write(
        creance_vm::paths::join(&rig.instance_dir, "cage-gate.json"),
        r#"{"stale":true}"#,
    )
    .unwrap();
    let result = creance_gate::gate::close_gates(&rig.profile);
    let cleaned = !Path::new(&creance_vm::paths::join(&rig.instance_dir, "cage-gate.json")).exists();
    check(
        "h3.2 死记录被 close_gates 清理",
        result.is_ok() && cleaned,
        &format!("{result:?} / cleaned={cleaned}"),
    );
}

// ---------------------------------------------------------------- H4

/// 假核心：在 socket(profile) 上应答 check_running 查询集内的自述。
/// `rules` 只用于探针自己的叙事——check_running 从不请求 /rules。
fn fake_core_answer(profile: &str, mode: &str, selected: &str) -> (std::thread::JoinHandle<()>, Arc<Mutex<Vec<String>>>)
{
    let sock_path = creance_proxy::socket(profile);
    let dir = Path::new(&sock_path).parent().unwrap().to_path_buf();
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::remove_file(&sock_path);
    let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_t = seen.clone();
    let mode = mode.to_owned();
    let selected = selected.to_owned();
    let handle = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if std::time::Instant::now() > deadline {
                return;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut raw = Vec::new();
                    let _ = stream.read_to_end(&mut raw);
                    let text = String::from_utf8_lossy(&raw).into_owned();
                    let path = text
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or_default()
                        .to_owned();
                    seen_t.lock().unwrap().push(path.clone());
                    let body = match path.split('?').next().unwrap_or(&path) {
                        "/configs" => serde_json::json!({
                            "mixed-port": 17896u64,
                            "interface-name": "en0",
                            "mode": mode,
                            "unified-delay": true,
                        }),
                        p if p.starts_with("/proxies/") => serde_json::json!({ "now": selected }),
                        _ => serde_json::json!({}),
                    };
                    let payload = body.to_string();
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                            payload.len()
                        )
                        .as_bytes(),
                    );
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(_) => return,
            }
        }
    });
    (handle, seen)
}

fn h4_f042_check_running() {
    println!("H4 F-042 残余：check_running 的对账=对核心自述的对账（假核心在环）");
    let profile = std::env::temp_dir()
        .join(format!("r8-core-{}", creance_proxy::token()[..12].to_owned()))
        .to_string_lossy()
        .into_owned();
    std::fs::create_dir_all(creance_proxy::dir(&profile)).unwrap();
    let mut store = creance_proxy::load(&profile).unwrap();
    store.port = 17896;
    store.auth = creance_proxy::token();
    store.selected = "id-exit".to_owned();
    store.revision = "rev".to_owned();
    creance_proxy::save(&profile, &store).unwrap();
    // 生成的运行配置含 interface-name（对账基线从磁盘 config.yaml 读）。
    std::fs::write(
        creance_vm::paths::join(&creance_proxy::dir(&profile), "config.yaml"),
        "interface-name: en0\nmode: rule\n",
    )
    .unwrap();

    // 变体 A（残余面）：核心自述完全合规——mode=rule、同端口、同 interface、
    // unified-delay、组选择=selected。这正是"规则级翻转重载"（rules: MATCH,DIRECT
    // 或 MATCH,evil-chain，保 mode=rule + 保留名为 CAGE 的 selector 并预选回
    // store.selected）在 /configs 与 /proxies/CAGE 上的自述形态。
    let (handle, seen) = fake_core_answer(&profile, "rule", &store.selected);
    std::thread::sleep(std::time::Duration::from_millis(100));
    let result = creance_proxy::service::check_running(&profile, &store);
    let rules_asked = seen
        .lock()
        .unwrap()
        .iter()
        .any(|p| p.starts_with("/rules"));
    check(
        "h4.1 预测：规则级翻转形态的自述通过对账（对账集盲区）",
        result.is_ok(),
        &format!("{result:?}"),
    );
    check(
        "h4.2 预测：对账从未查询 /rules（盲区实证）",
        !rules_asked,
        &format!("queries={:?}", seen.lock().unwrap()),
    );
    drop(handle);

    // 负对照：mode=direct 自述（F-042 已记录的 PATCH 攻击形态）→ 被拒。
    let (handle, _) = fake_core_answer(&profile, "direct", &store.selected);
    std::thread::sleep(std::time::Duration::from_millis(100));
    let result = creance_proxy::service::check_running(&profile, &store);
    check(
        "h4.3 预测：mode=direct 自述被拒（night-09 修复对已记录攻击有效）",
        result.is_err(),
        &format!("{result:?}"),
    );
    drop(handle);
    let _ = std::fs::remove_dir_all(&profile);
    let _ = std::fs::remove_file(creance_proxy::socket(&profile));
    let _ = std::fs::remove_dir_all(Path::new(&creance_proxy::socket(&profile)).parent().unwrap());
}

fn main() {
    if maybe_daemon() {
        return;
    }
    h1_f041_matrix();
    h2_f040_stamp();
    h3_f043_close();
    h4_f042_check_running();
    std::process::exit(finished());
}
