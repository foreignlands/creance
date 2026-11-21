//! R6 探针主程序：三个假设各一组断言。全部走真实库函数（parse_trace /
//! Gate::start / GateClient / select_and_apply），不做逻辑复刻。
//! 退出码：0 = 全部观测与预测一致；非 0 = 存在偏离（无论哪种方向都记录）。

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
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

// ---------------------------------------------------------------- H1

fn h1_parse_trace_matrix() {
    println!("H1 parse_trace malformed-body matrix (real fn)");
    use creance::evidence::parse_trace;

    let ok = |s: &str| parse_trace(s).is_ok();

    // 期望 fail-closed 的畸形
    check("BOM-prefixed ip key", !ok("\u{feff}ip=8.8.8.8\nloc=US\n"), "BOM 应使键不匹配→缺 ip→Err");
    check("leading-space key", !ok(" ip=8.8.8.8\nloc=US\n"), "键前导空格→不匹配→Err");
    check("uppercase key IP=", !ok("IP=8.8.8.8\nloc=US\n"), "键大小写敏感→Err");
    check("v6 ip", !ok("ip=2001:db8::1\nloc=US\n"), "v6 不接受");
    check("3-letter loc", !ok("ip=8.8.8.8\nloc=usa\n"), "loc 必须 2 字母");
    check("loc ZZ", ok("ip=8.8.8.8\nloc=ZZ\n"), "ZZ 在 parse 层接受（拒绝在 check_exit_country）");
    check("loc zz lowercase", ok("ip=8.8.8.8\nloc=zz\n"), "小写会 to_ascii_uppercase");
    check("value with trailing junk", !ok("ip=8.8.8.8 x\nloc=US\n"), "值内空格→IPv4 解析失败");
    check("no '=' line only", !ok("garbage\n"), "无 ip/loc→Err");
    check("empty body", !ok(""), "空 body→Err");
    check("unicode loc (non-ascii 2 bytes)", !ok("ip=8.8.8.8\nloc=µs\n"), "µs=3 字节→len!=2→Err");
    // 宽松面（记录，不判安全）
    check("value leading space ok", ok("ip= 8.8.8.8\nloc=US\n"), "值前导空格 trim 后接受（宽松点）");
    check("CRLF ok", ok("ip=8.8.8.8\r\nloc=US\r\n"), "lines() 剥 \r");
    // last-wins 重复键：解析层行为（伪造者本就控制全文，无安全增量）
    let dup = parse_trace("ip=1.1.1.1\nloc=CN\nip=8.8.8.8\nloc=US\n").unwrap();
    check("duplicate keys last-wins", dup.ip == "8.8.8.8" && dup.country_code == "US",
        "重复键后者覆盖前者（攻击者控制全文，无安全增量，仅记录语义）");
    // 大输入：request_bounded 64KiB 截断在传输层；parse 层喂 1MiB 应仍可控
    let big = format!("ip=8.8.8.8\nloc=US\n{}", "x=1\n".repeat(200_000));
    check("huge body parse ok (bounded upstream)", ok(&big), "parse 不设上限（传输层 64KiB 兜底）");
}

// ---------------------------------------------------------------- 公共脚手架

struct Profile {
    dir: PathBuf,
    config_path: PathBuf,
    instance_dir: PathBuf,
}

fn make_profile(tag: &str) -> Profile {
    let dir = std::env::temp_dir().join(format!("r6-probe-{tag}-{}", creance_proxy::token()[..12].to_owned()));
    std::fs::create_dir_all(dir.join("proxy")).unwrap();
    std::fs::create_dir_all(dir.join("lima/inst")).unwrap();
    let mut store = creance_proxy::load(dir.to_str().unwrap()).unwrap();
    let node = |id: &str, server: &str| creance_proxy::Node {
        id: id.to_owned(),
        name: id.to_owned(),
        node_type: "ss".to_owned(),
        config: {
            let mut m = serde_json::Map::new();
            m.insert("server".to_owned(), serde_json::json!(server));
            m.insert("port".to_owned(), serde_json::json!(8388));
            m.insert("cipher".to_owned(), serde_json::json!("aes-128-gcm"));
            m.insert("password".to_owned(), serde_json::json!("x"));
            m
        },
    };
    store.sources.push(creance_proxy::Source {
        id: "src".to_owned(),
        name: "s".to_owned(),
        url: String::new(),
        interval_hours: 0,
        updated_at: String::new(),
        attempted_at: String::new(),
        error: String::new(),
        usage: String::new(),
        nodes: vec![node("node-us", "192.0.2.10"), node("node-cn", "192.0.2.11")],
        skipped: Vec::new(),
    });
    store.selected = "node-us".to_owned();
    store.revision = creance_proxy::token();
    creance_proxy::save(dir.to_str().unwrap(), &store).unwrap();
    let config_path = dir.join("config.json");
    let mut config = creance_vm::config::default_config();
    config.proxy_url = store.endpoint();
    config.proxy_revision = store.revision.clone();
    config.exit_policy.mode = "dynamic".to_owned();
    config.exit_policy.scope = "country".to_owned();
    config.exit_policy.country_code = "JP".to_owned();
    creance_vm::config::write_private_config(config_path.to_str().unwrap(), &config).unwrap();
    Profile {
        instance_dir: dir.join("lima/inst"),
        config_path,
        dir,
    }
}

fn grant_body(check_id: &str, exit_ip: &str, exit_country: &str) -> serde_json::Value {
    let mut c = serde_json::Map::new();
    for k in ["egress_policy", "fail_closed", "udp_policy", "ipv6_policy", "exit_consistency"] {
        c.insert(k.to_owned(), serde_json::json!("passed"));
    }
    c.insert("exit_ip".to_owned(), serde_json::json!(exit_ip));
    c.insert("exit_country".to_owned(), serde_json::json!(exit_country));
    serde_json::json!({
        "action": "grant",
        "report_id": check_id,
        "report": {"report_id": check_id, "checks": c},
    })
}

/// 原始 HTTP over unix socket（自绘头，可控 Authorization）。
fn call_raw(record_socket: &str, token: &str, body: &str) -> Result<(String, serde_json::Value), String> {
    let mut s = UnixStream::connect(record_socket).map_err(|e| e.to_string())?;
    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let req = format!(
        "POST /control HTTP/1.1\r\nHost: gate\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("no header end")?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let code = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1).map(str::to_owned))
        .ok_or("no status line")?;
    let body = serde_json::from_slice(&raw[split + 4..]).unwrap_or(serde_json::json!({}));
    Ok((code, body))
}

fn status_of(record_path: &Path) -> Option<creance_gate::gate::GateStatus> {
    match std::fs::symlink_metadata(record_path) {
        Err(e) => println!("    [status_of] metadata({}): {e}", record_path.display()),
        Ok(m) => println!("    [status_of] metadata({}): {:?} mode={:o}", record_path.display(), m.is_file(), m.permissions().mode()),
    }
    match creance_gate::gate::GateClient::open(record_path.to_str().unwrap()) {
        Err(e) => {
            println!("    [status_of] client open error: {e}");
            None
        }
        Ok(client) => match client.status() {
            Ok(s) => Some(s),
            Err(e) => {
                println!("    [status_of] status error: {e}");
                None
            }
        },
    }
}

// ---------------------------------------------------------------- H2

fn h2_empty_bearer_fail_open() {
    println!("H2 record unreadable → empty-bearer control accepted (Go: in-memory token, never empty)");
    let p = make_profile("h2");
    let handle = creance_gate::gate::Gate::start(
        p.instance_dir.to_str().unwrap(),
        p.config_path.to_str().unwrap(),
        p.dir.to_str().unwrap(),
        "inst",
        17896,
    )
    .unwrap();
    let record_path = p.instance_dir.join("cage-gate.json");
    let record: creance_gate::gate::GateRecord =
        serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();

    // 基线：错 token 拒绝
    let (code, _) = call_raw(&record.socket, "deadbeef", r#"{"action":"check"}"#).unwrap();
    check("wrong token → 403", code == "403", &code);

    // 让 record 不可读（同 uid 可行；daemon 主循环视 unreadable 为 transient → 存活）
    std::fs::set_permissions(&record_path, std::fs::Permissions::from_mode(0o000)).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(600)); // 跨一个主循环 tick

    // 空 Bearer（无凭证）→ record_token() 读不到 → unwrap_or_default → "" == ""
    let (code, body) = call_raw(&record.socket, "", r#"{"action":"check"}"#).unwrap();
    check("empty bearer check accepted", code == "200", &format!("{code} {body}"));

    // 无凭证 grant：check_id 绑定层仍在（伪造 report_id → 409 并关闭）
    let forged = grant_body("forged", "203.0.113.7", "US");
    let (code, body) = call_raw(&record.socket, "", &forged.to_string()).unwrap();
    check("no-token grant with forged window id → refused", code == "409", &format!("{code} {body}"));

    // 完整链：无凭证 → check（响应自带新 check_id）→ grant（五键伪造+该 id）→ Open
    // 注：上一步 409 已把 gate 关掉，这里重新无凭证 check 开新窗口
    let (code, body) = call_raw(&record.socket, "", r#"{"action":"check"}"#).unwrap();
    let leaked_id = body["check_id"].as_str().unwrap_or_default().to_owned();
    let full = grant_body(&leaked_id, "203.0.113.7", "US");
    let (code2, body2) = call_raw(&record.socket, "", &full.to_string()).unwrap();
    check("FULL CHAIN: no token + no evidence → Open (check_id from own check response)",
        code == "200" && code2 == "200" && body2["state"] == serde_json::json!("open"),
        &format!("check={code} grant={code2} {body2}"));

    // status：无 token GET /status 仍泄漏状态面
    let mut s = UnixStream::connect(&record.socket).unwrap();
    let req = "GET /status HTTP/1.1\r\nHost: gate\r\nAuthorization: Bearer \r\nConnection: close\r\n\r\n";
    s.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let head = String::from_utf8_lossy(&raw).into_owned();
    let code = head.lines().next().unwrap_or_default().split_whitespace().nth(1).unwrap_or_default().to_owned();
    check("GET /status empty bearer → 200 (leaks status)", code == "200", &code);

    let _ = handle; // 保持守护活着到探针结束
    std::fs::set_permissions(&record_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let _ = std::fs::remove_dir_all(&p.dir);
}

// ---------------------------------------------------------------- H3

fn h3_exit_drift_detection_gap() {
    println!("H3 exit drift: select_and_apply 换节点后 daemon 逐命令校验仍放行");
    let p = make_profile("h3");
    let handle = creance_gate::gate::Gate::start(
        p.instance_dir.to_str().unwrap(),
        p.config_path.to_str().unwrap(),
        p.dir.to_str().unwrap(),
        "inst",
        17896,
    )
    .unwrap();
    let record_path = p.instance_dir.join("cage-gate.json");
    let record: creance_gate::gate::GateRecord =
        serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
    let client = creance_gate::gate::GateClient::open(p.instance_dir.to_str().unwrap()).unwrap();

    // 正常序列：check → grant（伪造五键=cmd_gate 的实际行为，daemon 无法区分真证据）→ Open
    client.begin_check().unwrap();
    let check_id = client.status().unwrap().check_id;
    let body = grant_body(&check_id, "203.0.113.7", "US");
    let (code, _) = call_raw(&record.socket, &record.token, &body.to_string()).unwrap();
    let st = status_of(&p.instance_dir);
    check("grant → Open", code == "200" && st.as_ref().map(|s| s.state == creance_gate::gate::GateState::Open).unwrap_or(false),
        &format!("{code} state={:?}", st.map(|s| s.state)));

    // 换节点：select_and_apply 轮换 revision 并同步写 config.json → applied() 一致
    let store = match creance_proxy::select_and_apply(p.dir.to_str().unwrap(), p.config_path.to_str().unwrap(), "node-cn") {
        Ok(s) => s,
        Err(e) => {
            check("select_and_apply ok", false, &e);
            drop(handle);
            let _ = std::fs::remove_dir_all(&p.dir);
            return;
        }
    };
    assert_eq!(store.selected, "node-cn");

    // 换节点后的第一个 mutating 命令：daemon 重载 config + applied() —— 预测：不关
    match client.begin_check() {
        Err(e) => check("after switch, begin_check accepted", false, &e),
        Ok(_) => {
            let st = status_of(&p.instance_dir);
            check("after node switch, mutating command still accepted (no drift detection)",
                st.as_ref().map(|s| s.state == creance_gate::gate::GateState::Checking).unwrap_or(false),
                &format!("state={:?}", st.as_ref().map(|s| (s.state.clone(), s.reason.clone()))));
            // 伪造五键再授权 → Open（出口已是 node-cn，无任何新证据）
            if let Some(st) = st {
                let check_id = st.check_id;
                let body2 = grant_body(&check_id, "203.0.113.7", "US");
                let (code, _) = call_raw(&record.socket, &record.token, &body2.to_string()).unwrap();
                let after = status_of(&p.instance_dir);
                check("re-grant after switch → Open (anchor never re-evidenced)",
                    code == "200" && after.as_ref().map(|s| s.state == creance_gate::gate::GateState::Open).unwrap_or(false),
                    &format!("{code} state={:?}", after.map(|s| s.state)));
            }
        }
    }

    // 对照组：显式 proxy-revision 能察觉并关闭（revision 变更 → adopt → Closed）
    let sync = client.sync_proxy_revision();
    check("explicit proxy-revision closes the gate",
        sync.as_ref().map(|s| s.state == creance_gate::gate::GateState::Closed).unwrap_or(false),
        &format!("{:?}", sync.map(|s| s.state)));

    // C5 预埋分支实测修正：action 层对 Ok/Err 都无条件 close（gate.rs:607-619）——
    // 函数级 "Nothing to adopt: the gate keeps its state" 注释与 action 行为矛盾；
    // 锚定 JP→US（revision 不动）→ Ok → 仍 Closed。fail-closed 方向，但幂等
    // no-change sync 也关 gate（每次 proxy-start 强制重取证）。
    client.begin_check().unwrap();
    let check_id = client.status().unwrap().check_id;
    let body3 = grant_body(&check_id, "203.0.113.7", "US");
    let (code, _) = call_raw(&record.socket, &record.token, &body3.to_string()).unwrap();
    let mut cfg3 = creance_vm::config::load(p.config_path.to_str().unwrap()).unwrap();
    cfg3.exit_policy.country_code = "US".to_owned();
    creance_vm::config::write_private_config(p.config_path.to_str().unwrap(), &cfg3).unwrap();
    let sync2 = client.sync_proxy_revision();
    let st2 = status_of(&p.instance_dir);
    check("ANCHOR SWAP JP->US (no revision change): action closes gate even on Ok (comment mismatch, fail-closed)",
        code == "200" && sync2.is_ok()
            && st2.as_ref().map(|s| s.state == creance_gate::gate::GateState::Closed).unwrap_or(false),
        &format!("grant={code} sync={} state={:?}",
            sync2.map(|s| format!("{:?}", s.state)).unwrap_or_else(|e| e),
            st2.map(|s| s.state)));

    drop(handle);
    let _ = std::fs::remove_dir_all(&p.dir);
}

// ---------------------------------------------------------------- H4

fn h4_fingerprint_covers_proxy_fields() {
    println!("H4 fingerprint() 覆盖 proxy 字段：合法 select 也会漂移 setup 戳（探针恒红前提）");
    let p = make_profile("h4");
    let cfg1 = creance_vm::config::load(p.config_path.to_str().unwrap()).unwrap();
    let f1 = cfg1.fingerprint();
    let store = creance_proxy::select_and_apply(p.dir.to_str().unwrap(), p.config_path.to_str().unwrap(), "node-cn").unwrap();
    let cfg2 = creance_vm::config::load(p.config_path.to_str().unwrap()).unwrap();
    let f2 = cfg2.fingerprint();
    check("select_and_apply rotates fingerprint (stamp F1 != current F2)", f1 != f2,
        &format!("F1={} F2={}", &f1[..8], &f2[..8]));
    // 对照：guest 可见字段（timezone/locale）才是"VM 承诺"的本体——它们没变
    check("guest-visible fields unchanged by select", cfg1.timezone == cfg2.timezone && cfg1.locale == cfg2.locale,
        "探针把纯宿主侧变化（proxy_url/revision）也计入承诺 → escape-test 误报 Escaped");
    let _ = store;
    let _ = std::fs::remove_dir_all(&p.dir);
}

fn main() {
    h1_parse_trace_matrix();
    h2_empty_bearer_fail_open();
    h3_exit_drift_detection_gap();
    h4_fingerprint_covers_proxy_fields();
    std::process::exit(finished());
}
