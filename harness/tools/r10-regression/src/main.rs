//! R10 探针：night-11 修复面纯回归（HEAD c76b2a3 / v0.5.5）。
//! 运行：`cargo run --release`（仓库根，.toolchain 环境）。
//! H1 F-048 形状矩阵 / H2 F-049 探针 stamp 矩阵 / H3 F-050 load 文案。
//!
//! 假核心注意：macOS 上 accept() 的 socket 继承 listener 的 O_NONBLOCK——
//! 必须显式 `set_nonblocking(false)`，否则 write_all 在 ~8KB 处被
//! WouldBlock 截断（r9 同型探针的隐性竞态来源）。

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;

fn main() {
    println!("=== R10 regression: night-11 faces @ v0.5.5 ===");
    h1_rules_judge();
    h2_stamp_probe_matrix();
    h3_store_load_messages();
    println!("=== done ===");
}

// ---------------------------------------------------------------- 基建

/// 假核心：/configs 与 /proxies/{GROUP} 完全合规；/rules 按 (status, body) 应答。
/// 请求读取：读到 \r\n\r\n 为止（api() 的请求恒为 Content-Length: 0 单段写）。
fn fake_core(profile: &str, rules_status: u16, rules_body: String) -> std::thread::JoinHandle<()> {
    let sock_path = creance_proxy::socket(profile);
    let dir = Path::new(&sock_path).parent().unwrap().to_path_buf();
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path).unwrap();
    let rules_status = Arc::new(rules_status);
    let rules_body = Arc::new(rules_body);
    let handle = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if std::time::Instant::now() > deadline {
                return;
            }
            let mut stream = match listener.accept() {
                Ok((s, _)) => s,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    continue;
                }
                Err(_) => return,
            };
            stream.set_nonblocking(false).unwrap();
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        raw.extend_from_slice(&buf[..n]);
                        if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let text = String::from_utf8_lossy(&raw).into_owned();
            let path = text
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or_default()
                .to_owned();
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            let (status, payload) = match path.split('?').next().unwrap_or(&path) {
                "/configs" => (
                    200u16,
                    serde_json::json!({
                        "mixed-port": 17896u64,
                        "interface-name": "en0",
                        "mode": "rule",
                        "unified-delay": true,
                    })
                    .to_string(),
                ),
                p if p.starts_with("/proxies/") => {
                    (200u16, serde_json::json!({ "now": "id-exit" }).to_string())
                }
                "/rules" => ((*rules_status).clone(), (*rules_body).clone()),
                _ => (200u16, serde_json::json!({}).to_string()),
            };
            let reason = match status {
                200 => "OK",
                299 => "WHATEVER",
                401 => "Unauthorized",
                404 => "Not Found",
                _ => "Hm",
            };
            let resp = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
            drop(stream);
        }
    });
    handle
}

fn honest_store_fixture(tag: &str) -> String {
    let profile = std::env::temp_dir()
        .join(format!("r10-{tag}-{}", creance_proxy::token()[..12].to_owned()))
        .to_string_lossy()
        .into_owned();
    std::fs::create_dir_all(creance_proxy::dir(&profile)).unwrap();
    let mut store = creance_proxy::load(&profile).unwrap();
    store.port = 17896;
    store.auth = creance_proxy::token();
    store.selected = "id-exit".to_owned();
    store.revision = "rev".to_owned();
    creance_proxy::save(&profile, &store).unwrap();
    std::fs::write(
        creance_vm::paths::join(&creance_proxy::dir(&profile), "config.yaml"),
        "interface-name: en0\nmode: rule\n",
    )
    .unwrap();
    profile
}

fn live_shape() -> String {
    // F-048 夹具：实机捕获的 v1.19.x 响应原样。
    r#"{"rules":[{"index":0,"type":"Match","payload":"","proxy":"CAGE","size":-1,"extra":{"disabled":false,"hitCount":0}}]}"#.to_owned()
}

enum Expect {
    Ok,
    ErrSome(&'static str),
    ErrOther,
}
impl std::fmt::Display for Expect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expect::Ok => write!(f, "Ok"),
            Expect::ErrSome(s) => write!(f, "Err~{s}"),
            Expect::ErrOther => write!(f, "Err(*)"),
        }
    }
}

fn h1_rules_judge() {
    println!("\n-- H1 F-048 修复面：honest_routing 判定矩阵 + api() 传播 --");
    let cases: Vec<(&str, u16, String, Expect)> = vec![
        ("h1.1 实机形状（包装对象）", 200, live_shape(), Expect::Ok),
        (
            "h1.2 实机形状+顶层多余字段",
            200,
            format!(
                "{}{}",
                r#"{"latest":true,"rules-total":1,"#,
                r#""rules":[{"type":"Match","payload":"","proxy":"CAGE"}]}"#
            ),
            Expect::Ok,
        ),
        (
            "h1.3 规则翻转 DIRECT",
            200,
            r#"{"rules":[{"type":"Match","payload":"","proxy":"DIRECT"}]}"#.to_owned(),
            Expect::ErrSome("readiness: rules"),
        ),
        (
            "h1.4 夹带第二条规则",
            200,
            r#"{"rules":[{"type":"Match","proxy":"CAGE"},{"type":"Match","proxy":"DIRECT"}]}"#
                .to_owned(),
            Expect::ErrSome("readiness: rules"),
        ),
        (
            "h1.5 裸数组（night-10 误猜形状）",
            200,
            r#"[{"type":"Match","proxy":"CAGE"}]"#.to_owned(),
            Expect::ErrSome("readiness: rules"),
        ),
        (
            "h1.6 缺 rules 键",
            200,
            r#"{"foo":1}"#.to_owned(),
            Expect::ErrSome("readiness: rules"),
        ),
        (
            "h1.7 rules 为字符串",
            200,
            r#"{"rules":"Match,CAGE"}"#.to_owned(),
            Expect::ErrSome("readiness: rules"),
        ),
        (
            "h1.8 rules 为对象",
            200,
            r#"{"rules":{"type":"Match","proxy":"CAGE"}}"#.to_owned(),
            Expect::ErrSome("readiness: rules"),
        ),
        (
            "h1.9 rules 为 null",
            200,
            r#"{"rules":null}"#.to_owned(),
            Expect::ErrSome("readiness: rules"),
        ),
        (
            "h1.10 空数组",
            200,
            r#"{"rules":[]}"#.to_owned(),
            Expect::ErrSome("readiness: rules"),
        ),
        (
            "h1.11 首规则缺 proxy",
            200,
            r#"{"rules":[{"type":"Match"}]}"#.to_owned(),
            Expect::ErrSome("readiness: rules"),
        ),
        (
            "h1.12 type 大小写翻转为 match",
            200,
            r#"{"rules":[{"type":"match","proxy":"CAGE"}]}"#.to_owned(),
            Expect::ErrSome("readiness: rules"),
        ),
        (
            "h1.13 proxy 小写 cage",
            200,
            r#"{"rules":[{"type":"Match","proxy":"cage"}]}"#.to_owned(),
            Expect::ErrSome("readiness: rules"),
        ),
        (
            "h1.14 首规则是非对象标量",
            200,
            r#"{"rules":["Match,CAGE"]}"#.to_owned(),
            Expect::ErrSome("readiness: rules"),
        ),
        (
            "h1.15 1000 条诚实规则（超长数组）",
            200,
            {
                let mut s = String::from(r#"{"rules":["#);
                for _ in 0..1000 {
                    s.push_str(r#"{"type":"Match","proxy":"CAGE"},"#);
                }
                s.push_str(r#"{"type":"Match","proxy":"CAGE"}]}"#);
                s
            },
            Expect::ErrOther, // len==1 不满足 → 拒；任何 Err 都是 fail-closed
        ),
        (
            "h1.16 401 Unauthorized",
            401,
            r#"{"message":"Unauthorized"}"#.to_owned(),
            Expect::ErrSome("HTTP 401"),
        ),
        (
            "h1.17 404 Not Found",
            404,
            r#"{"message":"not found"}"#.to_owned(),
            Expect::ErrSome("HTTP 404"),
        ),
        (
            "h1.18 200 非 JSON 体",
            200,
            "<html>gateway error</html>".to_owned(),
            Expect::ErrOther,
        ),
        (
            "h1.19 200 体 >1MiB（take 截断→JSON 残缺）",
            200,
            format!(
                r#"{{"rules":[{{"type":"Match","proxy":"CAGE"}}],"pad":"{}"#,
                "A".repeat(1 << 21)
            ),
            Expect::ErrOther,
        ),
        (
            "h1.20 299 状态码（200..300 宽容边界）",
            299,
            live_shape(),
            Expect::Ok,
        ),
        (
            "h1.21 199 状态码（拒绝边界）",
            199,
            live_shape(),
            Expect::ErrSome("HTTP 199"),
        ),
    ];
    for (name, status, body, expect) in cases {
        let profile = honest_store_fixture(&name.replace(['.', ' '], "-"));
        let h = fake_core(&profile, status, body);
        std::thread::sleep(std::time::Duration::from_millis(120));
        let store = creance_proxy::load(&profile).unwrap();
        let r = creance_proxy::service::check_running(&profile, &store);
        let pass = match &expect {
            Expect::Ok => r.is_ok(),
            Expect::ErrSome(s) => r.as_ref().err().map(|e| e.contains(s)) == Some(true),
            Expect::ErrOther => r.is_err(),
        };
        println!(
            "{name:<44} 预测={expect:<28} 实际={}  {}",
            match &r {
                Ok(_) => "Ok".to_owned(),
                Err(e) => format!("Err({e})"),
            },
            if pass { "PASS" } else { "FAIL ←←←" }
        );
        drop(h);
        let _ = std::fs::remove_dir_all(&profile);
        let _ = std::fs::remove_file(creance_proxy::socket(&profile));
    }
}

// ---------------------------------------------------------------- H2

fn fresh_cage_profile(tag: &str) -> (String, String) {
    let dir = std::env::temp_dir().join(format!(
        "r10-cage-{tag}-{}",
        creance_vm::token()[..12].to_owned()
    ));
    let profile = dir.to_string_lossy().into_owned();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(creance_proxy::dir(&profile)).unwrap();
    let config_path = creance_vm::paths::join(&profile, "config.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&creance_vm::config::default_config()).unwrap(),
    )
    .unwrap();
    (profile, config_path)
}

fn fp_probe(profile: &str, config_path: &str) -> creance::escape::Outcome {
    creance::escape::host_probes(profile, config_path)
        .into_iter()
        .find(|p| p.id == "fingerprint-consistent")
        .unwrap()
        .outcome
}

fn write_fake_limactl(instance: &str, status: &str) -> String {
    let bin_dir = std::env::temp_dir().join(format!(
        "r10-fakebin-{}-{status}",
        creance_vm::token()[..8].to_owned()
    ));
    std::fs::create_dir_all(&bin_dir).unwrap();
    let script = bin_dir.join("limactl");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\necho \"{{\\\"name\\\":\\\"{instance}\\\",\\\"status\\\":\\\"{status}\\\"}}\"\n"
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    bin_dir.to_string_lossy().into_owned()
}

fn h2_stamp_probe_matrix() {
    println!("\n-- H2 F-049 修复面：探针 stamp 异常态矩阵（假 limactl 控制 Running）--");

    // h2.1 stamp 缺失 + 实例不存在（真 limactl，空 LIMA_HOME）→ NotEnforced（virgin 语义）。
    let (profile, config_path) = fresh_cage_profile("missing-stopped");
    let state = creance_vm::vm::state_dir(&profile);
    std::fs::create_dir_all(&state).unwrap();
    let o = fp_probe(&profile, &config_path);
    println!(
        "h2.1 stamp 缺失 + 实例不存在                  预测=NotEnforced  实际={o:?}  {}",
        if matches!(o, creance::escape::Outcome::NotEnforced) { "PASS" } else { "FAIL ←←←" }
    );

    // h2.2 stamp 缺失 + 假 limactl 报 Running → Escaped（F-049 修复主分支）。
    let instance =
        creance_vm::vm::instance_name(&profile, &creance_vm::vm::environment_dir(&profile));
    let fakebin_run = write_fake_limactl(&instance, "Running");
    let old_path = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("{fakebin_run}:{old_path}"));
    let o = fp_probe(&profile, &config_path);
    println!(
        "h2.2 stamp 缺失 + limactl 报 Running           预测=Escaped      实际={o:?}  {}",
        if matches!(&o, creance::escape::Outcome::Escaped(m) if m.contains("stamp missing")) {
            "PASS ← 修复分支生效"
        } else {
            "FAIL ←←←"
        }
    );

    // h2.3 stamp 缺失 + 假 limactl 报 Stopped → 预测 NotEnforced（运行态判定只认 Running）。
    let fakebin_stop = write_fake_limactl(&instance, "Stopped");
    std::env::set_var("PATH", format!("{fakebin_stop}:{old_path}"));
    let o = fp_probe(&profile, &config_path);
    println!(
        "h2.3 stamp 缺失 + limactl 报 Stopped           预测=NotEnforced  实际={o:?}  {}（观察：已存在但停止的实例缺失 stamp 也是 NotEnforced——修复注释称 only never-set-up，与代码略有出入）",
        if matches!(o, creance::escape::Outcome::NotEnforced) { "PASS" } else { "FAIL ←←←" }
    );
    std::env::set_var("PATH", old_path);
    let _ = std::fs::remove_dir_all(&profile);
    let _ = std::fs::remove_dir_all(&fakebin_run);
    let _ = std::fs::remove_dir_all(&fakebin_stop);

    // h2.4 stamp=目录 → exists() 真 → 读 Err → Escaped。
    let (profile, config_path) = fresh_cage_profile("stamp-dir");
    let cfg = creance_vm::config::load(&config_path).unwrap();
    let state = creance_vm::vm::state_dir(&profile);
    std::fs::create_dir_all(&state).unwrap();
    let stamp = creance_vm::paths::join(&state, "fingerprint.txt");
    std::fs::create_dir_all(&stamp).unwrap();
    let o = fp_probe(&profile, &config_path);
    println!(
        "h2.4 stamp=目录                               预测=Escaped      实际={o:?}  {}",
        if matches!(o, creance::escape::Outcome::Escaped(_)) {
            "PASS（读失败 fail-closed）"
        } else {
            "FAIL ←←←"
        }
    );

    // h2.5 stamp 不可读（chmod 000）→ Escaped。
    std::fs::remove_dir_all(&stamp).unwrap();
    std::fs::write(&stamp, cfg.guest_fingerprint()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stamp, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    let o = fp_probe(&profile, &config_path);
    println!(
        "h2.5 stamp chmod 000                          预测=Escaped      实际={o:?}  {}",
        if matches!(o, creance::escape::Outcome::Escaped(_)) { "PASS" } else { "FAIL ←←←" }
    );

    // h2.6 stamp 非 UTF-8 → Escaped。
    std::fs::remove_file(&stamp).unwrap();
    std::fs::write(&stamp, [0xFFu8, 0xFE, 0x00, 0xDD]).unwrap();
    let o = fp_probe(&profile, &config_path);
    println!(
        "h2.6 stamp 非 UTF-8 字节                      预测=Escaped      实际={o:?}  {}",
        if matches!(o, creance::escape::Outcome::Escaped(_)) { "PASS" } else { "FAIL ←←←" }
    );

    // h2.7 漂移 + stamp 在 → Escaped；escape-test 退出码非零（洗绿闭环确认关闭）。
    std::fs::write(&stamp, cfg.guest_fingerprint()).unwrap();
    let mut drifted = cfg.clone();
    drifted.timezone = "Asia/Tokyo".to_owned();
    creance_vm::config::write_private_config(&config_path, &drifted).unwrap();
    let probes = creance::escape::host_probes(&profile, &config_path);
    let o = fp_probe(&profile, &config_path);
    let exit = creance::escape::report(&probes);
    println!(
        "h2.7 漂移+stamp 在 → Escaped；exit={exit:<2}    预测=Escaped/非零  实际={o:?}  {}",
        if matches!(o, creance::escape::Outcome::Escaped(_)) && exit != 0 { "PASS" } else { "FAIL ←←←" }
    );
    let _ = std::fs::remove_dir_all(&profile);
}

// ---------------------------------------------------------------- H3

fn h3_store_load_messages() {
    println!("\n-- H3 F-050 修复面：load Err 文案（信息泄露检查：无路径无 serde 细节）--");
    // a) corrupt JSON
    let (profile, _) = fresh_cage_profile("h3a");
    let store_path = creance_vm::paths::join(&creance_proxy::dir(&profile), "sources.json");
    std::fs::write(&store_path, b"{{{not-json").unwrap();
    let e = creance_proxy::load(&profile).unwrap_err();
    println!(
        "h3.1 corrupt JSON    Err=「{e}」 {}",
        if e == "Cage 代理配置无效，请恢复私有配置备份" && !e.contains('/') {
            "PASS（恒定串，无路径）"
        } else {
            "FAIL ←←← 文案漂移或泄露"
        }
    );
    let _ = std::fs::remove_dir_all(&profile);

    // b) oversize（>32MiB）
    let (profile, _) = fresh_cage_profile("h3b");
    let store_path = creance_vm::paths::join(&creance_proxy::dir(&profile), "sources.json");
    std::fs::write(&store_path, vec![b'a'; (32 << 20) + 1]).unwrap();
    let e = creance_proxy::load(&profile).unwrap_err();
    println!(
        "h3.2 >32MiB          Err=「{e}」 {}",
        if e == "Cage 代理配置无效，请恢复私有配置备份" { "PASS" } else { "FAIL ←←←" }
    );
    let _ = std::fs::remove_dir_all(&profile);

    // c) 合法 JSON 但 version=2
    let (profile, _) = fresh_cage_profile("h3c");
    let store_path = creance_vm::paths::join(&creance_proxy::dir(&profile), "sources.json");
    std::fs::write(
        &store_path,
        br#"{"version":2,"port":17896,"auth":"000000000000000000000000000000000000000000000000"}"#,
    )
    .unwrap();
    let e = creance_proxy::load(&profile).unwrap_err();
    println!(
        "h3.3 version=2       Err=「{e}」 {}",
        if e == "Cage 代理配置无效，请恢复私有配置备份" { "PASS" } else { "FAIL ←←←" }
    );
    let _ = std::fs::remove_dir_all(&profile);

    // d) auth 长度错
    let (profile, _) = fresh_cage_profile("h3d");
    let store_path = creance_vm::paths::join(&creance_proxy::dir(&profile), "sources.json");
    std::fs::write(&store_path, br#"{"version":1,"port":17896,"auth":"short"}"#).unwrap();
    let e = creance_proxy::load(&profile).unwrap_err();
    println!(
        "h3.4 auth 长度≠48    Err=「{e}」 {}",
        if e == "Cage 代理配置无效，请恢复私有配置备份" { "PASS" } else { "FAIL ←←←" }
    );
    let _ = std::fs::remove_dir_all(&profile);
}
