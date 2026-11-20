//! R9 探针：night-10 修复面纯回归（HEAD 35a02f8 / v0.5.4）。
//! 运行：`cargo run --release`（仓库根，.toolchain 环境）。
//! H1 形状在环 / H2 stamp 矩阵 / H3 事务库侧件 / H4 fail-open 输入 / H5 白名单。

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::{Arc, Mutex};

fn main() {
    println!("=== R9 regression: night-10 faces @ v0.5.4 ===");
    h1_rules_shape();
    h2_stamp_matrix();
    h3_transactional_pieces();
    h4_failopen_inputs();
    h5_whitelist_injection();
    println!("=== done ===");
}

// ---------------------------------------------------------------- H1

/// 假核心：/configs 与 /proxies/{GROUP} 完全合规，/rules 形状可选
/// （wrapped = 真实 mihomo 形状（2026-11-20 冒烟锚定）/ bare = 修复自己的假设）。
fn fake_core(profile: &str, rules_wrapped: bool) -> std::thread::JoinHandle<()> {
    let sock_path = creance_proxy::socket(profile);
    let dir = Path::new(&sock_path).parent().unwrap().to_path_buf();
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path).unwrap();
    let handle = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
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
                    let body = match path.split('?').next().unwrap_or(&path) {
                        "/configs" => serde_json::json!({
                            "mixed-port": 17896u64,
                            "interface-name": "en0",
                            "mode": "rule",
                            "unified-delay": true,
                        }),
                        p if p.starts_with("/proxies/") => serde_json::json!({ "now": "id-exit" }),
                        "/rules" if rules_wrapped => serde_json::json!({
                            "rules": [{
                                "index": 0,
                                "type": "Match",
                                "payload": "",
                                "proxy": "CAGE",
                                "size": -1,
                                "extra": {
                                    "disabled": false,
                                    "hitCount": 0,
                                    "hitAt": "1970-01-01T08:00:00+08:00",
                                    "missCount": 0,
                                    "missAt": "1970-01-01T08:00:00+08:00"
                                }
                            }]
                        }),
                        "/rules" => serde_json::json!([
                            { "type": "Match", "proxy": "CAGE" }
                        ]),
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
    handle
}

fn honest_store_fixture(tag: &str) -> (String, String) {
    // (profile, config_path)：config.yaml 带对账基线 interface-name。
    let profile = std::env::temp_dir()
        .join(format!("r9-{tag}-{}", creance_proxy::token()[..12].to_owned()))
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
    (profile.clone(), profile)
}

fn h1_rules_shape() {
    println!("\n-- H1 F-046 修复面：/rules 对账形状 vs 真实核心（冒烟锚定）--");

    // 变体 A：真实形状（{"rules":[…]} 包装对象）——诚实核心必过对账（可用性）。
    let (profile, _) = honest_store_fixture("h1a");
    let h = fake_core(&profile, true);
    std::thread::sleep(std::time::Duration::from_millis(100));
    let store = creance_proxy::load(&profile).unwrap();
    let r = creance_proxy::service::check_running(&profile, &store);
    println!(
        "h1.1 真实形状（包装对象）诚实核心通过对账  预测=Err(readiness: rules)  实际={:?}  {}",
        r,
        if r.is_err() { "PASS ← 洞成立：诚实核心被拒" } else { "FAIL" }
    );
    drop(h);

    // 变体 B：修复假设的裸数组——只有这个不存在的形状能过。
    let (profile, _) = honest_store_fixture("h1b");
    let h = fake_core(&profile, false);
    std::thread::sleep(std::time::Duration::from_millis(100));
    let store = creance_proxy::load(&profile).unwrap();
    let r = creance_proxy::service::check_running(&profile, &store);
    println!(
        "h1.2 假设形状（裸数组）通过对账          预测=Ok                 实际={:?}  {}",
        r,
        if r.is_ok() { "PASS ← 修复只对虚构形状有效" } else { "FAIL" }
    );
    drop(h);
}

// ---------------------------------------------------------------- H2

fn fresh_cage_profile(tag: &str) -> (String, String) {
    let dir = std::env::temp_dir().join(format!(
        "r9-cage-{tag}-{}",
        creance_vm::token()[..12].to_owned()
    ));
    let profile = dir.to_string_lossy().into_owned();
    std::fs::create_dir_all(&dir).unwrap();
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

fn h2_stamp_matrix() {
    println!("\n-- H2 F-044 修复面：stamp 形态矩阵（探针 × up 前置检查语义）--");

    // h2.0 匹配 → Contained
    let (profile, config_path) = fresh_cage_profile("match");
    let cfg = creance_vm::config::load(&config_path).unwrap();
    let state = creance_vm::vm::state_dir(&profile);
    std::fs::create_dir_all(&state).unwrap();
    let stamp = creance_vm::paths::join(&state, "fingerprint.txt");
    std::fs::write(&stamp, cfg.guest_fingerprint()).unwrap();
    println!(
        "h2.0 stamp=匹配                            预测=Contained     实际={:?}  {}",
        fp_probe(&profile, &config_path),
        if matches!(fp_probe(&profile, &config_path), creance::escape::Outcome::Contained) { "PASS" } else { "FAIL" }
    );

    // h2.1 尾随空白 + 匹配 → Contained（trim 语义，up 同式）
    std::fs::write(&stamp, format!("{}\n  ", cfg.guest_fingerprint())).unwrap();
    println!(
        "h2.1 stamp=匹配+尾随空白                    预测=Contained     实际={:?}  {}",
        fp_probe(&profile, &config_path),
        if matches!(fp_probe(&profile, &config_path), creance::escape::Outcome::Contained) { "PASS" } else { "FAIL" }
    );

    // h2.2 guest 侧漂移 + stamp → Escaped（诚实）
    let mut drifted = cfg.clone();
    drifted.timezone = "Asia/Tokyo".to_owned();
    creance_vm::config::write_private_config(&config_path, &drifted).unwrap();
    println!(
        "h2.2 guest 漂移 + stamp 在                  预测=Escaped       实际={:?}  {}",
        fp_probe(&profile, &config_path),
        if matches!(fp_probe(&profile, &config_path), creance::escape::Outcome::Escaped(_)) { "PASS（up 会拒——修复有效）" } else { "FAIL" }
    );

    // h2.3 漂移 + stamp 缺失 → NotEnforced（fail-open 实证）
    std::fs::remove_file(&stamp).unwrap();
    let outcome = fp_probe(&profile, &config_path);
    let probes = creance::escape::host_probes(&profile, &config_path);
    let exit = creance::escape::report(&probes);
    println!(
        "h2.3 guest 漂移 + stamp 缺失                预测=NotEnforced   实际={outcome:?}  {}",
        if matches!(outcome, creance::escape::Outcome::NotEnforced) {
            "PASS ← 洞成立：up 跳过检查 + 探针不计失败"
        } else {
            "FAIL"
        }
    );
    println!(
        "h2.4 同状态下 escape-test 退出码            预测=0（⏭️不算失败） 实际={exit}  {}",
        if exit == 0 { "PASS ← 洗绿闭环成立" } else { "FAIL" }
    );

    // h2.5 空 stamp → Escaped（fail-closed 对照）
    let cfg = creance_vm::config::load(&config_path).unwrap(); // 漂移后的 cfg
    let _ = cfg;
    std::fs::write(&stamp, "").unwrap();
    // 注意：此时 config 已漂移过；再换回与 stamp 无关的形态——空 stamp 对任何 cfg 都 != fp
    println!(
        "h2.5 stamp=空文件                           预测=Escaped       实际={:?}  {}",
        fp_probe(&profile, &config_path),
        if matches!(fp_probe(&profile, &config_path), creance::escape::Outcome::Escaped(_)) { "PASS（空 stamp fail-closed，与缺失的 fail-open 不对称）" } else { "FAIL" }
    );
    let _ = std::fs::remove_dir_all(&profile);
}

// ---------------------------------------------------------------- H3

fn gate_record_fixture(profile: &str, socket_path: &str) -> String {
    // instance dir + cage-gate.json（0600，GateClient::open 的私文检查）。
    let instance = creance_vm::vm::instance_name(
        &profile,
        &creance_vm::vm::environment_dir(&profile),
    );
    let dir = creance_vm::paths::join(&creance_vm::vm::lima_home(&profile), &instance);
    std::fs::create_dir_all(&dir).unwrap();
    let record = serde_json::json!({
        "socket": socket_path,
        "token": creance_vm::token(),
        "run_id": creance_vm::token()[..32].to_owned(),
    });
    let path = creance_vm::paths::join(&dir, "cage-gate.json");
    std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    dir
}

fn h3_transactional_pieces() {
    println!("\n-- H3 F-047 修复面：事务性库侧件（CLI 顺序=close 先行且致命，见 main.rs:598-601）--");

    // h3.1 活 socket 但拒绝命令的假守护 → close_gates=Err（CLI `?` 中止 select）
    let (profile, _) = fresh_cage_profile("h3a");
    let sock = creance_vm::paths::join(&profile, "stubborn.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let h = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if std::time::Instant::now() > deadline {
                return;
            }
            match listener.accept() {
                Ok((s, _)) => drop(s), // 接受连接后立即断开：close 命令得不到应答
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(_) => return,
            }
        }
    });
    std::thread::sleep(std::time::Duration::from_millis(100));
    let _ = gate_record_fixture(&profile, &sock);
    let r = creance_gate::gate::close_gates(&profile);
    println!(
        "h3.1 假守护拒绝 close 命令                  预测=Err（select 不落地） 实际={:?}  {}",
        r.as_ref().map(|_| "Ok").map_err(|e| e.clone()).ok(),
        if r.is_err() { "PASS" } else { "FAIL" }
    );
    drop(h);

    // h3.2 死记录 → Ok + 就地清理（F-029 路径，不阻塞 select）
    let (profile, _) = fresh_cage_profile("h3b");
    let _ = gate_record_fixture(&profile, "/tmp/r9-nonexistent.sock");
    let r = creance_gate::gate::close_gates(&profile);
    let instance = creance_vm::vm::instance_name(
        &profile,
        &creance_vm::vm::environment_dir(&profile),
    );
    let record = creance_vm::paths::join(
        &creance_vm::paths::join(&creance_vm::vm::lima_home(&profile), &instance),
        "cage-gate.json",
    );
    println!(
        "h3.2 死记录                                预测=Ok+记录已清       实例记录存在={}  {}",
        Path::new(&record).exists(),
        if r.is_ok() && !Path::new(&record).exists() { "PASS" } else { "FAIL" }
    );

    // h3.3 未知节点 → select_and_apply=Err 且 store 不动（校验先于落盘）
    let (profile, config_path) = fresh_cage_profile("h3c");
    let store_path = creance_vm::paths::join(&creance_proxy::dir(&profile), "sources.json");
    let before = std::fs::read(&store_path).ok();
    let r = creance_proxy::select_and_apply(&profile, &config_path, "no-such-node");
    let after = std::fs::read(&store_path).ok();
    println!(
        "h3.3 未知节点 select                        预测=Err+store不动      实际={:?}  {}",
        r.as_ref().map(|_| "Ok").map_err(|e| e.clone()).ok(),
        if r.is_err() && before == after { "PASS（close 成功后 select 失败=gate 已关+节点未换，一致 fail-closed）" } else { "FAIL" }
    );
    let _ = std::fs::remove_dir_all(&profile);
}

// ---------------------------------------------------------------- H4

fn h4_failopen_inputs() {
    println!("\n-- H4 F-046b：对账的 fail-open 输入（cmd_gate 的 `if let Ok(load)`）--");

    // h4.1 corrupt sources.json → load=Err → CLI 两处对账全跳
    let (profile, _) = honest_store_fixture("h4a");
    let store_path = creance_vm::paths::join(&creance_proxy::dir(&profile), "sources.json");
    std::fs::write(&store_path, b"{{{not-json").unwrap();
    let r = creance_proxy::load(&profile);
    println!(
        "h4.1 sources.json 损坏                      预测=Err（对账被跳）    实际={}  {}",
        if r.is_err() { "Err" } else { "Ok" },
        if r.is_err() { "PASS ← 洞成立：同 uid 写坏一个文件=两次对账全灭" } else { "FAIL" }
    );

    // h4.2 缺失 sources.json → Ok(默认随机 auth+空 selected) → check_running 仍拒（selection）
    let (profile, _) = honest_store_fixture("h4b");
    let store_path = creance_vm::paths::join(&creance_proxy::dir(&profile), "sources.json");
    std::fs::remove_file(&store_path).unwrap();
    let store = creance_proxy::load(&profile).unwrap();
    let h = fake_core(&profile, true);
    std::thread::sleep(std::time::Duration::from_millis(100));
    let r = creance_proxy::service::check_running(&profile, &store);
    println!(
        "h4.2 sources.json 缺失→默认 store 对账       预测=Err(selection)    实际={:?}  {}",
        r,
        if r.as_ref().err().map(|e| e.contains("selection")) == Some(true) { "PASS（缺文件形态 fail-closed，与损坏形态不对称）" } else { "FAIL" }
    );
    drop(h);
}

// ---------------------------------------------------------------- H5

fn h5_whitelist_injection() {
    println!("\n-- H5 F-045 面：guest 三字段白名单 vs shell 元字符；heredoc 定界符 --");

    let hostile: Vec<(&str, &str, &str)> = vec![
        ("timezone", "Asia/Shanghai'; curl evil", "单引号+分号"),
        ("timezone", "Asia/$(id)", "命令替换"),
        ("timezone", "Asia/`id`", "反引号"),
        ("locale", "en_US.UTF-8; id", "分号"),
        ("locale", "en_US$x.UTF-8", "$ 展开"),
        ("browser_language", "en-US`id`", "反引号"),
        ("browser_language", "en'US", "单引号"),
        ("browser_language", "en-US$(id)", "命令替换"),
    ];
    let mut all_rejected = true;
    for &(field, value, why) in &hostile {
        let mut cfg = creance_vm::config::default_config();
        match field {
            "timezone" => cfg.timezone = value.to_owned(),
            "locale" => cfg.locale = value.to_owned(),
            _ => cfg.browser_language = value.to_owned(),
        }
        let ok = cfg.validate().is_err();
        if !ok {
            all_rejected = false;
        }
        println!(
            "h5.x {field}={value:?}（{why}）  预测=validate 拒   实际={}  {}",
            if ok { "Err" } else { "Ok" },
            if ok { "PASS" } else { "FAIL ← 注入面开放" }
        );
    }

    // 正控：合法值通过
    let mut cfg = creance_vm::config::default_config();
    cfg.browser_language = "zh-Hans-CN".to_owned();
    println!(
        "h5.y browser_language=zh-Hans-CN（合法）     预测=validate 过    实际={}  {}",
        if cfg.validate().is_ok() { "Ok" } else { "Err" },
        if cfg.validate().is_ok() { "PASS" } else { "FAIL" }
    );

    // heredoc 定界符带引号 → 供给时不展开（值只作为数据落地）
    let options = creance_vm::lima::SetupOptions {
        workspace: "/tmp/r9-ws".to_owned(),
        ..Default::default()
    };
    let yaml = String::from_utf8(creance_vm::lima::generate_lima_yaml(&options).unwrap()).unwrap();
    let quoted = yaml.contains("<<'CAGEENV'");
    let trio = yaml.contains("export CAGE_TZ=Etc/UTC")
        && yaml.contains("export CAGE_LOCALE=en_US.UTF-8")
        && yaml.contains("export CAGE_LANGUAGE=en-US");
    println!(
        "h5.z provision heredoc 定界符带引号 + 三 export 在  预测=是/是   实际={quoted}/{trio}  {}",
        if quoted && trio { "PASS（首启供给闭环成立：cage-env.sh 由首启 provision 写出）" } else { "FAIL" }
    );
}
