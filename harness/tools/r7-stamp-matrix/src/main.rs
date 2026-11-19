//! R7 探针主程序：R6-H4 戳刷新语义矩阵。退出码 0 = 全部观测与预测一致。

use creance_vm::config::Config;
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

fn config_with(url: &str) -> Config {
    Config {
        proxy_url: url.to_owned(),
        dns_url: "https://1.1.1.1/dns-query".to_owned(),
        timezone: "Etc/UTC".to_owned(),
        locale: "en_US.UTF-8".to_owned(),
        browser_language: "en-US".to_owned(),
        ..Default::default()
    }
}

struct Rig {
    profile: String,
    instance_dir: String,
}

fn prepare(name: &str) -> Rig {
    let profile = std::env::temp_dir()
        .join(format!("r7-stamp-{name}-{}", creance_vm::token()[..12].to_owned()))
        .to_string_lossy()
        .into_owned();
    std::fs::create_dir_all(&profile).unwrap();
    let instance_dir = creance_vm::paths::join(
        &creance_vm::vm::state_dir(&profile),
        "lima/test-vm",
    );
    std::fs::create_dir_all(&instance_dir).unwrap();
    Rig { profile, instance_dir }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}

fn stamp_path(profile: &str) -> String {
    creance_vm::paths::join(&creance_vm::vm::state_dir(profile), "fingerprint.txt")
}

fn fp_probe(rig: &Rig) -> String {
    let config_path = creance_vm::paths::join(&rig.profile, "config.json");
    let probes = creance::escape::host_probes(&rig.profile, &config_path);
    let p = probes
        .iter()
        .find(|p| p.id == "fingerprint-consistent")
        .expect("fingerprint-consistent probe exists");
    format!("{:?}", p.outcome)
}

fn main() {
    println!("S1/S2 check_running × 戳刷新顺序（真实 record_running/check_running/refresh）");
    let rig = prepare("order");
    let cfg_a = config_with("socks5://1.2.3.4:1080");
    let cfg_b = config_with("socks5://5.6.7.8:1080");
    assert!(cfg_a.fingerprint() != cfg_b.fingerprint());

    // setup 阶段：按 a 创建（戳 = a）。
    creance::escape::refresh_fingerprint_stamp(&rig.profile, &cfg_a).unwrap();
    check(
        "s0 setup 戳 = cfg_a",
        std::fs::read_to_string(stamp_path(&rig.profile)).unwrap().trim() == cfg_a.fingerprint(),
        "",
    );

    // 运行记录活（record_running 用探针自身 pid，天然 alive）+ config 漂到 b。
    creance_vm::running::record_running(&rig.instance_dir, &cfg_a).unwrap();
    let blocked = creance_vm::running::check_running(
        &creance_vm::vm::state_dir(&rig.profile),
        &cfg_b,
    );
    check(
        "s1 活记录+config 漂移 → check_running 拒",
        blocked.is_err(),
        &format!("{blocked:?}"),
    );
    check(
        "s2 拒后戳未被刷新（仍是 a；up 刷新在 vm::up 成功之后才可达）",
        std::fs::read_to_string(stamp_path(&rig.profile)).unwrap().trim() == cfg_a.fingerprint(),
        "",
    );

    // 记录死：手工写一个死 pid 的记录（RunningProfile 私有，serde 形状已知）。
    let dead = serde_json::json!({
        "pid": -1,
        "started": "",
        "fingerprint": cfg_a.fingerprint(),
        "job_id": "",
    });
    std::fs::write(
        Path::new(&rig.instance_dir).join("cage-running.json"),
        serde_json::to_vec(&dead).unwrap(),
    )
    .unwrap();
    let allowed = creance_vm::running::check_running(
        &creance_vm::vm::state_dir(&rig.profile),
        &cfg_b,
    );
    check("s3 记录死 → check_running 放行", allowed.is_ok(), &format!("{allowed:?}"));
    // 合法 up 路径：refresh 落新指纹。
    creance::escape::refresh_fingerprint_stamp(&rig.profile, &cfg_b).unwrap();
    check(
        "s4 合法 up 后戳 = cfg_b",
        std::fs::read_to_string(stamp_path(&rig.profile)).unwrap().trim() == cfg_b.fingerprint(),
        "",
    );

    println!("S3 fingerprint-consistent 探针红绿矩阵（真实 host_probes）");
    // host_probes 读 profile/config.json：先落一份与戳一致的 config。
    creance_vm::config::write_private_config(
        &creance_vm::paths::join(&rig.profile, "config.json"),
        &cfg_b,
    )
    .unwrap();
    // s4 已落戳：先删，测缺戳分支。
    std::fs::remove_file(stamp_path(&rig.profile)).unwrap();
    check("p1 缺戳 → NotEnforced（无戳=未实施，非绿）", fp_probe(&rig).contains("NotEnforced"), &fp_probe(&rig));
    creance::escape::refresh_fingerprint_stamp(&rig.profile, &cfg_b).unwrap();
    check("p2 戳=当前 → Contained", fp_probe(&rig).contains("Contained"), &fp_probe(&rig));
    std::fs::write(stamp_path(&rig.profile), "stale-fingerprint").unwrap();
    check("p3 戳漂移 → Escaped", fp_probe(&rig).contains("Escaped"), &fp_probe(&rig));

    println!("S4 040 场景核对：select 后不 up，探针红（双源冲突仍在案）");
    // select 改 config（b→c 指纹），活记录仍是 b 指纹 → check_running 拒 up；
    // 此时跑探针：戳=b≠c → 红。040 已立案：合法 select 后戳永久报警。
    let cfg_c = config_with("socks5://9.9.9.9:1080");
    creance_vm::running::record_running(&rig.instance_dir, &cfg_b).unwrap();
    // 把 config.json 落到 profile 下供 host_probes 读取（探针以 config_path 读 cfg）。
    creance_vm::config::write_private_config(
        &creance_vm::paths::join(&rig.profile, "config.json"),
        &cfg_c,
    )
    .unwrap();
    let up_blocked = creance_vm::running::check_running(
        &creance_vm::vm::state_dir(&rig.profile),
        &cfg_c,
    );
    let red = fp_probe(&rig);
    check(
        "p5 040 证实：活记录(b)+config(c) → up 拒 & 探针 Escaped（戳源永久报警）",
        up_blocked.is_err() && red.contains("Escaped"),
        &format!("{up_blocked:?} / {red}"),
    );

    std::process::exit(finished());
}
