//! R11 探针：night-12 修复面收敛回归（基线 c20332d / v0.5.6）。
//! 运行：`cargo run --release`（仓库根，.toolchain 环境）。
//!
//! H1 F-053 修复面：实例名小写化全局一致（lima 2.3 create 小写化）。
//! H2 F-052 修复面（库侧锚）：stamp 路径 + guest_fingerprint 摘要形状。
//!
//! CLI 侧四 case（无戳拒/漂移拒/实例缺失拒/绿路径）在
//! `f052-up-branches.sh`（用 target/release/creance 实机驱动）。

use sha2::{Digest, Sha256};

fn main() {
    println!("=== R11 regression: night-12 faces @ v0.5.6 ===");
    h1_lowercase_matrix();
    h2_stamp_anchors();
    println!("=== done ===");
}

// ---------------------------------------------------------------- H1

fn tmp_profile(tag: &str) -> String {
    let dir = std::env::temp_dir().join(format!(
        "r11-{tag}-{}",
        creance_vm::token()[..12].to_owned()
    ));
    let profile = dir.to_string_lossy().into_owned();
    std::fs::create_dir_all(&dir).unwrap();
    profile
}

fn h1_lowercase_matrix() {
    println!("\n-- H1 F-053 修复面：实例名小写化全局一致 --");

    // h1.1 混合大小写 workspace 名 → 小写 base（lima 2.3 create 语义）。
    let n = creance_vm::vmname::Limit(0).name("/tmp/My Project (v2)");
    let lower_ok = n == n.to_lowercase();
    println!(
        "h1.1 混合大小写名「{n}」                       预测=全小写  实际={}  {}",
        if lower_ok { "全小写" } else { "含大写" },
        if lower_ok { "PASS" } else { "FAIL ←←←" }
    );

    // h1.2 大写 ASCII 字母折叠；非 ASCII 折叠为 `-`（与 lima 的 [^a-z0-9-] 一致面）。
    let n2 = creance_vm::vmname::Limit(0).name("/tmp/ÅBC-Def");
    let lower2_ok = !n2.chars().any(|c| c.is_ascii_uppercase());
    println!(
        "h1.2 非 ASCII+大写折叠「{n2}」                    预测=无大写字母  实际={}  {}",
        if lower2_ok { "无" } else { "有" },
        if lower2_ok { "PASS" } else { "FAIL ←←←" }
    );

    // h1.3 instance_name 主路径：真 lima home + 小写实例目录 → 返回小写名。
    let profile = tmp_profile("main");
    let expected = creance_vm::vm::instance_name(&profile, &creance_vm::vm::environment_dir(&profile));
    let home = creance_vm::vm::lima_home(&profile);
    std::fs::create_dir_all(creance_vm::paths::join(&home, &format!("{expected}/lima.yaml"))).unwrap();
    let got = creance_vm::vm::instance_name(&profile, &creance_vm::vm::environment_dir(&profile));
    let main_ok = got == expected && !got.chars().any(|c| c.is_ascii_uppercase());
    println!(
        "h1.3 instance_name 主路径「{got}」             预测=小写恒等  实际={}  {}",
        if main_ok { "恒等" } else { "失配" },
        if main_ok { "PASS" } else { "FAIL ←←←" }
    );
    let _ = std::fs::remove_dir_all(&profile);
    let _ = std::fs::remove_file(&home);

    // h1.4 恢复路径：旧预算截断实例（小写）被唯一识别——修复语义不破坏恢复。
    let profile = tmp_profile("recover");
    let home = creance_vm::vm::lima_home(&profile);
    let full = creance_vm::vmname::Limit(0).name("/tmp/r11/recover-ws");
    // 造一个比预算更短的截断名（模拟旧 home 下的实例）。
    let trunc = creance_vm::vmname::Limit(full.len() - 4).name("/tmp/r11/recover-ws");
    if trunc != full {
        std::fs::create_dir_all(creance_vm::paths::join(&home, &format!("{trunc}/lima.yaml"))).unwrap();
        // home 的物理路径预算 >= 名长时，instance_name 应恢复到截断名。
        let got = creance_vm::vm::instance_name(&profile, "/tmp/r11/recover-ws");
        println!(
            "h1.4 恢复路径（trunc={trunc}）got={got}   预测=截断名  实际={}  {}",
            if got == trunc { "恢复" } else { "未恢复" },
            if got == trunc { "PASS" } else { "FAIL（浅 home 无截断需求，观察项）←←←" }
        );
    } else {
        println!("h1.4 恢复路径                                 SKIP（浅 home 不产生截断名）");
    }
    let _ = std::fs::remove_dir_all(&profile);
    let _ = std::fs::remove_file(&home);

    // h1.5 消费点口径：CLI instance() 与 escape/gate 用同一 vmname::name
    // （grep 级验证在 STATE 记录）；此处固化「两个入口对同一 workspace 同名」。
    let profile = tmp_profile("consumers");
    let ws = creance_vm::vm::environment_dir(&profile);
    let a = creance_vm::vmname::home_limit(&creance_vm::vm::lima_home(&profile), false).name(&ws);
    let b = creance_vm::vm::instance_name(&profile, &ws);
    let same = a == b;
    println!(
        "h1.5 两入口同名「{a}」                        预测=恒等  实际={}  {}",
        if same { "恒等" } else { "失配" },
        if same { "PASS" } else { "FAIL ←←←" }
    );
    let _ = std::fs::remove_dir_all(&profile);
    let _ = std::fs::remove_file(&creance_vm::vm::lima_home(&profile));
}

// ---------------------------------------------------------------- H2

fn h2_stamp_anchors() {
    println!("\n-- H2 F-052 修复面（库侧锚）：stamp 路径 + fingerprint 摘要形状 --");
    let profile = tmp_profile("stamp");
    let config_path = creance_vm::paths::join(&profile, "config.json");
    std::fs::write(
        &config_path,
        serde_json_pretty(&creance_vm::config::default_config()),
    )
    .unwrap();
    let cfg = creance_vm::config::load(&config_path).unwrap();
    let fp = cfg.guest_fingerprint();
    // 独立重算：("Etc/UTC","en_US.UTF-8","en-US") 的 JSON 数组序列化 + sha256。
    let mut h = Sha256::new();
    h.update(br#"["Etc/UTC","en_US.UTF-8","en-US"]"#);
    let expect = hex(&h.finalize());
    let anchor_ok = fp == expect;
    println!(
        "h2.1 guest_fingerprint 锚                     预测={expect}  实际={fp}  {}",
        if anchor_ok { "PASS" } else { "FAIL ←←←（shell 侧 stamp 构造失去依据）" }
    );
    // h2.2 stamp 路径恒等式：state_dir/fingerprint.txt（up/探针/setup 三处口径）。
    let stamp = creance_vm::paths::join(&creance_vm::vm::state_dir(&profile), "fingerprint.txt");
    println!(
        "h2.2 stamp 路径「{stamp}」 {}",
        if stamp.ends_with("/state/fingerprint.txt") && stamp.contains(&profile) {
            "PASS"
        } else {
            "FAIL ←←←"
        }
    );
    let _ = std::fs::remove_dir_all(&profile);
}

fn serde_json_pretty(v: &creance_vm::config::Config) -> String {
    // 与 cmd_init 相同的序列化路径（serde_json::to_vec_pretty）。
    serde_json::to_string_pretty(v).unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
