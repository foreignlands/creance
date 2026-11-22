//! R14 收敛轮探针（F-062 修复面复核）。逻辑镜像基线：6155c1f 的
//! crates/creance/src/main.rs（cmd_escape_test 的缺行提取器 + cmd_up 的
//! 防火墙守门），脚本输入来自真 `creance::escape::guest_script()` 渲染。
//!
//! 验证面：
//!   A 提取器的 expected id 集合（与脚本字面发射点对照）
//!   B 提取器自洽：过滤 `$` 参数化发射点后与独立枚举一致
//!   C 健康模拟：11 行全到 → 零 missing
//!   D 致盲模拟：空输出 → 11 个全 missing（缺行网对字面探针 fail-closed）
//!   E 部分致盲模拟：fs-flag-readable（probe() 助手路由，$id 参数化）
//!     被单独吞掉 → 缺行网无感（062 修复的覆盖缺口观测）
//!   F 子串碰撞矩阵：任一 expected id 不得是其它探针行的子串
//!   G up 守门真值表（10 行，fail-closed 方向全断言）

use creance::escape::guest_script;

// —— 以下三个函数逐字符镜像 main.rs（仅去掉所有权细节）——

/// main.rs cmd_escape_test 的 expected 提取器镜像。
fn expected_ids(script: &str) -> Vec<String> {
    script
        .lines()
        .filter_map(|l| {
            l.split_once("echo \"PROBE ")
                .and_then(|(_, rest)| rest.split('"').next())
                .and_then(|id| id.split_whitespace().next())
        })
        .filter(|id| !id.contains('$'))
        .map(|id| id.to_owned())
        .collect()
}

/// main.rs cmd_escape_test 的缺行判定镜像。
fn missing(expected: &[String], stdout: &str) -> Vec<String> {
    expected
        .iter()
        .filter(|id| {
            !stdout
                .lines()
                .any(|l| l.starts_with("PROBE ") && l.contains(id.as_str()))
        })
        .cloned()
        .collect()
}

/// main.rs cmd_up 守门判定镜像。
fn guard(out: &str) -> Result<(), String> {
    let tcp_ok = out.contains("tcp-blocked") && !out.contains("tcp-open");
    let icmp_ok = out.contains("icmp-blocked")
        || (out.contains("icmp-unknown") && !out.contains("icmp-open"));
    if !tcp_ok || !icmp_ok {
        Err(format!("refuse delivery: {out:?}"))
    } else {
        Ok(())
    }
}

fn die(section: &str, msg: String) -> ! {
    eprintln!("[FAIL {section}] {msg}");
    std::process::exit(1);
}

fn main() {
    let script = guest_script(&r23_flag(), "deadbeef", 17896, "devabc12345");
    let expected = expected_ids(&script);

    // [A] 集合本身
    println!("[A] expected ids ({}): {expected:?}", expected.len());
    for id in [
        "fs-flag-readable",
        "guest-identity",
        "guest-privilege",
        "env-credentials",
        "env-hex-tokens",
        "ssh-material",
        "sock-abstract",
        "net-direct-egress",
        "net-dns-external",
        "net-ipv6",
        "net-icmp-external",
        "proxy-path",
    ] {
        if !expected.iter().any(|e| e == id) {
            die("A", format!("缺少应覆盖的字面探针 id：{id}"));
        }
    }
    // F-064（night-16 修复后断言，翻转自原观测）：fs-flag-readable 必须
    // 在网内（字面发射），且脚本不得再出现 helper 调用形态。
    if script
        .lines()
        .any(|l| l.starts_with("probe fs-flag-readable"))
    {
        die(
            "A",
            "脚本仍含 probe fs-flag-readable 助手调用（064 回归形态）".to_owned(),
        );
    }

    // [B] 自洽：独立枚举 `echo "PROBE <字面>` 发射点（id 不含 `$`），须等于提取器集合
    let mut listed: Vec<String> = script
        .lines()
        .filter_map(|l| l.split_once("echo \"PROBE "))
        .map(|(_, rest)| rest)
        .filter_map(|rest| rest.split_whitespace().next())
        .filter(|id| !id.contains('$'))
        .map(|id| id.to_owned())
        .collect();
    listed.sort();
    listed.dedup();
    let mut sorted_expected = expected.clone();
    sorted_expected.sort();
    sorted_expected.dedup();
    if listed != sorted_expected {
        die(
            "B",
            format!("独立枚举与提取器集合不一致：{listed:?} vs {sorted_expected:?}"),
        );
    }
    println!(
        "[B] 提取器与独立发射点枚举一致（{} 字面 id）",
        listed.len()
    );

    // [C] 健康模拟：每个 expected id 一行 PASS
    let healthy: String = expected
        .iter()
        .map(|id| format!("PROBE {id} PASS\n"))
        .collect();
    let m = missing(&expected, &healthy);
    if !m.is_empty() {
        die("C", format!("健康输出被判缺行：{m:?}"));
    }
    println!("[C] 健康模拟：{} 行全到，missing 为空", expected.len());

    // [D] 致盲模拟：空输出 → 全 missing
    let m = missing(&expected, "");
    if m.len() != expected.len() {
        die("D", format!("空输出未触发全量缺行：{m:?}"));
    }
    println!(
        "[D] 致盲模拟：空输出 → {} 个全 missing（对字面探针 fail-closed）",
        expected.len()
    );

    // [E] 部分致盲（F-064 修复后裁判，翻转自原观测）：剔除 fs-flag-readable
    //     行 → missing 必须非空（transport ESCAPE 触发）。修复前该行经
    //     probe() 助手发射、不在网内，缺失无感（finding 064 原实证形态）。
    let blinded: String = healthy
        .lines()
        .filter(|l| !l.starts_with("PROBE fs-flag-readable "))
        .map(|l| format!("{l}\n"))
        .collect();
    let m = missing(&expected, &blinded);
    if m.is_empty() {
        die(
            "E",
            "fs-flag-readable 行被吞但缺行网无感（064 回归）".to_owned(),
        );
    }
    println!("[E] 部分致盲：fs-flag-readable 行缺失 → missing={m:?}（非空，fail-closed）");

    // [F] 子串碰撞矩阵：任一 expected id 不得是其它探针可发射行的子串
    let mut emit_lines: Vec<String> = Vec::new();
    for id in &expected {
        for verdict in ["PASS", "SKIP", "ESCAPE"] {
            emit_lines.push(format!("PROBE {id} {verdict}"));
        }
    }
    // 参数化发射点（真实脚本里的动态行）
    emit_lines.push("PROBE sock-docker ESCAPE".into());
    emit_lines.push("PROBE sock-lima-guestagent ESCAPE".into());
    for a in &expected {
        let tagged = format!("PROBE {a} ");
        for line in &emit_lines {
            if !line.contains(&tagged) && line.contains(a.as_str()) {
                die("F", format!("子串碰撞：id {a} 会误匹配行 {line:?}"));
            }
        }
    }
    println!(
        "[F] 子串碰撞矩阵：{} id × {} 行，无误匹配",
        expected.len(),
        emit_lines.len()
    );

    // [G] up 守门真值表
    let cases: &[(&str, bool)] = &[
        ("tcp-blocked\nicmp-blocked", true),
        ("tcp-blocked\nicmp-unknown", true),
        ("tcp-blocked\nicmp-blocked\nicmp-unknown", true),
        ("tcp-open\nicmp-blocked", false),
        ("tcp-blocked\nicmp-open", false),
        ("", false),
        ("tcp-blocked", false),
        ("icmp-blocked", false),
        ("tcp-blocked tcp-open\nicmp-blocked", false),
        ("tcp-block", false),
    ];
    for (i, (out, want_ok)) in cases.iter().enumerate() {
        let got = guard(out).is_ok();
        if got != *want_ok {
            die(
                "G",
                format!("守门第 {} 行 {out:?} 期望 ok={} 实得 ok={}", i + 1, want_ok, got),
            );
        }
    }
    println!("[G] up 守门真值表 {} 行全过（fail-closed 方向成立）", cases.len());
    println!("ALL SECTIONS DONE (night-16 后：[A]/[E] 均为修复后断言)");
}

// R23: v0.6.14 guest_script places the oracle itself; "/nonexistent-flag" (1c55b30) is unwritable -> SKIP world.
// A writable temp path restores the PASS/ESCAPE world these judges were written for.
fn r23_flag() -> String {
    let p = std::env::temp_dir().join(format!("r23-judge-flag-{}", std::process::id()));
    p.to_string_lossy().into_owned()
}
