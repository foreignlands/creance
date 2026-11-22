//! R15：064 修复增量复核。四组断言：
//!   NC1 负控（修复前形态）：回植 probe() 助手后，提取器 expected 集合
//!       不得含 fs-flag-readable（复现 finding 064 的 [A] 观测 = 11 id）。
//!   NC2 负控（修复前形态）：fs-flag-readable 行被吞 → missing 为空
//!       （复现 064 [E-OBS] = 缺行网无感 → 修复前会被 r14 裁判 [E] 判死）。
//!   PF1 修复后：dedup 后 expected 恰为 12 个字面 id（提取网全覆盖）。
//!   PF2 修复后：fs-flag-readable 行被吞 → missing 非空（fail-closed）。
//!   EQ1 行为等价：修复前/后 fs-flag 发射块在真 /bin/sh 下对
//!       FLAG 存在/不存在两种世界输出逐字节一致（无行为回归）。
//!   EQ2 修复后整份脚本 `sh -n` 语法通过（POSIX 形态不回归）。

use std::process::Command;

// —— 以下两个函数逐字符镜像 d220e1b 的 main.rs cmd_escape_test 消费逻辑 ——
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

/// 把修复后脚本回植成修复前形态（文本逐字取自 d220e1b diff 的 `-` 行，
/// `{{`→`{` 为 format! 渲染差异）。
fn revert_to_prefix(script: &str) -> String {
    let a = script
        .find("# Filesystem: the host flag must not be reachable by any guest path.")
        .unwrap_or_else(|| panic!("锚点缺失：Filesystem 注释"));
    let pass_rel = script[a..]
        .find("  echo \"PROBE fs-flag-readable PASS\"\n")
        .unwrap_or_else(|| panic!("锚点缺失：fs-flag PASS 发射行"));
    let fi_rel = script[a + pass_rel..]
        .find("fi\n")
        .unwrap_or_else(|| panic!("锚点缺失：if/else 闭合 fi"));
    let end = a + pass_rel + fi_rel + "fi\n".len();
    let prefix_block = "probe() {\n  id=\"$1\"; shift\n  if [ -f \"$FLAG\" ]; then\n    echo \"PROBE $id ESCAPE\"\n  else\n    echo \"PROBE $id PASS\"\n  fi\n}\n# Filesystem: the host flag must not be reachable by any guest path.\nprobe fs-flag-readable true\n";
    format!("{}{}{}", &script[..a], prefix_block, &script[end..])
}

fn die(section: &str, msg: String) -> ! {
    eprintln!("[FAIL {section}] {msg}");
    std::process::exit(1);
}

fn main() {
    let post = creance::escape::guest_script("/nonexistent-flag", true, "deadbeef", 17896, "devabc12345");
    let pre = revert_to_prefix(&post);
    let expected_pre = expected_ids(&pre);

    // NC1：修复前提取器集合无 fs-flag-readable（064 原观测复现）
    let mut distinct_pre = expected_pre.clone();
    distinct_pre.sort();
    distinct_pre.dedup();
    if distinct_pre.iter().any(|id| id == "fs-flag-readable") {
        die("NC1", "负控失效：修复前形态竟然已在网内（镜像或回植有误）".into());
    }
    println!(
        "[NC1] 修复前形态：expected 集合 = {} 条（{} 个去重 id），无 fs-flag-readable —— r14 裁判 [A] 会 die",
        expected_pre.len(),
        distinct_pre.len()
    );

    // NC2：修复前 fs-flag 行被吞 → missing 为空（064 [E-OBS] 复现）
    let healthy_pre: String = distinct_pre
        .iter()
        .map(|id| format!("PROBE {id} PASS\n"))
        .collect();
    let m = missing(&expected_pre, &healthy_pre);
    if !m.is_empty() {
        die("NC2", format!("负控失效：修复前缺行网竟然有感：{m:?}"));
    }
    println!(
        "[NC2] 修复前形态：11 行 PASS（fs-flag 行不存在）→ missing 为空 —— r14 裁判 [E] 会 die"
    );

    // PF1：修复后 dedup 恰为 12 id，且与既定清单一致
    let expected_post = expected_ids(&post);
    let mut distinct_post = expected_post.clone();
    distinct_post.sort();
    distinct_post.dedup();
    let want: Vec<String> = [
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
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let mut want_sorted = want.clone();
    want_sorted.sort();
    if distinct_post != want_sorted {
        die("PF1", format!("12 id 集合不符：{distinct_post:?}"));
    }
    println!("[PF1] 修复后：提取网去重后恰为 12 个字面 id，与清单逐一相等");

    // PF2：修复后 fs-flag 行被吞 → missing 非空
    let blinded_post: String = want
        .iter()
        .filter(|id| id.as_str() != "fs-flag-readable")
        .map(|id| format!("PROBE {id} PASS\n"))
        .collect();
    let m = missing(&expected_post, &blinded_post);
    if m.is_empty() {
        die("PF2", "修复后 fs-flag 行被吞但缺行网无感（064 回归）".into());
    }
    println!("[PF2] 修复后：fs-flag-readable 行缺失 → missing 非空（fail-closed）");

    // EQ1：修复前/后发射块真 /bin/sh 行为等价（FLAG 不存在 / 存在）
    let pre_snippet = "FLAG=\"$1\"\nprobe() {\n  id=\"$1\"; shift\n  if [ -f \"$FLAG\" ]; then\n    echo \"PROBE $id ESCAPE\"\n  else\n    echo \"PROBE $id PASS\"\n  fi\n}\nprobe fs-flag-readable true\n";
    let post_snippet = "FLAG=\"$1\"\nif [ -f \"$FLAG\" ]; then\n  echo \"PROBE fs-flag-readable ESCAPE\"\nelse\n  echo \"PROBE fs-flag-readable PASS\"\nfi\n";
    let dir = std::env::temp_dir().join("r15-064-recheck");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p_pre = dir.join("pre.sh");
    let p_post = dir.join("post.sh");
    std::fs::write(&p_pre, pre_snippet).unwrap();
    std::fs::write(&p_post, post_snippet).unwrap();
    let flag = dir.join("the-flag");
    for (exists, want_line) in [
        (false, "PROBE fs-flag-readable PASS"),
        (true, "PROBE fs-flag-readable ESCAPE"),
    ] {
        if exists {
            std::fs::write(&flag, b"x").unwrap();
        } else {
            let _ = std::fs::remove_file(&flag);
        }
        let out_pre = Command::new("/bin/sh").arg(&p_pre).arg(&flag).output().unwrap();
        let out_post = Command::new("/bin/sh").arg(&p_post).arg(&flag).output().unwrap();
        let s_pre = String::from_utf8_lossy(&out_pre.stdout).trim().to_owned();
        let s_post = String::from_utf8_lossy(&out_post.stdout).trim().to_owned();
        if s_pre != s_post || s_pre != want_line {
            die(
                "EQ1",
                format!("行为不等价：pre={s_pre:?} post={s_post:?} want={want_line:?}"),
            );
        }
    }
    println!("[EQ1] 修复前/后发射块两种世界输出逐字节一致（PASS/ESCAPE）");

    // EQ2：整份修复后脚本 sh -n 语法通过
    let script_path = dir.join("guest.sh");
    std::fs::write(&script_path, &post).unwrap();
    let st = Command::new("/bin/sh")
        .arg("-n")
        .arg(&script_path)
        .status()
        .unwrap();
    if !st.success() {
        die("EQ2", format!("sh -n 语法检查失败 rc={st}"));
    }
    println!("[EQ2] 修复后整份 guest_script `sh -n` 语法通过");

    let _ = std::fs::remove_dir_all(&dir);
    println!("ALL SECTIONS DONE (NC1/NC2 证裁判鉴别力；PF1/PF2/EQ1/EQ2 证修复落地且无行为回归)");
}
