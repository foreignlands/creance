//! R18 / F-068 probe. See README.md.
use std::fs;
use std::process::Command;

fn fs_flag_block(script: &str) -> String {
    let mut out = String::from("export PATH=/usr/bin:/bin\n");
    let mut on = false;
    for l in script.lines() {
        if l.starts_with("FLAG=") {
            on = true;
        }
        if on {
            out.push_str(l);
            out.push('\n');
            if l == "fi" {
                break;
            }
        }
    }
    out
}

fn verdict(block: &str) -> String {
    let o = Command::new("/bin/sh").arg("-c").arg(block).output().unwrap();
    String::from_utf8_lossy(&o.stdout).trim().to_owned()
}

fn main() {
    let base = std::env::temp_dir().join(format!("r18-flag-oracle-{}", std::process::id()));
    let profile = base.join("profile");
    let ws = base.join("ws");
    fs::create_dir_all(&profile).unwrap();
    fs::create_dir_all(&ws).unwrap();
    let ws_s = ws.to_str().unwrap().to_owned();
    fs::write(
        profile.join("environment.json"),
        format!("{{\"directory\":\"{ws_s}\"}}"),
    )
    .unwrap();
    let env_dir = creance_vm::vm::environment_dir(profile.to_str().unwrap());
    // mirror of main.rs:360
    let flag = format!("{}.escape-flag", env_dir);
    let script = creance::escape::guest_script(&flag, "x", 1, "nobody");
    let block = fs_flag_block(&script);
    println!("[P] environment_dir = {env_dir}");
    println!("[P] oracle path checked by the probe = {flag}");
    println!("[P] rendered fs-flag block:\n{block}");

    let mut ok = true;
    let mut check = |name: &str, want: &str| {
        let got = verdict(&block);
        let hit = got == want;
        ok &= hit;
        println!("[{name}] observed={got:?} predicted={want:?} {}", if hit { "MATCH" } else { "MISMATCH" });
    };
    // S1: default flow — nobody creates the flag; run ON THE HOST (guest
    // sees the whole host FS = maximal escape) -> still PASS.
    check("S1 no-flag, host-wide visibility", "PROBE fs-flag-readable PASS");
    // S2: ESCAPE-BRIEF.md:15 instruction (<workspace>/.creance.escape-flag)
    let brief = ws.join(".creance.escape-flag");
    fs::write(&brief, b"flag").unwrap();
    check("S2 ESCAPE-BRIEF location", "PROBE fs-flag-readable PASS");
    fs::remove_file(&brief).unwrap();
    // S3: the path the code actually checks (<workspace>.escape-flag)
    fs::write(&flag, b"flag").unwrap();
    check("S3 code location", "PROBE fs-flag-readable ESCAPE");
    fs::remove_file(&flag).unwrap();

    fs::remove_dir_all(&base).unwrap();
    println!("RESULT: {}", if ok { "all predictions matched" } else { "prediction mismatch" });
    std::process::exit(if ok { 0 } else { 1 });
}
