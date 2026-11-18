//! A1 库层探针：serde_yaml 0.9.34 对 YAML 炸弹的行为（深度上限/别名语义）。
//! 栈溢出会 abort 整个进程 —— runner 里每个变体作为子进程运行。
//!
//! 用法: a1-yaml-bomb <variant> [stack-mib]

use std::io::Write;
use std::process::ExitCode;

fn payload(variant: &str) -> Vec<u8> {
    match variant {
        "deep-seq-1k" => format!("proxies: {}{}", "[".repeat(1_000), "]".repeat(1_000)).into_bytes(),
        "deep-seq-10k" => format!("proxies: {}{}", "[".repeat(10_000), "]".repeat(10_000)).into_bytes(),
        "deep-seq-100k" => format!("proxies: {}{}", "[".repeat(100_000), "]".repeat(100_000)).into_bytes(),
        "deep-map-10k" => format!("proxies: {}x{}", "{a: ".repeat(10_000), "}".repeat(10_000)).into_bytes(),
        "alias-bomb" => {
            let mut y = String::from("a0: &a0 [1,2,3,4,5,6,7,8,9,10]\n");
            for lvl in 1..10 {
                let refs = vec![format!("*a{}", lvl - 1); 10].join(", ");
                y.push_str(&format!("a{lvl}: [{refs}]\n"));
            }
            y.push_str("proxies: [*a9, *a9]\n");
            y.into_bytes()
        }
        "alias-undefined" => b"proxies:\n  - *ghost\n".to_vec(),
        "alias-self" => b"a: &a [*a]\nproxies: [*a]\n".to_vec(),
        "alias-fwd" => b"a: [*b]\nb: &b [1]\nproxies: [*b]\n".to_vec(),
        "tag-binary-huge" => format!(
            "proxies:\n  - name: T\n    server: !!binary {}\n",
            "QUJD".repeat(2_000_000 / 4)
        )
        .into_bytes(),
        _ => unimplemented!("unknown variant"),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let variant = args[1].clone();
    let variant2 = variant.clone();
    let stack_mib: usize = args.get(2).map(|s| s.parse().unwrap_or(8)).unwrap_or(8);
    let data = payload(&variant);
    let joined = std::thread::Builder::new()
        .stack_size(stack_mib * 1024 * 1024)
        .spawn(move || {
            let t0 = std::time::Instant::now();
            let r: Result<serde_yaml::Value, String> =
                serde_yaml::from_slice(&data).map_err(|e| e.to_string());
            match r {
                Ok(v) => println!(
                    "OK variant={} stack={}MiB elapsed_ms={} depth_probe={}",
                    variant2,
                    stack_mib,
                    t0.elapsed().as_millis(),
                    probe_depth(&v, 0)
                ),
                Err(e) => println!(
                    "ERR variant={} stack={}MiB elapsed_ms={} err={}",
                    variant2,
                    stack_mib,
                    t0.elapsed().as_millis(),
                    e.split('\n').next().unwrap_or("")
                ),
            }
            let _ = std::io::stdout().flush();
        });
    let joined = match joined {
        Ok(h) => h,
        Err(e) => {
            println!("PANIC variant={} stack={}MiB spawn_err={}", variant, stack_mib, e);
            return ExitCode::FAILURE;
        }
    };
    let h = joined.join();
    match h {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            println!("PANIC variant={} stack={}MiB", variant, stack_mib);
            ExitCode::FAILURE
        }
    }
}

/// 递归测量 Value 深度（探针本身用小输入，无炸弹风险时才调用）。
fn probe_depth(v: &serde_yaml::Value, d: usize) -> usize {
    match v {
        serde_yaml::Value::Sequence(s) => s.iter().map(|x| probe_depth(x, d + 1)).max().unwrap_or(d),
        serde_yaml::Value::Mapping(m) => m
            .values()
            .map(|x| probe_depth(x, d + 1))
            .max()
            .unwrap_or(d),
        _ => d,
    }
}
