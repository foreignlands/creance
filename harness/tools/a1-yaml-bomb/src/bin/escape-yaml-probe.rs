//! R2→011 回归：畸形 lima.yaml 在探针解析路径上的行为。
//! 复刻 escape.rs 的判定逻辑：get("mounts")+as_sequence+unwrap_or(0)。
use serde_yaml::Value;

fn probe_outcome(bytes: &[u8]) -> &'static str {
    match serde_yaml::from_slice::<Value>(bytes) {
        Ok(value) => {
            let mounts = value
                .get("mounts")
                .and_then(Value::as_sequence)
                .map(|s| s.len())
                .unwrap_or(0);
            if mounts <= 1 { "Contained" } else { "Escaped" }
        }
        Err(_) => "Escaped(parse-err)",
    }
}

fn main() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("root-sequence", b"[a, b]\n".to_vec()),
        ("root-scalar",   b"just a string\n".to_vec()),
        ("root-number",   b"123\n".to_vec()),
        ("root-null",     b"null\n".to_vec()),
        ("multi-doc",     b"---\nmounts: []\n---\nmounts: []\n".to_vec()),
        ("alias-mass",    b"x: &x [{}, {}, {}, {}]\nmounts: *x\n".to_vec()),
        ("mounts-map",    b"mounts: {a: 1}\n".to_vec()),
        ("mounts-str",    b"mounts: four\n".to_vec()),
        ("normal-1",      b"mounts:\n  - location: /w\n".to_vec()),
    ("merge-key",     b"base: &b\n  location: /secret\nmounts:\n  - <<: *b\n".to_vec()),
    ("merge-extra",   b"base: &b {location: /secret}\nmounts:\n  - <<: *b\n    writable: true\n".to_vec()),

    ];
    for (name, bytes) in cases {
        println!("[{name:12}] -> {}", probe_outcome(&bytes));
    }
}
