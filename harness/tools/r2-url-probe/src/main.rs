//! 004 回归矩阵：找尾斜杠启发式的误放行与误拒绝。
//! 基准=Go url.Parse 语义（Path != "" 即拒；"http://u:p@h:p" Path="" 放行）。

use creance_net::egress::validate_proxy_url;

/// (输入, Go 语义预期) —— Go: Path=="" 且无 query/fragment 才放行
const CASES: &[(&str, bool)] = &[
    // 基线（两侧一致）
    ("socks5://1.2.3.4:1080", true),
    ("socks5://1.2.3.4:1080/", false),          // R1 已修：尾斜杠拒
    ("socks5://[::1]:1080", true),
    ("socks5://[::1]:1080/", false),
    ("http://cage:pw@1.2.3.4:1080", true),       // userinfo 无 path 放行
    ("socks5://1.2.3.4:1080/admin", false),
    // 误放行候选（WHATWG trim/规范化 vs 原始串 ends_with('/')）
    ("socks5://1.2.3.4:1080/ ", false),          // 尾斜杠+空格：WHATWG trim 后 path="/"
    ("socks5://1.2.3.4:1080/\t", false),         // 尾斜杠+tab
    ("socks5://1.2.3.4:1080/\r", false),         // 尾斜杠+CR
    ("http://1.2.3.4:1080\\", false),            // special scheme 反斜杠=斜杠
    ("http://1.2.3.4:1080/\\", false),           // 斜杠+反斜杠
    ("socks5://1.2.3.4:1080//", false),          // 双斜杠
    ("socks5://1.2.3.4:1080/./", false),         // 点段
    ("socks5://1.2.3.4:1080/;", false),          // 分号参数
    ("socks5://1.2.3.4:1080/%2F", false),        // 编码斜杠
    ("SOCKS5://1.2.3.4:1080/", false),           // 大小写
    ("socks5://1.2.3.4:1080/#", false),          // 空 fragment
    ("socks5://1.2.3.4:1080?x=1", false),        // query
    // 误拒绝候选（合法但被新逻辑误伤）
    ("socks5://cage:pw@1.2.3.4:1080", true),     // userinfo 非 special
    ("http://1.2.3.4:1080", true),               // special 无 userinfo（默认 / 不拒）
    ("https://1.2.3.4:8443", true),
    ("socks5://0.0.0.0:1", true),                // unspecified 也是数字 IP
    ("socks5://255.255.255.255:65535", true),
];

fn main() {
    let mut drift = 0;
    for (input, go_ok) in CASES {
        let rust_ok = validate_proxy_url(input).is_ok();
        let tag = if rust_ok == *go_ok { "match" } else { "DRIFT" };
        if rust_ok != *go_ok {
            drift += 1;
        }
        println!(
            "[{:5}] go={:5} rust={:5}  {:?}",
            tag,
            if *go_ok { "pass" } else { "rej" },
            if rust_ok { "pass" } else { "rej" },
            input
        );
    }
    println!("--- {drift} drift(s) vs Go semantics ---");
}
