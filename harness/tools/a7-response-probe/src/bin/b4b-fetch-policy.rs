//! B4b：fetch.rs vs Go fetch.go 的订阅策略漂移黑盒。
//! Go Fetch：初始必须 https + 无 userinfo/fragment（"订阅需要完整的 HTTPS 网址"）；
//! CheckRedirect：via>=3 拒 + 重定向后必须 https + User nil。
//! Rust fetch.rs：全部缺失。本探针用 http 明文链路证明。

use creance_net::egress::{request_bounded, Egress};
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[path = "tf/testsupport_fixed.rs"]
mod testsupport_fixed;
use testsupport_fixed::MixedProxy;

const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_IMPORT: usize = 8 << 20;

/// fetch.rs 的循环（无 scheme/userinfo 检查，MAX_REDIRECTS=5，原样）。
fn fetch_rust(egress: &Egress, url: &str) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + FETCH_TIMEOUT;
    let mut current = url.to_owned();
    for _ in 0..=5usize {
        let response = request_bounded(egress, "GET", &current, None, &[], deadline, MAX_IMPORT)?;
        match response.status {
            200..=299 => return Ok(response.body),
            301 | 302 | 303 | 307 | 308 => {
                let location = response
                    .header("location")
                    .ok_or("redirect response without Location")?;
                let base = url::Url::parse(&current).map_err(|e| e.to_string())?;
                let next = base
                    .join(location)
                    .map_err(|e| format!("invalid redirect target: {e}"))?;
                let host = next.host_str().unwrap_or_default();
                let bare = host.trim_start_matches('[').trim_end_matches(']');
                if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
                    let blocked = match ip {
                        std::net::IpAddr::V4(v4) => {
                            v4.is_loopback()
                                || v4.is_private()
                                || v4.is_link_local()
                                || v4.is_unspecified()
                                || v4.is_broadcast()
                                || v4.is_multicast()
                        }
                        std::net::IpAddr::V6(v6) => {
                            v6.is_loopback()
                                || v6.is_unspecified()
                                || v6.is_multicast()
                                || (v6.segments()[0] & 0xfe00) == 0xfc00
                                || (v6.segments()[0] & 0xffc0) == 0xfe80
                        }
                    };
                    if blocked {
                        return Err(format!("订阅重定向指向内网或本机地址（{host}），已拒绝"));
                    }
                }
                current = next.to_string();
            }
            status => return Err(format!("subscription fetch returned HTTP {status}")),
        }
    }
    Err("subscription fetch exceeded 5 redirects".to_owned())
}

/// 计数重定向链服务器：/n<N> → 302 → /n<N+1>；/end → 200 "DONE"。
/// 返回命中计数器，用于测跳数。
fn chain_server() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let hits = Arc::new(AtomicUsize::new(0));
    let h2 = hits.clone();
    let l2 = listener.try_clone().unwrap();
    std::thread::spawn(move || {
        for mut stream in l2.incoming().flatten() {
            let h = h2.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let text = String::from_utf8_lossy(&buf);
                let path = text
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .to_owned();
                h.fetch_add(1, Ordering::SeqCst);
                let resp = if path.starts_with("/plain") || path == "/target" {
                    "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nDONE".to_string()
                } else if path == "/user-target" {
                    // userinfo 目标
                    "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nDONE".to_string()
                } else {
                    let n: usize = path
                        .trim_start_matches('/')
                        .trim_start_matches('n')
                        .parse()
                        .unwrap_or(0);
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: /n{}\r\nContent-Length: 0\r\n\r\n",
                        n + 1
                    )
                };
                let _ = stream.write_all(resp.as_bytes());
            });
        }
    });
    (addr, hits)
}

fn run(label: &str, url: &str, expect_go: &str) {
    let proxy = MixedProxy::start(vec![]);
    let egress = Egress::new(&proxy.socks5_url(), "https://1.1.1.1/dns-query").unwrap();
    match fetch_rust(&egress, url) {
        Ok(b) => println!(
            "[RUST-OK  ] {label} body={}B   | Go 预期: {expect_go}",
            b.len()
        ),
        Err(e) => println!("[RUST-REJ ] {label} :: {e}   | Go 预期: {expect_go}"),
    }
}

fn main() {
    let (addr, hits) = chain_server();
    let port = addr.rsplit(':').next().unwrap();

    println!("chain server at {addr}");
    // 1. 初始 http 明文订阅（Go：拒绝——初始必须 https）
    run("init-plaintext-http", &format!("http://{addr}/plain"), "拒绝：订阅需要完整的 HTTPS 网址");
    // 2. 重定向降级 https→http 需 TLS 起点，此处测 http→http 链（Go：CheckRedirect 拒非 https target）
    run("redirect-stays-http", &format!("http://localhost:{port}/n0"), "拒绝：订阅重定向被拒绝（scheme != https）");
    // 3. 跳数：Rust 5 跳 vs Go via>=3 拒（2 跳后第 3 个 redirect 拒）
    hits.store(0, Ordering::SeqCst);
    run("redirect-count", &format!("http://localhost:{port}/n0"), "拒绝：via>=3");
    let n = hits.load(Ordering::SeqCst);
    println!("           -> server 命中 {n} 次（Rust 允许 6 次请求 = 5 跳；Go 只允许 3 次请求 = 2 跳）");
    // 4. userinfo 注入（Go：r.URL.User != nil 拒 + 初始 User != nil 拒）
    run("redirect-userinfo", &format!("http://attacker:pw@{addr}/plain"), "拒绝：不支持地址内用户名和密码");
    // 5. 重定向到带 userinfo 的目标
    run("redirect-to-userinfo", &format!("http://localhost:{port}/n0x-user"), "拒绝：r.URL.User != nil");
}
