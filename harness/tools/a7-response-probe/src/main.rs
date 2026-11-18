//! A7/A8/B2/B3 矩阵：恶意 HTTP 目标服务器 × 生产 request_bounded。
//! 每个 case 一个独立端口；输出 [ACCEPT body=…]/[REJECT err]/[HANG]。

use creance_net::egress::{request_bounded, Egress};
mod testsupport_fixed;
use testsupport_fixed::MixedProxy;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 恶意目标：读掉请求头，回 `payload`（按字节），然后关闭。
/// `keep_open` 时关闭前保持连接 `hold_ms`（测 deadline 行为）。
fn evil_server(payload: Vec<u8>, hold_ms: u64) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let payload = payload.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buf = [0u8; 4096];
                // 吞 CONNECT 之前的请求头（隧道后是 GET 请求）
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(&payload);
                if hold_ms > 0 {
                    std::thread::sleep(Duration::from_millis(hold_ms));
                }
                drop(stream);
            });
        }
    });
    addr
}

fn run(case: &str, payload: Vec<u8>, hold_ms: u64, max_body: usize) {
    let proxy = MixedProxy::start(vec![]);
    let egress = Egress::new(&proxy.socks5_url(), "https://1.1.1.1/dns-query").unwrap();
    let addr = evil_server(payload, hold_ms);
    let deadline = Instant::now() + Duration::from_secs(if hold_ms > 0 { 2 } else { 10 });
    match request_bounded(&egress, "GET", &format!("http://{addr}/"), None, b"", deadline, max_body)
    {
        Ok(r) => println!(
            "[ACCEPT] {case} status={} body={}B body_hex={:?}",
            r.status,
            r.body.len(),
            String::from_utf8_lossy(&r.body).chars().take(40).collect::<String>()
        ),
        Err(e) => println!("[REJECT] {case} :: {e}"),
    }
}

fn head(he: &str) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\n{he}\r\n\r\n").into_bytes()
}

fn main() {
    // A8 chunked
    run("chunked-clean", head("Transfer-Encoding: chunked") .into_iter().chain(b"3\r\nabc\r\n0\r\n\r\n".to_vec()).collect(), 0, 64 << 10);
    run("chunked-eof-at-chunk-line", head("Transfer-Encoding: chunked").into_iter().chain(b"3\r\nabc\r\n".to_vec()).collect(), 0, 64 << 10);
    run("chunked-eof-mid-data", head("Transfer-Encoding: chunked").into_iter().chain(b"5\r\nab".to_vec()).collect(), 0, 64 << 10);
    run("chunk-line-17b", head("Transfer-Encoding: chunked").into_iter().chain(b"FFFFFFFFFFFFFFFFFF\r\n".to_vec()).collect(), 0, 64 << 10);
    run("chunk-size-over-max", head("Transfer-Encoding: chunked").into_iter().chain(b"F0000\r\nxx".to_vec()).collect(), 0, 64 << 10);
    run("chunk-garbage-after-crlf", head("Transfer-Encoding: chunked").into_iter().chain(b"3\r\nabcZZ5\r\nhello\r\n0\r\n\r\n".to_vec()).collect(), 0, 64 << 10);
    run("chunk-negative-size", head("Transfer-Encoding: chunked").into_iter().chain(b"-3\r\nabc\r\n0\r\n\r\n".to_vec()).collect(), 0, 64 << 10);
    // A7/B3 CL 语义
    run("dual-cl-different", head("Content-Length: 3\r\nContent-Length: 10").into_iter().chain(b"abcdefghij".to_vec()).collect(), 0, 64 << 10);
    run("cl-garbage", head("Content-Length: abc").into_iter().chain(b"0123456789".repeat(10)).collect(), 0, 64 << 10);
    run("cl-short-eof", head("Content-Length: 5").into_iter().chain(b"ab".to_vec()).collect(), 0, 64 << 10);
    run("cl-over-max", head("Content-Length: 99999999"), 0, 64 << 10);
    // A7 状态行/头块
    run("head-eof-half", b"HTTP/1.1 200 OK\r\nX".to_vec(), 0, 64 << 10);
    run("status-no-reason", head(""), 0, 64 << 10);
    run("status-nonutf8", b"HTTP/1.1 200 \xff\xff\r\nContent-Length: 0\r\n\r\n".to_vec(), 0, 64 << 10);
    run("header-16k-exact", head(&format!("X-Pad: {}", "a".repeat(16384 - 40))), 0, 64 << 10);
    run("header-16k-plus", head(&format!("X-Pad: {}", "a".repeat(16384 - 20))), 0, 64 << 10);
    // B2/B6 deadline
    run("slow-header-1B/s", b"HTTP/1.1 200 OK\r\n".to_vec(), 3000, 64 << 10);
    run("no-cl-hold-open", head("X-Pad: 1"), 3000, 64 << 10);
}
