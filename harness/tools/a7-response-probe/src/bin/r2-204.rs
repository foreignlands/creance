//! R2：204/304 无 body 响应 × 保持连接的服务器。
//! Go net/http 按状态码立即完成；若 egress 等 EOF 到 deadline 即缺陷。

use creance_net::egress::{request_bounded, Egress};
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::time::{Duration, Instant};

#[path = "tf/testsupport_fixed.rs"]
mod testsupport_fixed;
use testsupport_fixed::MixedProxy;

fn hold_open_server(status_line: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let head = format!("{}\r\n\r\n", status_line);
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let head = head.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(head.as_bytes());
                // 合理服务器：204/304 无 body，连接保持打开（keepalive 池）
                std::thread::sleep(Duration::from_secs(10));
            });
        }
    });
    addr
}

fn main() {
    for (label, line) in [
        ("204-no-cl-hold", "HTTP/1.1 204 No Content"),
        ("304-no-cl-hold", "HTTP/1.1 304 Not Modified"),
        ("200-cl0-hold", "HTTP/1.1 200 OK\r\nContent-Length: 0"),
    ] {
        let proxy = MixedProxy::start(vec![]);
        let egress = Egress::new(&proxy.socks5_url(), "https://1.1.1.1/dns-query").unwrap();
        let addr = hold_open_server(line);
        let deadline = Instant::now() + Duration::from_secs(4);
        let t0 = Instant::now();
        match request_bounded(&egress, "GET", &format!("http://{addr}/"), None, b"", deadline, 64 << 10) {
            Ok(r) => println!("[{label}] ACCEPT status={} body={}B elapsed={:.1}s", r.status, r.body.len(), t0.elapsed().as_secs_f32()),
            Err(e) => println!("[{label}] REJECT :: {e} elapsed={:.1}s", t0.elapsed().as_secs_f32()),
        }
    }
}
