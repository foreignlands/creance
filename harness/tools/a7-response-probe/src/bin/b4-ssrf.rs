//! B4 SSRF 守卫绕过探针。fetch_subscription_through 从
//! crates/creance-proxy/src/fetch.rs（2026-11-19 快照）逐行复制
//! （creance-proxy 无法独立 path-dep：workspace 继承路径错位）。
//!
//! 端到端证明方式：重定向到各种"本机地址变体"，用挂在 127.0.0.1 的
//! listener 判断连接是否真的到达本机（= SSRF 链成立）。
//! 用 testsupport_fixed（relay 顺序修正版）的 RedirectServer + MixedProxy。

use creance_net::egress::{request_bounded, Egress};
use std::io::Read;
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[path = "tf/testsupport_fixed.rs"]
mod testsupport_fixed;
use testsupport_fixed::{MixedProxy, RedirectServer};

const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 5;
const MAX_IMPORT: usize = 8 << 20;

/// —— fetch.rs 原样复制（守卫逻辑逐行相同）——
fn fetch_subscription_through(egress: &Egress, url: &str) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + FETCH_TIMEOUT;
    let mut current = url.to_owned();
    for _ in 0..=MAX_REDIRECTS {
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
    Err(format!("subscription fetch exceeded {MAX_REDIRECTS} redirects"))
}

/// —— 探针部分 ——

/// 挂在 127.0.0.1:port 的受害者 listener：任何连接都被计数。
fn victim() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let hits = Arc::new(AtomicUsize::new(0));
    let h2 = hits.clone();
    let l2 = listener.try_clone().unwrap();
    std::thread::spawn(move || {
        for stream in l2.incoming().flatten() {
            h2.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (addr, hits)
}

fn case(label: &str, location: String, victim_addr: &str, hits: &Arc<AtomicUsize>) {
    let proxy = MixedProxy::start(vec![]);
    let egress = Egress::new(&proxy.socks5_url(), "https://1.1.1.1/dns-query").unwrap();
    let redirect = RedirectServer::start(&location);
    let before = hits.load(Ordering::SeqCst);
    let started = Instant::now();
    let outcome = match fetch_subscription_through(
        &egress,
        &format!("http://{}/sub", redirect.addr),
    ) {
        Ok(b) => format!("FETCH-OK body={}B", b.len()),
        Err(e) => format!("FETCH-ERR {e}"),
    };
    let after = hits.load(Ordering::SeqCst);
    let reached = after > before;
    println!(
        "[{}] {} -> {}{} victim_hits={} elapsed={:.1}s",
        if reached { "SSRF-REACHED-VICTIM" } else { "no-conn" },
        label,
        outcome,
        if reached { "  <<< 守卫绕过：连接到达 127.0.0.1 受害者" } else { "" },
        after - before,
        started.elapsed().as_secs_f32()
    );
    let _ = victim_addr;
}

fn main() {
    let (vaddr, hits) = victim();
    println!("victim listener at {vaddr}");

    // 守卫明确拒绝的对照（应 REJECT 且无连接）
    case("baseline-127.0.0.1", format!("http://127.0.0.1:{vaddr}/admin"), &vaddr, &hits);
    case("baseline-10.x", format!("http://10.9.9.9:{vaddr}/x"), &vaddr, &hits);

    // 绕过候选
    case("v4mapped-loopback", format!("http://[::ffff:127.0.0.1]:{}/admin", vaddr.split(':').last().unwrap()), &vaddr, &hits);
    case("v4mapped-meta", format!("http://[::ffff:169.254.169.254]/latest/meta-data/"), &vaddr, &hits);
    case("decimal-ip", format!("http://2130706433:{}/admin", vaddr.split(':').last().unwrap()), &vaddr, &hits);
    case("octal-ip", format!("http://0177.0.0.1:{}/admin", vaddr.split(':').last().unwrap()), &vaddr, &hits);
    case("short-ip", format!("http://127.1:{}/admin", vaddr.split(':').last().unwrap()), &vaddr, &hits);
    case("hex-ip", format!("http://0x7f000001:{}/admin", vaddr.split(':').last().unwrap()), &vaddr, &hits);
    case("v6-zoneid", format!("http://[fe80::1%25lo0]:{}/x", vaddr.split(':').last().unwrap()), &vaddr, &hits);
    case("v6-nat64-64", format!("http://[64:ff9b::7f00:1]/x"), &vaddr, &hits);
}
