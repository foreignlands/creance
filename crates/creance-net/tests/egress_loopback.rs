//! End-to-end egress tests against loopback proxies that mimic the bundled
//! core's mixed port (one-byte peek dispatch, mihomo's auth semantics).
//!
//! These run fully offline: nothing leaves 127.0.0.1.

use creance_net::egress::{request, Egress};
use creance_net::testsupport::{dead_addr, MixedProxy, TargetServer, TARGET_BODY};
use std::time::{Duration, Instant};

fn egress_with(proxy_url: &str) -> Egress {
    Egress::new(proxy_url, "https://1.1.1.1/dns-query").expect("egress builds")
}

fn get_through(
    egress: &Egress,
    target_addr: &str,
    path: &str,
) -> Result<creance_net::egress::HttpResponse, String> {
    request(
        egress,
        "GET",
        &format!("http://{target_addr}{path}"),
        None,
        &[],
        Instant::now() + Duration::from_secs(10),
    )
}

#[test]
fn socks5_without_auth_carries_traffic() {
    let proxy = MixedProxy::start(vec![]);
    let target = TargetServer::start();
    let egress = egress_with(&proxy.socks5_url());
    let response = get_through(&egress, &target.addr, "/hello").expect("request through socks5");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, TARGET_BODY.as_bytes());
}

#[test]
fn socks5_with_auth_carries_traffic() {
    let proxy = MixedProxy::start(vec![("cage", "hunter2")]);
    let target = TargetServer::start();
    let egress = egress_with(&proxy.socks5_url_with_auth("cage", "hunter2"));
    let response = get_through(&egress, &target.addr, "/auth").expect("request with auth");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, TARGET_BODY.as_bytes());
}

#[test]
fn socks5_bad_credentials_fail_without_fallback() {
    let proxy = MixedProxy::start(vec![("cage", "hunter2")]);
    let target = TargetServer::start();
    let egress = egress_with(&proxy.socks5_url_with_auth("cage", "wrong"));
    let err = get_through(&egress, &target.addr, "/nope").expect_err("must fail");
    assert!(err.contains("认证失败"), "{err}");
    // The contract sentence must always be present: the proxy is the only path.
    assert!(err.contains("请检查代理"), "{err}");
    assert!(err.contains("不会改为直连"), "{err}");
}

#[test]
fn socks5_client_without_credentials_when_required_fails() {
    let proxy = MixedProxy::start(vec![("cage", "hunter2")]);
    let target = TargetServer::start();
    let egress = egress_with(&proxy.socks5_url());
    let err = get_through(&egress, &target.addr, "/nope").expect_err("must fail");
    assert!(err.contains("认证") || err.contains("SOCKS5"), "{err}");
}

#[test]
fn http_connect_with_auth_carries_traffic() {
    let proxy = MixedProxy::start(vec![("cage", "pw")]);
    let target = TargetServer::start();
    let egress = egress_with(&proxy.http_url_with_auth("cage", "pw"));
    let response = get_through(&egress, &target.addr, "/connect").expect("request through CONNECT");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, TARGET_BODY.as_bytes());
}

#[test]
fn http_connect_wrong_credentials_answer_407() {
    let proxy = MixedProxy::start(vec![("cage", "pw")]);
    let target = TargetServer::start();
    let egress = egress_with(&proxy.http_url_with_auth("cage", "nope"));
    let err = get_through(&egress, &target.addr, "/nope").expect_err("must fail");
    // The proxy's 407 is surfaced, never bypassed.
    assert!(err.contains("407"), "{err}");
    assert!(err.contains("不会改为直连"), "{err}");
}

#[test]
fn dead_proxy_fails_closed() {
    let egress = egress_with(&format!("socks5://{}", dead_addr()));
    let err = get_through(&egress, "127.0.0.1:1", "/").expect_err("must fail");
    assert!(err.contains("不会改为直连"), "{err}");
}

#[test]
fn unreachable_target_reports_proxy_error_not_direct() {
    // Proxy is healthy; the target does not exist. The error must name the
    // proxy path, never a direct route.
    let proxy = MixedProxy::start(vec![]);
    let egress = egress_with(&proxy.socks5_url());
    let err = get_through(&egress, &dead_addr(), "/").expect_err("must fail");
    assert!(err.contains("代理") || err.contains("SOCKS5"), "{err}");
}

#[test]
fn requests_never_resolve_hosts_locally() {
    // A hostname target is passed to the proxy as a name (ATYP 3). Our mixed
    // proxy would have to resolve it, which fails closed for ".invalid" —
    // the important part is the request REACHES the proxy (socks5 reply code
    // 0x01 host unreachable), proving no local resolution happened first.
    let proxy = MixedProxy::start(vec![]);
    let egress = egress_with(&proxy.socks5_url());
    let err = get_through(&egress, "never-resolves.invalid:80", "/")
        .expect_err("proxy cannot reach it either");
    assert!(!err.contains("域名解析"), "{err}");
}

// ---------- Online smoke tests: opt-in via CAGE_ONLINE_PROXY ----------
// Set CAGE_ONLINE_PROXY to a real proxy URL (e.g. a node you configured in
// the managed core) and run: cargo test -- --ignored

fn online_egress() -> Option<Egress> {
    let url = std::env::var("CAGE_ONLINE_PROXY").ok()?;
    Some(egress_with(&url))
}

#[test]
#[ignore]
fn online_trace_through_real_proxy() {
    let Some(egress) = online_egress() else {
        eprintln!("CAGE_ONLINE_PROXY not set; skipping");
        return;
    };
    let response = request(
        &egress,
        "GET",
        "https://1.1.1.1/cdn-cgi/trace",
        None,
        &[],
        Instant::now() + Duration::from_secs(25),
    )
    .expect("trace through real proxy");
    assert_eq!(response.status, 200);
    let body = String::from_utf8_lossy(&response.body);
    assert!(body.contains("ip="), "trace body should carry the exit IP");
}

#[test]
#[ignore]
fn online_doh_through_real_proxy() {
    let Some(egress) = online_egress() else {
        eprintln!("CAGE_ONLINE_PROXY not set; skipping");
        return;
    };
    let reply = egress
        .exchange_dns(&creance_net::dnsmsg::Message::query(
            0x42,
            "example.com",
            creance_net::dnsmsg::TYPE_A,
        ))
        .expect("DoH through real proxy");
    assert!(reply.response);
}
