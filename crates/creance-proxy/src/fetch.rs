//! Subscription fetching through the cage egress: proxy-only transport,
//! hostnames handed to the proxy unresolved, the 8 MiB import cap enforced,
//! and a bounded redirect chain.

use creance_net::egress::{Egress, request_bounded};
use creance_vm::config::Config;
use std::time::{Duration, Instant};

/// One fetch budget, matching the Go fetcher.
const FETCH_TIMEOUT: Duration = Duration::from_secs(60);
/// Go's client issues at most 3 requests (initial + 2 redirects).
const MAX_REDIRECTS: usize = 2;
/// Escape hatch for plain-http sources on trusted intranets: a plaintext
/// subscription sends node credentials in the clear to the exit. Off by
/// default (FINDING-009).
const ALLOW_HTTP_ENV: &str = "CREANCE_ALLOW_HTTP_SUB";

fn http_allowed() -> bool {
    std::env::var(ALLOW_HTTP_ENV).as_deref() == Ok("1")
}

/// The Go fetch policy: https-only, no userinfo, no fragment — for the
/// initial URL and every redirect target alike. `allow_http` is the
/// explicit intranet escape hatch (off in production).
fn validate_fetch_url(u: &url::Url, allow_http: bool) -> Result<(), String> {
    if u.scheme() != "https" && !allow_http {
        return Err(format!(
            "订阅地址必须使用 https；明文 http 会把订阅凭据暴露给链路（确需内网明文源可设 {ALLOW_HTTP_ENV}=1 自担风险）"
        ));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err("订阅地址不能携带 userinfo（凭据会进入日志与 store）".to_owned());
    }
    if u.fragment().is_some() {
        return Err("订阅地址不能携带 fragment".to_owned());
    }
    Ok(())
}

fn is_blocked_v4(v4: std::net::Ipv4Addr) -> bool {
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
}

/// Fetches `url` through `config`'s proxy and returns the body. Relative
/// redirects are joined against the current URL; anything outside 2xx after
/// `MAX_REDIRECTS` hops is an error.
pub fn fetch_subscription(config: &Config, url: &str) -> Result<Vec<u8>, String> {
    let egress = Egress::new(&config.resolved_proxy_url()?, &config.dns_url)?;
    fetch_subscription_through(&egress, url)
}

pub fn fetch_subscription_through(egress: &Egress, url: &str) -> Result<Vec<u8>, String> {
    fetch_loop(url, |u, deadline| {
        request_bounded(egress, "GET", u, None, &[], deadline, crate::MAX_IMPORT)
    })
}

/// 主机直连下载订阅（0.8.3 引导）：首次配置尚无可用代理时，用户明示
/// 勾选后不经代理直连下载订阅文本。下载的是配置数据而非环境流量，
/// 不构成 fail-closed 缺口；SSRF 防护与重定向纪律与代理路径完全相同
/// （直连路径的 SSRF 风险反而更高——本机解析+本机拨号，内网目标
/// 必须同样拒绝）。
pub fn fetch_subscription_host(url: &str) -> Result<Vec<u8>, String> {
    fetch_loop(url, |u, deadline| {
        creance_net::egress::request_direct("GET", u, deadline, crate::MAX_IMPORT)
    })
}

fn fetch_loop(
    url: &str,
    fetch: impl Fn(&str, Instant) -> Result<creance_net::egress::HttpResponse, String>,
) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + FETCH_TIMEOUT;
    let mut current = url.to_owned();
    for _ in 0..=MAX_REDIRECTS {
        let next_url = url::Url::parse(&current).map_err(|e| e.to_string())?;
        validate_fetch_url(&next_url, http_allowed())?;
        let response = fetch(&current, deadline)?;
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
                // A literal loopback/private/link-local target is dialed by
                // the LOCAL core, turning a hostile subscription into an
                // SSRF probe of the host and LAN. Hostnames resolve at the
                // remote exit, so only literals need refusing here.
                let host = next.host_str().unwrap_or_default();
                let bare = host.trim_start_matches('[').trim_end_matches(']');
                if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
                    // FINDING-007: an IPv4-mapped IPv6 (::ffff:a.b.c.d) is an
                    // IPv4 address to every dialer — mihomo normalizes it and
                    // dials the v4 — so it must be judged by IPv4 rules.
                    let blocked = match ip {
                        std::net::IpAddr::V4(v4) => is_blocked_v4(v4),
                        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                            Some(v4) => is_blocked_v4(v4),
                            None => {
                                v6.is_loopback()
                                    || v6.is_unspecified()
                                    || v6.is_multicast()
                                    || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique-local
                                    || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local
                            }
                        },
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
    Err(format!(
        "subscription fetch exceeded {MAX_REDIRECTS} redirects"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // These integration tests ride plaintext loopback servers; the https
    // policy itself is covered by the direct unit tests below.
    fn allow_http_for_tests() {
        // Tests only ever write the same "1" value, so concurrent
        // writers cannot observe a torn or differing value.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var(ALLOW_HTTP_ENV, "1")
        };
    }

    #[test]
    fn fetch_policy_matches_go() {
        let https = "https://example.com/sub.yaml";
        let mk = |u: &str| url::Url::parse(u).unwrap();
        // https clean: accepted, either mode.
        assert!(validate_fetch_url(&mk(https), false).is_ok());
        assert!(validate_fetch_url(&mk(https), true).is_ok());
        // Plaintext: rejected unless the explicit intranet hatch is on.
        assert!(validate_fetch_url(&mk("http://example.com/sub.yaml"), false).is_err());
        assert!(validate_fetch_url(&mk("http://example.com/sub.yaml"), true).is_ok());
        // Userinfo and fragments are never acceptable (credentials/fragments
        // leak into logs and stores).
        for bad in [
            "https://user:pw@example.com/sub.yaml",
            "https://user@example.com/sub.yaml",
            "https://example.com/sub.yaml#frag",
        ] {
            assert!(validate_fetch_url(&mk(bad), false).is_err(), "{bad}");
            assert!(validate_fetch_url(&mk(bad), true).is_err(), "{bad}");
        }
    }
    use creance_net::testsupport::{MixedProxy, RedirectServer, StaticServer};

    fn loopback_egress(proxy_addr: &str) -> Egress {
        Egress::new(
            &format!("socks5://{proxy_addr}"),
            "https://1.1.1.1/dns-query",
        )
        .unwrap()
    }

    #[test]
    fn fetch_carries_bodies_within_the_import_cap() {
        allow_http_for_tests();
        let proxy = MixedProxy::start(vec![]);
        let target = StaticServer::start(vec![b'x'; 1024]);
        let egress = loopback_egress(&proxy.addr);
        let body =
            fetch_subscription_through(&egress, &format!("http://{}/sub", target.addr)).unwrap();
        assert_eq!(body.len(), 1024);
    }

    #[test]
    fn fetch_rejects_oversized_bodies() {
        allow_http_for_tests();
        // The import cap is enforced at the transport, not after download.
        let proxy = MixedProxy::start(vec![]);
        let target = StaticServer::start(vec![b'a'; crate::MAX_IMPORT + 1]);
        let egress = loopback_egress(&proxy.addr);
        let err = fetch_subscription_through(&egress, &format!("http://{}/sub", target.addr))
            .unwrap_err();
        assert!(err.contains("too large"), "{err}");
    }

    #[test]
    fn fetch_follows_redirects_within_proxy() {
        allow_http_for_tests();
        let proxy = MixedProxy::start(vec![]);
        let target = StaticServer::start(b"moved".to_vec());
        let target_host = target.addr.replace("127.0.0.1", "localhost");
        let redirect = RedirectServer::start(&format!("http://{target_host}/next"));
        let egress = loopback_egress(&proxy.addr);
        let body =
            fetch_subscription_through(&egress, &format!("http://{}/sub", redirect.addr)).unwrap();
        assert_eq!(body, b"moved");
    }

    #[test]
    fn fetch_refuses_private_redirect_targets() {
        allow_http_for_tests();
        // SSRF guard: a redirect to loopback/private/link-local literals is
        // dialed by the LOCAL core and must be refused, not followed.
        let proxy = MixedProxy::start(vec![]);
        for target in [
            "http://127.0.0.1:8080/admin",
            "http://10.1.2.3/x",
            "http://169.254.169.254/latest/meta-data/",
            "http://192.168.1.1/router",
            "http://[::1]:80/x",
        ] {
            let redirect = RedirectServer::start(target);
            let egress = loopback_egress(&proxy.addr);
            let err = fetch_subscription_through(&egress, &format!("http://{}/sub", redirect.addr))
                .unwrap_err();
            assert!(err.contains("内网或本机"), "target {target}: {err}");
        }
        // IPv4-mapped IPv6 literals are the same internal addresses
        // (FINDING-007): refused end to end.
        for mapped in [
            "http://[::ffff:127.0.0.1]:8080/x",
            "http://[::ffff:10.1.2.3]/x",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://[::ffff:192.168.1.1]/router",
        ] {
            let redirect = RedirectServer::start(mapped);
            let egress = Egress::new(&proxy.socks5_url(), "https://1.1.1.1/dns-query").unwrap();
            let err = fetch_subscription_through(&egress, &format!("http://{}/sub", redirect.addr))
                .unwrap_err();
            assert!(err.contains("内网或本机"), "mapped {mapped}: {err}");
        }
        // Hostnamed (resolvable) targets still follow normally — the guard
        // is about literal addresses the local core would dial.
        let target = StaticServer::start(b"ok".to_vec());
        let target_host = target.addr.replace("127.0.0.1", "localhost");
        let redirect = RedirectServer::start(&format!("http://{target_host}/next"));
        let egress = loopback_egress(&proxy.addr);
        let body =
            fetch_subscription_through(&egress, &format!("http://{}/sub", redirect.addr)).unwrap();
        assert_eq!(body, b"ok");
    }

    #[test]
    fn fetch_bounds_redirect_loops() {
        allow_http_for_tests();
        // One server redirecting to itself by hostname: an endless loop the
        // hop bound must cut, via a hostname so the literal-IP guard stays
        // out of the picture.
        let proxy = MixedProxy::start(vec![]);
        let redirect = RedirectServer::start_self();
        let egress = loopback_egress(&proxy.addr);
        let err = fetch_subscription_through(&egress, &format!("http://{}/sub", redirect.addr))
            .unwrap_err();
        assert!(err.contains("redirect"), "{err}");
    }
}
