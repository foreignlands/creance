//! Subscription fetching through the cage egress: proxy-only transport,
//! hostnames handed to the proxy unresolved, the 8 MiB import cap enforced,
//! and a bounded redirect chain.

use crate::config::Config;
use crate::egress::{request_bounded, Egress};
use std::time::{Duration, Instant};

/// One fetch budget, matching the Go fetcher.
const FETCH_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_REDIRECTS: usize = 5;

/// Fetches `url` through `config`'s proxy and returns the body. Relative
/// redirects are joined against the current URL; anything outside 2xx after
/// `MAX_REDIRECTS` hops is an error.
pub fn fetch_subscription(config: &Config, url: &str) -> Result<Vec<u8>, String> {
    let egress = Egress::new(config)?;
    fetch_subscription_through(&egress, url)
}

pub fn fetch_subscription_through(egress: &Egress, url: &str) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + FETCH_TIMEOUT;
    let mut current = url.to_owned();
    for _ in 0..=MAX_REDIRECTS {
        let response = request_bounded(
            egress,
            "GET",
            &current,
            None,
            &[],
            deadline,
            crate::proxy::MAX_IMPORT,
        )?;
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
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
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
                                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique-local
                                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local
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
    Err(format!(
        "subscription fetch exceeded {MAX_REDIRECTS} redirects"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::{MixedProxy, RedirectServer, StaticServer};

    fn loopback_config(proxy_addr: &str) -> Config {
        Config {
            proxy_url: format!("socks5://{proxy_addr}"),
            dns_url: "https://1.1.1.1/dns-query".to_owned(),
            timezone: "Etc/UTC".to_owned(),
            locale: "en_US.UTF-8".to_owned(),
            browser_language: "en-US".to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn fetch_carries_bodies_within_the_import_cap() {
        let proxy = MixedProxy::start(vec![]);
        let target = StaticServer::start(vec![b'x'; 1024]);
        let egress = Egress::new(&loopback_config(&proxy.addr)).unwrap();
        let body =
            fetch_subscription_through(&egress, &format!("http://{}/sub", target.addr)).unwrap();
        assert_eq!(body.len(), 1024);
    }

    #[test]
    fn fetch_rejects_oversized_bodies() {
        // The import cap is enforced at the transport, not after download.
        let proxy = MixedProxy::start(vec![]);
        let target = StaticServer::start(vec![b'a'; crate::proxy::MAX_IMPORT + 1]);
        let egress = Egress::new(&loopback_config(&proxy.addr)).unwrap();
        let err = fetch_subscription_through(&egress, &format!("http://{}/sub", target.addr))
            .unwrap_err();
        assert!(err.contains("too large"), "{err}");
    }

    #[test]
    fn fetch_follows_redirects_within_proxy() {
        let proxy = MixedProxy::start(vec![]);
        let target = StaticServer::start(b"moved".to_vec());
        let redirect = RedirectServer::start(&format!("http://{}/next", target.addr));
        let egress = Egress::new(&loopback_config(&proxy.addr)).unwrap();
        let body =
            fetch_subscription_through(&egress, &format!("http://{}/sub", redirect.addr)).unwrap();
        assert_eq!(body, b"moved");
    }

    #[test]
    fn fetch_refuses_private_redirect_targets() {
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
            let egress = Egress::new(&loopback_config(&proxy.addr)).unwrap();
            let err = fetch_subscription_through(&egress, &format!("http://{}/sub", redirect.addr))
                .unwrap_err();
            assert!(err.contains("内网或本机"), "target {target}: {err}");
        }
        // Public literals and hostnames still follow normally.
        let target = StaticServer::start(b"ok".to_vec());
        let redirect = RedirectServer::start(&format!("http://{}/next", target.addr));
        let egress = Egress::new(&loopback_config(&proxy.addr)).unwrap();
        let body =
            fetch_subscription_through(&egress, &format!("http://{}/sub", redirect.addr)).unwrap();
        assert_eq!(body, b"ok");
    }

    #[test]
    fn fetch_bounds_redirect_loops() {
        // The redirect points at the server itself: an endless loop that the
        // hop bound must cut.
        let proxy = MixedProxy::start(vec![]);
        let redirect = RedirectServer::start("self");
        let self_url = format!("http://{}/sub", redirect.addr);
        let _redirect = RedirectServer::start(&self_url);
        let egress = Egress::new(&loopback_config(&proxy.addr)).unwrap();
        let err = fetch_subscription_through(&egress, &self_url).unwrap_err();
        assert!(err.contains("redirect"), "{err}");
        let _ = proxy;
    }
}
