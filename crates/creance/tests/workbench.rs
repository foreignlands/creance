//! Workbench service tests: loopback-only routing, CSRF guard, and API
//! responses against a real server. One serial test: parallel instances
//! would race for ephemeral ports.

use creance_net::testsupport::{MixedProxy, StaticServer};

mod util;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const SUB_YAML: &str = "proxies:\n  - name: US-Exit\n    type: ss\n    server: 192.0.2.10\n    port: 8388\n    cipher: aes-128-gcm\n    password: x\n";

fn start_server(profile: &str, config_path: &str) -> u16 {
    // serve() binds an explicit port; pick a free one first and hand it over.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let (profile, config_path) = (profile.to_owned(), config_path.to_owned());
    std::thread::spawn(move || {
        let _ = creance::serve::serve(&profile, &config_path, port);
    });
    // Wait until it answers an HTTP request, not merely accepts TCP: the
    // bind may still be settling when a bare connect succeeds.
    for _ in 0..100 {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
            if stream
                .write_all(b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .is_ok()
            {
                let mut buf = Vec::new();
                if stream.read_to_end(&mut buf).is_ok()
                    && String::from_utf8_lossy(&buf).contains("200")
                {
                    return port;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("workbench did not start");
}

fn raw(port: u16, request: &str) -> (String, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0);
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let body = String::from_utf8_lossy(&raw[split + 4..]).into_owned();
    let status = head.lines().next().unwrap_or_default().to_owned();
    (status, body)
}

fn post(port: u16, path: &str, body: &str) -> (String, String) {
    raw(
        port,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
}

#[test]
fn workbench_end_to_end() {
    // The loopback stub servers speak plaintext http; the https-only
    // subscription policy (FINDING-009) has its own unit coverage.
    std::env::set_var("CREANCE_ALLOW_HTTP_SUB", "1");
    let (profile, config_path) = util::fresh_profile();
    let port = start_server(&profile, &config_path);

    // ---- routing ----
    let (status, body) = raw(port, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    assert!(status.contains("200"), "{status}");
    assert!(body.contains("creance"));
    let (status, body) = raw(port, "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    assert!(status.contains("200"), "{status}");
    assert!(body.contains("\"applied\":false"), "{body}");
    let (status, _) = raw(port, "GET /api/none HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    assert!(status.contains("404"), "{status}");

    // ---- CSRF guard ----
    let (status, _) = post(port, "/api/proxy/stop", "{}");
    assert!(status.contains("200"), "no Origin header: allowed {status}");
    let (status, body) = raw(
        port,
        "POST /api/proxy/stop HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://evil.example\r\nContent-Length: 2\r\n\r\n{}",
    );
    assert!(status.contains("403"), "{status}: {body}");

    // Oversized bodies are rejected before parsing.
    let (status, _) = post(port, "/api/check", "x");
    // (small body passes the size guard and reaches the handler; the check
    // itself fails closed against a dead proxy)
    assert!(status.contains("409"), "{status}");

    // ---- import over the loopback proxy, then select ----
    let proxy = MixedProxy::start(vec![]);
    let target = StaticServer::start(SUB_YAML.as_bytes().to_vec());
    let config = {
        let mut c = creance_vm::config::load(&config_path).unwrap();
        c.proxy_url = proxy.socks5_url();
        c
    };
    creance_vm::config::write_private_config(&config_path, &config).unwrap();

    let import = format!("{{\"name\":\"wb\",\"url\":\"http://{}/sub\"}}", target.addr);
    let (status, body) = post(port, "/api/proxy/import", &import);
    assert!(status.contains("200"), "{status}: {body}");
    assert!(body.contains("\"nodes\":1"), "{body}");

    let select = "{\"node\":\"US-Exit\"}";
    let (status, _) = post(port, "/api/proxy/select", select);
    assert!(status.contains("200"), "{status}");

    let (status, body) = raw(port, "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    assert!(status.contains("200"));
    assert!(body.contains("\"applied\":true"), "{body}");
}
