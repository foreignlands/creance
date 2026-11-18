//! Loopback test infrastructure for the egress: a mixed proxy with mihomo's
//! real dispatch semantics (one-byte peek; socks5 with optional RFC1929 auth;
//! HTTP CONNECT with Basic auth) and a plain HTTP target server.
//!
//! These mirror what the bundled core accepts, so a test that passes here
//! exercises the same wire shapes `cage check` and DoH see in production.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

/// A minimal HTTP target: answers every request with 200 and a fixed body.
pub struct TargetServer {
    pub addr: String,
    listener: TcpListener,
}

impl TargetServer {
    pub fn start() -> TargetServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind target");
        let addr = listener.local_addr().expect("addr").to_string();
        let server = TargetServer { addr, listener };
        let listener = server.listener.try_clone().expect("clone listener");
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || handle_target(stream));
            }
        });
        server
    }
}

/// Connects by IP literal without getaddrinfo — a hung resolver must never
/// stall loopback test relays.
fn connect_ip(host: &str, port: u16) -> std::io::Result<std::net::TcpStream> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return std::net::TcpStream::connect(std::net::SocketAddr::new(ip, port));
    }
    std::net::TcpStream::connect((host, port))
        .or_else(|_| std::net::TcpStream::connect(format!("{host}:{port}").as_str()))
}

/// The response body the target returns for every request.
pub const TARGET_BODY: &str = "cage-target-ok";

fn handle_target(mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let head = match read_header_block(&mut stream) {
        Ok(h) if !h.is_empty() => h,
        _ => return,
    };
    let text = String::from_utf8_lossy(&head);
    let len: usize = text
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse().ok())?
        })
        .unwrap_or(0);
    if len > 0 {
        let mut body = vec![0u8; len];
        if stream.read_exact(&mut body).is_err() {
            return;
        }
    }
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        TARGET_BODY.len(),
        TARGET_BODY
    );
    let _ = stream.write_all(response.as_bytes());
}

/// A mixed proxy with mihomo's dispatch semantics.
///
/// With `users` empty the proxy accepts any SOCKS5 method and ignores HTTP
/// Proxy-Authorization (mihomo's authenticator is nil without users). With
/// users set, SOCKS5 requires method 0x02 plus valid RFC1929 credentials and
/// HTTP requires a matching Basic header; failures answer exactly like the
/// bundled core (socks `[0x01, 0x01]`, HTTP `407`).
pub struct MixedProxy {
    pub addr: String,
}

impl MixedProxy {
    /// `users`: (username, password) pairs; empty = no auth required.
    pub fn start(users: Vec<(&str, &str)>) -> MixedProxy {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let addr = listener.local_addr().expect("addr").to_string();
        let users: Arc<Vec<(String, String)>> = Arc::new(
            users
                .into_iter()
                .map(|(u, p)| (u.to_owned(), p.to_owned()))
                .collect(),
        );
        let listener = listener.try_clone().expect("clone listener");
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let users = users.clone();
                std::thread::spawn(move || handle_mixed(stream, users));
            }
        });
        MixedProxy { addr }
    }

    pub fn socks5_url(&self) -> String {
        format!("socks5://{}", self.addr)
    }

    pub fn socks5_url_with_auth(&self, user: &str, pass: &str) -> String {
        format!("socks5://{user}:{pass}@{}", self.addr)
    }

    pub fn http_url_with_auth(&self, user: &str, pass: &str) -> String {
        format!("http://{user}:{pass}@{}", self.addr)
    }
}

/// mihomo's dispatch: one byte peek, no consumption — 0x05 socks5, 0x04
/// socks4 (rejected here), anything else HTTP.
fn handle_mixed(stream: TcpStream, users: Arc<Vec<(String, String)>>) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let mut peek = [0u8; 1];
    let mut stream = match stream.peek(&mut peek) {
        Ok(1) => stream,
        _ => return,
    };
    match peek[0] {
        0x05 => handle_socks5(&mut stream, users),
        0x04 => {
            let _ = stream.write_all(b"\x00\x5boperation not permitted\x00");
        }
        _ => handle_http_connect(&mut stream, users),
    }
}

fn socks5_auth_ok(users: &[(String, String)], username: &[u8], password: &[u8]) -> bool {
    users.is_empty()
        || users
            .iter()
            .any(|(u, p)| u.as_bytes() == username && p.as_bytes() == password)
}

fn handle_socks5(stream: &mut TcpStream, users: Arc<Vec<(String, String)>>) {
    let mut head = [0u8; 2];
    if stream.read_exact(&mut head).is_err() || head[0] != 0x05 {
        return;
    }
    let mut methods = vec![0u8; head[1] as usize];
    if stream.read_exact(&mut methods).is_err() {
        return;
    }
    // mihomo semantics: without configured users every method is accepted;
    // with users, only username/password auth.
    let need_auth = !users.is_empty();
    let pick = if need_auth && methods.contains(&0x02) {
        0x02
    } else if !need_auth && methods.contains(&0x00) {
        0x00
    } else {
        let _ = stream.write_all(&[0x05, 0xff]);
        return;
    };
    if stream.write_all(&[0x05, pick]).is_err() {
        return;
    }
    if pick == 0x02 {
        // RFC 1929 subnegotiation: VER(0x01), ULEN, UNAME, PLEN, PASSWD.
        let mut ver = [0u8; 1];
        if stream.read_exact(&mut ver).is_err() || ver[0] != 0x01 {
            return;
        }
        let mut ulen = [0u8; 1];
        if stream.read_exact(&mut ulen).is_err() {
            return;
        }
        let mut username = vec![0u8; ulen[0] as usize];
        if stream.read_exact(&mut username).is_err() {
            return;
        }
        let mut plen = [0u8; 1];
        if stream.read_exact(&mut plen).is_err() {
            return;
        }
        let mut password = vec![0u8; plen[0] as usize];
        if stream.read_exact(&mut password).is_err() {
            return;
        }
        let ok = socks5_auth_ok(&users, &username, &password);
        // clash-rs / mihomo both answer [0x01, 0x01] and drop on failure.
        if stream
            .write_all(&[0x01, if ok { 0x00 } else { 0x01 }])
            .is_err()
            || !ok
        {
            return;
        }
    }
    let mut head = [0u8; 4];
    if stream.read_exact(&mut head).is_err() || head[0] != 0x05 || head[1] != 0x01 {
        let _ = stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        return;
    }
    let (host, port) = match head[3] {
        0x01 => {
            let mut octets = [0u8; 4];
            if stream.read_exact(&mut octets).is_err() {
                return;
            }
            let mut port = [0u8; 2];
            if stream.read_exact(&mut port).is_err() {
                return;
            }
            (
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)).to_string(),
                u16::from_be_bytes(port),
            )
        }
        0x03 => {
            let mut len = [0u8; 1];
            if stream.read_exact(&mut len).is_err() {
                return;
            }
            let mut host = vec![0u8; len[0] as usize];
            if stream.read_exact(&mut host).is_err() {
                return;
            }
            let mut port = [0u8; 2];
            if stream.read_exact(&mut port).is_err() {
                return;
            }
            (
                String::from_utf8_lossy(&host).into_owned(),
                u16::from_be_bytes(port),
            )
        }
        0x04 => {
            let mut octets = [0u8; 16];
            if stream.read_exact(&mut octets).is_err() {
                return;
            }
            let mut port = [0u8; 2];
            if stream.read_exact(&mut port).is_err() {
                return;
            }
            (
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)).to_string(),
                u16::from_be_bytes(port),
            )
        }
        _ => {
            let _ = stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            return;
        }
    };
    let upstream = match connect_ip(&host, port) {
        Ok(s) => s,
        Err(_) => {
            let _ = stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            return;
        }
    };
    // Bound address: ATYP 1 + zeros + port, like the core's success reply.
    let _ = stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    relay(stream, upstream);
}

fn handle_http_connect(stream: &mut TcpStream, users: Arc<Vec<(String, String)>>) {
    let head = match read_header_block(stream) {
        Ok(h) if !h.is_empty() => h,
        _ => return,
    };
    let text = String::from_utf8_lossy(&head).into_owned();
    let first = text.lines().next().unwrap_or_default().to_owned();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or_default().to_uppercase();
    let target = parts.next().unwrap_or_default().to_owned();
    if method != "CONNECT" {
        let _ = stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n");
        return;
    }
    // Basic auth, honored only when users are configured.
    let auth_ok = users.is_empty()
        || text.lines().any(|l| {
            let Some((k, v)) = l.split_once(':') else {
                return false;
            };
            if !k.trim().eq_ignore_ascii_case("proxy-authorization") {
                return false;
            }
            let Some(encoded) = v.trim().strip_prefix("Basic ") else {
                return false;
            };
            decode_basic(encoded)
                .map(|c| users.iter().any(|(u, p)| c == format!("{u}:{p}")))
                .unwrap_or(false)
        });
    if !auth_ok {
        let _ = stream.write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"cage\"\r\nContent-Length: 0\r\n\r\n",
        );
        return;
    }
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (
            h.trim_start_matches('[').trim_end_matches(']').to_owned(),
            p.parse::<u16>().unwrap_or(0),
        ),
        None => (target.clone(), 80),
    };
    let upstream = match connect_ip(&host, port) {
        Ok(s) => s,
        Err(_) => {
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
            return;
        }
    };
    let _ = stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
    relay(stream, upstream);
}

fn decode_basic(encoded: &str) -> Result<String, ()> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut out = Vec::new();
    for c in encoded.bytes() {
        if c == b'=' {
            break;
        }
        let v = TABLE.iter().position(|t| *t == c).ok_or(())? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

/// Full-duplex copy between client and upstream.
fn relay(client: &mut TcpStream, upstream: TcpStream) {
    let mut upstream = upstream;
    let mut upstream_clone = match upstream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut client_clone = match client.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let up = std::thread::spawn(move || {
        let _ = std::io::copy(&mut client_clone, &mut upstream);
        let _ = upstream.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut upstream_clone, client);
    let _ = up.join();
    let _ = client.shutdown(std::net::Shutdown::Write);
}

fn read_header_block(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut block = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte)? {
            0 => break,
            _ => {
                block.push(byte[0]);
                if block.ends_with(b"\r\n\r\n") || block.ends_with(b"\n\n") {
                    break;
                }
                if block.len() > 32 << 10 {
                    return Err(std::io::Error::other("header too large"));
                }
            }
        }
    }
    Ok(block)
}

/// A port that nothing is listening on, for dead-upstream tests.
pub fn dead_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind dead");
    let addr = listener.local_addr().expect("addr").to_string();
    drop(listener);
    addr
}

/// An HTTP server answering every request with one fixed body (any size).
#[allow(dead_code)]
pub struct StaticServer {
    pub addr: String,
}

#[allow(dead_code)]
impl StaticServer {
    pub fn start(body: Vec<u8>) -> StaticServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind static");
        let addr = listener.local_addr().expect("addr").to_string();
        let listener = listener.try_clone().expect("clone listener");
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let body = body.clone();
                std::thread::spawn(move || {
                    let mut stream = stream;
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
                    if read_header_block(&mut stream)
                        .map(|h| h.is_empty())
                        .unwrap_or(true)
                    {
                        return;
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.write_all(&body);
                });
            }
        });
        StaticServer { addr }
    }
}

/// An HTTP server answering every request with one 301 redirect.
#[allow(dead_code)]
pub struct RedirectServer {
    pub addr: String,
}

impl RedirectServer {
    /// A server whose redirect points back at itself by hostname — for
    /// redirect-loop tests without literal-IP guards firing. The listener
    /// binds first so the Location names THIS server's port.
    pub fn start_self() -> RedirectServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind self-redirect");
        let addr = listener.local_addr().expect("addr").to_string();
        let port = addr.rsplit(':').next().unwrap().to_owned();
        let response = format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: http://localhost:{port}/sub\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let listener = listener.try_clone().expect("clone");
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
                if read_header_block(&mut stream)
                    .map(|h| h.is_empty())
                    .unwrap_or(true)
                {
                    continue;
                }
                let _ = stream.write_all(response.as_bytes());
            }
        });
        RedirectServer { addr }
    }
}

#[allow(dead_code)]
impl RedirectServer {
    pub fn start(location: &str) -> RedirectServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind redirect");
        let addr = listener.local_addr().expect("addr").to_string();
        let listener = listener.try_clone().expect("clone listener");
        let response = format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
                if read_header_block(&mut stream)
                    .map(|h| h.is_empty())
                    .unwrap_or(true)
                {
                    continue;
                }
                let _ = stream.write_all(response.as_bytes());
            }
        });
        RedirectServer { addr }
    }
}
