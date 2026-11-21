//! The cage egress: exactly one upstream, never a direct fallback.
//!
//! All guest TCP connections and DNS exchanges cross the configured proxy.
//! Hostnames are handed to the proxy unresolved — the host resolver never
//! sees guest destinations, and a failed proxy never degrades into a direct
//! connection.
//!
//! Wire shapes, by proxy scheme and target:
//! - `socks5`  → SOCKS5 stream (RFC 1928/1929), TLS added on top for HTTPS targets
//! - `http`    → CONNECT tunnel, TLS added on top for HTTPS targets
//! - `https`   → TLS to the proxy, CONNECT through it, then TLS to the target

use crate::dnsmsg::Message;
use rustls_pki_types::ServerName;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// One attempt budget, matching the Go egress.
const DIAL_TIMEOUT: Duration = Duration::from_secs(20);
const DNS_TOTAL_TIMEOUT: Duration = Duration::from_secs(20);
const DNS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(6);
/// A header block cannot be larger than this.
const MAX_HEADER: usize = 16 << 10;
const MAX_HTTP_BODY: usize = 64 << 10;

/// The proxy endpoint must be http(s)/socks5 with a numeric host and port —
/// the proxy bootstrap itself may not need a resolver.
pub fn validate_proxy_url(s: &str) -> Result<(), String> {
    let u = url::Url::parse(s).map_err(|_| "invalid proxy URL".to_owned())?;
    if !matches!(u.scheme(), "http" | "https" | "socks5" | "socks5h") {
        return Err("proxy must use http, https or socks5".to_owned());
    }
    // FINDING-004: strip the brackets Go's Hostname() never returns —
    // `[::1]` is as numeric as `::1`.
    let host = u
        .host_str()
        .unwrap_or_default()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if host.parse::<std::net::IpAddr>().is_err() {
        return Err(
            "proxy endpoint must be a numeric IP address; DNS bootstrap is not allowed".to_owned(),
        );
    }
    let port = u.port().ok_or("proxy requires a valid explicit port")?;
    if !(1..=65535).contains(&port) {
        return Err("proxy requires a valid explicit port".to_owned());
    }
    // FINDING-004/015: Go rejects any Path — `/` is a path too. The WHATWG
    // parser cannot distinguish an absent path from a spelled `/` (it
    // defaults special schemes to "/"), so decide structurally on a
    // normalized copy of the input: the URL has an explicit path iff the
    // authority is directly followed by '/'. Mirrors WHATWG's trimming of
    // leading/trailing C0-space and its backslash-is-slash rule, which the
    // old raw `ends_with('/')` heuristic missed.
    if explicit_path(s) || u.query().is_some() || u.fragment().is_some() {
        return Err("proxy URL must not contain a path, query or fragment".to_owned());
    }
    Ok(())
}

/// Whether `raw` spells a path after its authority: WHATWG-normalize
/// (C0/space trim, `\` as `/`, case-insensitive scheme delimiter), then
/// look at the first `/ ? #` after `://` — a `/` there is a real path.
fn explicit_path(raw: &str) -> bool {
    let normalized: String = raw.trim_matches(|c: char| c <= ' ').replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();
    let Some(after_scheme) = lower.split_once("://").map(|(_, rest)| rest) else {
        return false;
    };
    match after_scheme.find(['/', '?', '#']) {
        Some(i) => after_scheme.as_bytes()[i] == b'/',
        None => false,
    }
}

/// The resolver must be an HTTPS DoH endpoint without credentials.
pub fn validate_dns_url(s: &str) -> Result<(), String> {
    let u = url::Url::parse(s)
        .map_err(|_| "DNS URL must be an HTTPS DNS-over-HTTPS endpoint".to_owned())?;
    if u.scheme() != "https"
        || u.host_str().unwrap_or_default().is_empty()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
    {
        return Err("DNS URL must be an HTTPS DNS-over-HTTPS endpoint".to_owned());
    }
    Ok(())
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A TCP tunnel through the proxy: SOCKS5 or CONNECT. TLS layers stack on
/// top, type-erased, so an HTTPS proxy carrying an HTTPS target works.
pub struct Channel(TunnelKind);

enum TunnelKind {
    Plain(Tunnel),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, Box<dyn RW>>>),
}

/// The IO surface a stackable TLS layer needs.
trait RW: Read + Write + 'static {
    fn set_deadline(&self, at: Instant);
    fn clear_deadline(&self);
}

impl RW for Tunnel {
    fn set_deadline(&self, at: Instant) {
        // An already-passed deadline means the budget is spent: fail fast
        // with a 1ms timeout instead of silently leaving the old one.
        let remaining = at
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_millis(1))
            .max(Duration::from_millis(1));
        let _ = self.0.set_read_timeout(Some(remaining));
        let _ = self.0.set_write_timeout(Some(remaining));
    }

    fn clear_deadline(&self) {
        let _ = self.0.set_read_timeout(None);
        let _ = self.0.set_write_timeout(None);
    }
}

impl RW for rustls::StreamOwned<rustls::ClientConnection, Box<dyn RW>> {
    fn set_deadline(&self, at: Instant) {
        self.sock.set_deadline(at)
    }

    fn clear_deadline(&self) {
        self.sock.clear_deadline()
    }
}

impl Read for Channel {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.0 {
            TunnelKind::Plain(t) => t.read(buf),
            TunnelKind::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Channel {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match &mut self.0 {
            TunnelKind::Plain(t) => t.write(buf),
            TunnelKind::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.0 {
            TunnelKind::Plain(t) => t.flush(),
            TunnelKind::Tls(s) => s.flush(),
        }
    }
}

impl Channel {
    fn set_deadline(&self, at: Instant) {
        self.0.set_deadline(at)
    }

    /// Removes read/write timeouts: the tunnel is unbounded from here on and
    /// the next reader sets its own budget.
    fn clear_deadline(&self) {
        self.0.clear_deadline();
    }
}

impl TunnelKind {
    fn clear_deadline(&self) {
        match self {
            TunnelKind::Plain(t) => t.clear_deadline(),
            TunnelKind::Tls(s) => s.sock.clear_deadline(),
        }
    }

    fn set_deadline(&self, at: Instant) {
        match self {
            TunnelKind::Plain(t) => t.set_deadline(at),
            TunnelKind::Tls(s) => s.sock.set_deadline(at),
        }
    }
}

/// A TCP stream to the proxy, with per-operation deadlines.
struct Tunnel(TcpStream);

impl Read for Tunnel {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for Tunnel {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// The single-upstream egress.
pub struct Egress {
    upstream: url::Url,
    dns_url: String,
}

impl Egress {
    /// Builds an egress from its two primitives. The endpoint must be a
    /// numeric IP (no DNS bootstrap) and the resolver an HTTPS DoH URL.
    pub fn new(proxy_url: &str, dns_url: &str) -> Result<Egress, String> {
        validate_proxy_url(proxy_url)?;
        validate_dns_url(dns_url)?;
        Ok(Egress {
            upstream: url::Url::parse(proxy_url).map_err(|_| "invalid proxy URL".to_owned())?,
            dns_url: dns_url.to_owned(),
        })
    }

    /// Opens a TCP connection to `addr` (`host:port`) through the upstream
    /// with the default dial budget. The host is never resolved locally.
    pub fn dial(&self, addr: &str) -> Result<Channel, String> {
        self.dial_deadline(addr, Instant::now() + DIAL_TIMEOUT)
    }

    /// `dial` with a caller-owned deadline: the whole tunnel setup (TCP,
    /// optional TLS, proxy handshake) must finish inside it.
    pub fn dial_deadline(&self, addr: &str, deadline: Instant) -> Result<Channel, String> {
        let (host, port) = split_addr(addr)?;
        let upstream_host = self.upstream.host_str().unwrap_or_default().to_owned();
        let upstream_port = self
            .upstream
            .port()
            .ok_or("proxy requires a valid explicit port")?;
        let socks = self.upstream.scheme().starts_with("socks5");
        let stream =
            tcp_connect(&format!("{upstream_host}:{upstream_port}"), deadline).map_err(|e| {
                user_error(
                    if socks {
                        "连接指定 SOCKS5 代理"
                    } else {
                        "连接指定代理"
                    },
                    e,
                )
            })?;
        let tunnel = Tunnel(stream);
        tunnel.set_deadline(deadline);
        match self.upstream.scheme() {
            s if s.starts_with("socks5") => {
                let tunnel = self.socks5_connect(tunnel, host, port)?;
                Ok(Channel(TunnelKind::Plain(tunnel)))
            }
            "http" => self.http_connect(Channel(TunnelKind::Plain(tunnel)), host, port),
            "https" => {
                let tls =
                    tls_wrap(Box::new(tunnel), &upstream_host).map_err(|_| user_tls_failure())?;
                self.http_connect(Channel(TunnelKind::Tls(tls)), host, port)
            }
            other => Err(format!("unsupported proxy scheme {other}")),
        }
    }

    /// RFC 1928 handshake on our own socket, so half-close stays available
    /// to the relay after authentication.
    fn socks5_connect(&self, mut tunnel: Tunnel, host: &str, port: u16) -> Result<Tunnel, String> {
        const FAIL: &str = "连接指定 SOCKS5 代理";
        let auth = self
            .upstream
            .password()
            .map(|pw| (self.upstream.username().to_owned(), pw.to_owned()));
        // RFC 1929 carries each credential in one length byte: refuse
        // over-long values instead of truncating them into a broken frame.
        if let Some((user, pass)) = &auth {
            if user.len() > 255 || pass.len() > 255 {
                return Err(
                    "SOCKS5 代理凭据过长（用户名与密码各限 255 字节）；请检查代理；请求不会改为直连。"
                        .to_owned(),
                );
            }
        }
        let mut greeting = vec![0x05u8];
        match &auth {
            Some(_) => greeting.extend([0x02, 0x00, 0x02]),
            None => greeting.extend([0x01, 0x00]),
        }
        tunnel
            .write_all(&greeting)
            .map_err(|e| user_error(FAIL, e))?;
        let mut reply = [0u8; 2];
        tunnel
            .read_exact(&mut reply)
            .map_err(|e| user_error(FAIL, e))?;
        if reply[0] != 0x05 {
            return Err("代理不是 SOCKS5 协议；请检查代理；请求不会改为直连。".to_owned());
        }
        match reply[1] {
            0x00 => {}
            0x02 => {
                let (user, pass) = auth
                    .clone()
                    .ok_or("SOCKS5 代理要求用户名密码认证，但配置中没有凭据")?;
                let mut req = vec![0x01u8, user.len() as u8];
                req.extend_from_slice(user.as_bytes());
                req.push(pass.len() as u8);
                req.extend_from_slice(pass.as_bytes());
                tunnel.write_all(&req).map_err(|e| user_error(FAIL, e))?;
                let mut status = [0u8; 2];
                tunnel
                    .read_exact(&mut status)
                    .map_err(|e| user_error(FAIL, e))?;
                if status[1] != 0x00 {
                    return Err("SOCKS5 代理认证失败；请检查代理；请求不会改为直连。".to_owned());
                }
            }
            _ => {
                return Err(
                    "SOCKS5 代理拒绝了全部认证方式；请检查代理；请求不会改为直连。".to_owned(),
                )
            }
        }
        let mut req = vec![0x05u8, 0x01, 0x00];
        push_socks5_target(&mut req, host, port)?;
        tunnel.write_all(&req).map_err(|e| user_error(FAIL, e))?;
        let mut head = [0u8; 4];
        tunnel
            .read_exact(&mut head)
            .map_err(|e| user_error(FAIL, e))?;
        if head[0] != 0x05 {
            return Err("代理不是 SOCKS5 协议；请检查代理；请求不会改为直连。".to_owned());
        }
        if head[1] != 0x00 {
            return Err(format!(
                "SOCKS5 代理拒绝连接（code {}）；请检查代理；请求不会改为直连。",
                head[1]
            ));
        }
        let skip = match head[3] {
            0x01 => 4 + 2,
            0x04 => 16 + 2,
            0x03 => {
                let mut len = [0u8; 1];
                tunnel
                    .read_exact(&mut len)
                    .map_err(|e| user_error(FAIL, e))?;
                len[0] as usize + 2
            }
            other => return Err(format!("SOCKS5 代理返回未知地址类型 {other}")),
        };
        let mut bound = vec![0u8; skip];
        tunnel
            .read_exact(&mut bound)
            .map_err(|e| user_error(FAIL, e))?;
        Ok(tunnel)
    }

    /// HTTP CONNECT on the (possibly TLS-wrapped) upstream channel.
    fn http_connect(&self, mut channel: Channel, host: &str, port: u16) -> Result<Channel, String> {
        let target = join_addr(host, port);
        let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if !self.upstream.username().is_empty() || self.upstream.password().is_some() {
            let credentials = format!(
                "{}:{}",
                self.upstream.username(),
                self.upstream.password().unwrap_or_default()
            );
            req.push_str(&format!(
                "Proxy-Authorization: Basic {}\r\n",
                base64(credentials.as_bytes())
            ));
        }
        req.push_str("\r\n");
        channel
            .write_all(req.as_bytes())
            .map_err(|e| user_error("发送代理 CONNECT 请求", e))?;
        let (head, _leftover) = crate::wire::read_header_block(&mut channel, MAX_HEADER)
            .map_err(|e| user_error("读取代理 CONNECT 响应", e))?;
        let status = parse_status(&head).ok_or_else(|| {
            "读取代理 CONNECT 响应失败；请检查代理；请求不会改为直连。".to_owned()
        })?;
        if status != 200 {
            return Err(format!(
                "代理拒绝 CONNECT 请求（HTTP {status}）；请求不会改为直连"
            ));
        }
        // Go clears the socket deadline once the tunnel is live; the caller
        // imposes its own per-request budget.
        channel.clear_deadline();
        Ok(channel)
    }

    /// DNS over HTTPS through the same upstream. The host resolver is never
    /// consulted, even when the upstream fails.
    pub fn exchange_dns(&self, q: &Message) -> Result<Message, String> {
        // The exit policy measures IPv4; no unmeasured IPv6 route is offered.
        if q.is_aaaa_query() {
            return Ok(Message::reply(q, 0, Vec::new()));
        }
        if q.asks_local_name() {
            return Ok(Message::reply(
                q,
                crate::dnsmsg::RCODE_NAME_ERROR,
                Vec::new(),
            ));
        }
        let wire = q.pack()?;
        let deadline = Instant::now() + DNS_TOTAL_TIMEOUT;
        let mut last = String::new();
        for attempt in 0..3 {
            if Instant::now() >= deadline {
                return Err(dns_unavailable());
            }
            match self.exchange_dns_once(q, &wire, deadline) {
                Ok(msg) => return Ok(msg),
                Err((retry, message)) => {
                    last = message;
                    if !retry {
                        return Err(last);
                    }
                    if attempt < 2 {
                        let backoff = Duration::from_millis(150 * (attempt as u64 + 1));
                        if Instant::now() + backoff > deadline {
                            return Err(last);
                        }
                        std::thread::sleep(backoff);
                    }
                }
            }
        }
        Err(last)
    }

    fn exchange_dns_once(
        &self,
        q: &Message,
        wire: &[u8],
        deadline: Instant,
    ) -> Result<Message, (bool, String)> {
        // Every attempt gets its own fresh connection and its own cap, within
        // the total budget.
        let attempt_deadline = Instant::now()
            + DNS_ATTEMPT_TIMEOUT.min(
                deadline
                    .checked_duration_since(Instant::now())
                    .unwrap_or_default(),
            );
        let response = request(
            self,
            "POST",
            &self.dns_url,
            Some("application/dns-message"),
            wire,
            attempt_deadline,
        )
        .map_err(|_| (true, dns_unavailable()))?;
        if response.status == 429 || response.status >= 500 {
            return Err((
                true,
                format!("cage DNS upstream returned HTTP {}", response.status),
            ));
        }
        if response.status != 200 {
            return Err((
                false,
                format!("cage DNS upstream returned HTTP {}", response.status),
            ));
        }
        let msg = Message::unpack(&response.body)
            .map_err(|_| (false, "invalid DNS upstream response".to_owned()))?;
        if !msg.response || msg.id != q.id {
            return Err((false, "mismatched DNS upstream response".to_owned()));
        }
        Ok(msg)
    }
}

fn dns_unavailable() -> String {
    "cage DNS upstream unavailable; check the configured DoH endpoint through the selected proxy"
        .to_owned()
}

/// Errors that keep the no-direct-fallback contract: actionable, never
/// hinting at a direct route.
fn user_error(action: &str, cause: std::io::Error) -> String {
    if matches!(cause.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
        return format!("{action}超时；请检查代理；请求不会改为直连。");
    }
    format!("{action}失败（{cause}）；请检查代理；请求不会改为直连。")
}

fn user_tls_failure() -> String {
    "验证 HTTPS 代理的加密连接失败；请检查代理；请求不会改为直连。".to_owned()
}

fn split_addr(addr: &str) -> Result<(&str, u16), String> {
    // F-030: the target lands verbatim in `CONNECT {target}` — C0 controls
    // (CR/LF especially) would inject request headers. Production callers
    // only hand over WHATWG-normalized hosts, but this is a public API;
    // reject the whole shape here, not just the header-splits.
    if addr.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err(format!("invalid target address {addr:?}"));
    }
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| format!("invalid target address {addr}"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("invalid target port in {addr}"))?;
    Ok((host.trim_start_matches('[').trim_end_matches(']'), port))
}

/// `host:port`, with IPv6 literals re-bracketed.
fn join_addr(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn push_socks5_target(req: &mut Vec<u8>, host: &str, port: u16) -> Result<(), String> {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            req.push(0x01);
            req.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            req.push(0x04);
            req.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            let bytes = host.as_bytes();
            if bytes.is_empty() || bytes.len() > 255 {
                return Err("invalid SOCKS5 target name".to_owned());
            }
            req.push(0x03);
            req.push(bytes.len() as u8);
            req.extend_from_slice(bytes);
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

fn tcp_connect(target: &str, deadline: Instant) -> std::io::Result<TcpStream> {
    // Numeric endpoints (which the cage config mandates) never go through
    // getaddrinfo: a hung host resolver must not stall the egress dial.
    let addrs: Vec<std::net::SocketAddr> = match target
        .rsplit_once(':')
        .and_then(|(h, p)| Some((h, p.parse::<u16>().ok()?)))
    {
        Some((host, port)) => match host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
        {
            Ok(ip) => vec![std::net::SocketAddr::new(ip, port)],
            Err(_) => target.to_socket_addrs()?.collect(),
        },
        None => target.to_socket_addrs()?.collect(),
    };
    let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, "no address for upstream");
    for addr in addrs {
        let budget = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_millis(1))
            .max(Duration::from_millis(1));
        match TcpStream::connect_timeout(&addr, budget) {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                let _ = s.set_read_timeout(Some(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .max(Duration::from_millis(1)),
                ));
                return Ok(s);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

static TLS_CONFIG: OnceLock<std::sync::Arc<rustls::ClientConfig>> = OnceLock::new();

fn tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    TLS_CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            std::sync::Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

type TlsStream = rustls::StreamOwned<rustls::ClientConnection, Box<dyn RW>>;

/// TLS-wraps a tunnel and completes the handshake before returning.
fn tls_wrap(inner: Box<dyn RW>, host: &str) -> Result<Box<TlsStream>, String> {
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| format!("invalid TLS server name {host}"))?;
    let mut conn = rustls::ClientConnection::new(tls_config(), server_name)
        .map_err(|e| format!("TLS setup failed: {e}"))?;
    let mut sock: Box<dyn RW> = inner;
    let deadline = Instant::now() + DIAL_TIMEOUT;
    sock.set_deadline(deadline);
    while conn.is_handshaking() {
        if Instant::now() >= deadline {
            return Err(
                "验证 HTTPS 代理的加密连接超时；请检查代理；请求不会改为直连。".to_string(),
            );
        }
        match conn.complete_io(&mut sock) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => {
                return Err(format!(
                    "验证 HTTPS 代理的加密连接失败（{e}）；请检查代理；请求不会改为直连。"
                ))
            }
        }
    }
    Ok(Box::new(rustls::StreamOwned::new(conn, sock)))
}

/// One HTTP/1.1 request through `egress`'s upstream. No redirects, no
/// direct fallback. `max_body` bounds the response (64 KiB for DoH and
/// probes, the 8 MiB import cap for subscriptions).
pub fn request(
    egress: &Egress,
    method: &str,
    url: &str,
    content_type: Option<&str>,
    body: &[u8],
    deadline: Instant,
) -> Result<HttpResponse, String> {
    request_bounded(
        egress,
        method,
        url,
        content_type,
        body,
        deadline,
        MAX_HTTP_BODY,
    )
}

pub fn request_bounded(
    egress: &Egress,
    method: &str,
    url: &str,
    content_type: Option<&str>,
    body: &[u8],
    deadline: Instant,
    max_body: usize,
) -> Result<HttpResponse, String> {
    let u = url::Url::parse(url).map_err(|_| format!("invalid request URL {url}"))?;
    let https = match u.scheme() {
        "https" => true,
        "http" => false,
        other => return Err(format!("unsupported request scheme {other}")),
    };
    let host = u.host_str().ok_or("request URL has no host")?.to_owned();
    let default_port = if https { 443 } else { 80 };
    let port = u.port().unwrap_or(default_port);
    let channel = egress.dial_deadline(&join_addr(&host, port), deadline)?;
    let Channel(mut kind) = channel;
    if https {
        let inner: Box<dyn RW> = match kind {
            TunnelKind::Plain(t) => Box::new(t),
            // An HTTPS proxy's TLS layer already ends at the target; stack one more.
            TunnelKind::Tls(s) => Box::new(*s),
        };
        kind = TunnelKind::Tls(tls_wrap(inner, &host)?);
    }
    let mut channel = Channel(kind);
    let path = if u.path().is_empty() {
        "/".to_owned()
    } else {
        let mut p = u.path().to_owned();
        if let Some(q) = u.query() {
            p.push('?');
            p.push_str(q);
        }
        p
    };
    let host_header = if port == default_port {
        host.clone()
    } else {
        join_addr(&host, port)
    };
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(ct) = content_type {
        req.push_str(&format!("Content-Type: {ct}\r\nAccept: {ct}\r\n"));
    }
    req.push_str("User-Agent: cage\r\n\r\n");
    channel.set_deadline(deadline);
    channel
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    channel.write_all(body).map_err(|e| e.to_string())?;
    let (head, mut body_stream) =
        crate::wire::read_header_block(&mut channel, MAX_HEADER).map_err(|e| e.to_string())?;
    let status = parse_status(&head).ok_or("invalid HTTP response")?;
    let headers = parse_headers(&head);
    // FINDING-017: 1xx/204/304 responses have no body by definition — a
    // peer that legitimately keeps the tunnel open must not stall us until
    // the deadline (Go's net/http ends the body by status code).
    if (100..200).contains(&status) || status == 204 || status == 304 {
        return Ok(HttpResponse {
            status,
            headers,
            body: Vec::new(),
        });
    }
    let http_body = read_body(&mut body_stream, &headers, max_body)?;
    Ok(HttpResponse {
        status,
        headers,
        body: http_body,
    })
}

fn parse_status(head: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(head).ok()?;
    let line = text.lines().next()?;
    let mut parts = line.split_whitespace();
    parts.next()?;
    parts.next()?.parse().ok()
}

fn parse_headers(head: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(head);
    text.lines()
        .skip(1)
        .take_while(|l| !l.is_empty())
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            Some((k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect()
}

fn read_body<C: Read>(
    channel: &mut C,
    headers: &[(String, String)],
    max_body: usize,
) -> Result<Vec<u8>, String> {
    let header = |name: &str| -> Option<&str> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    let mut body = Vec::new();
    if header("transfer-encoding")
        .map(|v| v.eq_ignore_ascii_case("chunked"))
        .unwrap_or(false)
    {
        body = read_chunked(channel, max_body)?;
    } else {
        // FINDING-006: Content-Length must be unambiguous and parseable.
        let lengths: Vec<&str> = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .map(|(_, v)| v.as_str())
            .collect();
        let len = match lengths.as_slice() {
            [] => None,
            [only] => Some(
                only.trim()
                    .parse::<u64>()
                    .map_err(|_| "invalid Content-Length".to_owned())?,
            ),
            many => {
                let first = many[0].trim();
                if many.iter().all(|v| v.trim() == first) {
                    Some(
                        first
                            .parse::<u64>()
                            .map_err(|_| "invalid Content-Length".to_owned())?,
                    )
                } else {
                    return Err("ambiguous Content-Length".to_owned());
                }
            }
        };
        match len {
            // Exact read: EOF is never required — peers may hold the tunnel
            // open after the body.
            Some(len) => {
                if len > max_body as u64 {
                    return Err("HTTP response body too large".to_owned());
                }
                (&mut *channel)
                    .take(len)
                    .read_to_end(&mut body)
                    .map_err(|e| e.to_string())?;
                if body.len() as u64 != len {
                    return Err("incomplete HTTP response body".to_owned());
                }
            }
            None => {
                // Without Content-Length the stream ends at EOF; read one
                // byte past the cap so an oversized body errors instead of
                // importing silently truncated.
                (&mut *channel)
                    .take(max_body as u64 + 1)
                    .read_to_end(&mut body)
                    .map_err(|e| e.to_string())?;
                if body.len() > max_body {
                    return Err("HTTP response body too large".to_owned());
                }
            }
        }
    }
    Ok(body)
}

fn read_chunked<C: Read>(channel: &mut C, max_body: usize) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    loop {
        let mut line = Vec::new();
        loop {
            let mut b = [0u8; 1];
            if channel.read(&mut b).map_err(|e| e.to_string())? == 0 {
                // FINDING-006: EOF between chunks is a truncated body, not
                // a silent success.
                return Err("incomplete HTTP response body".to_owned());
            }
            line.push(b[0]);
            if line.ends_with(b"\r\n") {
                break;
            }
            if line.len() > 16 {
                return Err("invalid chunk header".to_owned());
            }
        }
        let text = String::from_utf8_lossy(&line);
        let size = usize::from_str_radix(text.trim().split(';').next().unwrap_or("0"), 16)
            .map_err(|_| "invalid chunk size".to_owned())?;
        if size == 0 {
            return Ok(body);
        }
        if body.len() + size > max_body {
            return Err("HTTP response body too large".to_owned());
        }
        let mut chunk = vec![0u8; size];
        channel.read_exact(&mut chunk).map_err(|e| e.to_string())?;
        body.extend_from_slice(&chunk);
        // The chunk terminator must be exactly CRLF — anything else is a
        // corrupted stream, not something to swallow and resync past.
        let mut crlf = [0u8; 2];
        channel
            .read_exact(&mut crlf)
            .map_err(|_| "invalid chunk terminator".to_owned())?;
        if &crlf != b"\r\n" {
            return Err("invalid chunk terminator".to_owned());
        }
    }
}

/// RFC 4648, padding included — one call site (proxy auth), no dependency.
fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TABLE[(n >> 18 & 63) as usize] as char);
        out.push(TABLE[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn addr_helpers() {
        assert_eq!(split_addr("1.2.3.4:1080").unwrap(), ("1.2.3.4", 1080));
        assert_eq!(split_addr("[::1]:8080").unwrap(), ("::1", 8080));
        assert!(split_addr("no-port").is_err());
        assert_eq!(join_addr("::1", 80), "[::1]:80");
        assert_eq!(join_addr("1.2.3.4", 80), "1.2.3.4:80");
        // F-030: the target is spliced verbatim into `CONNECT {target}` —
        // controls (R4's M2 injected headers via a trailing numeric port)
        // and spaces are refused before any request is built.
        for hostile in [
            "1.2.3.4\r\nX-Injected: yes\r\nHost: x:99",
            "1.2.3.4\nX-Injected: yes:99",
            "host with space:99",
            "ho\x7ft:99",
        ] {
            assert!(split_addr(hostile).is_err(), "must refuse {hostile:?}");
        }
    }

    #[test]
    fn socks5_target_encoding() {
        let mut req = vec![0x05, 0x01, 0x00];
        push_socks5_target(&mut req, "claude.ai", 443).unwrap();
        assert_eq!(req[3], 0x03);
        assert_eq!(req[4], 9);
        assert_eq!(&req[5..14], b"claude.ai");
        assert_eq!(&req[14..16], &443u16.to_be_bytes());
        let mut req2 = vec![0x05, 0x01, 0x00];
        push_socks5_target(&mut req2, "1.2.3.4", 8080).unwrap();
        assert_eq!(req2[3], 0x01);
        assert_eq!(&req2[4..8], &[1, 2, 3, 4]);
    }

    fn read_body_from(
        wire: &[u8],
        headers: &[(&str, &str)],
        max: usize,
    ) -> Result<Vec<u8>, String> {
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut reader = wire;
        read_body(&mut reader, &headers, max)
    }

    /// A SOCKS5 stub that demands username/password auth and records the
    /// ULEN of any sub-negotiation frame it receives (FINDING-013: over-long
    /// credentials must be refused before any frame is written).
    fn auth_demanding_socks5() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let got_frame = Arc::new(AtomicUsize::new(0));
        let hits = got_frame.clone();
        let listener = listener.try_clone().unwrap();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buf = [0u8; 1024];
                if stream.read(&mut buf).unwrap_or(0) == 0 {
                    continue;
                }
                if stream.write_all(&[0x05, 0x02]).is_err() {
                    continue;
                }
                // Sub-negotiation: [0x01, ULEN, user.., PLEN, pass..].
                let n = stream.read(&mut buf).unwrap_or(0);
                if n >= 2 && buf[0] == 0x01 {
                    hits.store(buf[1] as usize, Ordering::SeqCst);
                    let _ = stream.write_all(&[0x01, 0x01]); // auth failed
                }
            }
        });
        (addr, got_frame)
    }

    #[test]
    fn socks5_overlong_credentials_are_refused_without_frames() {
        use std::sync::atomic::Ordering;
        let user = "u".repeat(300);
        let (addr, got_frame) = auth_demanding_socks5();
        let e = loopback_egress(
            &format!("{user}:p@{addr}"),
            "https://1.1.1.1/dns-query".to_string(),
        );
        let err = match e.dial("1.2.3.4:443") {
            Err(err) => err,
            Ok(_) => panic!("overlong username refused"),
        };
        assert!(err.contains("255"), "{err}");
        assert_eq!(
            got_frame.load(Ordering::SeqCst),
            0,
            "no sub-negotiation frame may be sent for over-long credentials"
        );
    }

    #[test]
    fn socks5_password_over_255_is_refused() {
        use std::sync::atomic::Ordering;
        let pass = "p".repeat(256);
        let (addr, got_frame) = auth_demanding_socks5();
        let e = loopback_egress(
            &format!("u:{pass}@{addr}"),
            "https://1.1.1.1/dns-query".to_string(),
        );
        let err = match e.dial("1.2.3.4:443") {
            Err(err) => err,
            Ok(_) => panic!("overlong password refused"),
        };
        assert!(err.contains("255"), "{err}");
        assert_eq!(got_frame.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn lenient_response_defects_are_rejected() {
        // FINDING-006: all five lenient-acceptance classes refused.
        // Double Content-Length with different values.
        let err = read_body_from(
            b"abcdef",
            &[("Content-Length", "3"), ("content-length", "10")],
            64,
        )
        .unwrap_err();
        assert!(err.contains("ambiguous"), "{err}");
        // Garbage Content-Length.
        let err = read_body_from(b"abcdef", &[("Content-Length", "abc")], 64).unwrap_err();
        assert!(err.contains("invalid Content-Length"), "{err}");
        // Duplicate-but-equal Content-Length is accepted.
        let body = read_body_from(
            b"abc",
            &[("Content-Length", "3"), ("content-length", "3")],
            64,
        )
        .unwrap();
        assert_eq!(body, b"abc");
        // Chunked: EOF at a chunk-line boundary.
        let err =
            read_body_from(b"3\r\nabc\r\n", &[("Transfer-Encoding", "chunked")], 64).unwrap_err();
        assert!(err.contains("incomplete"), "{err}");
        // Chunked: garbage where CRLF belongs.
        let err = read_body_from(
            b"3\r\nabcZZ5\r\nhello\r\n0\r\n\r\n",
            &[("Transfer-Encoding", "chunked")],
            64,
        )
        .unwrap_err();
        assert!(err.contains("terminator"), "{err}");
        // Chunked: complete honest stream still parses.
        let body = read_body_from(
            b"3\r\nabc\r\n5\r\nhello\r\n0\r\n\r\n",
            &[("Transfer-Encoding", "chunked")],
            64,
        )
        .unwrap();
        assert_eq!(body, b"abchello");
    }

    #[test]
    fn proxy_url_path_detection_is_structural() {
        // FINDING-015: trailing C0/space and backslash variants must be
        // rejected like the plain trailing slash (Go url.Parse semantics).
        for bad in [
            "socks5://1.2.3.4:1080/ ",
            "socks5://1.2.3.4:1080/\t",
            "socks5://1.2.3.4:1080/\r",
            "http://1.2.3.4:1080\\",
            "http://1.2.3.4:1080/",
            "http://1.2.3.4:1080/p",
            "http://1.2.3.4:1080?q",
            "http://1.2.3.4:1080#f",
            " http://1.2.3.4:1080/ ",
        ] {
            assert!(validate_proxy_url(bad).is_err(), "{bad:?}");
        }
        for good in [
            "socks5://1.2.3.4:1080",
            "http://10.0.0.1:8080",
            "http://1.2.3.4:1080 ",
            "https://1.2.3.4:1080",
            "SOCKS5://1.2.3.4:1080",
        ] {
            assert!(validate_proxy_url(good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn bodiless_statuses_return_without_waiting_for_eof() {
        // FINDING-017: a 304 that legitimately keeps the connection open
        // must return immediately, not stall until the deadline.
        use crate::testsupport::MixedProxy;
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                std::thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    let _ =
                        stream.write_all(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\n\r\n");
                    // Hold the connection open — a perfectly legal peer.
                    std::thread::sleep(std::time::Duration::from_secs(8));
                });
            }
        });
        let proxy = MixedProxy::start(vec![]);
        let egress = Egress {
            upstream: url::Url::parse(&format!("socks5://{}", proxy.addr)).unwrap(),
            dns_url: String::new(),
        };
        let start = std::time::Instant::now();
        let response = request(
            &egress,
            "GET",
            &format!("http://{addr}/sub"),
            None,
            &[],
            std::time::Instant::now() + std::time::Duration::from_secs(6),
        )
        .expect("304 must return immediately");
        assert_eq!(response.status, 304);
        assert!(response.body.is_empty());
        assert!(
            start.elapsed() < std::time::Duration::from_secs(3),
            "took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn status_and_header_parsing() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
        assert_eq!(parse_status(head), Some(200));
        let headers = parse_headers(head);
        assert_eq!(headers[0].0, "Content-Type");
        assert_eq!(headers[0].1, "text/plain");
        assert_eq!(parse_status(b"garbage"), None);
    }

    /// Builds an egress against a loopback proxy and an `http://` DoH stub.
    /// Only tests may bypass the https-only validation this way; production
    /// goes through `Egress::new`.
    fn loopback_egress(proxy_addr: &str, dns_url: String) -> Egress {
        Egress {
            upstream: url::Url::parse(&format!("socks5://{proxy_addr}")).unwrap(),
            dns_url,
        }
    }

    fn query(name: &str, qtype: u16) -> Message {
        Message::query(0x1234, name, qtype)
    }

    #[test]
    fn doh_parses_answers_through_the_proxy() {
        let stub = support_doh(|q| {
            let reply = Message::reply(
                q,
                0,
                vec![crate::dnsmsg::Resource {
                    name: q.questions[0].name.clone(),
                    rtype: crate::dnsmsg::TYPE_A,
                    class: crate::dnsmsg::CLASS_INET,
                    ttl: 60,
                    data: vec![1, 2, 3, 4],
                }],
            );
            (200, reply.pack().unwrap())
        });
        let egress = loopback_egress(
            &crate::testsupport::MixedProxy::start(vec![]).addr,
            stub.url(),
        );
        let reply = egress
            .exchange_dns(&query("example.com", crate::dnsmsg::TYPE_A))
            .unwrap();
        assert!(reply.response);
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(reply.answers[0].data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn doh_fences_aaaa_queries_before_the_wire() {
        let stub = support_doh(|_| (200, Vec::new()));
        let egress = loopback_egress(
            &crate::testsupport::MixedProxy::start(vec![]).addr,
            stub.url(),
        );
        let reply = egress
            .exchange_dns(&query("example.com", crate::dnsmsg::TYPE_AAAA))
            .unwrap();
        assert!(reply.response);
        assert!(
            reply.answers.is_empty(),
            "AAAA gets an empty Success, never upstream"
        );
        assert_eq!(stub.hits(), 0, "no DoH request may be made for AAAA");
    }

    #[test]
    fn doh_fences_local_names_before_the_wire() {
        let stub = support_doh(|_| (200, Vec::new()));
        let egress = loopback_egress(
            &crate::testsupport::MixedProxy::start(vec![]).addr,
            stub.url(),
        );
        for name in [
            "localhost",
            "api.localhost",
            "svc.internal",
            "printer.local",
        ] {
            let reply = egress
                .exchange_dns(&query(name, crate::dnsmsg::TYPE_A))
                .unwrap();
            assert_eq!(reply.rcode, crate::dnsmsg::RCODE_NAME_ERROR, "{name}");
        }
        assert_eq!(stub.hits(), 0);
    }

    #[test]
    fn doh_retries_server_errors_then_succeeds() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let stub = support_doh(move |q| {
            if counter_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
                return (500, Vec::new());
            }
            (200, Message::reply(q, 0, Vec::new()).pack().unwrap())
        });
        let egress = loopback_egress(
            &crate::testsupport::MixedProxy::start(vec![]).addr,
            stub.url(),
        );
        let reply = egress
            .exchange_dns(&query("retry.example.com", crate::dnsmsg::TYPE_A))
            .unwrap();
        assert!(reply.response);
        assert!(counter.load(std::sync::atomic::Ordering::Relaxed) >= 2);
    }

    #[test]
    fn doh_rejects_mismatched_replies() {
        // A reply with the wrong id is invalid, not a retry.
        let stub = support_doh(|q| {
            let mut reply = Message::reply(q, 0, Vec::new());
            reply.id = reply.id.wrapping_add(1);
            (200, reply.pack().unwrap())
        });
        let egress = loopback_egress(
            &crate::testsupport::MixedProxy::start(vec![]).addr,
            stub.url(),
        );
        let err = egress
            .exchange_dns(&query("wrong-id.example.com", crate::dnsmsg::TYPE_A))
            .unwrap_err();
        assert!(err.contains("mismatched"), "{err}");
    }

    #[test]
    fn doh_client_errors_are_terminal_not_retried() {
        let stub = support_doh(|_| (404, Vec::new()));
        let egress = loopback_egress(
            &crate::testsupport::MixedProxy::start(vec![]).addr,
            stub.url(),
        );
        let err = egress
            .exchange_dns(&query("gone.example.com", crate::dnsmsg::TYPE_A))
            .unwrap_err();
        assert!(err.contains("HTTP 404"), "{err}");
        assert_eq!(stub.hits(), 1, "4xx must not be retried");
    }
}

#[cfg(test)]
/// Handles for the DoH stub tests above: a loopback socks5 relay and a plain
/// HTTP DoH stub, both std-only.
mod doh_support {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;

    type Answer = Arc<dyn Fn(&crate::dnsmsg::Message) -> (u16, Vec<u8>) + Send + Sync>;

    /// A DoH stub speaking plain HTTP on loopback; counts requests so tests
    /// can assert whether the wire was touched at all.
    pub fn doh(answer: Answer) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind doh stub");
        let addr = listener.local_addr().expect("addr").to_string();
        let listener = listener.try_clone().expect("clone");
        let hits_clone = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let answer = answer.clone();
                let hits = hits_clone.clone();
                std::thread::spawn(move || {
                    hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let mut stream = stream;
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
                    let mut block = Vec::new();
                    let mut byte = [0u8; 1];
                    loop {
                        match stream.read(&mut byte) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {
                                block.push(byte[0]);
                                if block.ends_with(b"\r\n\r\n") {
                                    break;
                                }
                            }
                        }
                    }
                    let text = String::from_utf8_lossy(&block);
                    let len: usize = text
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse().ok())?
                        })
                        .unwrap_or(0);
                    eprintln!("DOHSTUB: head ok len={len}");
                    let mut wire = vec![0u8; len];
                    if stream.read_exact(&mut wire).is_err() {
                        eprintln!("DOHSTUB: body read FAILED");
                        return;
                    }
                    eprintln!("DOHSTUB: body ok");
                    let body = match crate::dnsmsg::Message::unpack(&wire) {
                        Ok(query) => {
                            let (status, body) = answer(&query);
                            format!(
                                "HTTP/1.1 {status}\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            )
                            .into_bytes()
                            .into_iter()
                            .chain(body)
                            .collect::<Vec<u8>>()
                        }
                        Err(_) => b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".to_vec(),
                    };
                    match stream.write_all(&body) {
                        Ok(()) => eprintln!("DOHSTUB: resp written {}", body.len()),
                        Err(e) => eprintln!("DOHSTUB: resp write ERR {e}"),
                    }
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                });
            }
        });
        (format!("http://{addr}/dns-query"), hits)
    }
}

#[cfg(test)]
struct DohHandle {
    url: String,
    hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
impl DohHandle {
    fn url(&self) -> String {
        self.url.clone()
    }
    fn hits(&self) -> usize {
        self.hits.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
fn support_doh(answer: impl Fn(&Message) -> (u16, Vec<u8>) + Send + Sync + 'static) -> DohHandle {
    let (url, hits) = doh_support::doh(std::sync::Arc::new(answer));
    DohHandle { url, hits }
}
