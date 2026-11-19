// B1: SOCKS5 handshake violations against the real creance-net egress client.
// Each variant runs its own listener + attacker thread; the client dial must
// fail closed (Err). Lenient outcomes are recorded as drift notes.

use creance_net::egress::Egress;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Runs a malicious SOCKS5 server: after accepting, `attack` plays the
/// protocol from the server side. Returns once the client disconnects.
fn serve(attack: fn(&mut TcpStream)) -> u16 {
    let port = free_port();
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
            attack(&mut s);
        }
    });
    port
}

fn greeting(stream: &mut TcpStream) -> [u8; 2] {
    let mut g = [0u8; 2];
    let _ = stream.read_exact(&mut g); // ver, nmethods (ignored by attacker)
    let _ = stream.read_exact(&mut vec![0u8; g[1] as usize][..]);
    g
}

fn full_connect_request(stream: &mut TcpStream) {
    let mut head = [0u8; 4];
    let _ = stream.read_exact(&mut head);
    let extra = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut l = [0u8; 1];
            let _ = stream.read_exact(&mut l);
            l[0] as usize + 2
        }
        _ => 0,
    };
    if extra > 0 {
        let _ = stream.read_exact(&mut vec![0u8; extra][..]);
    }
}

/// success then leave the tunnel open until the client drops it
fn tunnel_open(stream: &mut TcpStream) {
    let _ = stream.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]);
    let mut buf = [0u8; 64];
    while let Ok(n) = stream.read(&mut buf) {
        if n == 0 {
            break;
        }
    }
}

fn dial(proxy_port: u16, scheme_user: Option<&str>) -> Result<(), String> {
    let proxy_url = match scheme_user {
        Some(u) => format!("{u}127.0.0.1:{proxy_port}"),
        None => format!("socks5://127.0.0.1:{proxy_port}"),
    };
    let egress = Egress::new(&proxy_url, "https://192.0.2.53/dns-query").expect("egress builds");
    egress
        .dial_deadline("example.invalid:80", Instant::now() + Duration::from_secs(4))
        .map(|_| ())
}

fn expect_err(name: &str, proxy_port: u16, user: Option<&str>, want_sub: &str) {
    match dial(proxy_port, user) {
        Ok(()) => println!("VARIANTS-FAIL  {name}: dial SUCCEEDED, expected rejection"),
        Err(e) if e.contains(want_sub) => println!("ok  {name}: rejected as expected ({want_sub})"),
        Err(e) => println!("ok* {name}: rejected with different reason: {e}"),
    }
}

fn main() {
    // A. wrong version in method reply
    let p = serve(|s| {
        greeting(s);
        let _ = s.write_all(&[0x06, 0x00]);
    });
    expect_err("A wrong-method-version", p, None, "不是 SOCKS5");

    // B. demands user/pass auth though none configured
    let p = serve(|s| {
        greeting(s);
        let _ = s.write_all(&[0x05, 0x02]);
    });
    expect_err("B auth-demanded-no-creds", p, None, "没有凭据");

    // C. unoffered method (0xFF)
    let p = serve(|s| {
        greeting(s);
        let _ = s.write_all(&[0x05, 0xFF]);
    });
    expect_err("C method-0xff", p, None, "拒绝了全部认证方式");

    // D. success reply then abrupt teardown before the CONNECT reply
    let p = serve(|s| {
        greeting(s);
        let _ = s.write_all(&[0x05, 0x00]);
        drop(s);
    });
    expect_err("D success-then-rst", p, None, "");

    // E. auth sub-negotiation reply with junk version byte (01 00) + creds.
    //    Rust checks only status[1] (egress.rs:340-346) — compare Go x/net.
    let p = serve(|s| {
        greeting(s);
        let _ = s.write_all(&[0x05, 0x02]);
        let mut ul = [0u8; 1];
        let _ = s.read_exact(&mut ul);
        let _ = s.read_exact(&mut vec![0u8; ul[0] as usize][..]);
        let mut pl = [0u8; 1];
        let _ = s.read_exact(&mut pl);
        let _ = s.read_exact(&mut vec![0u8; pl[0] as usize][..]);
        let _ = s.write_all(&[0x01, 0x00]); // version 0x01 junk, status ok
        full_connect_request(s);
        tunnel_open(s);
    });
    match dial(p, Some("socks5://u:p@")) {
        Ok(()) => println!("DRIFT  E auth-reply-junk-version: ACCEPTED (status[0] unchecked)"),
        Err(e) => println!("ok   E auth-reply-junk-version: rejected ({e})"),
    }

    // F. CONNECT reply wrong version (04)
    let p = serve(|s| {
        greeting(s);
        let _ = s.write_all(&[0x05, 0x00]);
        full_connect_request(s);
        let _ = s.write_all(&[0x04, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]);
    });
    expect_err("F connect-version-4", p, None, "不是 SOCKS5");

    // G. CONNECT reply failure code
    let p = serve(|s| {
        greeting(s);
        let _ = s.write_all(&[0x05, 0x00]);
        full_connect_request(s);
        let _ = s.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    });
    expect_err("G connect-rep-1", p, None, "拒绝连接");

    // H. CONNECT reply unknown atyp
    let p = serve(|s| {
        greeting(s);
        let _ = s.write_all(&[0x05, 0x00]);
        full_connect_request(s);
        let _ = s.write_all(&[0x05, 0x00, 0x00, 0x09]);
    });
    expect_err("H connect-atyp-9", p, None, "未知地址类型");

    // I. domain-typed BND.ADDR with len 255 but truncated stream
    let p = serve(|s| {
        greeting(s);
        let _ = s.write_all(&[0x05, 0x00]);
        full_connect_request(s);
        let _ = s.write_all(&[0x05, 0x00, 0x00, 0x03, 255, b'a']);
        drop(s);
    });
    expect_err("I bnd-truncated", p, None, "");

    // J. slow drip of the method reply inside the deadline (0.4s steps)
    let p = serve(|s| {
        let g = greeting(s);
        for b in [0x05u8, g[1].min(0x00)] {
            let _ = s.write_all(&[b]);
            s.flush().ok();
            std::thread::sleep(Duration::from_millis(400));
        }
        full_connect_request(s);
        tunnel_open(s);
    });
    match dial(p, None) {
        Ok(()) => println!("ok   J slow-drip-in-deadline: accepted (slow but legal)"),
        Err(e) => println!("note J slow-drip-in-deadline: rejected ({e})"),
    }

    // K. method reply beyond the deadline
    let p = serve(|s| {
        greeting(s);
        std::thread::sleep(Duration::from_secs(1));
        let _ = s.write_all(&[0x05, 0x00]);
        std::thread::sleep(Duration::from_secs(6));
        full_connect_request(s);
    });
    expect_err("K slow-beyond-deadline", p, None, "");

    // L. no reply at all (EOF)
    let p = serve(|s| {
        greeting(s);
        drop(s);
    });
    expect_err("L eof-after-greeting", p, None, "");

    // M2. CRLF target whose LAST colon yields a numeric port — the request
    //    line then carries injected header text (reachability: direct dial
    //    callers only; the fetch path normalizes URLs upstream).
    let p = {
        let port = free_port();
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
                let mut text = String::new();
                let mut byte = [0u8; 1];
                while s.read_exact(&mut byte).is_ok() {
                    text.push(byte[0] as char);
                    if text.ends_with("\r\n\r\n") {
                        break;
                    }
                }
                if text.contains("X-Injected") {
                    println!("HOLE   M2 crlf-numeric-port: header injection in CONNECT request:\n{text}");
                } else {
                    println!("      M2 request: {}", text.lines().next().unwrap_or(""));
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                let mut b2 = [0u8; 64];
                let _ = s.read(&mut b2);
            }
        });
        port
    };
    let egress = Egress::new(&format!("http://127.0.0.1:{p}"), "https://192.0.2.53/dns-query")
        .expect("egress builds");
    let r = egress.dial_deadline("1.2.3.4\r\nX-Injected: yes\r\nHost: x:99", Instant::now() + Duration::from_secs(3));
    match r {
        Ok(_) => println!("HOLE?  M2 crlf-numeric-port: dial SUCCEEDED"),
        Err(e) => println!("ok   M2 crlf-numeric-port: rejected ({e})"),
    }


    let p = serve(|s| {
        greeting(s);
        let _ = s.write_all(&[0x05, 0x00]);
        // capture the CONNECT request raw bytes to look for injected header
        let mut head = [0u8; 4];
        let _ = s.read_exact(&mut head);
        let extra = match head[3] {
            0x01 => 4 + 2,
            0x04 => 16 + 2,
            0x03 => {
                let mut l = [0u8; 1];
                let _ = s.read_exact(&mut l);
                l[0] as usize + 2
            }
            _ => 0,
        };
        if extra > 0 {
            let _ = s.read_exact(&mut vec![0u8; extra][..]);
        }
        println!("      M captured CONNECT req head: {head:?}");
        let _ = s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]);
    });
    let egress = Egress::new(&format!("http://127.0.0.1:{p}"), "https://192.0.2.53/dns-query")
        .expect("egress builds");
    let crlf_target = "1.2.3.4\r\nX-Injected: yes";
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        egress.dial_deadline(crlf_target, Instant::now() + Duration::from_secs(3))
    }));
    match r {
        Ok(Ok(_)) => println!("HOLE   M crlf-target: CONNECT accepted with injected header!"),
        Ok(Err(e)) => println!("ok   M crlf-target: rejected ({e})"),
        Err(_) => println!("panic M crlf-target: dial panicked on CRLF target"),
    }

    // N. HTTP CONNECT replies 204 (2xx but not 200)
    let p2 = {
        let port = free_port();
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
                let mut b2 = [0u8; 64];
                let _ = s.read(&mut b2);
            }
        });
        port
    };
    let egress = Egress::new(&format!("http://127.0.0.1:{p2}"), "https://192.0.2.53/dns-query")
        .expect("egress builds");
    match egress.dial_deadline("example.invalid:80", Instant::now() + Duration::from_secs(3)) {
        Ok(_) => println!("DRIFT  N connect-204: accepted (2xx non-200 tolerated)"),
        Err(e) => println!("ok   N connect-204: rejected ({e})"),
    }

    println!("b1 done");
}
