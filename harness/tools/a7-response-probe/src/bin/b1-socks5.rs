//! B1：恶意 SOCKS5 服务器 × egress socks5_connect。
//! 变体：错版本/1 字节 EOF/认证循环/认证成功后 RST/ulen 截断观察。

use creance_net::egress::Egress;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::time::Duration;

/// 恶意 SOCKS5 服务器：`script` 描述对 greeting 的响应。
/// 返回捕获到的（method 之后的）后续字节记录。
fn evil_socks5(responder: impl Fn(&TcpListener) + Send + 'static) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || responder(&listener));
    addr
}

fn run(label: &str, url_host: &str, responder: impl Fn(&TcpListener) + Send + 'static) {
    let addr = evil_socks5(responder);
    let egress = Egress::new(&format!("socks5://{url_host}@{addr}"), "https://1.1.1.1/dns-query").unwrap();
    let started = std::time::Instant::now();
    let out = match egress.dial("1.2.3.4:443") {
        Ok(_) => "DIAL-OK".to_string(),
        Err(e) => format!("DIAL-ERR {e}"),
    };
    println!("[{}] {} :: {out} ({:.1}s)", "B1", label, started.elapsed().as_secs_f32());
}

fn main() {
    // 1. 错版本：回 HTTP 文本
    run("wrong-version", "u:p", |l| {
        for s in l.incoming().flatten() {
            let mut s = s;
            let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
            let mut buf = [0u8; 8];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 400 Bad\r\n\r\n");
        }
    });
    // 2. greeting 处 1 字节即 EOF
    run("greeting-eof-1byte", "u:p", |l| {
        for s in l.incoming().flatten() {
            let mut s = s;
            let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
            let mut b = [0u8; 1];
            let _ = s.read(&mut b);
            drop(s);
        }
    });
    // 3. 要求认证但凭据错（method 循环→auth 失败）
    run("auth-loop-fail", "u:p", |l| {
        for s in l.incoming().flatten() {
            let mut s = s;
            let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).unwrap_or(0);
            let _ = s.write_all(&[0x05, 0x02]);
            let _ = s.read(&mut buf); // sub-negotiation
            let _ = s.write_all(&[0x01, 0x01]); // 认证失败
        }
    });
    // 4. 成功（无认证）→ CONNECT 请求 → 回成功 → 立即 RST（shutdown + SO_LINGER 0）
    run("success-then-rst", "u:p", |l| {
        for s in l.incoming().flatten() {
            let mut s = s;
            let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
            let mut buf = [0u8; 64];
            let _ = s.read(&mut buf);
            let _ = s.write_all(&[0x05, 0x00]);
            let n = s.read(&mut buf).unwrap_or(0); // CONNECT 请求
            let _ = s.write_all(&[0x05, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0, 80]);
            // 立即 RST：SO_LINGER 0 + close
            // RST via SO_LINGER 0 (libc)
            unsafe {
                let fd = std::os::unix::io::AsRawFd::as_raw_fd(&s);
                let linger = libc::linger { l_onoff: 1, l_linger: 0 };
                libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_LINGER,
                    &linger as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::linger>() as libc::socklen_t);
            }
            drop(s);
        }
    });
    // 5. ulen 截断观察：捕获 sub-negotiation 的 ULEN 字节值
    run("ulen-capture-300char-user", &format!("{}:p", "u".repeat(300)), |l| {
        for s in l.incoming().flatten() {
            let mut s = s;
            let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf); // greeting
            let _ = s.write_all(&[0x05, 0x02]); // 选认证
            let n = s.read(&mut buf).unwrap_or(0); // sub-negotiation: [0x01, ULEN, user..., PLEN, pass]
            if n >= 2 {
                println!("[B1-CAPTURE] sub-negotiation {} bytes: ULEN={} (user 实际 300 字节)", n, buf[1]);
            }
            let _ = s.write_all(&[0x01, 0x00]);
        }
    });
}
