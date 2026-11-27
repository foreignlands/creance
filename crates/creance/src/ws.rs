//! RFC6455 WebSocket 最小实现（0.8.5 终端通道）：std-only，无外部依赖。
//! 覆盖：服务端握手（SHA1+base64 accept）、帧解码（含客户端掩码）、
//! 帧编码（服务端不掩码）、ping/pong、close。不支持分片控制帧以外的
//! 复杂场景——终端通道消息短小，xterm 侧不分片大帧。

use std::io::{Read, Write};

const WS_MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// FIPS 180-1 SHA1，内联实现——只用于 WS 握手的 accept 计算。
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let ml = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&ml.to_be_bytes());
    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// 计算握手 accept 值。
pub fn accept_key(client_key: &str) -> String {
    let mut v = client_key.as_bytes().to_vec();
    v.extend_from_slice(WS_MAGIC.as_bytes());
    b64(&sha1(&v))
}

#[derive(Debug, PartialEq)]
pub enum Frame {
    Text(Vec<u8>),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close,
}

/// 从流读一帧（客户端→服务端，必须掩码）。返回 None 表示连接关闭/错误。
pub fn read_frame(r: &mut impl Read) -> Option<Frame> {
    let mut head = [0u8; 2];
    r.read_exact(&mut head).ok()?;
    let opcode = head[0] & 0x0f;
    let masked = head[1] & 0x80 != 0;
    let mut len = (head[1] & 0x7f) as u64;
    if len == 126 {
        let mut b = [0u8; 2];
        r.read_exact(&mut b).ok()?;
        len = u16::from_be_bytes(b) as u64;
    } else if len == 127 {
        let mut b = [0u8; 8];
        r.read_exact(&mut b).ok()?;
        len = u64::from_be_bytes(b);
    }
    // 终端通道防御：单帧 1 MiB 帽
    if len > (1 << 20) {
        return None;
    }
    let mask = if masked {
        let mut m = [0u8; 4];
        r.read_exact(&mut m).ok()?;
        Some(m)
    } else {
        None
    };
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).ok()?;
    if let Some(m) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= m[i % 4];
        }
    }
    Some(match opcode {
        0x1 => Frame::Text(payload),
        0x2 => Frame::Binary(payload),
        0x9 => Frame::Ping(payload),
        0xA => Frame::Pong(payload),
        0x8 => Frame::Close,
        // continuation/未知帧：终端通道不分片，按关闭处理
        _ => Frame::Close,
    })
}

/// 写一帧（服务端→客户端，不掩码）。
pub fn write_frame(w: &mut impl Write, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut head = vec![0x80 | opcode];
    if payload.len() < 126 {
        head.push(payload.len() as u8);
    } else if payload.len() <= 0xffff {
        head.push(126);
        head.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        head.push(127);
        head.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    w.write_all(&head)?;
    w.write_all(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_rfc_vector() {
        // RFC 3174 测试向量
        assert_eq!(
            hex::encode(sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn accept_key_rfc6455_vector() {
        // RFC6455 §1.3 官方握手样例
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn frame_roundtrip_masked() {
        // 手工构造掩码文本帧 "hi"：0x81 0x82 mask(4) xored
        let mut wire = vec![0x81u8, 0x82, 1, 2, 3, 4];
        wire.push(b'h' ^ 1);
        wire.push(b'i' ^ 2);
        let mut cur = std::io::Cursor::new(wire);
        match read_frame(&mut cur) {
            Some(Frame::Text(p)) => assert_eq!(p, b"hi"),
            other => panic!("bad frame {other:?}"),
        }
    }

    #[test]
    fn write_frame_shapes() {
        let mut out = Vec::new();
        write_frame(&mut out, 0x1, b"ab").unwrap();
        assert_eq!(out, vec![0x81, 2, b'a', b'b']);
    }
}
