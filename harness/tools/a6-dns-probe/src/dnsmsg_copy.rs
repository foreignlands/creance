//! Minimal DNS wire-format codec for the DoH path.
//!
//! Only what the cage egress needs: pack one query, unpack a reply (with
//! name decompression), and build the synthesized replies used to fence off
//! IPv6 and local names.

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_INET: u16 = 1;

const FLAG_RESPONSE: u16 = 1 << 15;
const FLAG_RECURSION_DESIRED: u16 = 1 << 8;
/// NXDOMAIN, returned for local and internal names.
pub const RCODE_NAME_ERROR: u8 = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resource {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub response: bool,
    pub rcode: u8,
    pub questions: Vec<Question>,
    pub answers: Vec<Resource>,
}

impl Message {
    /// A recursive query for `name`/`qtype`.
    pub fn query(id: u16, name: &str, qtype: u16) -> Message {
        Message {
            id,
            questions: vec![Question {
                name: name.to_owned(),
                qtype,
                qclass: CLASS_INET,
            }],
            ..Default::default()
        }
    }

    /// A reply echoing `q`'s id and question, with `rcode` and `answers`.
    pub fn reply(q: &Message, rcode: u8, answers: Vec<Resource>) -> Message {
        Message {
            id: q.id,
            response: true,
            rcode,
            questions: q.questions.clone(),
            answers,
        }
    }

    pub fn is_aaaa_query(&self) -> bool {
        self.questions.iter().any(|q| q.qtype == TYPE_AAAA)
    }

    /// Whether any question names a local or internal zone, which cage never
    /// forwards: `localhost`, `*.localhost`, `*.internal`, `*.local`.
    pub fn asks_local_name(&self) -> bool {
        self.questions.iter().any(|q| {
            let n = q.name.trim_end_matches('.').to_lowercase();
            n == "localhost"
                || n.ends_with(".localhost")
                || n.ends_with(".internal")
                || n.ends_with(".local")
        })
    }

    /// Serializes this message; 64 KiB is DNS's ceiling.
    pub fn pack(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(512);
        let mut flags = self.rcode as u16 & 0x0f;
        if self.response {
            flags |= FLAG_RESPONSE;
        } else {
            flags |= FLAG_RECURSION_DESIRED;
        }
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        for q in &self.questions {
            push_name(&mut out, &q.name)?;
            out.extend_from_slice(&q.qtype.to_be_bytes());
            out.extend_from_slice(&q.qclass.to_be_bytes());
        }
        for a in &self.answers {
            push_name(&mut out, &a.name)?;
            out.extend_from_slice(&a.rtype.to_be_bytes());
            out.extend_from_slice(&a.class.to_be_bytes());
            out.extend_from_slice(&a.ttl.to_be_bytes());
            out.extend_from_slice(&(a.data.len() as u16).to_be_bytes());
            out.extend_from_slice(&a.data);
        }
        Ok(out)
    }

    /// Parses a wire-format message. Names are decompressed.
    pub fn unpack(buf: &[u8]) -> Result<Message, String> {
        if buf.len() < 12 {
            return Err("truncated DNS message".to_owned());
        }
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let (qd, an) = (
            u16::from_be_bytes([buf[4], buf[5]]),
            u16::from_be_bytes([buf[6], buf[7]]),
        );
        let mut m = Message {
            id,
            response: flags & FLAG_RESPONSE != 0,
            rcode: (flags & 0x0f) as u8,
            ..Default::default()
        };
        let mut cur = 12;
        for _ in 0..qd {
            let (name, next) = skip_or_take_name(buf, cur, true)?;
            if next + 4 > buf.len() {
                return Err("truncated DNS question".to_owned());
            }
            m.questions.push(Question {
                name,
                qtype: u16::from_be_bytes([buf[next], buf[next + 1]]),
                qclass: u16::from_be_bytes([buf[next + 2], buf[next + 3]]),
            });
            cur = next + 4;
        }
        for _ in 0..an {
            let (name, next) = skip_or_take_name(buf, cur, true)?;
            if next + 10 > buf.len() {
                return Err("truncated DNS answer".to_owned());
            }
            let rtype = u16::from_be_bytes([buf[next], buf[next + 1]]);
            let class = u16::from_be_bytes([buf[next + 2], buf[next + 3]]);
            let ttl =
                u32::from_be_bytes([buf[next + 4], buf[next + 5], buf[next + 6], buf[next + 7]]);
            let rdlen = u16::from_be_bytes([buf[next + 8], buf[next + 9]]) as usize;
            let data_at = next + 10;
            if data_at + rdlen > buf.len() {
                return Err("truncated DNS rdata".to_owned());
            }
            m.answers.push(Resource {
                name,
                rtype,
                class,
                ttl,
                data: buf[data_at..data_at + rdlen].to_vec(),
            });
            cur = data_at + rdlen;
        }
        Ok(m)
    }
}

/// Encodes `name` as uncompressed labels.
fn push_name(out: &mut Vec<u8>, name: &str) -> Result<(), String> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        out.push(0);
        return Ok(());
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("invalid DNS name".to_owned());
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Reads a name at `at`, following compression pointers, returning the
/// decomposed name and the offset after it. Bounded so a crafted pointer
/// loop cannot spin.
fn skip_or_take_name(buf: &[u8], at: usize, take: bool) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut jumps = 0;
    let mut cur = at;
    let mut end = None;
    loop {
        if cur >= buf.len() {
            return Err("truncated DNS name".to_owned());
        }
        match buf[cur] {
            0 => {
                if end.is_none() {
                    end = Some(cur + 1);
                }
                break;
            }
            n if n & 0xc0 == 0xc0 => {
                if cur + 1 >= buf.len() {
                    return Err("truncated DNS pointer".to_owned());
                }
                let target = (((n & 0x3f) as usize) << 8) | buf[cur + 1] as usize;
                if end.is_none() {
                    end = Some(cur + 2);
                }
                jumps += 1;
                if jumps > 128 || target >= buf.len() {
                    return Err("invalid DNS compression".to_owned());
                }
                cur = target;
            }
            n => {
                let label_at = cur + 1;
                if label_at + n as usize > buf.len() {
                    return Err("truncated DNS label".to_owned());
                }
                labels.extend_from_slice(&buf[label_at..label_at + n as usize]);
                labels.push(b'.');
                cur = label_at + n as usize;
            }
        }
    }
    let name = String::from_utf8_lossy(&labels)
        .trim_end_matches('.')
        .to_owned();
    let _ = take; // names are always decomposed; the caller only wants one form
    Ok((name, end.unwrap_or(at)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_roundtrip_through_unpack() {
        let q = Message::query(0x1234, "Example.COM.", TYPE_A);
        let wire = q.pack().unwrap();
        let back = Message::unpack(&wire).unwrap();
        assert_eq!(back.questions[0].name, "Example.COM");
        assert_eq!(back.questions[0].qtype, TYPE_A);
        assert!(!back.response);
        assert!(!back.is_aaaa_query());
    }

    #[test]
    fn reply_flags_and_answers() {
        let q = Message::query(0xabcd, "example.com", TYPE_A);
        let answer = Resource {
            name: "example.com".to_owned(),
            rtype: TYPE_A,
            class: CLASS_INET,
            ttl: 300,
            data: vec![1, 2, 3, 4],
        };
        let r = Message::reply(&q, 0, vec![answer.clone()]);
        let wire = r.pack().unwrap();
        let back = Message::unpack(&wire).unwrap();
        assert!(back.response);
        assert_eq!(back.id, 0xabcd);
        assert_eq!(back.answers, vec![answer]);
    }

    #[test]
    fn local_name_fence() {
        let mut q = Message::query(1, "api.example.internal", TYPE_A);
        assert!(q.asks_local_name());
        q = Message::query(1, "localhost", TYPE_A);
        assert!(q.asks_local_name());
        q = Message::query(1, "claude.ai", TYPE_A);
        assert!(!q.asks_local_name());
    }

    #[test]
    fn compression_loop_is_bounded() {
        let mut buf = vec![0u8; 12];
        buf[0] = 0x42; // id
        buf[2] = 0x80; // response
        buf[4] = 0;
        buf[5] = 1; // qdcount 1
                    // A name that points at itself.
        buf.push(0xc0);
        buf.push(12);
        buf.extend_from_slice(&[0, 1, 0, 1]);
        let err = Message::unpack(&buf);
        assert!(err.is_err());
    }

    #[test]
    fn truncated_input_fails() {
        let q = Message::query(9, "a.co", TYPE_A);
        let wire = q.pack().unwrap();
        assert!(Message::unpack(&wire[..7]).is_err());
    }
}
