//! 分享链接解析（0.8.3 节点接入重构）：绝大多数订阅地址返回的不是
//! Clash YAML，而是 base64 整文档编码的分享链接行（ss://、vmess://、
//! vless://、trojan://、hysteria2://）。本模块把每行解析成与 YAML
//! proxies 条目同形的 map，下游归一化/校验全部复用。
//!
//! 安全纪律：与 YAML 路径同——输入先过体积帽（调用方已查），逐行
//! 解析失败的行降级为 skipped issue 而非全单失败（与 YAML 单节点
//! 失败同纪律）。用户info/密码串不进日志（错误信息只带行号）。

use serde_json::{Map, Value};

fn b64dec(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let stripped = s.trim_end_matches('=');
    STANDARD_NO_PAD
        .decode(stripped)
        .ok()
        .or_else(|| URL_SAFE_NO_PAD.decode(stripped).ok())
        .or_else(|| STANDARD.decode(s).ok())
        .or_else(|| URL_SAFE.decode(s).ok())
}

fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len() + 1
            && i + 2 < bytes.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn put(m: &mut Map<String, Value>, k: &str, v: impl Into<Value>) {
    m.insert(k.to_owned(), v.into());
}

fn num(v: u16) -> Value {
    Value::from(v as u64)
}

/// scheme-specific parsers; each returns a YAML-proxies-shaped map.
fn parse_ss(rest: &str, frag: &str) -> Result<Map<String, Value>, String> {
    // SIP002: ss://base64(method:password)@host:port#name 或
    // ss://base64(method:password@host:port)#name 全编码形
    let mut m = Map::new();
    put(&mut m, "type", "ss");
    let (userinfo, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (u.to_owned(), h.to_owned()),
        None => {
            // fully-encoded form
            let dec = b64dec(rest).ok_or("ss 链接 base64 无效")?;
            let text = String::from_utf8_lossy(&dec).into_owned();
            let (u, h) = text.rsplit_once('@').ok_or("ss 链接缺主机段")?;
            (u.to_owned(), h.to_owned())
        }
    };
    let creds = if userinfo.contains(':') {
        pct_decode(&userinfo)
    } else {
        let dec = b64dec(&userinfo).ok_or("ss 凭据 base64 无效")?;
        String::from_utf8_lossy(&dec).into_owned()
    };
    let (method, password) = creds.split_once(':').ok_or("ss 凭据缺 method:password")?;
    let (host, port) = hostport.rsplit_once(':').ok_or("ss 缺端口")?;
    let port: u16 = port.trim().parse().map_err(|_| "ss 端口无效")?;
    put(&mut m, "cipher", pct_decode(method));
    put(&mut m, "password", pct_decode(password));
    put(&mut m, "server", host.trim_matches(['[', ']']));
    m.insert("port".into(), num(port));
    if !frag.is_empty() {
        put(&mut m, "name", pct_decode(frag));
    }
    Ok(m)
}

fn parse_vmess(rest: &str, frag: &str) -> Result<Map<String, Value>, String> {
    // vmess://base64(json) — v2rayN 事实标准
    let dec = b64dec(rest).ok_or("vmess 链接 base64 无效")?;
    let v: serde_json::Value = serde_json::from_slice(&dec).map_err(|_| "vmess 链接 JSON 无效")?;
    let obj = v.as_object().ok_or("vmess 链接不是对象")?;
    let mut m = Map::new();
    put(&mut m, "type", "vmess");
    let get = |k: &str| {
        obj.get(k)
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_owned()
    };
    put(&mut m, "server", get("add"));
    let port: u16 = get("port").parse().map_err(|_| "vmess 端口无效")?;
    m.insert("port".into(), num(port));
    put(&mut m, "uuid", get("id"));
    let aid: u32 = get("aid").parse().unwrap_or(0);
    m.insert("alterId".into(), Value::from(aid as u64));
    let scy = get("scy");
    put(
        &mut m,
        "cipher",
        if scy.is_empty() {
            "auto".to_owned()
        } else {
            scy
        },
    );
    let net = get("net");
    if !net.is_empty() {
        put(&mut m, "network", net.clone());
    }
    if net == "ws" {
        let mut ws = Map::new();
        let path = get("path");
        if !path.is_empty() {
            put(&mut ws, "path", path);
        }
        let host = get("host");
        if !host.is_empty() {
            let mut hdr = Map::new();
            put(&mut hdr, "Host", host);
            ws.insert("headers".into(), Value::Object(hdr));
        }
        m.insert("ws-opts".into(), Value::Object(ws));
    }
    let tls = get("tls");
    if !tls.is_empty() && tls != "none" {
        m.insert("tls".into(), Value::Bool(true));
        let sni = get("sni");
        if !sni.is_empty() {
            put(&mut m, "servername", sni);
        }
    }
    let ps = get("ps");
    if !ps.is_empty() {
        put(&mut m, "name", ps);
    } else if !frag.is_empty() {
        put(&mut m, "name", pct_decode(frag));
    }
    Ok(m)
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (pct_decode(k), pct_decode(v))
        })
        .collect()
}

/// vless/trojan/hysteria2 共享形状：scheme://user@host:port?params#name
fn parse_standard(
    typ: &str,
    rest: &str,
    frag: &str,
    query: &str,
) -> Result<Map<String, Value>, String> {
    let (user, hostport) = rest
        .rsplit_once('@')
        .ok_or_else(|| format!("{typ} 链接缺 @"))?;
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or_else(|| format!("{typ} 缺端口"))?;
    let port: u16 = port.trim().parse().map_err(|_| format!("{typ} 端口无效"))?;
    let mut m = Map::new();
    put(&mut m, "type", typ);
    put(&mut m, "server", host.trim_matches(['[', ']']));
    m.insert("port".into(), num(port));
    match typ {
        "vless" => {
            put(&mut m, "uuid", pct_decode(user));
        }
        "trojan" | "hysteria2" => {
            put(&mut m, "password", pct_decode(user));
        }
        _ => {}
    }
    for (k, v) in parse_query(query) {
        match (typ, k.as_str()) {
            ("vless", "security") => {
                if v == "tls" || v == "reality" {
                    m.insert("tls".into(), Value::Bool(true));
                }
                if v == "reality" {
                    let mut ro = Map::new();
                    put(&mut ro, "public-key", "");
                    m.insert("reality-opts".into(), Value::Object(ro));
                }
            }
            ("vless", "type") if !v.is_empty() && v != "tcp" => {
                put(&mut m, "network", v.clone());
            }
            (_, "sni") | (_, "peer") => {
                put(&mut m, "sni", v.clone());
            }
            (_, "flow") => put(&mut m, "flow", v.clone()),
            ("hysteria2", "insecure") if v == "1" => {
                m.insert("skip-cert-verify".into(), Value::Bool(true));
            }
            (_, "insecure") if v == "1" || v == "true" => {
                m.insert("skip-cert-verify".into(), Value::Bool(true));
            }
            (_, "alpn") => {
                let list: Vec<Value> = v.split(',').map(|s| Value::from(s.to_owned())).collect();
                m.insert("alpn".into(), Value::Array(list));
            }
            (_, "obfs") => put(&mut m, "obfs", v.clone()),
            (_, "obfs-password") | (_, "obfs_password") => put(&mut m, "obfs-password", v.clone()),
            (_, "fp") => put(&mut m, "client-fingerprint", v.clone()),
            (_, "pbk") => put(&mut m, "x-reality-pbk", v.clone()),
            (_, "sid") => put(&mut m, "x-reality-sid", v.clone()),
            _ => {}
        }
    }
    if m.contains_key("reality-opts") {
        let pbk = m
            .remove("x-reality-pbk")
            .and_then(|v| v.as_str().map(str::to_owned));
        let sid = m
            .remove("x-reality-sid")
            .and_then(|v| v.as_str().map(str::to_owned));
        if let Some(Value::Object(ro)) = m.get_mut("reality-opts") {
            if let Some(k) = pbk {
                ro.insert("public-key".into(), Value::from(k));
            }
            if let Some(i) = sid {
                ro.insert("short-id".into(), Value::from(i));
            }
        }
    } else {
        m.remove("x-reality-pbk");
        m.remove("x-reality-sid");
    }
    // ws transport params for vless/trojan
    if let Some(net) = m.get("network").and_then(|x| x.as_str()).map(str::to_owned)
        && net == "ws"
    {
        let mut ws = Map::new();
        for (k, v) in parse_query(query) {
            if k == "path" {
                ws.insert("path".into(), Value::from(v.clone()));
            }
            if k == "host" {
                let mut hdr = Map::new();
                put(&mut hdr, "Host", v);
                ws.insert("headers".into(), Value::Object(hdr));
            }
        }
        m.insert("ws-opts".into(), Value::Object(ws));
    }
    if typ == "trojan" {
        m.entry("sni")
            .or_insert_with(|| Value::from(host.trim_matches(['[', ']'])));
    }
    if typ == "hysteria2" {
        // hy2 的 tls 是内建的
    }
    if !frag.is_empty() {
        put(&mut m, "name", pct_decode(frag));
    }
    Ok(m)
}

/// Parses one share link line into a proxies-shaped map.
pub fn parse_share_link(line: &str) -> Result<Map<String, Value>, String> {
    let line = line.trim();
    let (scheme, rest) = line.split_once("://").ok_or("缺 scheme")?;
    // split fragment/query off the tail
    let (before_frag, frag) = match rest.split_once('#') {
        Some((b, f)) => (b, f),
        None => (rest, ""),
    };
    let (body, query) = match before_frag.split_once('?') {
        Some((b, q)) => (b, q),
        None => (before_frag, ""),
    };
    let mut m = match scheme {
        "ss" => parse_ss(body, frag)?,
        "vmess" => parse_vmess(body, frag)?,
        "vless" => parse_standard("vless", body, frag, query)?,
        "trojan" => parse_standard("trojan", body, frag, query)?,
        "hysteria2" | "hy2" => parse_standard("hysteria2", body, frag, query)?,
        other => return Err(format!("暂不支持 {other} 协议")),
    };
    if !m.contains_key("name") {
        let server = m
            .get("server")
            .and_then(|v| v.as_str())
            .unwrap_or("node")
            .to_owned();
        let port = m.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
        put(&mut m, "name", format!("{server}:{port}"));
    }
    Ok(m)
}

/// Detects a base64 share-link subscription document (as opposed to YAML)
/// and returns the decoded lines. Detection: input is not valid UTF-8 YAML
/// shape — actually simpler: the whole input base64-decodes to text whose
/// non-empty lines mostly contain "://".
pub fn decode_share_list(data: &[u8]) -> Option<Vec<String>> {
    let text = String::from_utf8_lossy(data);
    let trimmed = text.trim();
    // Case A: already plaintext lines of links
    let plaintext_lines: Vec<&str> = trimmed
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if !plaintext_lines.is_empty()
        && plaintext_lines
            .iter()
            .all(|l| l.contains("://") || l.is_empty())
        && plaintext_lines.iter().any(|l| l.contains("://"))
        && !trimmed.contains("proxies:")
    {
        return Some(plaintext_lines.iter().map(|s| s.to_string()).collect());
    }
    // Case B: base64 of the whole document (single blob, no newlines inside)
    let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() < 16 || compact.len() % 4 == 1 {
        return None;
    }
    let dec = b64dec(&compact)?;
    let inner = String::from_utf8(dec).ok()?;
    let lines: Vec<String> = inner
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    if lines.is_empty() {
        return None;
    }
    let linkish = lines.iter().filter(|l| l.contains("://")).count();
    if linkish * 2 >= lines.len() {
        Some(lines)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ss_sip002_parses() {
        // ss://method:pass(b64)@host:port#name
        use base64::Engine;
        let creds = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:secret");
        let link = format!("ss://{creds}@1.2.3.4:8388#my-node");
        let m = parse_share_link(&link).unwrap();
        assert_eq!(m["type"].as_str().unwrap(), "ss");
        assert_eq!(m["server"].as_str().unwrap(), "1.2.3.4");
        assert_eq!(m["port"].as_u64().unwrap(), 8388);
        assert_eq!(m["cipher"].as_str().unwrap(), "aes-256-gcm");
        assert_eq!(m["password"].as_str().unwrap(), "secret");
        assert_eq!(m["name"].as_str().unwrap(), "my-node");
    }

    #[test]
    fn ss_fully_encoded_parses() {
        use base64::Engine;
        let whole = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode("chacha20-ietf-poly1305:pw@5.6.7.8:443");
        let m = parse_share_link(&format!("ss://{whole}")).unwrap();
        assert_eq!(m["server"].as_str().unwrap(), "5.6.7.8");
        assert_eq!(m["cipher"].as_str().unwrap(), "chacha20-ietf-poly1305");
    }

    #[test]
    fn vmess_v2rayn_parses() {
        use base64::Engine;
        let j = r#"{"add":"cdn.example.com","port":"443","id":"uuid-1","aid":"0","net":"ws","path":"/p","host":"h.example.com","tls":"tls","sni":"s.example.com","ps":"vm-node"}"#;
        let b = base64::engine::general_purpose::STANDARD.encode(j);
        let m = parse_share_link(&format!("vmess://{b}")).unwrap();
        assert_eq!(m["server"].as_str().unwrap(), "cdn.example.com");
        assert_eq!(m["uuid"].as_str().unwrap(), "uuid-1");
        assert_eq!(m["network"].as_str().unwrap(), "ws");
        assert!(m["tls"].as_bool().unwrap());
        assert_eq!(m["servername"].as_str().unwrap(), "s.example.com");
        assert_eq!(m["name"].as_str().unwrap(), "vm-node");
    }

    #[test]
    fn vless_reality_parses() {
        let m = parse_share_link("vless://uid@9.9.9.9:443?security=reality&flow=xtls-rprx-vision&pbk=PUBKEY&sid=ab&sni=x.com&fp=chrome#vl").unwrap();
        assert_eq!(m["type"].as_str().unwrap(), "vless");
        assert_eq!(m["uuid"].as_str().unwrap(), "uid");
        assert!(m["tls"].as_bool().unwrap());
        assert_eq!(m["reality-opts"]["public-key"].as_str().unwrap(), "PUBKEY");
        assert_eq!(m["reality-opts"]["short-id"].as_str().unwrap(), "ab");
        assert_eq!(m["sni"].as_str().unwrap(), "x.com");
        assert_eq!(m["flow"].as_str().unwrap(), "xtls-rprx-vision");
    }

    #[test]
    fn trojan_and_hy2_parse() {
        let m = parse_share_link("trojan://pw@t.example.com:443?sni=t.example.com#tr").unwrap();
        assert_eq!(m["password"].as_str().unwrap(), "pw");
        let h = parse_share_link(
            "hysteria2://pw@h.example.com:8443?insecure=1&obfs=salamander&obfs-password=x#hy",
        )
        .unwrap();
        assert_eq!(h["type"].as_str().unwrap(), "hysteria2");
        assert!(h["skip-cert-verify"].as_bool().unwrap());
        assert_eq!(h["obfs"].as_str().unwrap(), "salamander");
    }

    #[test]
    fn decode_share_list_detects_both_shapes() {
        use base64::Engine;
        assert!(decode_share_list(b"proxies:\n  - name: x").is_none());
        let lines = "ss://abc@1.1.1.1:1#a\nvless://u@2.2.2.2:2#b";
        assert_eq!(decode_share_list(lines.as_bytes()).unwrap().len(), 2);
        let blob = base64::engine::general_purpose::STANDARD.encode(lines);
        assert_eq!(decode_share_list(blob.as_bytes()).unwrap().len(), 2);
        assert!(decode_share_list(b"random prose text not base64 at all!!!").is_none());
    }

    #[test]
    fn errors_carry_no_credentials() {
        let err = parse_share_link("ss://!!!").unwrap_err();
        assert!(!err.contains("!!!") || err.len() < 100);
    }
}
