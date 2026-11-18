//! Subscription import: extracts proxy nodes from Clash/Mihomo YAML with
//! cage's import boundaries enforced.
//!
//! Only node bodies are kept — a remote file can never change listeners,
//! routes, or file paths. Protocol parameters are interpreted by the bundled
//! core, never here.

use super::{Node, NodeIssue, MAX_IMPORT};
use serde_json::{Map, Value};
use serde_yaml::Value as YamlValue;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// The protocols the bundled core supports for imports.
const SUPPORTED_TYPES: &[&str] = &[
    "http",
    "socks5",
    "ss",
    "ssr",
    "vmess",
    "vless",
    "trojan",
    "hysteria",
    "hysteria2",
    "tuic",
    "anytls",
    "mieru",
    "ssh",
];

/// Parses one subscription payload into usable nodes and skipped-node details.
pub fn parse_nodes(data: &[u8], source_id: &str) -> Result<(Vec<Node>, Vec<NodeIssue>), String> {
    if data.is_empty() || data.len() > MAX_IMPORT {
        return Err("配置为空或超过 8 MiB".to_owned());
    }
    let yaml: serde_yaml::Value = serde_yaml::from_slice(data).map_err(|_| {
        "无法读取 YAML，请导入 Clash/Mihomo 节点订阅或配置；暂不支持 Base64 列表或分享链接"
            .to_owned()
    })?;
    let mut proxies: Vec<serde_yaml::Value> = yaml
        .get("proxies")
        .and_then(YamlValue::as_sequence)
        .or_else(|| yaml.get("payload").and_then(YamlValue::as_sequence))
        .cloned()
        .unwrap_or_default();
    if proxies.is_empty() || proxies.len() > 3000 {
        return Err(
            "配置需要包含 1–3000 个 proxies 节点；仅含远程 provider 的配置请改为导入节点订阅链接"
                .to_owned(),
        );
    }

    let mut entries: Vec<(Option<Map<String, Value>>, NodeIssue)> =
        Vec::with_capacity(proxies.len());
    let mut name_counts: HashMap<String, usize> = HashMap::new();
    for (i, item) in proxies.drain(..).enumerate() {
        let mut issue = NodeIssue {
            index: i + 1,
            ..Default::default()
        };
        let map = match yaml_object(item) {
            Ok(m) => {
                let name = str_field(&m, "name");
                if name.len() <= 240 {
                    issue.name = name.clone();
                }
                let typ = str_field(&m, "type");
                if SUPPORTED_TYPES.contains(&typ.as_str()) {
                    issue.r#type = typ.clone();
                }
                *name_counts.entry(name).or_default() += 1;
                Some(m)
            }
            Err(e) => {
                issue.reason = e;
                None
            }
        };
        entries.push((map, issue));
    }

    let mut candidates: Vec<Node> = Vec::with_capacity(entries.len());
    let mut name_to_id: HashMap<String, String> = HashMap::new();
    let mut id_to_index: HashMap<String, usize> = HashMap::new();
    for (i, (map, issue)) in entries.iter_mut().enumerate() {
        let Some(map) = map else {
            continue;
        };
        let key_error =
            normalize_import_keys(map, &["name", "type", "server", "udp", "dialer-proxy"]).err();
        let name = str_field(map, "name");
        let typ = str_field(map, "type");
        let server = str_field(map, "server");
        issue.reason = if let Some(e) = key_error {
            e
        } else if name.trim().is_empty() || name.len() > 240 {
            "节点名称为空或过长".to_owned()
        } else if name_counts[&name] > 1 {
            "节点名称重复，无法确定代理链引用".to_owned()
        } else if !SUPPORTED_TYPES.contains(&typ.as_str()) {
            "节点协议暂不支持".to_owned()
        } else if server.is_empty() || server.len() > 253 {
            "节点服务器缺失或过长".to_owned()
        } else if let Err(e) = normalize_websocket(map) {
            e
        } else if typ == "ssh" && ssh_private_key_is_path(map) {
            "SSH 节点的 private-key 必须直接填写私钥内容，不能引用本机文件".to_owned()
        } else if unsafe_option(&Value::Object(without_ssh_private_key(map))) {
            "节点不能引用本机文件、网络接口或额外路由".to_owned()
        } else if typ == "hysteria2" {
            match normalize_hysteria2(map) {
                Ok(()) => String::new(),
                Err(e) => e,
            }
        } else {
            String::new()
        };
        if !issue.reason.is_empty() {
            continue;
        }
        let digest = Sha256::digest(format!("{source_id}\x00{name}").as_bytes());
        let id = hex::encode(&digest[..12]);
        name_to_id.insert(name.clone(), id.clone());
        id_to_index.insert(id.clone(), i);
        candidates.push(Node {
            id,
            name,
            node_type: typ,
            config: map.clone(),
        });
    }

    // Rewrite references and validate dialer chains before retaining anything.
    let mut by_id: HashMap<String, Node> = HashMap::new();
    for node in &candidates {
        let mut config = node.config.clone();
        config.insert("name".to_owned(), Value::String(node.id.clone()));
        config.insert("udp".to_owned(), Value::Bool(false));
        if let Some(target) = config.get("dialer-proxy").cloned() {
            let resolved = target.as_str().and_then(|t| name_to_id.get(t)).cloned();
            match resolved {
                Some(id) => {
                    config.insert("dialer-proxy".to_owned(), Value::String(id));
                }
                None => {
                    if let Some(&i) = id_to_index.get(&node.id) {
                        entries[i].1.reason = "代理链必须引用同一来源中成功导入的具体节点，不能引用 DIRECT 或选择分组".to_owned();
                    }
                }
            }
        }
        by_id.insert(
            node.id.clone(),
            Node {
                id: node.id.clone(),
                name: node.name.clone(),
                node_type: node.node_type.clone(),
                config,
            },
        );
    }

    // A failed dialer must drop its dependents too: dropping a transit hop
    // silently would remove it from a working chain.
    #[derive(Default)]
    struct Visit {
        state: u8, // 1 visiting, 2 done
    }
    let mut visits: HashMap<String, Visit> = HashMap::new();
    fn usable(
        id: &str,
        by_id: &HashMap<String, Node>,
        id_to_index: &HashMap<String, usize>,
        entries: &mut [(Option<Map<String, Value>>, NodeIssue)],
        visits: &mut HashMap<String, Visit>,
    ) -> bool {
        let Some(&i) = id_to_index.get(id) else {
            return false;
        };
        if !entries[i].1.reason.is_empty() {
            return false;
        }
        let state = visits.entry(id.to_owned()).or_default().state;
        match state {
            2 => return true,
            1 => {
                entries[i].1.reason = "代理链存在循环".to_owned();
                return false;
            }
            _ => {}
        }
        visits.get_mut(id).unwrap().state = 1;
        let dialer = by_id
            .get(id)
            .and_then(|n| n.config.get("dialer-proxy"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if !dialer.is_empty() && !usable(&dialer, by_id, id_to_index, entries, visits) {
            if entries[i].1.reason.is_empty() {
                entries[i].1.reason = "代理链依赖的中转节点不可用或存在循环".to_owned();
            }
            return false;
        }
        visits.get_mut(id).unwrap().state = 2;
        true
    }
    let mut out = Vec::with_capacity(candidates.len());
    for node in &candidates {
        if usable(&node.id, &by_id, &id_to_index, &mut entries, &mut visits) {
            out.push(by_id[node.id.as_str()].clone());
        }
    }
    let skipped: Vec<NodeIssue> = entries
        .iter()
        .filter(|(_, issue)| !issue.reason.is_empty())
        .map(|(_, issue)| issue.clone())
        .collect();
    if out.is_empty() {
        let details: Vec<String> = skipped
            .iter()
            .take(3)
            .map(|i| format!("第 {} 个节点 {:?}：{}", i.index, i.name, i.reason))
            .collect();
        return Err(format!(
            "没有可导入的节点，已跳过 {} 个；{}",
            skipped.len(),
            details.join("；")
        ));
    }
    Ok((out, skipped))
}

/// Mihomo's decoder matches keys case-insensitively and treats `_` as `-`;
/// cage canonicalizes only the fields it reads or rewrites.
pub(super) fn option_key(key: &str) -> String {
    key.to_lowercase().replace('_', "-")
}

fn yaml_object(item: serde_yaml::Value) -> Result<Map<String, Value>, String> {
    match item {
        serde_yaml::Value::Mapping(m) => {
            let mut out = Map::new();
            for (k, v) in m {
                let Some(key) = k.as_str().map(str::to_owned) else {
                    return Err("节点字段使用了非字符串键".to_owned());
                };
                out.insert(key, yaml_to_json(v)?);
            }
            Ok(out)
        }
        _ => Err("proxies 中的节点必须是映射".to_owned()),
    }
}

fn yaml_to_json(v: serde_yaml::Value) -> Result<Value, String> {
    Ok(match v {
        serde_yaml::Value::Null => Value::Null,
        serde_yaml::Value::Bool(b) => Value::Bool(b),
        serde_yaml::Value::Number(n) => {
            serde_json::Number::from_f64(n.as_f64().unwrap_or_default())
                .map(Value::Number)
                .ok_or("节点包含非有限数字")?
        }
        serde_yaml::Value::String(s) => Value::String(s),
        serde_yaml::Value::Sequence(seq) => Value::Array(
            seq.into_iter()
                .map(yaml_to_json)
                .collect::<Result<_, _>>()?,
        ),
        serde_yaml::Value::Mapping(m) => {
            let mut out = Map::new();
            for (k, v) in m {
                let Some(key) = k.as_str().map(str::to_owned) else {
                    return Err("节点字段使用了非字符串键".to_owned());
                };
                out.insert(key, yaml_to_json(v)?);
            }
            Value::Object(out)
        }
        serde_yaml::Value::Tagged(t) => yaml_to_json(t.value)?,
    })
}

fn str_field(map: &Map<String, Value>, key: &str) -> String {
    map.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Canonicalizes variant spellings of `keys`; two variants of one key is an
/// error, one variant is renamed in place.
pub(super) fn normalize_import_keys(
    map: &mut Map<String, Value>,
    keys: &[&str],
) -> Result<(), String> {
    for canonical in keys {
        let mut found: Option<String> = None;
        for key in map.keys() {
            if option_key(key) == option_key(canonical) {
                if found.is_some() {
                    return Err(format!("节点字段 {canonical} 存在重复写法，请仅保留一种"));
                }
                found = Some(key.clone());
            }
        }
        if let Some(found) = found {
            if found != *canonical {
                let value = map.remove(&found).expect("key just listed");
                map.insert((*canonical).to_owned(), value);
            }
        }
    }
    Ok(())
}

/// The core reads private-key as a file path unless the value contains
/// "PRIVATE KEY"; only inline key content keeps imports away from local files.
fn ssh_private_key_is_path(map: &mut Map<String, Value>) -> bool {
    if normalize_import_keys(map, &["private-key"]).is_err() {
        return true;
    }
    match map.get("private-key") {
        Some(Value::String(s)) => !s.contains("PRIVATE KEY"),
        Some(_) => true,
        None => false,
    }
}

/// Exempts only an SSH node's inline top-level key from the file checks;
/// nested options and every other protocol keep the full checks.
fn without_ssh_private_key(map: &Map<String, Value>) -> Map<String, Value> {
    if str_field(map, "type") != "ssh" || !map.contains_key("private-key") {
        return map.clone();
    }
    let mut clone = map.clone();
    clone.remove("private-key");
    clone
}

/// Files, network interfaces, and extra routes never enter a node config.
pub(super) fn unsafe_option(v: &Value) -> bool {
    match v {
        Value::Object(map) => map.iter().any(|(k, v)| unsafe_field(k, v)),
        Value::Array(items) => items.iter().any(unsafe_option),
        _ => false,
    }
}

fn unsafe_field(key: &str, value: &Value) -> bool {
    let key = option_key(key);
    if key.contains("path") && key != "path" {
        return true;
    }
    if matches!(
        key.as_str(),
        "ca" | "certificate" | "private-key" | "interface-name" | "routing-mark"
    ) {
        return true;
    }
    unsafe_option(value)
}

/// Legacy `ws-path` / `ws-headers` fields are accepted by the core but ignored
/// by its transport; nodes carrying aliases are rewritten to `ws-opts`.
pub(super) fn normalize_websocket(map: &mut Map<String, Value>) -> Result<(), String> {
    let legacy = map.keys().any(|k| {
        let k = option_key(k);
        k == "ws-path" || k == "ws-headers"
    });
    if !legacy {
        return Ok(());
    }
    normalize_import_keys(map, &["ws-path", "ws-headers", "ws-opts", "network"])?;
    if !matches!(
        str_field(map, "type").as_str(),
        "vmess" | "vless" | "trojan"
    ) {
        return Err("旧 WebSocket 字段仅适用于 VMess、VLESS 或 Trojan 节点".to_owned());
    }
    if str_field(map, "network") != "ws" {
        return Err("旧 WebSocket 字段需要显式设置 network: ws，请核对节点传输方式".to_owned());
    }
    let mut opts = match map.get("ws-opts") {
        Some(Value::Object(o)) => o.clone(),
        Some(_) => return Err("WebSocket 字段 ws-opts 无效，未忽略旧字段".to_owned()),
        None => Map::new(),
    };
    normalize_import_keys(&mut opts, &["path", "headers"])?;
    if let Some(path) = map.get("ws-path").cloned() {
        let Some(path) = path.as_str().map(str::to_owned) else {
            return Err("WebSocket 字段 ws-path 无效，未忽略该字段".to_owned());
        };
        if let Some(current) = opts.get("path") {
            if current.as_str() != Some(path.as_str()) {
                return Err("WebSocket 字段 ws-path 与 ws-opts.path 冲突".to_owned());
            }
        }
        opts.insert("path".to_owned(), Value::String(path));
        map.remove("ws-path");
    }
    if let Some(headers) = map.get("ws-headers").cloned() {
        let incoming = web_socket_headers(&headers)?;
        if let Some(current) = opts.get("headers") {
            let modern = web_socket_headers(current)?;
            for (k, v) in &modern {
                if let Some(prev) = incoming.get(k) {
                    if prev != v {
                        return Err("WebSocket 字段 ws-headers 与 ws-opts.headers 冲突".to_owned());
                    }
                }
            }
        }
        opts.insert("headers".to_owned(), Value::Object(incoming));
        map.remove("ws-headers");
    }
    map.insert("ws-opts".to_owned(), Value::Object(opts));
    Ok(())
}

fn web_socket_headers(raw: &Value) -> Result<Map<String, Value>, String> {
    let Value::Object(input) = raw else {
        return Err("WebSocket 请求头必须为字符串映射，未忽略该字段".to_owned());
    };
    let mut headers = Map::new();
    for (key, value) in input {
        let Some(value) = value.as_str() else {
            return Err("WebSocket 请求头无效，未忽略该字段".to_owned());
        };
        if !valid_header_field_name(key) || !valid_header_field_value(value) {
            return Err("WebSocket 请求头无效，未忽略该字段".to_owned());
        }
        let canonical = canonical_header_key(key);
        if let Some(prev) = headers.get(&canonical) {
            if prev.as_str() != Some(value) {
                return Err("WebSocket 请求头存在大小写不同的冲突写法".to_owned());
            }
        }
        headers.insert(canonical, Value::String(value.to_owned()));
    }
    Ok(headers)
}

/// RFC 7230 token characters.
fn valid_header_field_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn valid_header_field_value(s: &str) -> bool {
    s.bytes()
        .all(|c| c == b'\t' || (0x20..=0x7e).contains(&c) || c >= 0x80)
}

/// Go's http.CanonicalHeaderKey.
fn canonical_header_key(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut upper = true;
    for c in s.chars() {
        if c == '-' {
            upper = true;
            out.push('-');
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// One hysteria2 alias: source field, canonical field, and its normalizer.
type Alias = (
    &'static str,
    &'static str,
    fn(&Value) -> Result<String, String>,
);

fn normalize_hysteria2(map: &mut Map<String, Value>) -> Result<(), String> {
    normalize_import_keys(map, &["mport", "ports", "pinSHA256", "fingerprint"])?;
    let aliases: [Alias; 2] = [
        ("mport", "ports", hysteria2_ports),
        ("pinSHA256", "fingerprint", hysteria2_pin),
    ];
    for (from, to, normalize) in aliases {
        let Some(raw) = map.get(from).cloned() else {
            continue;
        };
        let value =
            normalize(&raw).map_err(|_| format!("Hysteria2 字段 {from} 无效，未忽略该字段"))?;
        if let Some(current) = map.get(to) {
            match normalize(current) {
                Ok(canonical) if canonical == value => {}
                _ => return Err(format!("Hysteria2 字段 {from} 与 {to} 冲突")),
            }
        }
        map.insert(to.to_owned(), Value::String(value));
        map.remove(from);
    }
    Ok(())
}

fn hysteria2_ports(raw: &Value) -> Result<String, String> {
    let ports = match raw {
        Value::String(s) => s.trim().to_owned(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    };
    let normalized = ports.replace('/', ",");
    let parts: Vec<&str> = normalized.split(',').collect();
    if ports.is_empty() || parts.len() > 28 {
        return Err("invalid ports".to_owned());
    }
    let mut out = Vec::with_capacity(parts.len());
    for part in parts {
        let range: Vec<&str> = part.trim().split('-').collect();
        if range.len() > 2 {
            return Err("invalid port range".to_owned());
        }
        let mut norm = Vec::with_capacity(range.len());
        for port in range {
            let n: i64 = port.trim().parse().map_err(|_| "invalid port".to_owned())?;
            if !(1..=65535).contains(&n) {
                return Err("invalid port".to_owned());
            }
            norm.push(n.to_string());
        }
        out.push(norm.join("-"));
    }
    Ok(out.join(","))
}

fn hysteria2_pin(raw: &Value) -> Result<String, String> {
    let Some(value) = raw.as_str() else {
        return Err("invalid pin".to_owned());
    };
    let value = value.replace(':', "");
    let pin = hex::decode(value.trim()).map_err(|_| "invalid pin".to_owned())?;
    if pin.len() != 32 {
        return Err("invalid pin".to_owned());
    }
    Ok(hex::encode(pin))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
proxies:
  - name: "Exit A"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-128-gcm
    password: "hunter2"
  - name: "Transit B"
    type: vmess
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    alterId: 0
    cipher: auto
    dialer-proxy: "Exit A"
  - name: "Bad Type"
    type: quantum-tunnel
    server: 5.6.7.8
    port: 1
"#;

    #[test]
    fn parses_good_nodes_and_skips_bad() {
        let (nodes, skipped) = parse_nodes(GOOD.as_bytes(), "src").unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].reason.contains("协议暂不支持"));
        // Node identity is a hash of source + name; the config name is replaced.
        for n in &nodes {
            assert!(n.name.len() <= 240);
            assert_eq!(
                n.config.get("name").and_then(Value::as_str),
                Some(n.id.as_str())
            );
            assert_eq!(n.config.get("udp"), Some(&Value::Bool(false)));
        }
        // dialer-proxy is rewritten to the target node's ID.
        let transit = nodes.iter().find(|n| n.node_type == "vmess").unwrap();
        let exit = nodes.iter().find(|n| n.node_type == "ss").unwrap();
        assert_eq!(
            transit.config.get("dialer-proxy").and_then(Value::as_str),
            Some(exit.id.as_str())
        );
    }

    #[test]
    fn empty_or_huge_payload_is_rejected() {
        assert!(parse_nodes(b"", "src").is_err());
        assert!(parse_nodes(b"proxies: []", "src").is_err());
        assert!(parse_nodes(b"not yaml at all: [[[[", "src").is_err());
    }

    #[test]
    fn duplicate_names_are_refused() {
        let y = r#"
proxies:
  - name: "Exit A"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-128-gcm
    password: "hunter2"
  - name: "Exit A"
    type: ss
    server: 9.9.9.9
    port: 8388
    cipher: aes-128-gcm
    password: "hunter2"
"#;
        let err = parse_nodes(y.as_bytes(), "src").unwrap_err();
        assert!(err.contains("没有可导入的节点"));
    }

    #[test]
    fn local_file_references_are_refused() {
        let y = r#"
proxies:
  - name: "Sneaky"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-128-gcm
    password: "x"
    ca: "/etc/ssl/ca.crt"
"#;
        let err = parse_nodes(y.as_bytes(), "src").unwrap_err();
        assert!(err.contains("没有可导入的节点"), "{err}");
        let y = r#"
proxies:
  - name: "Sneaky Too"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-128-gcm
    password: "x"
    ca-path: "/etc/ssl/ca.crt"
"#;
        assert!(parse_nodes(y.as_bytes(), "src").is_err());
    }

    #[test]
    fn ssh_requires_inline_key() {
        let y = r#"
proxies:
  - name: "SSHL over files"
    type: ssh
    server: 1.2.3.4
    port: 22
    private-key: "/Users/me/.ssh/id_ed25519"
"#;
        assert!(parse_nodes(y.as_bytes(), "src").is_err());
        let y = r#"
proxies:
  - name: "SSHL inline"
    type: ssh
    server: 1.2.3.4
    port: 22
    private-key: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"
"#;
        assert!(parse_nodes(y.as_bytes(), "src").is_ok());
    }

    #[test]
    fn dialer_cycle_is_cut() {
        let y = r#"
proxies:
  - name: "A"
    type: ss
    server: 1.1.1.1
    port: 1
    dialer-proxy: "B"
  - name: "B"
    type: ss
    server: 1.1.1.1
    port: 1
    dialer-proxy: "A"
"#;
        assert!(parse_nodes(y.as_bytes(), "src").is_err());
    }

    #[test]
    fn hysteria2_aliases_normalize() {
        let y = r#"
proxies:
  - name: "H2"
    type: hysteria2
    server: 1.2.3.4
    port: 443
    auth: "pw"
    mport: 20000-30000
"#;
        let (nodes, _) = parse_nodes(y.as_bytes(), "src").unwrap();
        assert_eq!(
            nodes[0].config.get("ports").and_then(Value::as_str),
            Some("20000-30000")
        );
        assert!(!nodes[0].config.contains_key("mport"));
    }

    #[test]
    fn legacy_websocket_fields_are_merged() {
        let y = r#"
proxies:
  - name: "WS legacy"
    type: vmess
    server: example.com
    port: 443
    uuid: "00000000-0000-0000-0000-000000000000"
    alterId: 0
    cipher: auto
    network: ws
    ws-path: "/api"
    ws-headers:
      Host: "example.com"
"#;
        let (nodes, _) = parse_nodes(y.as_bytes(), "src").unwrap();
        let opts = nodes[0].config.get("ws-opts").unwrap();
        assert_eq!(opts.get("path").and_then(Value::as_str), Some("/api"));
        assert_eq!(
            opts.get("headers")
                .and_then(|h| h.get("Host"))
                .and_then(Value::as_str),
            Some("example.com")
        );
        assert!(!nodes[0].config.contains_key("ws-path"));
    }

    #[test]
    fn payload_field_is_accepted() {
        let y = "payload:\n  - name: P\n    type: ss\n    server: 1.1.1.1\n    port: 1\n    cipher: aes-128-gcm\n    password: x\n";
        let (nodes, _) = parse_nodes(y.as_bytes(), "src").unwrap();
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn node_ids_are_deterministic() {
        let nodes = parse_nodes(GOOD.as_bytes(), "src").unwrap().0;
        let again = parse_nodes(GOOD.as_bytes(), "src").unwrap().0;
        assert_eq!(
            nodes.iter().map(|n| n.id.clone()).collect::<Vec<_>>(),
            again.iter().map(|n| n.id.clone()).collect::<Vec<_>>()
        );
        // id = sha256(sourceID NUL name)[:12] — 24 hex chars.
        let digest = Sha256::digest(b"src\x00Exit A");
        let exit = nodes.iter().find(|n| n.name == "Exit A").unwrap();
        assert_eq!(exit.id, hex::encode(&digest[..12]));
        assert_eq!(exit.id.len(), 24);
    }
}
