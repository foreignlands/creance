//! Subscription import: extracts proxy nodes from Clash/Mihomo YAML with
//! cage's import boundaries enforced.
//!
//! Only node bodies are kept — a remote file can never change listeners,
//! routes, or file paths. Protocol parameters are interpreted by the bundled
//! core, never here.

use crate::{Node, NodeIssue, MAX_IMPORT};
use serde_json::{Map, Value};
use serde_yaml::Value as YamlValue;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// The protocols the bundled core supports for imports.
/// True when the payload visibly contains a decimal integer too wide for
/// 64 bits — the one parse failure serde_yaml cannot represent (Go's
/// yaml.v3 degrades to float64 instead).
fn contains_overflow_integer(data: &[u8]) -> bool {
    let mut run = 0usize;
    for &b in data.iter().chain(std::iter::once(&b' ')) {
        if b.is_ascii_digit() {
            run += 1;
            // 20 digits already overflows u64 for values ≥ 10^19; a rare
            // in-range 20-digit number only trades the generic message for
            // a more specific one.
            if run >= 20 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// A single linear pass over the raw bytes: refuse absurd flow-nesting
/// depth (>128 — the parser's own limit, but reached here in O(n)) and
/// absurd single-line length (>1 MiB, another quadratic-scanner vector).
fn precheck_depth(data: &[u8]) -> Result<(), String> {
    let mut depth: u32 = 0;
    let mut line_start = 0usize;
    // FINDING-018: brackets inside quoted scalars are data, not structure —
    // a legitimate `password: "[[[…"` must not trip the depth counter.
    // YAML flow scalars escape `''` and `\"`; both are handled.
    let (mut in_single, mut in_double) = (false, false);
    let mut prev_escape = false;
    for (i, &b) in data.iter().enumerate() {
        if in_double {
            if prev_escape {
                prev_escape = false;
            } else if b == b'\\' {
                prev_escape = true;
            } else if b == b'"' {
                in_double = false;
            }
            continue;
        }
        if in_single {
            if b == b'\'' {
                // Either closes the scalar or is the first half of ''.
                in_single = data.get(i + 1) != Some(&b'\'');
            }
            continue;
        }
        match b {
            b'"' => in_double = true,
            b'\'' => in_single = true,
            b'[' | b'{' => {
                depth = depth.saturating_add(1);
                if depth > 128 {
                    return Err("订阅嵌套过深（>128 层），已拒绝".to_owned());
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            b'\n' => {
                if i - line_start > 1 << 20 {
                    return Err("订阅包含超长单行（>1 MiB），已拒绝".to_owned());
                }
                line_start = i + 1;
            }
            _ => {}
        }
    }
    // The final line has no trailing newline — check it too.
    if data.len() - line_start > 1 << 20 {
        return Err("订阅包含超长单行（>1 MiB），已拒绝".to_owned());
    }
    Ok(())
}

/// The node fields cage canonicalizes (case/underscore-insensitively) before
/// reading or counting them.
const CANONICAL_KEYS: &[&str] = &["name", "type", "server", "udp", "dialer-proxy"];

const SUPPORTED_TYPES: &[&str] = &[
    "direct",
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
    // FINDING-001: deep flow nesting is quadratic in the YAML scanner's
    // event stream — a 1 MiB bomb burns minutes of CPU before the parser's
    // own recursion limit rejects it. One linear pass refuses it instantly.
    precheck_depth(data)?;
    let yaml: serde_yaml::Value = serde_yaml::from_slice(data).map_err(|_| {
        // FINDING-002: serde_yaml rejects whole documents over a single
        // integer wider than 64 bits (Go's yaml.v3 falls back to float64);
        // point the user at the actual cause instead of the generic text.
        if contains_overflow_integer(data) {
            "订阅包含超出 64 位范围的整数（如端口或端口范围写成超大数字），请修正后重试".to_owned()
        } else {
            "无法读取 YAML，请导入 Clash/Mihomo 节点订阅或配置；暂不支持 Base64 列表或分享链接"
                .to_owned()
        }
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
            Ok(mut m) => {
                // Canonicalize the cage-managed keys BEFORE anything reads
                // them: mihomo matches keys case-insensitively, so `Name:`
                // and `name:` are the same field and duplicate detection
                // must see one spelling only.
                match normalize_import_keys(&mut m, CANONICAL_KEYS) {
                    Ok(()) => {
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
                }
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
        let name = str_field(map, "name");
        let typ = str_field(map, "type");
        let server = str_field(map, "server");
        issue.reason = if name.trim().is_empty() || name.len() > 240 {
            "节点名称为空或过长".to_owned()
        } else if name_counts.get(&name).copied().unwrap_or(1) > 1 {
            "节点名称重复，无法确定代理链引用".to_owned()
        } else if !SUPPORTED_TYPES.contains(&typ.as_str()) {
            "节点协议暂不支持".to_owned()
        } else if typ != "direct" && (server.is_empty() || server.len() > 253) {
            // direct nodes carry no server: their "endpoint" is the exit
            // itself and the user owns that choice.
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
                out.insert(yaml_key_string(k), yaml_to_json(v)?);
            }
            Ok(out)
        }
        _ => Err("proxies 中的节点必须是映射".to_owned()),
    }
}

/// FINDING-012: YAML maps with non-string keys still carry core option
/// values — stringify the key (Go's map[any]any semantics, where a non-string
/// key just stops matching option names) instead of rejecting the whole node.
fn yaml_key_string(k: serde_yaml::Value) -> String {
    match k {
        serde_yaml::Value::String(s) => s,
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Tagged(t) => yaml_key_string(t.value),
        _ => String::new(),
    }
}

fn yaml_to_json(v: serde_yaml::Value) -> Result<Value, String> {
    Ok(match v {
        serde_yaml::Value::Null => Value::Null,
        serde_yaml::Value::Bool(b) => Value::Bool(b),
        serde_yaml::Value::Number(n) => {
            // FINDING-003: integral scalars must stay integral — the old
            // blanket f64 conversion turned `mport: 443` into "443.0" and
            // every downstream integer parser rejected it.
            if let Some(i) = n.as_i64() {
                Value::Number(serde_json::Number::from(i))
            } else if let Some(u) = n.as_u64() {
                Value::Number(serde_json::Number::from(u))
            } else {
                serde_json::Number::from_f64(n.as_f64().unwrap_or_default())
                    .map(Value::Number)
                    .ok_or("节点包含非有限数字")?
            }
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
                out.insert(yaml_key_string(k), yaml_to_json(v)?);
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
        let mut merged = web_socket_headers(&headers)?;
        if let Some(current) = opts.get("headers") {
            let modern = web_socket_headers(current)?;
            // Go semantics: the modern set merges into the legacy one —
            // equal values overwrite harmlessly, differing values conflict,
            // and modern-only headers are KEPT, never dropped.
            for (k, v) in modern {
                if let Some(prev) = merged.get(&k) {
                    if prev != &v {
                        return Err("WebSocket 字段 ws-headers 与 ws-opts.headers 冲突".to_owned());
                    }
                }
                merged.insert(k, v);
            }
        }
        opts.insert("headers".to_owned(), Value::Object(merged));
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
    fn numeric_hysteria2_fields_stay_integral() {
        // FINDING-003: `mport: 443` (a number, not a string) must normalize
        // to ports "443", not be rejected as "443.0".
        let y = "proxies:\n  - name: H2num\n    type: hysteria2\n    server: 1.2.3.4\n    port: 443\n    mport: 443\n    auth: pw\n";
        let (nodes, _) = parse_nodes(y.as_bytes(), "src").unwrap();
        assert_eq!(
            nodes[0].config.get("ports").and_then(Value::as_str),
            Some("443"),
            "{:?}",
            nodes[0].config
        );
    }

    #[test]
    fn overflow_integers_get_an_actionable_error() {
        // FINDING-002: the document is still rejected (serde_yaml cannot
        // hold the number), but the message names the cause.
        let y = "proxies:\n  - name: big\n    type: ss\n    server: 1.2.3.4\n    port: 99999999999999999999\n    cipher: aes-128-gcm\n    password: x\n";
        let err = parse_nodes(y.as_bytes(), "src").unwrap_err();
        assert!(err.contains("超出 64 位范围"), "{err}");
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

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    #[test]
    fn deep_flow_bombs_are_refused_in_linear_time() {
        // FINDING-001 regression: the same payload that burned 14s in the
        // scanner must now be refused by the precheck in milliseconds.
        let mut bomb = b"proxies: ".to_vec();
        bomb.extend(std::iter::repeat_n(b'[', 100_000));
        bomb.extend(std::iter::repeat_n(b']', 100_000));
        let t = std::time::Instant::now();
        let err = parse_nodes(&bomb, "src").unwrap_err();
        assert!(err.contains("嵌套过深"), "{err}");
        assert!(
            t.elapsed() < std::time::Duration::from_secs(1),
            "precheck must be linear: took {:?}",
            t.elapsed()
        );
        // The oversized single-line variant too.
        let mut long_line = b"proxies: [".to_vec();
        long_line.extend(std::iter::repeat_n(b'x', 2 << 20));
        long_line.extend(b"]");
        let err = parse_nodes(&long_line, "src").unwrap_err();
        assert!(err.contains("超长单行"), "{err}");
    }

    #[test]
    fn quoted_bracket_scalars_do_not_trip_the_depth_guard() {
        // FINDING-018: 129 literal brackets inside a quoted password are
        // data; the precheck must look through them.
        let pw = "[".repeat(129);
        let y = format!(
            "proxies:\n  - name: quoted\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-128-gcm\n    password: \"{pw}\"\n"
        );
        let (nodes, _) = parse_nodes(y.as_bytes(), "src").expect("quoted brackets are data");
        assert_eq!(nodes.len(), 1);
        // Single-quoted scalars and the '' escape likewise.
        let y2 = format!(
            "proxies:\n  - name: q2\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-128-gcm\n    password: '{pw}''x'\n"
        );
        assert!(parse_nodes(y2.as_bytes(), "src").is_ok());
        // And the real (unquoted) bomb is still refused instantly.
        let mut bomb = b"proxies: ".to_vec();
        bomb.extend(std::iter::repeat_n(b'[', 100_000));
        bomb.extend(std::iter::repeat_n(b']', 100_000));
        assert!(parse_nodes(&bomb, "src").unwrap_err().contains("嵌套过深"));
    }

    #[test]
    fn case_variant_keys_never_panic_and_count_once() {
        // mihomo matches keys case-insensitively; a subscription spelling
        // `Name:` must import identically to `name:`.
        let y = "proxies:\n  - Name: CaseExit\n    TYPE: ss\n    Server: 192.0.2.9\n    PORT: 8388\n    cipher: aes-128-gcm\n    password: x\n";
        let (nodes, skipped) = parse_nodes(y.as_bytes(), "src").expect("case variants import");
        assert!(skipped.is_empty(), "{skipped:?}");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "CaseExit");

        // Same-name nodes through case variants are still duplicates: one
        // canonical spelling means one count of two.
        let dup = "proxies:\n  - name: X\n    type: ss\n    server: 1.1.1.1\n    port: 1\n    cipher: aes-128-gcm\n    password: x\n  - NAME: X\n    type: ss\n    server: 2.2.2.2\n    port: 1\n    cipher: aes-128-gcm\n    password: x\n";
        let err = parse_nodes(dup.as_bytes(), "src").unwrap_err();
        assert!(err.contains("没有可导入的节点"), "{err}");
    }

    #[test]
    fn duplicate_key_spellings_are_refused() {
        // `name` and `NAME` in one node: two spellings of one field.
        let y = "proxies:\n  - name: A\n    NAME: B\n    type: ss\n    server: 1.1.1.1\n    port: 1\n    cipher: aes-128-gcm\n    password: x\n";
        let err = parse_nodes(y.as_bytes(), "src").unwrap_err();
        assert!(err.contains("重复写法"), "{err}");
    }

    #[test]
    fn ws_headers_merge_keeps_modern_only_headers() {
        // Legacy ws-headers + modern ws-opts.headers: the union survives,
        // a modern-only header is never dropped, conflicts still error.
        let y = "proxies:\n  - name: WS\n    type: vmess\n    server: example.com\n    port: 443\n    uuid: 00000000-0000-0000-0000-000000000000\n    network: ws\n    ws-path: /api\n    ws-headers:\n      Host: example.com\n    ws-opts:\n      path: /api\n      headers:\n        User-Agent: cage-test\n";
        let (nodes, _) = parse_nodes(y.as_bytes(), "src").unwrap();
        let headers = &nodes[0].config["ws-opts"]["headers"];
        assert_eq!(
            headers.get("Host").and_then(Value::as_str),
            Some("example.com"),
            "legacy header kept"
        );
        assert_eq!(
            headers.get("User-Agent").and_then(Value::as_str),
            Some("cage-test"),
            "modern-only header kept (union, not legacy-only)"
        );
    }

    #[test]
    fn ws_headers_conflicting_values_still_refused() {
        let y = "proxies:\n  - name: WS2\n    type: trojan\n    server: example.com\n    port: 443\n    password: x\n    network: ws\n    ws-headers:\n      Host: a.example\n    ws-opts:\n      headers:\n        Host: b.example\n";
        let err = parse_nodes(y.as_bytes(), "src").unwrap_err();
        assert!(
            err.contains("冲突") || err.contains("没有可导入的节点"),
            "{err}"
        );
    }

    #[test]
    fn non_string_keys_stringify_instead_of_rejecting() {
        // FINDING-012: Go's map[any]any branch keeps values under non-string
        // keys; the node imports with the keys stringified.
        let y = "proxies:\n  - name: IK\n    type: ss\n    server: 1.2.3.4\n    port: 1\n    cipher: aes-128-gcm\n    password: x\n    123: junk-value\n    true: junk\n";
        let (nodes, skipped) = parse_nodes(y.as_bytes(), "src").unwrap();
        assert_eq!(skipped.len(), 0, "{skipped:?}");
        assert_eq!(nodes.len(), 1);
        assert_eq!(
            nodes[0].config.get("123").and_then(Value::as_str),
            Some("junk-value")
        );
        assert_eq!(
            nodes[0].config.get("true").and_then(Value::as_str),
            Some("junk")
        );
    }

    #[test]
    fn non_string_key_nodes_keep_their_name_when_skipped() {
        // The issue line stays user-locatable: name is read even when the
        // node carries non-string keys and is refused for another reason.
        let y = "proxies:\n  - name: NK\n    type: quantum-tunnel\n    server: 1.2.3.4\n    port: 1\n    123: x\n";
        let err = parse_nodes(y.as_bytes(), "src").unwrap_err();
        assert!(err.contains("NK"), "{err}");
        assert!(err.contains("协议暂不支持"), "{err}");
    }
}
