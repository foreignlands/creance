//! Generation of the mihomo runtime configuration and the physical-interface
//! binding.
//!
//! The generated config exposes exactly one mixed port on loopback with
//! store-backed auth, routes MATCH to the applied exit, and resolves its own
//! server domains over bootstrap DoH only. Guest DNS stays behind the cage
//! egress.

use crate::{Store, GROUP};
use serde_json::Value;
use serde_yaml::{Mapping, Value as Yaml};

/// The generated core configuration. `MATCH` always resolves to the select
/// group holding the applied exit.
pub fn generate(store: &Store, profile: &str) -> Result<Vec<u8>, String> {
    // Route() is the gate: no route, no config.
    let route = store.route()?;
    // Explicit chains override node-level dialers at runtime without touching
    // subscription nodes or their credentials.
    let mut dialers = std::collections::HashMap::new();
    for (i, id) in store.chain.iter().enumerate() {
        dialers.insert(
            id.clone(),
            if i > 0 {
                store.chain[i - 1].clone()
            } else {
                String::new()
            },
        );
    }
    let mut proxies: Vec<Yaml> = Vec::new();
    for source in &store.sources {
        for node in &source.nodes {
            let mut config = node.config.clone();
            // Older stores may carry legacy headers accepted before normalization.
            crate::import::normalize_websocket(&mut config)
                .map_err(|e| format!("节点 {:?}：{e}", node.name))?;
            if let Some(via) = dialers.get(&node.id) {
                config.remove("dialer-proxy");
                if !via.is_empty() {
                    config.insert("dialer-proxy".to_owned(), Value::String(via.clone()));
                }
            }
            proxies.push(serde_yaml::to_value(Value::Object(config)).map_err(|e| e.to_string())?);
        }
    }
    let _ = route;

    let bootstrap = crate::bootstrap_dns_urls();
    let mut dns = Mapping::new();
    dns.insert("enable".into(), true.into());
    dns.insert("ipv6".into(), false.into());
    dns.insert("use-hosts".into(), false.into());
    dns.insert("use-system-hosts".into(), false.into());
    dns.insert("default-nameserver".into(), yaml_strings(&bootstrap));
    dns.insert("proxy-server-nameserver".into(), yaml_strings(&bootstrap));
    dns.insert(
        "nameserver".into(),
        yaml_strings(&[format!("https://1.1.1.1/dns-query#{GROUP}")]),
    );

    let mut tun = Mapping::new();
    tun.insert("enable".into(), false.into());

    let mut profile_section = Mapping::new();
    profile_section.insert("store-selected".into(), false.into());

    let mut group = Mapping::new();
    group.insert("name".into(), Yaml::from(GROUP));
    group.insert("type".into(), Yaml::from("select"));
    group.insert(
        "proxies".into(),
        yaml_strings(std::slice::from_ref(&store.selected)),
    );

    let mut root = Mapping::new();
    root.insert("mixed-port".into(), Yaml::from(store.port));
    root.insert("bind-address".into(), Yaml::from("127.0.0.1"));
    root.insert("allow-lan".into(), Yaml::from(false));
    root.insert("skip-auth-prefixes".into(), Yaml::Sequence(Vec::new()));
    root.insert(
        "authentication".into(),
        yaml_strings(&[format!("cage:{}", store.auth)]),
    );
    root.insert("mode".into(), Yaml::from("rule"));
    root.insert("ipv6".into(), Yaml::from(false));
    root.insert("log-level".into(), Yaml::from("warning"));
    root.insert("find-process-mode".into(), Yaml::from("off"));
    root.insert(
        "external-controller-unix".into(),
        Yaml::from(crate::socket(profile)),
    );
    // F-042: the controller used to be credential-less — a same-uid
    // process could flip the running egress (mode=direct, a MATCH,DIRECT
    // reload) with one unauthenticated request and no on-disk trace,
    // hijacking the exit-evidence oracle. The controller now requires
    // the store's auth as its bearer secret (same trust domain as the
    // mixed-port credential, held by exactly the same holders).
    root.insert("secret".into(), Yaml::from(store.auth.clone()));
    root.insert("tun".into(), Yaml::Mapping(tun));
    root.insert("dns".into(), Yaml::Mapping(dns));
    root.insert("geo-auto-update".into(), Yaml::from(false));
    root.insert("profile".into(), Yaml::Mapping(profile_section));
    root.insert("proxies".into(), Yaml::Sequence(proxies));
    root.insert(
        "proxy-groups".into(),
        Yaml::Sequence(vec![Yaml::Mapping(group)]),
    );
    root.insert("rules".into(), yaml_strings(&[format!("MATCH,{GROUP}")]));
    // Measure a request on the established connection rather than folding
    // protocol and TLS setup into the node's displayed HTTP latency.
    root.insert("unified-delay".into(), Yaml::from(true));

    let text = serde_yaml::to_string(&Yaml::Mapping(root)).map_err(|e| e.to_string())?;
    Ok(text.into_bytes())
}

fn yaml_strings(items: &[String]) -> Yaml {
    Yaml::Sequence(items.iter().map(|s| Yaml::String(s.clone())).collect())
}

/// Points only the core's host transport at the physical uplink. MATCH
/// routing and proxy credentials remain intact; this does not create a guest
/// direct route.
pub fn bind_interface(data: &[u8], name: &str) -> Result<Vec<u8>, String> {
    if name.is_empty() {
        return Err("缺少物理网卡，不能启动代理".to_owned());
    }
    let mut config: Yaml =
        serde_yaml::from_slice(data).map_err(|_| "代理运行配置无效".to_owned())?;
    let Yaml::Mapping(ref mut root) = config else {
        return Err("代理运行配置无效".to_owned());
    };
    root.insert("interface-name".into(), Yaml::from(name));
    // Older imports may carry a node-level binding, which overrides the global.
    if let Some(Yaml::Sequence(nodes)) = root.get_mut("proxies") {
        for node in nodes.iter_mut() {
            if let Yaml::Mapping(node) = node {
                if node.contains_key("interface-name") {
                    node.insert("interface-name".into(), Yaml::from(name));
                }
            }
        }
    }
    let text = serde_yaml::to_string(&config).map_err(|e| e.to_string())?;
    Ok(text.into_bytes())
}

/// The interface the running config binds to, if any.
pub fn bound_interface(path: &str) -> Result<String, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let config: Yaml = serde_yaml::from_slice(&data).map_err(|_| "代理运行配置无效".to_owned())?;
    Ok(config
        .get("interface-name")
        .and_then(Yaml::as_str)
        .unwrap_or_default()
        .to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{token, Node, Source, Store};

    fn store() -> Store {
        let mut config = serde_json::Map::new();
        config.insert("name".to_owned(), Value::String("id-exit".to_owned()));
        config.insert("type".to_owned(), Value::String("ss".to_owned()));
        config.insert("server".to_owned(), Value::String("1.2.3.4".to_owned()));
        config.insert("port".to_owned(), Value::Number(8388.into()));
        // As import leaves every node: udp pinned off.
        config.insert("udp".to_owned(), Value::Bool(false));
        Store {
            version: 1,
            port: 17896,
            auth: token(),
            revision: "rev".to_owned(),
            selected: "id-exit".to_owned(),
            sources: vec![Source {
                id: "src".to_owned(),
                name: "s".to_owned(),
                url: String::new(),
                interval_hours: 0,
                updated_at: String::new(),
                attempted_at: String::new(),
                error: String::new(),
                usage: String::new(),
                nodes: vec![Node {
                    id: "id-exit".to_owned(),
                    name: "exit".to_owned(),
                    node_type: "ss".to_owned(),
                    config,
                }],
                skipped: Vec::new(),
            }],
            ..Default::default()
        }
    }

    fn parse(bytes: &[u8]) -> Yaml {
        serde_yaml::from_slice(bytes).unwrap()
    }

    #[test]
    fn generated_config_has_cage_boundaries() {
        let s = store();
        let yaml = generate(&s, "/tmp/prof").unwrap();
        let v = parse(&yaml);
        assert_eq!(v["mixed-port"].as_i64(), Some(17896));
        assert_eq!(v["bind-address"], "127.0.0.1");
        assert_eq!(v["allow-lan"], Yaml::Bool(false));
        assert_eq!(v["tun"]["enable"], Yaml::Bool(false));
        assert_eq!(v["unified-delay"], Yaml::Bool(true));
        assert_eq!(v["ipv6"], Yaml::Bool(false));
        assert_eq!(v["find-process-mode"], "off");
        // Auth is store-backed; anonymous access is impossible.
        let auth = v["authentication"].as_sequence().unwrap();
        assert!(auth[0].as_str().unwrap().starts_with("cage:"));
        assert!(v["skip-auth-prefixes"].as_sequence().unwrap().is_empty());
        // MATCH routes to the group holding exactly the selected exit.
        assert_eq!(
            v["rules"].as_sequence().unwrap()[0],
            Yaml::String(format!("MATCH,{GROUP}"))
        );
        let groups = v["proxy-groups"].as_sequence().unwrap();
        assert_eq!(groups[0]["name"], GROUP);
        assert_eq!(groups[0]["proxies"][0], "id-exit");
        // Node names are the store IDs; udp is pinned off.
        let proxies = v["proxies"].as_sequence().unwrap();
        assert_eq!(proxies[0]["name"], "id-exit");
        assert_eq!(proxies[0]["udp"], Yaml::Bool(false));
        // The control socket is namespaced by profile hash, and the
        // controller demands the store's auth as its secret (F-042).
        assert!(v["external-controller-unix"]
            .as_str()
            .unwrap()
            .starts_with("/tmp/cage-proxy-"));
        assert_eq!(v["secret"], Yaml::String(s.auth.clone()));
    }

    #[test]
    fn explicit_chain_overrides_dialers() {
        let mut s = store();
        s.chain = vec!["id-entry".to_owned(), "id-exit".to_owned()];
        s.sources[0].nodes.push(Node {
            id: "id-entry".to_owned(),
            name: "entry".to_owned(),
            node_type: "ss".to_owned(),
            config: {
                let mut m = serde_json::Map::new();
                m.insert("name".to_owned(), Value::String("id-entry".to_owned()));
                m.insert("type".to_owned(), Value::String("ss".to_owned()));
                m.insert("server".to_owned(), Value::String("5.6.7.8".to_owned()));
                // A stale node-level dialer must not survive the explicit chain.
                m.insert(
                    "dialer-proxy".to_owned(),
                    Value::String("somewhere-else".to_owned()),
                );
                m
            },
        });
        let yaml = generate(&s, "/tmp/prof").unwrap();
        let v = parse(&yaml);
        let proxies = v["proxies"].as_sequence().unwrap();
        let entry = proxies.iter().find(|p| p["name"] == "id-entry").unwrap();
        assert!(entry.get("dialer-proxy").is_none());
        let exit = proxies.iter().find(|p| p["name"] == "id-exit").unwrap();
        assert_eq!(exit["dialer-proxy"], "id-entry");
    }

    #[test]
    fn no_route_no_config() {
        let mut s = store();
        s.selected = "missing".to_owned();
        assert!(generate(&s, "/tmp/prof").is_err());
    }

    #[test]
    fn bind_interface_replaces_only_global_binding() {
        let s = store();
        let raw = generate(&s, "/tmp/prof").unwrap();
        let bound = bind_interface(&raw, "en0").unwrap();
        let v = parse(&bound);
        assert_eq!(v["interface-name"], "en0");
        // Node-level bindings are left alone when absent; overridden when present.
        assert!(v["proxies"].as_sequence().unwrap()[0]
            .get("interface-name")
            .is_none());
        assert!(bind_interface(&raw, "")
            .unwrap_err()
            .contains("缺少物理网卡"));
    }

    #[test]
    fn bound_interface_reads_back() {
        let s = store();
        let raw = generate(&s, "/tmp/prof").unwrap();
        let bound = bind_interface(&raw, "en5").unwrap();
        let tmp = std::env::temp_dir().join("cage-bind-test.yaml");
        std::fs::write(&tmp, &bound).unwrap();
        assert_eq!(bound_interface(tmp.to_str().unwrap()).unwrap(), "en5");
        std::fs::remove_file(&tmp).unwrap();
    }
}
