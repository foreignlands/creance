//! The managed proxy: Cage's private proxy sources, the applied node, and the
//! SOCKS5 endpoint the whole guest traffic is pinned to.
//!
//! The store lives at `<profile>/proxy/sources.json`. It is the single source
//! of truth for the endpoint: config.json must name the same endpoint and
//! revision or the gate stays closed.

use creance_vm::{iso8601_now, token};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// The select-group name every runtime config routes MATCH to.
pub const GROUP: &str = "CAGE";
/// 8 MiB cap per subscription import.
pub const MAX_IMPORT: usize = 8 << 20;
const MAX_STORE_SIZE: usize = 32 << 20;

/// Infrastructure DNS used only to bootstrap the core's own server domains.
/// Guest DNS stays behind the cage egress; there is no host resolver fallback.
pub fn bootstrap_dns_urls() -> Vec<String> {
    vec![
        "https://1.1.1.1/dns-query".to_owned(),
        "https://223.5.5.5/dns-query".to_owned(),
    ]
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub node_type: String,
    pub config: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NodeIssue {
    pub index: usize,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub r#type: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Source {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    pub interval_hours: u32,
    pub updated_at: String,
    pub attempted_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub usage: String,
    pub nodes: Vec<Node>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<NodeIssue>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Store {
    pub version: u32,
    pub port: u16,
    pub auth: String,
    #[serde(default)]
    pub revision: String,
    #[serde(default)]
    pub selected: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<String>,
    #[serde(default)]
    pub sources: Vec<Source>,
}

/// The proxy's private directory inside a profile.
pub fn dir(profile: &str) -> String {
    creance_vm::paths::join(profile, "proxy")
}

/// The core's control socket, hash-spaced so profiles never collide.
pub fn socket(profile: &str) -> String {
    let h = Sha256::digest(creance_vm::paths::clean(profile).as_bytes());
    let name = format!("cage-proxy-{}-{}", users_uid(), hex::encode(&h[..4]));
    if cfg!(windows) {
        std::env::temp_dir()
            .join(name)
            .join("control.sock")
            .to_string_lossy()
            .into_owned()
    } else {
        format!("/tmp/{name}/control.sock")
    }
}

#[allow(unsafe_code)] // libc::getuid is a trivially safe FFI read
fn users_uid() -> u32 {
    #[cfg(unix)]
    {
        unsafe { libc::getuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Loads the store, yielding a fresh one when absent. A malformed store
/// fails loudly: proxy credentials must never be silently reset.
pub fn load(profile: &str) -> Result<Store, String> {
    let path = Path::new(&dir(profile)).join("sources.json");
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(Store {
            version: 1,
            port: 17896,
            auth: token(),
            sources: Vec::new(),
            ..Default::default()
        });
    };
    if bytes.len() > MAX_STORE_SIZE {
        return Err("Cage 代理配置无效，请恢复私有配置备份".to_owned());
    }
    let s: Store = serde_json::from_slice(&bytes)
        .map_err(|_| "Cage 代理配置无效，请恢复私有配置备份".to_owned())?;
    if s.version != 1 || !(1024..=65535).contains(&s.port) || s.auth.len() != 48 {
        return Err("Cage 代理配置无效，请恢复私有配置备份".to_owned());
    }
    Ok(s)
}

/// Serializes with a two-space indent, the same shape users may inspect.
pub fn save(profile: &str, store: &Store) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(store).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    if bytes.len() > MAX_STORE_SIZE {
        return Err("代理来源配置总大小超过 32 MiB，请减少来源或节点；原配置已保留".to_owned());
    }
    write_private(
        Path::new(&dir(profile))
            .join("sources.json")
            .to_str()
            .unwrap_or_default(),
        &bytes,
    )
}

/// Atomically publishes a private file: temp file, fsync, rename.
pub fn write_private(path: &str, data: &[u8]) -> Result<(), String> {
    let parent = creance_vm::paths::join(path.rsplit_once('/').map(|(d, _)| d).unwrap_or("."), "");
    creance_vm::private::ensure_private_dir(&parent).map_err(|e| e.to_string())?;
    let (mut file, tmp) =
        creance_vm::private::create_private_temp(&parent, "proxy").map_err(|e| e.to_string())?;
    use std::io::Write;
    if let Err(e) = file.write_all(data).and_then(|_| file.sync_all()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.to_string());
    }
    drop(file);
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e.to_string()
    })
}

impl Store {
    /// The SOCKS5 endpoint guests are pinned to: loopback only, user `cage`,
    /// a 48-hex password from the store.
    pub fn endpoint(&self) -> String {
        format!("socks5://cage:{}@127.0.0.1:{}", self.auth, self.port)
    }

    pub fn find(&self, id: &str) -> Option<&Node> {
        self.sources
            .iter()
            .flat_map(|s| s.nodes.iter())
            .find(|n| n.id == id)
    }

    pub fn count(&self) -> usize {
        self.sources.iter().map(|s| s.nodes.len()).sum()
    }

    /// The actual hops from entry to exit. An explicit chain overrides
    /// node-level dialers without touching subscription credentials.
    pub fn route(&self) -> Result<Vec<String>, String> {
        if self.find(&self.selected).is_none() {
            return Err("请先选择有效的最终出口".to_owned());
        }
        if !self.chain.is_empty() {
            if self.chain.last().map(String::as_str) != Some(self.selected.as_str()) {
                return Err("代理链与最终出口不一致，请重新配置代理".to_owned());
            }
            let mut seen = std::collections::HashSet::new();
            for id in &self.chain {
                if self.find(id).is_none() {
                    return Err("代理链中的节点已被移除，请重新选择；原配置已保留".to_owned());
                }
                if !seen.insert(id.clone()) {
                    return Err("代理链不能重复使用同一个节点".to_owned());
                }
            }
            return Ok(self.chain.clone());
        }
        let mut reversed = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut id = self.selected.clone();
        while !id.is_empty() {
            let Some(node) = self.find(&id) else {
                return Err("导入的代理链存在循环或缺失节点，请检查来源配置".to_owned());
            };
            if !seen.insert(id.clone()) {
                return Err("导入的代理链存在循环或缺失节点，请检查来源配置".to_owned());
            }
            reversed.push(id.clone());
            id = node
                .config
                .get("dialer-proxy")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
        }
        reversed.reverse();
        Ok(reversed)
    }

    /// Imports or refreshes one source. A refresh must retain every hop of
    /// the saved route; losing the current exit or a transit hop aborts the
    /// import and keeps the old configuration.
    pub fn import(
        &mut self,
        name: &str,
        raw_url: &str,
        data: &[u8],
        id: &str,
        interval_hours: u32,
        usage: &str,
    ) -> Result<(), String> {
        let name = name.trim();
        if name.is_empty() || name.len() > 100 {
            return Err("请填写 1–100 字节的来源名称".to_owned());
        }
        let id = if id.is_empty() {
            token()[..16].to_owned()
        } else {
            id.to_owned()
        };
        let (nodes, skipped) = crate::import::parse_nodes(data, &id)?;
        let now = iso8601_now();
        let source = Source {
            id: id.clone(),
            name: name.to_owned(),
            url: raw_url.to_owned(),
            interval_hours,
            updated_at: now.clone(),
            attempted_at: now,
            error: String::new(),
            usage: usage.to_owned(),
            nodes,
            skipped,
        };
        let Some(i) = self.sources.iter().position(|s| s.id == id) else {
            self.sources.push(source);
            return Ok(());
        };
        // Refresh: the whole current route must survive.
        let route = if self.selected.is_empty() {
            Vec::new()
        } else {
            self.route()?
        };
        let available: std::collections::HashSet<&str> =
            source.nodes.iter().map(|n| n.id.as_str()).collect();
        for old in &self.sources[i].nodes {
            if route.contains(&old.id) && !available.contains(old.id.as_str()) {
                let reason = source
                    .skipped
                    .iter()
                    .find(|issue| issue.name == old.name)
                    .map(|issue| issue.reason.clone())
                    .unwrap_or_else(|| "节点未包含在更新中".to_owned());
                return Err(format!(
                    "订阅更新移除或跳过了当前出口或中转节点 {:?}：{}；原配置已保留，请先应用其他节点再更新",
                    old.name, reason
                ));
            }
        }
        self.sources[i] = source;
        Ok(())
    }

    /// The generated mihomo configuration (see [runtime]).
    pub fn runtime_yaml(&self, profile: &str) -> Result<Vec<u8>, String> {
        crate::runtime::generate(self, profile)
    }
}

/// An exclusive flock on the profile's store lock file. Hold it across a
/// whole load → modify → save sequence so concurrent importers, refreshes,
/// and selections cannot overwrite each other's sources (FINDING-014).
pub struct StoreLock {
    fd: std::os::unix::io::RawFd,
}

#[allow(unsafe_code)] // libc::flock/close on our own private lock file
impl Drop for StoreLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.fd, libc::LOCK_UN);
            libc::close(self.fd);
        }
    }
}

/// Takes the profile's store lock (an exclusive flock on `proxy/.lock`).
#[allow(unsafe_code)] // libc::flock/close on our own private lock file
fn store_lock(profile: &str) -> Result<StoreLock, String> {
    let d = dir(profile);
    creance_vm::private::ensure_private_dir(&d).map_err(|e| e.to_string())?;
    let path = Path::new(&d).join(".lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("cannot open store lock: {e}"))?;
    let fd = std::os::unix::io::IntoRawFd::into_raw_fd(file);
    unsafe {
        if libc::flock(fd, libc::LOCK_EX) != 0 {
            let err = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(format!("cannot lock store: {err}"));
        }
    }
    Ok(StoreLock { fd })
}

/// Runs `f` while holding the profile's store lock, serializing every
/// load → modify → save sequence against the same profile (FINDING-014).
/// Callers must not nest this: `select_and_apply` and `start_managed` lock
/// internally, so wrap only their own unlocked steps.
pub fn with_store_lock<T>(
    profile: &str,
    f: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let _guard = store_lock(profile)?;
    f()
}

/// The single source of truth for the private endpoint used by cage: the
/// store must agree with config.json down to the revision.
pub fn applied(profile: &str, endpoint: &str, revision: &str) -> Result<Store, String> {
    let store = load(profile)?;
    if store.find(&store.selected).is_none() {
        return Err("尚未选择代理节点，请在网络与代理中添加来源并选择节点".to_owned());
    }
    if revision.is_empty()
        || store.revision.is_empty()
        || revision != store.revision
        || endpoint != store.endpoint()
    {
        return Err("代理节点尚未应用或配置不一致，请重新应用节点；外网保持关闭".to_owned());
    }
    store.route()?;
    Ok(store)
}

/// Applies `node_id` as the selected exit end-to-end: store selection,
/// revision rotation, and the config.json fields that [`applied`] later
/// verifies.
/// Applies the named (or hashed) node as the selected exit end-to-end: store
/// selection, revision rotation, and the config.json fields that [`applied`]
/// later verifies.
pub fn select_and_apply(profile: &str, config_path: &str, node: &str) -> Result<Store, String> {
    let _guard = store_lock(profile)?;
    let mut store = load(profile)?;
    let resolved = store
        .sources
        .iter()
        .flat_map(|s| s.nodes.iter())
        .find(|n| n.id == node || n.name == node)
        .map(|n| n.id.clone())
        .ok_or_else(|| format!("节点 {node} 不存在于任何来源"))?;
    store.selected = resolved;
    store.revision = token();
    // Load the config before touching the store: an unreadable config must
    // never leave a half-applied selection behind (FINDING-014).
    let mut config = creance_vm::config::load(config_path)?;
    let previous = std::fs::read(Path::new(&dir(profile)).join("sources.json")).ok();
    save(profile, &store)?;
    config.proxy_url = store.endpoint();
    config.proxy_revision = store.revision.clone();
    if let Err(e) = creance_vm::config::write_private_config(config_path, &config) {
        // Roll the store back so applied() never sees a mismatched pair.
        let path = Path::new(&dir(profile))
            .join("sources.json")
            .to_str()
            .unwrap_or_default()
            .to_owned();
        match &previous {
            Some(bytes) => {
                let _ = write_private(&path, bytes);
            }
            None => {
                let _ = std::fs::remove_file(&path);
            }
        }
        return Err(format!("代理配置写入失败，选择已回滚：{e}"));
    }
    Ok(store)
}

/// Starts the managed core for the profile's applied node. An already
/// running, matching core is a no-op (no rotation, no gate disturbance) —
/// the revision rotates only when a real restart is about to happen, so a
/// stale record can never re-open a gate.
pub fn start_managed(profile: &str, config_path: &str) -> Result<(), String> {
    let _guard = store_lock(profile)?;
    let config = creance_vm::config::load(config_path)?;
    let store = applied(profile, &config.proxy_url, &config.proxy_revision)?;
    // Fast path (Go proxyCommand): same physical binding and a running,
    // matching core means nothing to do.
    let config_yaml = creance_vm::paths::join(&dir(profile), "config.yaml");
    let bound = crate::runtime::bound_interface(&config_yaml).unwrap_or_default();
    let physical = crate::service::physical_interface().unwrap_or_default();
    if !physical.is_empty() && bound == physical && crate::service::running(profile, &store) {
        return Ok(());
    }
    let mut store = store;
    store.revision = token();
    save(profile, &store)?;
    let mut config = config;
    config.proxy_revision = store.revision.clone();
    creance_vm::config::write_private_config(config_path, &config)?;
    crate::service::start(profile, &store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use creance_vm::civil_from_days;
    use serde_json::json;

    fn node(id: &str, name: &str, dialer: &str) -> Node {
        let mut config = serde_json::Map::new();
        config.insert("server".to_owned(), json!("1.2.3.4"));
        if !dialer.is_empty() {
            config.insert("dialer-proxy".to_owned(), json!(dialer));
        }
        Node {
            id: id.to_owned(),
            name: name.to_owned(),
            node_type: "ss".to_owned(),
            config,
        }
    }

    fn store_with(nodes: Vec<Node>, selected: &str, chain: Vec<String>) -> Store {
        Store {
            version: 1,
            port: 17896,
            auth: token(),
            revision: "rev-1".to_owned(),
            selected: selected.to_owned(),
            chain,
            sources: vec![Source {
                id: "src".to_owned(),
                name: "Test Source".to_owned(),
                url: String::new(),
                interval_hours: 0,
                updated_at: String::new(),
                attempted_at: String::new(),
                error: String::new(),
                usage: String::new(),
                nodes,
                skipped: Vec::new(),
            }],
        }
    }

    #[test]
    fn route_walks_dialer_proxy_backwards() {
        // dialer-proxy points back toward the entry: exit dials through
        // transit, transit through entry. Walking from the exit and
        // reversing yields entry -> transit -> exit.
        let s = store_with(
            vec![
                node("exit", "exit", "transit"),
                node("transit", "transit", "entry"),
                node("entry", "entry", ""),
            ],
            "exit",
            Vec::new(),
        );
        assert_eq!(s.route().unwrap(), vec!["entry", "transit", "exit"]);
    }

    #[test]
    fn route_rejects_cycles_and_missing() {
        let s = store_with(
            vec![node("a", "a", "b"), node("b", "b", "a")],
            "a",
            Vec::new(),
        );
        assert!(s.route().is_err());
        let s2 = store_with(vec![node("a", "a", "ghost")], "a", Vec::new());
        assert!(s2.route().is_err());
        let s3 = store_with(Vec::new(), "a", Vec::new());
        assert!(s3.route().is_err());
    }

    #[test]
    fn route_explicit_chain_overrides() {
        let s = store_with(
            vec![
                node("exit", "exit", ""),
                node("mid", "mid", "exit"),
                node("alt", "alt", ""),
            ],
            "exit",
            vec!["alt".to_owned(), "mid".to_owned(), "exit".to_owned()],
        );
        assert_eq!(s.route().unwrap(), vec!["alt", "mid", "exit"]);
        // A chain whose last hop is not the selected exit is inconsistent.
        let mut broken = s.clone();
        broken.chain = vec!["alt".to_owned()];
        assert!(broken.route().is_err());
        // Duplicate hop.
        let mut dup = s.clone();
        dup.chain = vec!["alt".to_owned(), "alt".to_owned(), "exit".to_owned()];
        assert!(dup.route().is_err());
    }

    #[test]
    fn import_refresh_may_not_drop_the_current_route() {
        let mut s = Store {
            version: 1,
            port: 17896,
            auth: token(),
            ..Default::default()
        };
        let chain = "proxies:\n  - name: exit\n    type: ss\n    server: 1.2.3.4\n    port: 1\n    cipher: aes-128-gcm\n    password: x\n    dialer-proxy: transit\n  - name: transit\n    type: ss\n    server: 5.6.7.8\n    port: 1\n    cipher: aes-128-gcm\n    password: x\n";
        s.import("src", "", chain.as_bytes(), "", 0, "").unwrap();
        // Select the exit node (first in the chain, dials through transit).
        s.selected = s.sources[0].nodes[0].id.clone();
        let route = s.route().unwrap();
        assert_eq!(route.len(), 2, "{route:?}");
        let (source_id, source_name) = (s.sources[0].id.clone(), s.sources[0].name.clone());

        // A refresh whose payload loses the transit hop must be refused and
        // must leave the old source untouched.
        let losing = "proxies:\n  - name: exit\n    type: ss\n    server: 1.2.3.4\n    port: 1\n    cipher: aes-128-gcm\n    password: x\n";
        let err = s
            .import(&source_name, "", losing.as_bytes(), &source_id, 0, "")
            .expect_err("route hop dropped");
        assert!(err.contains("中转节点"), "{err}");
        assert_eq!(s.route().unwrap(), route, "route intact");

        // A refresh keeping every route hop succeeds.
        s.import(&source_name, "", chain.as_bytes(), &source_id, 0, "")
            .expect("route preserved");
        assert_eq!(s.sources[0].nodes.len(), 2);
        assert_eq!(s.route().unwrap(), route);
    }

    #[test]
    fn endpoint_is_loopback_only() {
        let s = store_with(Vec::new(), "", Vec::new());
        let e = s.endpoint();
        assert!(e.starts_with("socks5://cage:"));
        assert!(e.ends_with("@127.0.0.1:17896"));
        assert_eq!(s.auth.len(), 48);
    }

    #[test]
    fn applied_demands_consistency() {
        let tmp = std::env::temp_dir().join(format!("cage-applied-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let profile = tmp.to_string_lossy().into_owned();
        let mut s = store_with(vec![node("exit", "exit", "")], "exit", Vec::new());
        save(&profile, &s).unwrap();
        // No revision in config yet.
        assert!(applied(&profile, &s.endpoint(), "").is_err());
        s.revision = token();
        save(&profile, &s).unwrap();
        assert!(applied(&profile, &s.endpoint(), &s.revision).is_ok());
        // Endpoint mismatch closes the gate.
        assert!(applied(&profile, "socks5://cage:wrong@127.0.0.1:1", &s.revision).is_err());
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn civil_dates_are_sane() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        let now = iso8601_now();
        assert!(now.ends_with('Z') && now.len() == 20, "{now}");
    }

    fn sub_yaml(name: &str, server: &str) -> String {
        format!(
            "proxies:\n  - name: {name}\n    type: ss\n    server: {server}\n    port: 1\n    cipher: aes-128-gcm\n    password: x\n"
        )
    }

    /// The CLI/workbench import entry is load → import → save. Two concurrent
    /// importers (FINDING-014) must not overwrite each other's source: the
    /// entry sequence runs under [`with_store_lock`], so both sources survive.
    #[test]
    fn concurrent_importers_do_not_lose_sources() {
        let tmp = std::env::temp_dir().join(format!("cage-c1-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let profile = tmp.to_string_lossy().into_owned();
        let yaml_a = sub_yaml("nodeA", "1.1.1.1");
        let yaml_b = sub_yaml("nodeB", "2.2.2.2");
        let run = |name: &str, yaml: &str, profile: &str| -> Result<(), String> {
            with_store_lock(profile, || {
                let mut s = load(profile)?;
                s.import(name, "", yaml.as_bytes(), "", 0, "")?;
                save(profile, &s)
            })
        };
        let p1 = profile.clone();
        let p2 = profile.clone();
        let h1 = std::thread::spawn(move || run("srcA", &yaml_a, &p1));
        let h2 = std::thread::spawn(move || run("srcB", &yaml_b, &p2));
        h1.join().unwrap().unwrap();
        h2.join().unwrap().unwrap();
        let s = load(&profile).unwrap();
        let names: Vec<&str> = s.sources.iter().map(|x| x.name.as_str()).collect();
        assert!(
            names.contains(&"srcA") && names.contains(&"srcB"),
            "both concurrent imports must survive: {names:?}"
        );
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    /// select_and_apply (FINDING-014, part 2): a config that cannot be loaded
    /// must leave the store untouched — no selected/revision written that
    /// applied() would then refuse.
    #[test]
    fn select_and_apply_leaves_store_untouched_when_config_is_unreadable() {
        let tmp = std::env::temp_dir().join(format!("cage-c1b-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let profile = tmp.to_string_lossy().into_owned();
        let mut s = store_with(vec![node("exit", "exit", "")], "exit", Vec::new());
        s.revision = "old-rev".to_owned();
        save(&profile, &s).unwrap();
        let config_path = creance_vm::paths::join(&profile, "missing.json");
        assert!(
            select_and_apply(&profile, &config_path, "exit").is_err(),
            "unreadable config must fail the select"
        );
        let after = load(&profile).unwrap();
        assert_eq!(after.selected, "exit", "selection unchanged");
        assert_eq!(after.revision, "old-rev", "revision unchanged");
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
