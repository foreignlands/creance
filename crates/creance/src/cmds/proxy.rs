use super::*;
use creance_gate::gate;

pub(crate) fn cmd_proxy_start() -> i32 {
    cmd_simple(|| {
        // F-036: tell the running gates FIRST — a changed exit closes the
        // gate while the OLD core is still serving, so there is never a
        // moment of "open gate + already-swapped exit". Restarting first
        // left exactly that window (and the sync error was swallowed).
        if let Ok(client) = gate::GateClient::open(&gate_instance_dir()) {
            let _ = client.sync_proxy_revision();
        }
        creance_proxy::start_managed(&profile(), &config::config_path())
    })
}

pub(crate) fn cmd_proxy_status() -> i32 {
    let path = config::config_path();
    let cfg = match config::load(&path) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let profile = profile();
    let store = match creance_proxy::load(&profile) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    println!("endpoint: {}", store.endpoint());
    println!("sources: {} ({} nodes)", store.sources.len(), store.count());
    match cfg
        .resolved_proxy_url()
        .and_then(|u| creance_proxy::applied(&profile, &u, &cfg.proxy_revision))
    {
        Ok(applied) => {
            let name = applied
                .find(&applied.selected)
                .map(|n| n.name.clone())
                .unwrap_or_default();
            println!("applied: {} ({name})", applied.selected);
            match applied.route() {
                Ok(route) => println!("route: {}", route.join(" -> ")),
                Err(e) => println!("route: unavailable ({e})"),
            }
            println!(
                "core running: {}",
                creance_proxy::service::running(&profile, &applied)
            );
            0
        }
        Err(e) => {
            println!("applied: none ({e})");
            2
        }
    }
}

pub(crate) fn cmd_proxy_import(
    name: String,
    file: Option<String>,
    url: Option<String>,
    interval: u32,
    select: Option<String>,
) -> i32 {
    if interval > 168 {
        return fail("更新间隔应为 0–168 小时，0 表示手动更新".to_owned());
    }
    let data = match (&file, &url) {
        (Some(file), _) => match std::fs::read(file) {
            Ok(d) => d,
            Err(e) => return fail(format!("cannot read {file}: {e}")),
        },
        (None, Some(url)) => {
            let cfg = match config::load(&config::config_path()) {
                Ok(c) => c,
                Err(e) => return fail(e),
            };
            match creance_proxy::fetch::fetch_subscription(&cfg, url) {
                Ok(d) => {
                    println!("fetched {} bytes from {url}", d.len());
                    d
                }
                Err(e) => return fail(e),
            }
        }
        (None, None) => return fail("pass --file or --url".to_owned()),
    };
    let profile = profile();
    let imported = creance_proxy::with_store_lock(&profile, || {
        let mut store = creance_proxy::load(&profile)?;
        store.import(
            &name,
            url.as_deref().unwrap_or(""),
            &data,
            "",
            interval,
            "cli",
        )?;
        let count = store.count();
        creance_proxy::save(&profile, &store)?;
        Ok(count)
    });
    let count = match imported {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    println!("imported {count} nodes from {name}");
    if let Some(node) = select {
        return cmd_proxy_select(node);
    }
    0
}

pub(crate) fn cmd_proxy_refresh() -> i32 {
    let path = config::config_path();
    let cfg = match config::load(&path) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let profile = profile();
    let store = match creance_proxy::load(&profile) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let mut refreshed = 0;
    for source in &store.sources {
        if source.url.is_empty() {
            continue;
        }
        match creance_proxy::fetch::fetch_subscription(&cfg, &source.url) {
            Ok(data) => {
                let outcome = creance_proxy::with_store_lock(&profile, || {
                    let mut store = creance_proxy::load(&profile)?;
                    store.import(
                        &source.name,
                        &source.url,
                        &data,
                        &source.id,
                        source.interval_hours,
                        "refresh",
                    )?;
                    creance_proxy::save(&profile, &store)
                });
                match outcome {
                    Ok(()) => refreshed += 1,
                    Err(e) => eprintln!("{}: {e}", source.name),
                }
            }
            Err(e) => eprintln!("{}: {e}", source.name),
        }
    }
    println!("refreshed {refreshed} source(s)");
    if refreshed > 0 {
        0
    } else {
        2
    }
}

/// The managed-core port of this profile (store); the default when no
/// store exists yet.
pub(crate) fn proxy_store_port(profile: &str) -> u16 {
    creance_proxy::load(profile)
        .map(|s| s.port)
        .unwrap_or(creance_proxy::DEFAULT_PORT)
}

pub(crate) fn cmd_proxy_select(node: String) -> i32 {
    cmd_simple(|| {
        let profile = profile();
        // F-043/F-047: revoking the OLD gate's evidence comes FIRST and
        // its failure is fatal to the switch (Go's applyProxy is
        // transactional: close fails → nothing lands). Selecting first
        // and swallowing the close error left an open gate behind a
        // config already declaring a different exit, reported as success.
        gate::close_gates(&profile)?;
        creance_proxy::select_and_apply(&profile, &config::config_path(), &node)?;
        println!("applied {node}; run `creance proxy-start` to launch the core");
        Ok(())
    })
}
