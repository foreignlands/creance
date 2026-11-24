//! creance — a contained workspace for AI agents.
//!
//! Every command operates on one profile: the directory holding config.json
//! (override with `CREANCE_CONFIG` or the legacy `CLAUDE_CAGE_CONFIG`).
//! Unsafe environment variables are stripped before anything runs.

use creance::{diagnose, escape, serve};

use clap::Parser;
use creance_gate::gate;
use creance_net::egress::Egress;
use creance_proxy::{self, service};
use creance_vm::{config, running};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

/// The default trace check target: a plain endpoint that reports the egress IP.
const CHECK_URL: &str = "https://1.1.1.1/cdn-cgi/trace";
const CHECK_BUDGET: Duration = Duration::from_secs(25);

fn main() {
    for name in [
        "AGENT_VM_UNSAFE_OPEN_NETWORK",
        "AGENT_VM_UNSAFE_WRITABLE_GIT",
        "AGENT_VM_UNSAFE_DISABLE_SECURITY_PROMPTS",
    ] {
        std::env::remove_var(name);
    }
    let cli = Cli::parse();
    std::process::exit(match cli.command {
        Commands::Init => cmd_init(),
        Commands::Check => cmd_check(),
        Commands::ProxyStart => cmd_proxy_start(),
        Commands::ProxyStop => cmd_simple(|| {
            let _ = gate::close_gates(&profile());
            creance_proxy::service::stop(&profile())
        }),
        Commands::ProxyStatus => cmd_proxy_status(),
        Commands::ProxyImport {
            name,
            file,
            url,
            interval,
            select,
        } => cmd_proxy_import(name, file, url, interval, select),
        Commands::ProxyRefresh => cmd_proxy_refresh(),
        Commands::ProxySelect { node } => cmd_proxy_select(node),
        Commands::Setup { memory, cpus } => cmd_setup(memory, cpus),
        Commands::List => creance_vm::vm::list(&profile()),
        Commands::Stop { keep_proxy } => cmd_stop(keep_proxy),
        Commands::Up => cmd_up(),
        Commands::Shell { command } => cmd_shell(command),
        Commands::Claude => cmd_shell(vec!["claude".to_owned()]),
        Commands::Oauth => cmd_oauth(),
        Commands::IdentityReset { memory, cpus } => cmd_identity_reset(memory, cpus),
        Commands::EscapeTest => cmd_escape_test(),
        Commands::GateOpen => cmd_gate(true),
        Commands::GateClose => cmd_gate(false),
        Commands::Doctor => {
            let report = diagnose::diagnose(&profile(), &config::config_path());
            print!("{}", diagnose::render(&report));
            if report.iter().any(|c| c.status == diagnose::Status::Fail) {
                1
            } else {
                0
            }
        }
        Commands::Serve { port } => match serve::serve(&profile(), &config::config_path(), port) {
            Ok(()) => 0,
            Err(e) => fail(e),
        },
        Commands::Version => {
            println!("creance {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Commands::GateDaemon {
            profile,
            instance,
            config_path,
            instance_dir,
            port,
        } => creance_gate::gate::run_daemon(&profile, &instance, &config_path, &instance_dir, port),
        Commands::LogRelay { kind } => {
            if kind != "proxy" {
                eprintln!("log-relay owns only the proxy core");
                2
            } else {
                service::log_relay_proxy(&profile())
            }
        }
    });
}

#[derive(clap::Parser)]
#[command(
    name = "creance",
    version,
    about = "creance — a contained workspace for AI agents",
    after_help = "Configuration: ~/.creance/config.json (override CREANCE_CONFIG; legacy ~/.claude-cage/CLAUDE_CAGE_CONFIG honored).\nEach configuration directory is an independent isolated profile.\nOnly explicitly opened project folders are shared. No host Claude credentials are imported."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Create a private profile configuration.
    Init,
    /// Verify the proxy transport through the configured upstream (no VM).
    Check,
    /// Start the managed proxy core with the applied node.
    ProxyStart,
    /// Stop the managed proxy core.
    ProxyStop,
    /// Show the applied node, route, endpoint and running state.
    ProxyStatus,
    /// Import nodes from a Clash/Mihomo YAML file or subscription URL.
    ProxyImport {
        #[arg(long)]
        name: String,
        #[arg(long)]
        file: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long, default_value_t = 0)]
        interval: u32,
        #[arg(long)]
        select: Option<String>,
    },
    /// Re-fetch every source that carries a URL.
    ProxyRefresh,
    /// Apply a node as the exit and record it in config.json.
    ProxySelect { node: String },
    /// Create the environment VM (Lima) for this profile.
    Setup {
        #[arg(long, default_value_t = 8)]
        memory: u32,
        #[arg(long, default_value_t = 4)]
        cpus: u32,
    },
    /// List this profile's VMs.
    List,
    /// Stop the environment VM and its proxy core.
    Stop {
        #[arg(long)]
        keep_proxy: bool,
    },
    /// Start the environment VM.
    Up,
    /// Open a shell (or run a command) in the environment VM.
    Shell {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Run Claude Code in the environment VM.
    Claude,
    /// On-demand OAuth/verify channel: noVNC over ssh forward, torn down on exit.
    Oauth,
    /// Rotate the guest identity fingerprint (hostname/username/session
    /// token/machine-id) by regenerating the guest profile and rebuilding
    /// the VM disk. The host workspace is untouched; the VM must be
    /// stopped first.
    IdentityReset {
        #[arg(long, default_value_t = 8)]
        memory: u32,
        #[arg(long, default_value_t = 4)]
        cpus: u32,
    },
    /// Run the containment probe suite (host checks + in-guest probes).
    EscapeTest,
    /// Open the environment gate (check window + grant). The wire follows.
    GateOpen,
    /// Close the environment gate: the guest loses its only route out.
    GateClose,
    /// Diagnose the environment VM.
    Doctor,
    /// Serve the lean workbench (loopback HTTP + single-page UI).
    Serve {
        #[arg(long, default_value_t = 5173)]
        port: u16,
    },
    /// Print this build's version.
    Version,
    /// Internal: own the proxy core's output as the supervised daemon. Not for direct use.
    #[command(hide = true)]
    LogRelay { kind: String },
    /// Internal: hold the environment gate until its record is removed.
    #[command(hide = true)]
    GateDaemon {
        profile: String,
        instance: String,
        config_path: String,
        instance_dir: String,
        port: u16,
    },
}

fn profile() -> String {
    let path = config::config_path();
    Path::new(&path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_owned())
}

fn instance() -> String {
    let profile = profile();
    creance_vm::vm::instance_name(&profile, &creance_vm::vm::environment_dir(&profile))
}

fn fail(err: String) -> i32 {
    eprintln!("{err}");
    1
}

fn cmd_simple<F: FnOnce() -> Result<(), String>>(f: F) -> i32 {
    match f() {
        Ok(()) => 0,
        Err(e) => fail(e),
    }
}

fn cmd_init() -> i32 {
    let path = config::config_path();
    let parent = Path::new(&path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_owned());
    if let Err(e) = creance_vm::private::ensure_private_dir(&parent) {
        return fail(e.to_string());
    }
    let bytes = match serde_json::to_vec_pretty(&config::default_config()) {
        Ok(b) => b,
        Err(e) => return fail(e.to_string()),
    };
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(mut f) => {
            use std::io::Write;
            if let Err(e) = f.write_all(&bytes) {
                return fail(e.to_string());
            }
            println!("Profile created: {path}");
            0
        }
        Err(e) => fail(e.to_string()),
    }
}

fn cmd_check() -> i32 {
    let path = config::config_path();
    let cfg = match config::load(&path) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let egress = match Egress::new(&cfg.proxy_url, &cfg.dns_url) {
        Ok(e) => e,
        Err(e) => return fail(e),
    };
    match creance_net::egress::request(
        &egress,
        "GET",
        CHECK_URL,
        None,
        &[],
        Instant::now() + CHECK_BUDGET,
    ) {
        Ok(r) if r.status == 200 => {
            println!("Proxy transport OK. Guest traffic still requires VM acceptance checks.");
            0
        }
        Ok(r) => fail(format!("proxy check returned HTTP {}", r.status)),
        Err(_) => fail("proxy transport check failed (no direct fallback)".to_owned()),
    }
}

fn cmd_gate(open: bool) -> i32 {
    let profile = profile();
    let instance = instance();
    let instance_dir =
        creance_vm::paths::join(&creance_vm::vm::instances_root(&profile), &instance);
    let outcome = if open {
        // 0.5: a grant needs live exit evidence. Observe the exit through
        // the configured proxy, evaluate it against the anchor (plus the
        // mandatory mainland deny list), and only a Passed verdict opens
        // the wire — anything else stays closed with the reason.
        let cfg = match config::load(&config::config_path()) {
            Ok(c) => c,
            Err(e) => return fail(e),
        };
        // F-042: the core's unix controller ignores the configured secret
        // (live-verified), so a flipped core (mode=direct, a MATCH,DIRECT
        // reload) would feed the evidence sample whatever the flipper
        // wants. Reconcile the running core against its generated config
        // first — a diverged core may not supply exit evidence.
        // F-050: a store that cannot be read is not a reason to skip the
        // reconciliation — corrupting sources.json used to blind both
        // checks at once. Gate-open is a safety-sensitive path: no store,
        // no evidence.
        match creance_proxy::load(&profile) {
            Ok(store) => {
                if let Err(e) = creance_proxy::service::check_running(&profile, &store) {
                    return fail(format!(
                        "核心运行态已偏离配置（{e}），拒绝采样出口证据，外网保持关闭"
                    ));
                }
            }
            Err(e) => return fail(format!("代理配置不可读，拒绝采样出口证据：{e}")),
        }
        let location = match creance::evidence::observe(&cfg) {
            Ok(l) => l,
            Err(e) => return fail(format!("出口观测失败，外网保持关闭：{e}")),
        };
        // F-046: reconcile AGAIN after the sample — a core flipped inside
        // the check→observe window cannot have supplied the evidence. The
        // residual window shrinks to the milliseconds between sample and
        // this check.
        match creance_proxy::load(&profile) {
            Ok(store) => {
                if let Err(e) = creance_proxy::service::check_running(&profile, &store) {
                    return fail(format!(
                        "核心运行态已偏离配置（{e}），拒绝采样出口证据，外网保持关闭"
                    ));
                }
            }
            Err(e) => return fail(format!("代理配置不可读，拒绝采样出口证据：{e}")),
        }
        let (state, message) = cfg.exit_policy.evaluate(&location.ip, Some(&location));
        if state != creance_vm::exit_policy::State::Passed {
            return fail(format!(
                "出口证据未通过，外网保持关闭：{message}（实测出口 {} {}）",
                location.ip, location.country_code
            ));
        }
        // 四元组一致性（0.7.0）：出口国别已实测——persona 的
        // 时区/语言/locale 落在该地区 plausible 集之外即"US IP + 东八区 +
        // 中文"式穿帮，fail-closed。未登记国别无判词（unknown 不定罪）。
        if let Some(Err(reason)) = creance_vm::exit_policy::fingerprint_verdict(
            &location.country_code,
            &cfg.timezone,
            &cfg.locale,
            &cfg.browser_language,
        ) {
            return fail(format!(
                "出口指纹四元组穿帮，外网保持关闭：{reason}（实测出口 {} {}）",
                location.ip, location.country_code
            ));
        }
        // 时区跟随（0.7.x）：实测出口落地后，把该国的规范时区写进 guest
        // ~/.creance-tz——OAuth 通道启动浏览器时优先采用。best-effort：
        // 写不进去不否定这次观测本身。
        if cfg.timezone == "auto" {
            if let Some(zone) = creance_vm::exit_policy::canonical_timezone(&location.country_code)
            {
                let _ = creance_vm::vm::guest_script(
                    &profile,
                    &instance,
                    &format!("printf '%s\\n' '{zone}' > \"${{HOME:-/tmp}}/.creance-tz"),
                );
            }
        }
        gate::open(&instance_dir, &creance::evidence::grant_checks(&location)).map(|s| {
            format!(
                "open (epoch {}，出口 {} {})",
                s.epoch, location.ip, location.country_code
            )
        })
    } else {
        gate::close_and_remove(&profile, &instance_dir, proxy_store_port(&profile))
            .map(|_| "closed".to_owned())
    };
    match outcome {
        Ok(msg) => {
            println!("gate: {msg}");
            0
        }
        Err(e) => fail(e),
    }
}

/// 指纹一键重置：轮换 guest 身份指纹（hostname/username/session_token，
/// 重建实例随之换 machine-id）。设计约束：必须先 `creance stop`——运行中
/// 的实例不能被 setup 的 rebuild 路径删除。客机配置文件不可读时拒绝盲删
/// （F-022 纪律：不可读的身份不重置）。
fn cmd_identity_reset(memory: u32, cpus: u32) -> i32 {
    let profile = profile();
    let instance = instance();
    if creance_vm::vm::instance_running(&profile, &instance) {
        return fail(format!(
            "实例 {instance} 仍在运行，先 `creance stop` 再重置指纹"
        ));
    }
    let guest_path = creance_vm::paths::join(&profile, creance_vm::guestprofile::FILENAME);
    if Path::new(&guest_path).exists() {
        if creance_vm::guestprofile::Profile::load_or_create(&profile).is_err() {
            return fail("客机配置不可读，拒绝重置身份；请修复权限或手动轮换".to_owned());
        }
        if let Err(e) = std::fs::remove_file(&guest_path) {
            return fail(format!("客机配置删除失败（{e}），重置中止"));
        }
    }
    cmd_setup(memory, cpus)
}

fn cmd_escape_test() -> i32 {
    let profile = profile();
    let config_path = config::config_path();
    // Host-side probes first: they need no VM.
    let probes = escape::host_probes(&profile, &config_path);
    let mut code = escape::report(&probes);
    // In-guest probes when the environment exists: stage the script and run
    // it through the VM shell. The flag file on the host is the oracle.
    let instance = instance();
    if std::path::Path::new(&creance_vm::vm::instance_marker(&profile, &instance)).exists() {
        let flag = format!("{}.escape-flag", creance_vm::vm::environment_dir(&profile));
        // The flag is the oracle: it must exist on the host for the guest
        // probe to have anything to look for. Without it fs-flag-readable
        // was a vacuous PASS (F-068).
        let store = creance_proxy::load(&profile).ok();
        let guest = creance_vm::guestprofile::Profile::load_or_create(&profile).ok();
        let script = escape::guest_script(
            &flag,
            &store.as_ref().map(|s| s.auth.clone()).unwrap_or_default(),
            store
                .as_ref()
                .map(|s| s.port)
                .unwrap_or(creance_proxy::DEFAULT_PORT),
            &guest.map(|g| g.username).unwrap_or_default(),
        );
        match creance_vm::vm::guest_script(&profile, &instance, &script) {
            Ok(stdout) => {
                // F-062: the transport is under guest control (Ubuntu's
                // patched bash sources ~/.bashrc for non-interactive ssh
                // sessions — rc files can swallow or forge output). A
                // missing probe line is therefore NOT a pass: every probe
                // the script defines must answer, with a known verdict.
                let expected: Vec<&str> = script
                    .lines()
                    .filter_map(|l| {
                        l.split_once("echo \"PROBE ")
                            .and_then(|(_, rest)| rest.split('"').next())
                            // The first token after "PROBE " is the id;
                            // the rest of the literal is the verdict.
                            .and_then(|id| id.split_whitespace().next())
                    })
                    // Only fully literal ids: the socket loop's
                    // `sock-$s` is a parameterized emit site, not a
                    // statically knowable probe name. (F-064 removed
                    // the probe() helper — every probe now emits
                    // literally and lands in this net.)
                    .filter(|id| !id.contains('$'))
                    .collect();
                let mut missing = Vec::new();
                for id in &expected {
                    let answered = stdout
                        .lines()
                        // The answer is the second whitespace token — a
                        // substring match would let `PROBE x` spoof `PROBE xy`.
                        .any(|l| l.split_whitespace().nth(1) == Some(*id));
                    if !answered {
                        missing.push(*id);
                    }
                }
                if !missing.is_empty() {
                    println!(
                        "PROBE transport ESCAPE — 探针行缺失（传输可能被 guest 致盲）：{missing:?}"
                    );
                    code = 1;
                }
                for line in stdout.lines() {
                    println!("{line}");
                    if line.contains(" ESCAPE") {
                        code = 1;
                    }
                }
            }
            Err(e) => eprintln!("cannot run in-guest probes: {e}"),
        }
        // The flag was placed (or attempted) inside guest_script itself;
        // removing it unconditionally is harmless when it never landed.
        let _ = std::fs::remove_file(&flag);
    }
    code
}

fn cmd_proxy_start() -> i32 {
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

fn gate_instance_dir() -> String {
    creance_vm::paths::join(&creance_vm::vm::instances_root(&profile()), &instance())
}

fn cmd_proxy_status() -> i32 {
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
    match creance_proxy::applied(&profile, &cfg.proxy_url, &cfg.proxy_revision) {
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

fn cmd_proxy_import(
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

fn cmd_proxy_refresh() -> i32 {
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
fn proxy_store_port(profile: &str) -> u16 {
    creance_proxy::load(profile)
        .map(|s| s.port)
        .unwrap_or(creance_proxy::DEFAULT_PORT)
}

fn cmd_setup(memory: u32, cpus: u32) -> i32 {
    let path = config::config_path();
    let cfg = match config::load(&path) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let profile = profile();
    let instance = instance();
    let guest = match creance_vm::guestprofile::Profile::load_or_create(&profile) {
        Ok(g) => g,
        Err(e) => return fail(e),
    };
    let options = creance_vm::vm::SetupOptions {
        memory_gib: memory,
        cpus,
        disk_gib: 24,
        workspace: creance_vm::vm::environment_dir(&profile),
        // "auto" follows the observed exit at gate-open time; the
        // provision-time guest env still needs a concrete IANA name, so
        // the neutral baseline stands in until the first observation.
        timezone: if cfg.timezone == "auto" {
            "Etc/UTC".to_owned()
        } else {
            cfg.timezone.clone()
        },
        locale: cfg.locale.clone(),
        browser_language: cfg.browser_language.clone(),
        guest,
    };
    // F-051: setup on an existing instance rebuilds it — the backend's
    // create refuses to touch a live directory, and every "re-run setup"
    // guidance (drift, promise changes) depends on this path existing.
    // The VM disk goes; the host workspace does not.
    if Path::new(&creance_vm::vm::instance_marker(&profile, &instance)).exists() {
        println!("rebuilding existing instance {instance} (VM disk replaced; workspace untouched)");
        let code = creance_vm::vm::delete(&profile, &instance);
        if code != 0 {
            return fail(format!(
                "cannot remove the existing instance {instance}; run `creance stop` first"
            ));
        }
    }
    let code = match creance_vm::vm::setup_instance(&profile, &instance, &options) {
        Ok(code) => code,
        Err(e) => return fail(e),
    };
    if code == 0 {
        // F-033: the fingerprint the VM was promised at creation. The
        // escape probe compares the live config against this snapshot —
        // drift after a config change means the VM and profile disagree
        // (re-run setup after `creance stop` to re-pin).
        let stamp =
            creance_vm::paths::join(&creance_vm::vm::state_dir(&profile), "fingerprint.txt");
        // F-049: a silently missing stamp permanently disarms the drift
        // check — failing to write it fails the setup.
        if let Err(e) = std::fs::write(&stamp, cfg.guest_fingerprint()) {
            return fail(format!("cannot write fingerprint stamp: {e}"));
        }
        println!("instance {instance} created; run `creance up` to start it");
    }
    code
}

fn cmd_proxy_select(node: String) -> i32 {
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

fn cmd_stop(keep_proxy: bool) -> i32 {
    let profile = profile();
    let code = creance_vm::vm::stop_vm(&profile, &instance());
    // F-019: the gate retires by its record going away — close over the
    // socket if a daemon still serves, remove the record either way, and
    // cut the tunnel now (close_and_remove does all three).
    let _ = gate::close_and_remove(&profile, &gate_instance_dir(), proxy_store_port(&profile));
    if code == 0 && !keep_proxy {
        let _ = gate::close_gates(&profile);
        return cmd_simple(|| creance_proxy::service::stop(&profile));
    }
    code
}

fn cmd_up() -> i32 {
    let path = config::config_path();
    let cfg = match config::load(&path) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let profile = profile();
    if let Err(e) = running::check_running(&creance_vm::vm::instances_root(&profile), &cfg) {
        return fail(e);
    }
    // F-044/F-052: the stamp records what the guest was provisioned with,
    // and a bare backend start never re-provisions. Any stamp read
    // failure (missing, unreadable, a directory) refuses `up` — a missing
    // stamp used to skip the check, and starting a nonexistent instance
    // must never end in an unprovisioned VM behind a green exit code.
    let stamp = creance_vm::paths::join(&creance_vm::vm::state_dir(&profile), "fingerprint.txt");
    match std::fs::read_to_string(&stamp) {
        Ok(pinned) if pinned.trim() == cfg.guest_fingerprint() => {}
        Ok(_) => {
            return fail(
                "guest 环境（时区/语言）自创建以来已变更，且启动不会重新供给；请先 creance stop 再 creance setup 重建环境"
                    .to_owned(),
            )
        }
        Err(_) => {
            return fail(
                "fingerprint 戳缺失或不可读（应由 creance setup 写入）；拒绝启动，请先 creance stop 再 creance setup 重建环境"
                    .to_owned(),
            )
        }
    }
    let instance = instance();
    // F-052's template trap: only an instance this profile set up may be
    // started — a bare start of an unknown name must refuse, not invent.
    if !Path::new(&creance_vm::vm::instance_marker(&profile, &instance)).exists() {
        return fail(format!(
            "实例 {instance} 不存在（未 setup 或已被删除）；拒绝启动，请先 creance setup"
        ));
    }
    let code = creance_vm::vm::up(&profile, &instance);
    if code == 0 {
        // 0.4: the gate owns the wire now — Closed gate = tunnel down. Raising
        // the daemon raises the tunnel with it; only on daemon failure do we
        // fall back to the unconditional tunnel so the VM stays usable.
        let port = creance_proxy::load(&profile)
            .map(|s| s.port)
            .unwrap_or(creance_proxy::DEFAULT_PORT);
        let instance_dir =
            creance_vm::paths::join(&creance_vm::vm::instances_root(&profile), &instance);
        if let Err(e) = gate::spawn_daemon(&profile, &instance, &path, &instance_dir, port) {
            eprintln!("warning: gate daemon not raised: {e}");
            if let Err(e) = creance_vm::tunnel::ensure(&profile, &instance, port) {
                eprintln!("warning: guest tunnel not established: {e}");
            }
        }
        let _ = running::record_running(&instance_dir, &cfg);
        // F-059's universal guard: whatever the backend did on THIS boot,
        // the guest must not reach the internet directly. Behavior, not
        // artifacts — a missing boot replay (or a backend that stopped
        // replaying) fails `up` loudly instead of shipping an open VM.
        // TCP is the hard gate; ICMP is checked when ping exists (F-060
        // scoped it to the NAT subnets, so external echoes must die).
        //
        // F-062: positive evidence only. The transport (guest login shell
        // sourcing ~/.bashrc on Ubuntu's patched bash) is under guest
        // control — empty or mangled output used to fall through `Ok(_)`
        // as a green light. The PATH reset at the top defeats PATH
        // shadowing of the probe's commands; absolute paths for the rest.
        // (Not defeatable from here: stdout redirection in rc files and
        // interpreter shadowing — the README's honest-boundaries section
        // says so; the host-side gate evidence is the security control.)
        // F-082: the probe runs as the unprivileged guest user — the
        // fw-armed evidence is a root-owned stamp under /run (written
        // by the egress-lock unit from the LIVE ruleset), not an
        // iptables read the guest user cannot perform.
        // F-099/F-100: the whole chain — probe, verdict, sealed token,
        // marker — is ONE call into creance-vm. No `out` exists here to
        // forge, no verdict result to neutralize, and the marker write
        // requires a token only a passing verdict can mint.
        match creance_vm::gateprobe::verify_and_mark(&profile, &instance) {
            Ok(wrote) => {
                if wrote {
                    println!(
                        "供给完成——下次 creance stop && creance up 起 slirp restrict=on 第二道防线生效"
                    );
                }
            }
            Err(e) => return fail(e),
        }
        println!("Environment is up. The guest's only route out is the managed core (`creance escape-test` proves it).");
    }
    code
}

fn cmd_oauth() -> i32 {
    let profile = profile();
    let instance = instance();
    // The channel is an ssh -L forward into the guest's loopback noVNC
    // plus the ephemeral display stack `creance-oauth` runs. Everything
    // tears down when this command exits — nothing outlives the session.
    let target = match creance_vm::vm::ssh_target(&profile, &instance) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    // Guest side is fixed 127.0.0.1:6080; the HOST side takes any free
    // loopback port — a fixed one collides with unrelated listeners.
    let local_port = match std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)) {
        Ok(l) => l.local_addr().map(|a| a.port()).unwrap_or(0),
        Err(e) => return fail(format!("cannot allocate a local port: {e}")),
    };
    let mut fwd = std::process::Command::new("ssh");
    creance_vm::vm::apply_ssh_options(&mut fwd, &target);
    let mut child = match fwd
        .arg("-o")
        .arg("StrictHostKeyChecking=yes")
        .arg("-o")
        .arg("ExitOnForwardFailure=yes")
        .arg("-N")
        .arg("-L")
        .arg(format!("127.0.0.1:{local_port}:127.0.0.1:6080"))
        .arg("127.0.0.1")
        .stdin(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return fail(format!("cannot spawn ssh forward: {e}")),
    };
    std::thread::sleep(std::time::Duration::from_millis(500));
    match child.try_wait() {
        Ok(Some(_)) => return fail("ssh forward exited immediately".to_owned()),
        Ok(None) => {}
        Err(e) => return fail(format!("ssh forward: {e}")),
    }
    if let Err(e) =
        creance_vm::vm::guest_script(&profile, &instance, "sh /usr/local/bin/creance-oauth start")
    {
        let _ = child.kill();
        return fail(e);
    }
    println!("OAuth 通道已开：在宿主浏览器打开 http://127.0.0.1:{local_port}/vnc.html");
    println!("完成验证后回车，通道即销毁（X 桌面、浏览器、noVNC 全部回收）");
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    let _ =
        creance_vm::vm::guest_script(&profile, &instance, "sh /usr/local/bin/creance-oauth stop");
    let _ = child.kill();
    let _ = child.wait();
    println!("oauth channel torn down");
    0
}

fn cmd_shell(command: Vec<String>) -> i32 {
    let path = config::config_path();
    let cfg = match config::load(&path) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let profile = profile();
    if let Err(e) = running::check_running(&creance_vm::vm::instances_root(&profile), &cfg) {
        return fail(e);
    }
    let instance = instance();
    let refs: Vec<&str> = command.iter().map(String::as_str).collect();
    creance_vm::vm::shell(&profile, &instance, &refs)
}

#[cfg(test)]
mod up_gate_tests {
    #[test]
    fn provisioned_marker_only_after_verdict() {
        // F-081/F-087/F-091/F-093/F-095: the marker write is a single
        // call site across the WHOLE crate — a relay through another
        // module (NC-MKmod) counts too. The needle is the BARE name so
        // `use … as` renames and `(mark_provisioned)(…)` parens still
        // count, and each file is cut at its LAST line-start
        // `#[cfg(test)]` so an injected `// #[cfg(test)]` comment or an
        // early test-attribute cannot truncate the scan (NC-MKcfg).
        // F-097: scan EVERY .rs under src/ RECURSIVELY (a new
        // submodule file is in scope — NC-MKsub). Per file, at most
        // one `#[cfg(test)]` attribute is allowed — a second one
        // (an early truncator or a fake mod appended) is itself the
        // mutation. The prod region is the whole file MINUS ONLY the
        // trailing test module: code appended after its column-0 `}`
        // still counts (NC-MKtail/NC-MKtailE).
        let mut total = 0usize;
        let mut dirs = vec![std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src"
        ))];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                // F-099/NC-CUTinner+PATHmod: an inner cfg-test
                // attribute is NOT counted by the `\n#[cfg(test)]`
                // count, and a path-attribute module pulls its SOURCE
                // outside src/ where the walk cannot see it — both
                // banned. Needles are concat-built so this comment
                // doesn't self-match.
                assert!(!text.contains(concat!("#", "![cfg")), "{path:?}");
                assert!(!text.contains(concat!("#", "[path")), "{path:?}");
                assert!(
                    text.matches("\n#[cfg(test)]").count() <= 1,
                    "{path:?}: at most one #[cfg(test)] attribute per file"
                );
                let prod = match text.rfind("\n#[cfg(test)]") {
                    Some(pos) => {
                        let end = pos
                            + text[pos..]
                                .find("\n}")
                                .map(|e| e + 2)
                                .unwrap_or(text.len() - pos);
                        format!("{}{}", &text[..pos], &text[end.min(text.len())..])
                    }
                    None => text.clone(),
                };
                // Prod code must never call INTO a test module —
                // `up_gate_tests::helper` hides the call inside the
                // excluded region while still arming the marker.
                assert!(!prod.contains("tests::"), "{path:?}");
                total += prod.matches("mark_provisioned").count();
            }
        }
        assert_eq!(
            total, 0,
            "mark_provisioned はクレート内では呼べない——封印トークンが要るので呼び出しは gateprobe::verify_and_mark だけ"
        );
        let src =
            &include_str!("main.rs")[..include_str!("main.rs").rfind("\n#[cfg(test)]").unwrap()];
        // F-099/F-100/F-107: the up-gate delegates the ENTIRE chain to
        // verify_and_mark — a single call is the only seam left to pin,
        // and its refusal must propagate (an `eprintln!`-and-continue
        // Err arm reports "Environment is up" on a dead firewall).
        assert_eq!(
            src.matches("verify_and_mark(").count(),
            1,
            "up ゲートは verify_and_mark 単一呼出（探針・verdict・marker の縫い目はもうここにはない）"
        );
        let call = src.find("verify_and_mark(&profile, &instance)").unwrap();
        let arm_region = &src[call..call + 600];
        // F-113/F-119: the refusal arm must be a real match arm — a
        // `// Err(e) => return fail(e)` comment, a guarded
        // `Err(e) if … =>` arm, OR a path-qualified
        // `Result::Err(e) if …` arm placed before it all swallow the
        // refusal while containing no `Err(` line start. Strip the
        // `Result::`/`std::result::Result::`/`core::result::Result::`
        // spellings before the line check, and the region's arm lines
        // must number exactly two (Ok + Err — a third arm is a guard).
        fn strip_result(l: &str) -> &str {
            l.trim()
                .trim_start_matches("std::result::Result::")
                .trim_start_matches("core::result::Result::")
                .trim_start_matches("Result::")
        }
        let arms: Vec<&str> = arm_region
            .lines()
            .map(str::trim)
            .filter(|l| strip_result(l).starts_with("Err(") || l.starts_with("Ok("))
            .collect();
        assert_eq!(arms.len(), 2, "the verdict match is exactly two arms");
        assert_eq!(arms[0], "Ok(wrote) => {", "the pass arm opens the block");
        let first_err = arms
            .iter()
            .map(|l| strip_result(l))
            .find(|l| l.starts_with("Err("))
            .expect("refusal arm");
        assert_eq!(
            first_err, "Err(e) => return fail(e),",
            "verify_and_mark の拒否は fail(e) で伝播する（コメント・ガード腕・パス修飾では駄目）"
        );
        // F-113: writing the marker file directly — any literal
        // "provisioned" or a non-`gate_` instance_dir() call ANYWHERE
        // in the creance crate (lib.rs included) bypasses the seal.
        let crate_srcs = [
            include_str!("main.rs"),
            include_str!("lib.rs"),
            include_str!("escape.rs"),
            include_str!("serve.rs"),
            include_str!("diagnose.rs"),
            include_str!("evidence.rs"),
        ];
        for csrc in crate_srcs {
            let prod = &csrc[..csrc.rfind("\n#[cfg(test)]").unwrap_or(csrc.len())];
            // F-119: the marker name survives neither whole nor split —
            // `concat!("provision","ed")`, a `format!("provision{}")`
            // fragment, or a `"isioned"` tail all hit these bans. (A
            // byte-array build carries no text at all — the honest
            // residual of any source scan.)
            assert!(
                !prod.contains("\"provision"),
                "a \"provision…\" literal or fragment writes the marker without the token"
            );
            assert!(
                !prod.contains("\"isioned\""),
                "a split marker-name fragment writes the marker without the token"
            );
            assert!(
                !prod.contains("concat!"),
                "concat! assembles a marker-name literal the scan cannot see"
            );
            // `gate_instance_dir(` is a different path (the gate's own
            // dir); a real instance_dir call carries 2 args. Ban any
            // `instance_dir(` occurrence not preceded by `gate_` — and
            // F-119: ban the FUNCTION being smuggled in at all: an
            // `instance_dir` import/alias in a `use` line, or a
            // `::instance_dir` path reference taken as a value.
            let mut rest = prod;
            while let Some(i) = rest.find("instance_dir(") {
                let head = &rest[..i];
                assert!(
                    head.ends_with("gate_") || head.ends_with("gate_instance"),
                    "an instance_dir() call outside gate_instance_dir writes the marker directly"
                );
                rest = &rest[i + "instance_dir(".len()..];
            }
            for l in prod.lines() {
                if l.contains("instance_dir") {
                    let t = l.trim();
                    assert!(
                        !t.starts_with("use "),
                        "importing instance_dir aliases the marker path: {l}"
                    );
                    assert!(
                        !l.contains("::instance_dir"),
                        "a path-qualified instance_dir reference: {l}"
                    );
                }
            }
        }
    }
}
