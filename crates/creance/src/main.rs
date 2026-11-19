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
use creance_vm::{config, running, vmname};
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
    after_help = "Configuration: ~/.claude-cage/config.json (override CLAUDE_CAGE_CONFIG).\nEach configuration directory is an independent cage profile.\nOnly explicitly opened project folders are shared. No host Claude credentials are imported."
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
    ProxySelect {
        node: String,
    },
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
    /// Diagnose the environment VM.
    /// Run the containment probe suite (host checks + in-guest probes).
    EscapeTest,
    /// Open the environment gate (check window + grant). The wire follows.
    GateOpen,
    /// Close the environment gate: the guest loses its only route out.
    GateClose,
    Doctor,
    /// Serve the lean workbench (loopback HTTP + single-page UI).
    Serve {
        #[arg(long, default_value_t = 5173)]
        port: u16,
    },
    /// Print this build's version.
    Version,
    /// Internal: own the proxy core's output for launchd. Not for direct use.
    #[command(hide = true)]
    LogRelay {
        kind: String,
    },
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
    vmname::home_limit(&creance_vm::vm::lima_home(&profile()), false)
        .name(&creance_vm::vm::environment_dir(&profile()))
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
    let instance_dir = creance_vm::paths::join(&creance_vm::vm::lima_home(&profile), &instance);
    let outcome = if open {
        gate::open(&instance_dir).map(|s| format!("open (epoch {})", s.epoch))
    } else {
        gate::close_and_remove(&instance_dir).map(|_| "closed".to_owned())
    };
    match outcome {
        Ok(msg) => {
            println!("gate: {msg}");
            if open {
                println!("note: grant carries self-checks only; exit-policy evidence lands in 0.5");
            }
            0
        }
        Err(e) => fail(e),
    }
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
    let instance_yaml = creance_vm::paths::join(
        &creance_vm::vm::lima_home(&profile),
        &format!("{instance}/lima.yaml"),
    );
    if std::path::Path::new(&instance_yaml).exists() {
        let flag = format!("{}.escape-flag", creance_vm::vm::environment_dir(&profile));
        let store = creance_proxy::load(&profile).ok();
        let script = escape::guest_script(
            &flag,
            &store.as_ref().map(|s| s.auth.clone()).unwrap_or_default(),
            store.as_ref().map(|s| s.port).unwrap_or(17896),
        );
        let child = std::process::Command::new("limactl")
            .env("LIMA_HOME", creance_vm::vm::lima_home(&profile))
            .arg("shell")
            .arg(&instance)
            .arg("sh")
            .arg("-s")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn();
        if let Ok(mut child) = child {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(script.as_bytes());
            }
            drop(child.stdin.take());
            if let Ok(output) = child.wait_with_output() {
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    println!("{line}");
                    if line.contains(" ESCAPE") {
                        code = 1;
                    }
                }
            }
        } else {
            eprintln!("cannot run in-guest probes (limactl unavailable)");
        }
    }
    code
}

fn cmd_proxy_start() -> i32 {
    cmd_simple(|| {
        creance_proxy::start_managed(&profile(), &config::config_path())?;
        // Running instances get told about the (re)started core so their
        // gates re-open only against the fresh revision.
        if let Ok(client) = gate::GateClient::open(&gate_instance_dir()) {
            let _ = client.sync_proxy_revision();
        }
        Ok(())
    })
}

fn gate_instance_dir() -> String {
    creance_vm::paths::join(&creance_vm::vm::lima_home(&profile()), &instance())
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
        store.import(&name, "", &data, "", interval, "cli")?;
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
        .unwrap_or(17896)
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
    let options = creance_vm::lima::SetupOptions {
        memory_gib: memory,
        cpus,
        disk_gib: 24,
        workspace: creance_vm::vm::environment_dir(&profile),
        timezone: cfg.timezone.clone(),
        locale: cfg.locale.clone(),
        proxy_port: proxy_store_port(&profile),
        guest,
    };
    if let Err(e) = creance_vm::lima::setup_instance(&profile, &instance, &options) {
        return fail(e);
    }
    let code = creance_vm::vm::create(&profile, &instance);
    if code == 0 {
        println!("instance {instance} created; run `creance up` to start it");
    }
    code
}

fn cmd_proxy_select(node: String) -> i32 {
    cmd_simple(|| {
        creance_proxy::select_and_apply(&profile(), &config::config_path(), &node)?;
        println!("applied {node}; run `creance proxy-start` to launch the core");
        Ok(())
    })
}

fn cmd_stop(keep_proxy: bool) -> i32 {
    let profile = profile();
    let code = creance_vm::vm::stop_vm(&profile, &instance());
    let _ = gate::close_gates(&profile); // removes cage-gate.json → daemon retires
    let _ = creance_vm::tunnel::stop(&profile);
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
    if let Err(e) = running::check_running(&creance_vm::vm::state_dir(&profile), &cfg) {
        return fail(e);
    }
    let instance = instance();
    let code = creance_vm::vm::up(&profile, &instance);
    if code == 0 {
        // 0.4: the gate owns the wire now — Closed gate = tunnel down. Raising
        // the daemon raises the tunnel with it; only on daemon failure do we
        // fall back to the unconditional tunnel so the VM stays usable.
        let port = creance_proxy::load(&profile)
            .map(|s| s.port)
            .unwrap_or(17896);
        let instance_dir = creance_vm::paths::join(&creance_vm::vm::lima_home(&profile), &instance);
        if let Err(e) = gate::spawn_daemon(&profile, &instance, &path, &instance_dir, port) {
            eprintln!("warning: gate daemon not raised: {e}");
            if let Err(e) = creance_vm::tunnel::ensure(&profile, &instance, port) {
                eprintln!("warning: guest tunnel not established: {e}");
            }
        }
        let _ = running::record_running(&instance_dir, &cfg);
        println!("Environment is up. The guest's only route out is the managed core (`creance escape-test` proves it).");
    }
    code
}

fn cmd_shell(command: Vec<String>) -> i32 {
    let path = config::config_path();
    let cfg = match config::load(&path) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let profile = profile();
    if let Err(e) = running::check_running(&creance_vm::vm::state_dir(&profile), &cfg) {
        return fail(e);
    }
    let instance = instance();
    let refs: Vec<&str> = command.iter().map(String::as_str).collect();
    creance_vm::vm::shell(&profile, &instance, &refs)
}
