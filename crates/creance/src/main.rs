//! creance — a contained workspace for AI agents.
//!
//! Every command operates on one profile: the directory holding config.json
//! (override with `CREANCE_CONFIG` or the legacy `CLAUDE_CAGE_CONFIG`).
//! Unsafe environment variables are stripped before anything runs.

use clap::Parser;
use creance::{diagnose, serve};
use creance_gate::gate;
use creance_proxy::service;
use creance_vm::config;

/// The default trace check target: a plain endpoint that reports the egress IP.
mod cmds;
use cmds::*;
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
        Commands::BundleExport { file } => cmd_bundle_export(&file),
        Commands::BundleImport { file } => cmd_bundle_import(&file),
        Commands::PersonaSave { name } => cmd_persona_save(&name),
        Commands::PersonaUse { name } => cmd_persona_use(&name),
        Commands::PersonaList => cmd_persona_list(),
        Commands::MigrateExport { file } => cmd_migrate_export(&file),
        Commands::Approve { action } => cmd_approve(&action),
        Commands::KeychainSet { entry } => cmd_keychain_set(&entry),
        Commands::KeychainDelete { entry } => cmd_keychain_delete(&entry),
        Commands::KeychainMigrate => cmd_keychain_migrate(),
        Commands::PluginList => cmd_plugin_list(cmds::profile()),
        Commands::PluginCall { name, args } => cmd_plugin_call(cmds::profile(), name, args),
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
    /// Export the profile persona as a password-sealed Identity Bundle.
    /// The master password comes from CREANCE_BUNDLE_PASSWORD.
    BundleExport {
        /// Output .crb path.
        #[arg(long)]
        file: String,
    },
    /// Unseal an Identity Bundle into this profile's directory. Refuses
    /// to overwrite existing files.
    BundleImport {
        /// Input .crb path.
        #[arg(long)]
        file: String,
    },
    /// Snapshot the current persona (identity + config + exits) under a
    /// name for later atomic switching.
    PersonaSave { name: String },
    /// Atomically switch to a saved persona: requires the VM stopped,
    /// restores the persona files and rebuilds the VM disk.
    PersonaUse { name: String },
    /// List saved personas.
    PersonaList,
    /// Export the whole machine state (persona + saved personas) as a
    /// password-sealed migration bundle. Password from
    /// CREANCE_BUNDLE_PASSWORD; import with `bundle-import`.
    MigrateExport {
        /// Output .crb path.
        #[arg(long)]
        file: String,
    },
    /// Request phone approval for a sensitive action (Telegram channel
    /// configured in config.json); grants a 10-minute pass on confirm.
    Approve { action: String },
    /// Store a secret in the OS keychain (entry referenced as
    /// `keychain:<entry>` in config.json). The secret is read from stdin
    /// — never argv, which is ps-visible.
    KeychainSet { entry: String },
    /// Delete a keychain entry.
    KeychainDelete { entry: String },
    /// Move plaintext secrets in config.json (proxy_url credentials,
    /// approval bot token) into the OS keychain, rewriting the fields as
    /// `keychain:` references. A backup is written first.
    KeychainMigrate,
    /// Run the containment probe suite (host checks + in-guest probes).
    EscapeTest,
    /// List registered plugins (profile's plugins.json).
    PluginList,
    /// Call an allowlisted plugin through the gate channel (micro
    /// gate-open: allowlist + optional phone grant).
    PluginCall {
        /// Plugin name from plugins.json.
        name: String,
        /// Arguments passed when the entry allows them.
        args: Vec<String>,
    },
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
        let src = &include_str!("cmds/vm.rs")[..include_str!("cmds/vm.rs")
            .rfind("\n#[cfg(test)]")
            .unwrap_or(include_str!("cmds/vm.rs").len())];
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
            include_str!("cmds/vm.rs"),
            include_str!("cmds/identity.rs"),
            include_str!("cmds/proxy.rs"),
            include_str!("cmds/plugin.rs"),
            include_str!("cmds/mod.rs"),
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
