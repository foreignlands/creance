//! `creance doctor`: one report of everything the environment needs, each item
//! judged ok / warn / fail with an actionable hint.

use creance_proxy::{self};
use creance_vm::config;
use creance_vm::host;
use creance_vm::paths;
use creance_vm::vm;
use std::path::Path;

pub struct Check {
    pub status: Status,
    pub name: &'static str,
    pub detail: String,
}

#[derive(PartialEq)]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

impl Check {
    fn marker(&self) -> &'static str {
        match self.status {
            Status::Ok => "✅",
            Status::Warn => "⚠️ ",
            Status::Fail => "❌",
        }
    }
}

/// Builds the full diagnostic report for one profile.
pub fn diagnose(profile: &str, config_path: &str) -> Vec<Check> {
    let mut out = Vec::new();

    // Tooling: the VM layer's backend needs its driver, the proxy layer
    // needs the core.
    #[cfg(target_os = "macos")]
    match which("limactl") {
        Some(_) => out.push(Check {
            status: Status::Ok,
            name: "limactl",
            detail: "Lima CLI available".to_owned(),
        }),
        None => out.push(Check {
            status: Status::Fail,
            name: "limactl",
            detail: "not installed; `brew install lima` is required for VM environments".to_owned(),
        }),
    }
    #[cfg(not(target_os = "macos"))]
    for tool in [
        creance_vm::qemu::runner::qemu_binary(),
        "qemu-img",
        "ssh-keygen",
        "pgrep",
    ] {
        out.push(Check {
            status: if which(tool).is_some() {
                Status::Ok
            } else {
                Status::Fail
            },
            name: "qemu",
            detail: if which(tool).is_some() {
                format!("{tool} available")
            } else {
                format!(
                    "not installed; `sudo apt install qemu-system-x86 qemu-utils procps` provides {tool}"
                )
            },
        });
    }
    #[cfg(not(target_os = "macos"))]
    {
        // KVM decides whether a VM is usable at all — TCG fallback would be
        // silent 8–12× pain, so it is judged here, loudly.
        match std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm") {
            Ok(_) => out.push(Check {
                status: Status::Ok,
                name: "kvm",
                detail: "/dev/kvm writable".to_owned(),
            }),
            Err(e) => out.push(Check {
                status: Status::Fail,
                name: "kvm",
                detail: format!(
                    "/dev/kvm unavailable ({e}); enable VT-x/AMD-V in firmware and add the user to the kvm group"
                ),
            }),
        }
    }
    match creance_proxy::service::core_path() {
        Ok(path) => out.push(Check {
            status: Status::Ok,
            name: "mihomo core",
            detail: path,
        }),
        Err(e) => out.push(Check {
            status: Status::Fail,
            name: "mihomo core",
            detail: e,
        }),
    }

    // Configuration and proxy state.
    match config::load(config_path) {
        Ok(cfg) => {
            out.push(Check {
                status: Status::Ok,
                name: "config",
                // F-R35-2: 明文形的 userinfo 密码不得上屏幕/日志——
                // 掩码 userinfo；keychain 引用形原样展示（本就无真值）。
                detail: format!("valid; proxy {}", mask_userinfo(&cfg.proxy_url)),
            });
            match cfg
                .resolved_proxy_url()
                .and_then(|u| creance_proxy::applied(profile, &u, &cfg.proxy_revision))
            {
                Ok(store) => {
                    out.push(Check {
                        status: Status::Ok,
                        name: "applied node",
                        detail: store.route().unwrap_or_default().join(" -> "),
                    });
                    out.push(Check {
                        status: if creance_proxy::service::running(profile, &store) {
                            Status::Ok
                        } else {
                            Status::Warn
                        },
                        name: "proxy core",
                        detail: if creance_proxy::service::running(profile, &store) {
                            "running and matching the applied store".to_owned()
                        } else {
                            "not running; `creance proxy-start` brings it up".to_owned()
                        },
                    });
                }
                Err(e) => out.push(Check {
                    status: Status::Warn,
                    name: "applied node",
                    detail: e,
                }),
            }
            // 审批通道：成对校验已在 config validate 兜底；这里报启用态。
            if !cfg.approval_bot_token.is_empty() {
                out.push(Check {
                    status: Status::Ok,
                    name: "approval channel",
                    detail: format!("Telegram bot 已配置，chat {}", cfg.approval_chat_id),
                });
            }
        }
        Err(e) => out.push(Check {
            status: Status::Fail,
            name: "config",
            detail: e,
        }),
    }

    // Host resources.
    match host::disk_free_bytes(if Path::new(profile).exists() {
        profile
    } else {
        "/tmp"
    }) {
        Ok(free) => out.push(Check {
            status: if free > 10 << 30 {
                Status::Ok
            } else {
                Status::Warn
            },
            name: "disk",
            detail: format!("{} free at {}", host::gib(free), profile),
        }),
        Err(e) => out.push(Check {
            status: Status::Warn,
            name: "disk",
            detail: e,
        }),
    }
    match host::total_memory_bytes() {
        Ok(total) => out.push(Check {
            status: if total >= 4 << 30 {
                Status::Ok
            } else {
                Status::Warn
            },
            name: "memory",
            detail: host::gib(total),
        }),
        Err(e) => out.push(Check {
            status: Status::Warn,
            name: "memory",
            detail: e,
        }),
    }

    // The environment VM, if it was ever created.
    let instance = vm::instance_name(profile, &vm::environment_dir(profile));
    if Path::new(&vm::instance_marker(profile, &instance)).exists() {
        out.push(Check {
            status: Status::Ok,
            name: "environment",
            detail: format!("instance {instance} created"),
        });
    } else {
        out.push(Check {
            status: Status::Warn,
            name: "environment",
            detail: format!("no instance yet; `creance setup` creates {instance}"),
        });
    }
    out
}

/// Masks the password (and username) in a proxy URL's userinfo for display.
/// Non-URL values pass through trimmed at the scheme separator.
fn mask_userinfo(url: &str) -> String {
    if creance_vm::secret::is_reference(url) {
        return url.to_owned();
    }
    // scheme://[userinfo@]host… — mask everything between // and @.
    if let Some(sep) = url.find("://") {
        let rest = &url[sep + 3..];
        if let Some(at) = rest.find('@') {
            return format!("{}://***:***{}", &url[..sep], &rest[at..]);
        }
    }
    url.to_owned()
}

fn which(program: &str) -> Option<String> {
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let candidate = paths::join(dir, program);
        // is_file, not exists: a directory named like the tool on PATH is
        // not an executable (same rule as runner::require_tools).
        if Path::new(&candidate).is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Renders the report as the CLI prints it, with a verdict line.
pub fn render(checks: &[Check]) -> String {
    let mut out = String::new();
    for c in checks {
        out.push_str(&format!("{} {}\n    {}\n", c.marker(), c.name, c.detail));
    }
    let fails = checks.iter().filter(|c| c.status == Status::Fail).count();
    let warns = checks.iter().filter(|c| c.status == Status::Warn).count();
    if fails > 0 {
        out.push_str(&format!("\n{fails} failing, {warns} warnings\n"));
    } else if warns > 0 {
        out.push_str(&format!("\nall critical checks passed, {warns} warnings\n"));
    } else {
        out.push_str("\nall checks passed\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnose_covers_the_essentials() {
        let profile = std::env::temp_dir()
            .join(format!(
                "cage-diag-{}",
                creance_proxy::token()[..12].to_owned()
            ))
            .to_string_lossy()
            .into_owned();
        std::fs::create_dir_all(&profile).unwrap();
        let config_path = paths::join(&profile, "config.json");
        let config = config::default_config();
        std::fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        let checks = diagnose(&profile, &config_path);
        let names: Vec<&str> = checks.iter().map(|c| c.name).collect();
        for required in [
            #[cfg(target_os = "macos")]
            "limactl",
            #[cfg(not(target_os = "macos"))]
            "qemu",
            #[cfg(not(target_os = "macos"))]
            "kvm",
            "mihomo core",
            "config",
            "disk",
            "memory",
            "environment",
        ] {
            assert!(names.contains(&required), "{required} missing: {names:?}");
        }
        let report = render(&checks);
        assert!(report.contains("config"), "{report}");
        // Fresh profile: config is valid, nothing applied.
        assert!(
            report.contains("not running") || report.contains("applied"),
            "{report}"
        );
        std::fs::remove_dir_all(&profile).unwrap();
    }
}
