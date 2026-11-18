//! `cage doctor`: one report of everything the environment needs, each item
//! judged ok / warn / fail with an actionable hint.

use crate::config;
use crate::host;
use crate::paths;
use crate::proxy::{self, service};
use crate::vm;
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

    // Tooling: the VM layer needs limactl, the proxy layer needs the core.
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
    match service::core_path() {
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
                detail: format!("valid; proxy {}", cfg.proxy_url),
            });
            match proxy::applied(profile, &cfg.proxy_url, &cfg.proxy_revision) {
                Ok(store) => {
                    out.push(Check {
                        status: Status::Ok,
                        name: "applied node",
                        detail: store.route().unwrap_or_default().join(" -> "),
                    });
                    out.push(Check {
                        status: if service::running(profile, &store) {
                            Status::Ok
                        } else {
                            Status::Warn
                        },
                        name: "proxy core",
                        detail: if service::running(profile, &store) {
                            "running and matching the applied store".to_owned()
                        } else {
                            "not running; `cage proxy-start` brings it up".to_owned()
                        },
                    });
                }
                Err(e) => out.push(Check {
                    status: Status::Warn,
                    name: "applied node",
                    detail: e,
                }),
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
    let instance_yaml = paths::join(&vm::lima_home(profile), &format!("{instance}/lima.yaml"));
    if Path::new(&instance_yaml).exists() {
        out.push(Check {
            status: Status::Ok,
            name: "environment",
            detail: format!("instance {instance} created"),
        });
    } else {
        out.push(Check {
            status: Status::Warn,
            name: "environment",
            detail: format!("no instance yet; `cage setup` creates {instance}"),
        });
    }
    out
}

fn which(program: &str) -> Option<String> {
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let candidate = paths::join(dir, program);
        if Path::new(&candidate).exists() {
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
                crate::proxy::token()[..12].to_owned()
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
            "limactl",
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
