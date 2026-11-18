//! cage-core — the control plane of Claude Cage's Rust rewrite.
//!
//! The isolation contract, in one place:
//! - one proxy upstream, loopback-bounded, store-backed auth ([`proxy`])
//! - one egress that never falls back to a direct route ([`egress`])
//! - one exit-policy anchor with a mandatory mainland-IP deny ([`exit_policy`])
//! - one config per profile; any change requires a stop ([`config`])
//!
//! Modules mirror the responsibilities of the original Go packages
//! (`internal/cage`, `internal/managedproxy`, `internal/exitpolicy`,
//! `internal/paths`, `internal/vmname`, `internal/state`) with leaner code.

pub mod config;
pub mod dnsmsg;
pub mod egress;
pub mod exit_policy;
pub mod paths;
pub mod private;
#[cfg(test)]
pub(crate) mod tests_support;

pub mod diagnose;
pub mod gate;
pub mod host;
pub mod lima;
pub mod proxy;
pub mod running;
pub mod serve;
pub mod state;
pub mod vm;
pub mod vmname;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
