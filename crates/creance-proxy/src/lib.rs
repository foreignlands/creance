//! creance-proxy — the managed proxy lifecycle.
//!
//! The private subscription store (the single source of truth for the
//! applied endpoint), Clash/Mihomo imports with cage's boundary rules, the
//! generated mihomo runtime configuration, and the launchd-managed core
//! service on macOS.

pub mod fetch;
pub mod import;
pub mod runtime;
pub mod service;

pub use creance_vm::{civil_from_days, iso8601_now, token};

mod store;
pub use store::*;
