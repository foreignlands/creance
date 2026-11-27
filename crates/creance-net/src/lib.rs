//! creance-net — the proxy-only network fabric.
//!
//! One upstream, never a direct fallback: SOCKS5/HTTP(S) CONNECT tunnels,
//! TLS stacking, DNS-over-HTTPS through the same proxy, and the DNS wire
//! codec. Hostnames are handed to the proxy unresolved.

pub mod dnsmsg;
pub mod egress;
/// Loopback servers for crate and integration tests. Compiled always so
/// out-of-crate tests can share the exact wire semantics; not public API.
#[doc(hidden)]
pub mod testsupport;
pub mod trace;
pub mod wire;

pub use egress::{Egress, validate_dns_url, validate_proxy_url};
