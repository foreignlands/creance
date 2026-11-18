//! creance-gate — exit policy and the network gate control plane.
//!
//! The exit anchor (static IP / country / region / city with the mandatory
//! mainland deny list) and the per-instance gate: a private unix-socket
//! HTTP service whose state machine decides whether an environment's
//! external networking may be open.

pub mod gate;

pub use creance_vm::exit_policy;
