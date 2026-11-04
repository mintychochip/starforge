//! Crate wiring + `CliPaths`/config + CLI skeleton (M1c task C1).
//!
//! Later tasks (C2–C7) replace the handler stubs with real implementations.
//! The cross-task contract types declared here must not be renamed.

pub mod auth;
pub mod cli;
pub mod config;
pub mod discovery;
pub mod queue;
pub mod spool;
pub mod upload;
