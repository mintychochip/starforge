//! Crate wiring + `CliPaths`/config + CLI skeleton (M1c task C1).
//!
//! Later tasks (C2–C7) replace the handler stubs with real implementations.
//! The cross-task contract types declared here must not be renamed.

pub mod api;
pub mod auth;
pub mod cli;
pub mod commands;
pub mod config;
pub mod discovery;
pub mod git;
pub mod hooks;
pub mod ingest;
pub mod queue;
pub mod spool;
pub mod untrusted;
pub mod upload;
