//! Crate wiring + `CliPaths`/config + CLI skeleton (M1c task C1).
//!
//! The cross-task contract types declared here must not be renamed.

pub mod api;
pub mod auth;
pub mod checkpoints;
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
