//! Real command handlers (C2 owns `auth`; later tasks add the rest).

pub mod auth;
pub mod bundle;
pub mod checkpoint;
pub mod ci;
pub mod doctor;
pub mod hook;
pub mod hooks;
pub mod runner;
pub mod sandbox;
pub mod session_admin;
pub mod sessions;
pub mod spool;
pub mod sshkey;
pub mod status;
pub mod sync;
pub mod trail;
