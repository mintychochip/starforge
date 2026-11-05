//! Real command handlers (C2 owns `auth`; later tasks add the rest).

pub mod auth;
pub mod doctor;
pub mod hooks;
pub mod sessions;
pub mod status;
pub mod sync;
pub mod trail;
