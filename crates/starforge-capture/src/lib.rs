//! Session capture adapters (spec §7.1).
//!
//! Normalizes native agent transcripts into [`starforge_format::Event`]s.
//! Adapters take their roots as parameters ([`Roots`]): this crate performs
//! no environment lookup, reads no `$HOME`, and reads no clock. Callers
//! supply timestamps (`fallback_ts`). No redaction happens here; that is
//! the CLI spool path.

pub mod adapter;
pub mod agents;
pub mod cursor;
pub mod discover;

pub use adapter::{Adapter, AdapterVersion, Candidate, CaptureError, ReadOutput, Roots};
pub use cursor::Cursor;
pub use discover::workdir_inside;
