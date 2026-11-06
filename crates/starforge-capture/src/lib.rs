//! Session capture adapters (spec §7.1).
//!
//! Normalizes native agent transcripts into [`starforge_format::Event`]s.
//! Adapters take their roots as parameters ([`Roots`]): this crate performs
//! no environment lookup, reads no `$HOME`, and reads no clock. Callers
//! supply timestamps (`fallback_ts`). No redaction happens here; that is
//! the CLI spool path.
//!
//! # Working-directory attribution (privacy rule)
//!
//! A session is captured only when its working directory is known from
//! the transcript itself and lies inside the repository being committed
//! ([`workdir_inside`]). A session whose working directory cannot be
//! determined — including an empty `cwd` string — is SKIPPED: it is
//! never defaulted to the worktree being committed, because that would
//! attribute (and upload) an unrelated session to the wrong repository.
//! The sole exception is Gemini CLI, where a chat without `cwd` may be
//! attributed from its `<project_hash>` store directory when that hash
//! equals the hash of the worktree path (see the Gemini adapter docs).
pub mod adapter;
pub mod agents;
pub mod cursor;
pub mod discover;

pub use adapter::{Adapter, AdapterVersion, Candidate, CaptureError, ReadOutput, Roots};
pub use cursor::Cursor;
pub(crate) use discover::repo_relative;
pub use discover::workdir_inside;
