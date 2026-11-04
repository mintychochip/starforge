use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

use starforge_format::{AgentName, Event, SessionMeta};

/// All paths an adapter may touch. No env, no `$HOME`: callers build this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roots {
    /// Hook files may be written ONLY here.
    pub config_dir: PathBuf,
    /// Native session stores are read ONLY under here.
    pub data_dir: PathBuf,
    /// `discover` keeps sessions whose workdir is inside here.
    pub worktree: PathBuf,
}

/// One native session found by `discover`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Stable id within the agent store (file stem, rollout name, row id…).
    pub session_key: String,
    /// Exact file (or db file) to read; must be under `Roots.data_dir`.
    pub native_path: PathBuf,
    /// Native version string observed for this session.
    pub agent_version: String,
    /// Session working directory (prefix-matched against `Roots.worktree`).
    pub workdir: PathBuf,
}

/// What `read` returns: new events plus the advanced cursor plus the header.
#[derive(Debug, Clone, PartialEq)]
pub struct ReadOutput {
    /// Newly parsed events.
    pub events: Vec<Event>,
    /// Cursor advanced past exactly the records read.
    pub next: crate::Cursor,
    /// SessionMeta-shaped header; `capture.adapter_version_verified` set from `version_status`.
    pub header: SessionMeta,
}

/// Whether `agent_version` is covered by golden fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterVersion {
    pub covered: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("native transcript is not valid JSONL/JSON: {0}")]
    BadNative(String),
    #[error("cursor points past end of transcript (offset {0} > len {1})")]
    CursorBeyondEnd(u64, u64),
    #[error("bad fallback timestamp (must be RFC 3339): {0}")]
    BadTimestamp(String),
    #[error("sqlite error: {0}")]
    Sqlite(String),
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
}

pub trait Adapter {
    fn id(&self) -> AgentName;
    /// Exact native versions pinned by golden fixtures in `tests/fixtures/<agent>/<version>/`.
    const COVERED: &[&str];
    fn version_status(&self, version: &str) -> AdapterVersion {
        AdapterVersion {
            covered: Self::COVERED.contains(&version),
        }
    }
    /// True when the agent's store markers exist under `roots.data_dir`.
    fn detect(&self, roots: &Roots) -> bool;
    /// Write hook integration under `roots.config_dir` only; return paths written.
    fn install_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>>;
    /// Remove only files containing the starforge marker; return paths removed.
    fn remove_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>>;
    /// Sessions under `roots.worktree` that are new or grew past `known`.
    fn discover(&self, roots: &Roots, known: &HashMap<String, crate::Cursor>) -> Vec<Candidate>;
    /// Parse records after `cursor`; empty growth → empty events, cursor unchanged.
    fn read(
        &self,
        candidate: &Candidate,
        cursor: &crate::Cursor,
        fallback_ts: &str,
    ) -> Result<ReadOutput, CaptureError>;
}
