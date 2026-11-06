//! Local session spool: sessions, segments, raw slices, cursors, links.
//!
//! Root is `<git common dir>/starforge` (see [`Spool::open`]):
//!
//! ```text
//! <root>/sessions/<ULID>/meta.json          SessionMeta (redaction fingerprint + counts)
//! <root>/sessions/<ULID>/segments/<n>.jsonl.zst   redacted, compressed event batches
//! <root>/sessions/<ULID>/raw/<n>.zst              redacted, compressed native slices
//! <root>/sessions/<ULID>/upload.json        {uploaded_segments: {n: blake3}, complete}
//! <root>/cursors.json                       {"sessions": {key: {ulid, cursor, native_path}}}
//! <root>/links.jsonl                        one LinkEntry object per line (append-only)
//! <root>/queue.jsonl                        one QueueEntry object per line
//! ```
//!
//! The spool stores; it does not capture or redact. Callers normalize with
//! `starforge_capture`, redact with `starforge_redact` (`redact_event` for
//! normalized events, `redact_text` for raw native slices), then persist the
//! redacted bytes here. `meta.json` carries the redaction fingerprint (from
//! [`load_rules`](Spool::load_rules)) plus accumulated per-detector counts.
//!
//! Crash order: segment/raw blobs are written (and fsynced) before `meta.json`
//! is updated; `meta.json`, `cursors.json`, `queue.jsonl`, and `upload.json`
//! are replaced atomically (temp file + rename). `links.jsonl` is append-only.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU64, Ordering};

use starforge_capture::Cursor;
use starforge_format::{SessionMeta, blake3_hex, compress, split_jsonl};
use starforge_redact::{Compiled, RuleSet};

/// Spool failures.
#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    /// Filesystem failure.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    /// A spool JSON file did not parse.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// `.starforge/redact.toml` did not parse or compile.
    #[error("invalid redaction rules: {0}")]
    Rules(#[from] starforge_redact::RuleError),
    /// The session key is not a ULID (rejects path traversal).
    #[error("bad session ULID `{0}`")]
    BadUlid(String),
    /// No session dir yet; call [`Spool::put_session`] first.
    #[error("unknown session `{0}`")]
    UnknownSession(String),
    /// The segment was never written.
    #[error("missing segment {1} for session `{0}`")]
    MissingSegment(String, u64),
}

/// Session spool rooted at `<git common dir>/starforge`.
pub struct Spool {
    /// `<git common dir>/starforge`.
    pub root: PathBuf,
}

/// Stored resume state for one `agent/session_key` source.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CursorRecord {
    /// ULID of the spool session (stable across resumes).
    pub ulid: String,
    /// Resume cursor in [`Cursor`]'s serde form.
    pub cursor: Cursor,
    /// Native transcript path the cursor belongs to.
    pub native_path: String,
}

/// Whole `cursors.json` file.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct CursorsFile {
    /// `"<agent>/<session_key>"` → resume state.
    #[serde(default)]
    sessions: BTreeMap<String, CursorRecord>,
}

/// Where a session link was claimed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkSource {
    /// Parsed from a commit trailer.
    Trailer,
    /// Claimed explicitly via the CLI.
    CliClaim,
}

/// How confident a session link is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkConfidence {
    /// Exact commit linkage.
    Exact,
    /// Heuristic (time/proximity) linkage.
    Heuristic,
}

/// One `links.jsonl` line.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinkEntry {
    /// Session ULID.
    pub ulid: String,
    /// Linked commit hash.
    pub commit: String,
    /// Link provenance.
    pub source: LinkSource,
    /// Link confidence.
    pub confidence: LinkConfidence,
    /// First covered event `seq`.
    pub seq_start: u64,
    /// One past the last covered event `seq`.
    pub seq_end: u64,
}

/// Per-session heuristic-link watermark: `sessions/<ULID>/link-watermark.json`.
///
/// Written atomically by `post-commit` (and `sessions link`) after a link is
/// recorded. `last_linked_seq` is the link's `seq_end`: one past the last
/// covered event. The prepare-commit-msg handler treats a session with no
/// events at or past this watermark as inactive, so heuristic linking fires
/// once per batch of new activity instead of on every commit.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinkWatermark {
    /// One past the last linked event `seq`.
    pub last_linked_seq: u64,
    /// RFC 3339 time the watermark was written.
    pub last_linked_at: String,
}

/// `upload.json`: idempotent re-upload progress (never uploaded itself).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UploadState {
    /// Uploaded segment number → blake3 hex of the exact compressed bytes.
    #[serde(default)]
    pub uploaded_segments: BTreeMap<u64, String>,
    /// The session is fully uploaded.
    #[serde(default)]
    pub complete: bool,
    /// Blake3 of the last successfully uploaded metadata JSON (`None` = never).
    #[serde(default)]
    pub meta_hash: Option<String>,
    /// Blake3 hashes of raw `links.jsonl` lines already POSTed.
    #[serde(default)]
    pub sent_links: Vec<String>,
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Create `path` (and ancestors) with mode `0700` on unix; plain
/// `create_dir_all` elsewhere. Existing dirs are tightened best-effort.
fn create_dir_private(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path)?;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
        Ok(())
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path)
}

/// Narrow `path` to `0700` (unix, best-effort: never fails the caller).
fn tighten_dir(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Narrow `path` to `0600` (unix, best-effort: never fails the caller).
fn tighten_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Write `bytes` to `path` atomically: temp file in the same directory,
/// fsync, then rename. The temp name carries no `:` so it stays Windows-safe.
/// The temp (and thus the result) is mode `0600` on unix.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let mut tmp = None;
    let mut file = None;
    for _ in 0..16 {
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_name = format!(
            "{}.tmp-{}-{n}",
            path.file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "spool".to_string()),
            std::process::id()
        );
        let candidate = path.with_file_name(tmp_name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        match opts.open(&candidate) {
            Ok(f) => {
                tmp = Some(candidate);
                file = Some(f);
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    let tmp = tmp.ok_or_else(|| io::Error::other("could not create unique spool temp"))?;
    let mut file = file.expect("spool temp opened");
    let result: io::Result<()> = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

impl Spool {
    /// Open the spool rooted at the given git common dir.
    pub fn open(common_dir: &Path) -> Self {
        Self {
            root: common_dir.join("starforge"),
        }
    }

    /// Create the spool directory layout (§7.3). Idempotent: existing files
    /// are never truncated or rewritten. Dirs are `0700`, files `0600`
    /// (unix); pre-existing root/dirs/files are tightened best-effort.
    pub fn ensure_layout(&self) -> io::Result<()> {
        create_dir_private(&self.root.join("sessions"))?;
        tighten_dir(&self.root);
        tighten_dir(&self.root.join("sessions"));
        if !self.root.join("cursors.json").exists() {
            let empty = CursorsFile::default();
            atomic_write(
                &self.root.join("cursors.json"),
                serde_json::to_vec_pretty(&empty)
                    .expect("empty cursors file serializes")
                    .as_slice(),
            )?;
        }
        tighten_file(&self.root.join("cursors.json"));
        for name in ["links.jsonl", "queue.jsonl"] {
            let path = self.root.join(name);
            if !path.exists() {
                atomic_write(&path, b"")?;
            }
            tighten_file(&path);
        }
        Ok(())
    }

    /// Load the effective redaction rules for `repo`: `built_in()` merged with
    /// `<repo>/.starforge/redact.toml` (the repo file wins on every `Some`
    /// setting); a missing repo file is fine and yields exactly `built_in()`.
    /// Returns the merged set plus its compiled form.
    pub fn load_rules(repo: &Path) -> Result<(RuleSet, Compiled), SpoolError> {
        let base = RuleSet::built_in();
        let file = repo.join(".starforge/redact.toml");
        let merged = match std::fs::read_to_string(&file) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => base,
            Err(e) => return Err(SpoolError::Io(e)),
            Ok(text) => base.merge(&RuleSet::parse_toml(&text)?),
        };
        let compiled = merged.compile()?;
        Ok((merged, compiled))
    }

    fn session_dir(&self, ulid: &str) -> Result<PathBuf, SpoolError> {
        ulid::Ulid::from_str(ulid).map_err(|_| SpoolError::BadUlid(ulid.to_string()))?;
        Ok(self.root.join("sessions").join(ulid))
    }

    fn known_session_dir(&self, ulid: &str) -> Result<PathBuf, SpoolError> {
        let dir = self.session_dir(ulid)?;
        if !dir.is_dir() {
            return Err(SpoolError::UnknownSession(ulid.to_string()));
        }
        Ok(dir)
    }

    fn segment_path(&self, ulid: &str, n: u64) -> Result<PathBuf, SpoolError> {
        Ok(self
            .known_session_dir(ulid)?
            .join("segments")
            .join(format!("{n}.jsonl.zst")))
    }

    fn raw_path(&self, ulid: &str, n: u64) -> Result<PathBuf, SpoolError> {
        Ok(self
            .known_session_dir(ulid)?
            .join("raw")
            .join(format!("{n}.zst")))
    }

    fn existing_segments(&self, ulid: &str) -> Result<Vec<u64>, SpoolError> {
        let dir = self.known_session_dir(ulid)?.join("segments");
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(SpoolError::Io(e)),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(n) = name
                .strip_suffix(".jsonl.zst")
                .and_then(|s| s.parse::<u64>().ok())
            {
                out.push(n);
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    /// Create (or refresh) a session: makes `sessions/<id>/`, `segments/`,
    /// `raw/`, writes `meta.json` atomically, and initializes `upload.json`
    /// when absent. The caller sets `meta.id`, `meta.redaction`, and the repo
    /// fields; the session dir name is `meta.id`.
    pub fn put_session(&self, meta: &SessionMeta) -> Result<(), SpoolError> {
        let dir = self.session_dir(&meta.id.to_string())?;
        create_dir_private(&dir.join("segments"))?;
        create_dir_private(&dir.join("raw"))?;
        atomic_write(
            &dir.join("meta.json"),
            serde_json::to_vec_pretty(meta)
                .expect("SessionMeta serializes")
                .as_slice(),
        )?;
        let upload = dir.join("upload.json");
        if !upload.exists() {
            let state = UploadState::default();
            atomic_write(
                &upload,
                serde_json::to_vec_pretty(&state)
                    .expect("UploadState serializes")
                    .as_slice(),
            )?;
        }
        Ok(())
    }

    /// Read back `sessions/<ulid>/meta.json`.
    pub fn read_meta(&self, ulid: &str) -> Result<SessionMeta, SpoolError> {
        let bytes = std::fs::read(self.known_session_dir(ulid)?.join("meta.json"))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Split redacted normalized JSONL at `cap` bytes (production callers pass
    /// [`DEFAULT_SEGMENT_CAP`](starforge_format::DEFAULT_SEGMENT_CAP)) and
    /// append the compressed batches under continuing segment numbers (`0`
    /// for a new session). Segment blobs are written and fsynced before
    /// `meta.json` gains the accumulated `counts`. Empty input writes nothing
    /// and returns no numbers. Returns the new segment numbers in order.
    pub fn append_events(
        &self,
        ulid: &str,
        jsonl: &str,
        cap: usize,
        counts: &BTreeMap<String, u64>,
    ) -> Result<Vec<u64>, SpoolError> {
        let dir = self.known_session_dir(ulid)?;
        let blobs = split_jsonl(jsonl, cap);
        if blobs.is_empty() {
            return Ok(Vec::new());
        }
        let next = self
            .existing_segments(ulid)?
            .last()
            .copied()
            .map(|n| n + 1)
            .unwrap_or(0);
        let mut nums = Vec::with_capacity(blobs.len());
        for (i, blob) in blobs.iter().enumerate() {
            let n = next + i as u64;
            atomic_write(&dir.join("segments").join(format!("{n}.jsonl.zst")), blob)?;
            nums.push(n);
        }
        let meta_path = dir.join("meta.json");
        let mut meta: SessionMeta = serde_json::from_slice(&std::fs::read(&meta_path)?)?;
        for (k, v) in counts {
            *meta.redaction.counts.entry(k.clone()).or_insert(0) += v;
        }
        atomic_write(
            &meta_path,
            serde_json::to_vec_pretty(&meta)
                .expect("SessionMeta serializes")
                .as_slice(),
        )?;
        Ok(nums)
    }

    /// Exact compressed bytes of segment `n` (hash-stable: [`blake3_hex`] of
    /// these bytes is the segment identity).
    pub fn segment_bytes(&self, ulid: &str, n: u64) -> Result<Vec<u8>, SpoolError> {
        match std::fs::read(self.segment_path(ulid, n)?) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                Err(SpoolError::MissingSegment(ulid.to_string(), n))
            }
            Err(e) => Err(SpoolError::Io(e)),
        }
    }

    /// Compress `raw` (a redacted native slice) with the standard helper and
    /// store it as `raw/<n>.zst` under the same numbering as segments.
    pub fn write_raw(&self, ulid: &str, n: u64, raw: &[u8]) -> Result<(), SpoolError> {
        let blob = compress(raw);
        atomic_write(&self.raw_path(ulid, n)?, &blob)?;
        Ok(())
    }

    /// Exact compressed bytes of raw slice `n`.
    pub fn raw_bytes(&self, ulid: &str, n: u64) -> Result<Vec<u8>, SpoolError> {
        match std::fs::read(self.raw_path(ulid, n)?) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                Err(SpoolError::MissingSegment(ulid.to_string(), n))
            }
            Err(e) => Err(SpoolError::Io(e)),
        }
    }

    /// Read back `sessions/<ulid>/upload.json` (default when absent).
    pub fn read_upload(&self, ulid: &str) -> Result<UploadState, SpoolError> {
        let path = self.known_session_dir(ulid)?.join("upload.json");
        match std::fs::read(&path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(UploadState::default()),
            Err(e) => Err(SpoolError::Io(e)),
        }
    }

    /// Record segment `n` as uploaded: stores [`blake3_hex`] of its exact
    /// compressed bytes in `upload.json` and returns the hash.
    pub fn mark_segment_uploaded(&self, ulid: &str, n: u64) -> Result<String, SpoolError> {
        let dir = self.known_session_dir(ulid)?;
        let bytes = match std::fs::read(dir.join("segments").join(format!("{n}.jsonl.zst"))) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(SpoolError::MissingSegment(ulid.to_string(), n));
            }
            Err(e) => return Err(SpoolError::Io(e)),
        };
        let mut state = self.read_upload(ulid)?;
        let hash = blake3_hex(&bytes);
        state.uploaded_segments.insert(n, hash.clone());
        atomic_write(
            &dir.join("upload.json"),
            serde_json::to_vec_pretty(&state)
                .expect("UploadState serializes")
                .as_slice(),
        )?;
        Ok(hash)
    }

    /// Record the metadata body hash as uploaded in `upload.json`.
    pub fn mark_meta_uploaded(&self, ulid: &str, hash: String) -> Result<(), SpoolError> {
        let dir = self.known_session_dir(ulid)?;
        let mut state = self.read_upload(ulid)?;
        state.meta_hash = Some(hash);
        atomic_write(
            &dir.join("upload.json"),
            serde_json::to_vec_pretty(&state)
                .expect("UploadState serializes")
                .as_slice(),
        )?;
        Ok(())
    }

    /// Record raw `links.jsonl` line hashes as sent in `upload.json`.
    pub fn mark_links_sent(&self, ulid: &str, hashes: &[String]) -> Result<(), SpoolError> {
        let dir = self.known_session_dir(ulid)?;
        let mut state = self.read_upload(ulid)?;
        for hash in hashes {
            if !state.sent_links.contains(hash) {
                state.sent_links.push(hash.clone());
            }
        }
        atomic_write(
            &dir.join("upload.json"),
            serde_json::to_vec_pretty(&state)
                .expect("UploadState serializes")
                .as_slice(),
        )?;
        Ok(())
    }

    /// Raw `links.jsonl` lines for `ulid` with the blake3 hash of each line.
    /// Hashing raw lines (not re-serialized values) keeps the record stable
    /// no matter how the JSON maps order keys.
    pub fn link_line_hashes(&self, ulid: &str) -> Result<Vec<(String, LinkEntry)>, SpoolError> {
        let text = match std::fs::read_to_string(self.root.join("links.jsonl")) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(SpoolError::Io(e)),
        };
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let entry: LinkEntry = serde_json::from_str(line).map_err(SpoolError::Json)?;
            if entry.ulid == ulid {
                out.push((blake3_hex(line.as_bytes()), entry));
            }
        }
        Ok(out)
    }

    fn read_cursors(&self) -> Result<CursorsFile, SpoolError> {
        match std::fs::read_to_string(self.root.join("cursors.json")) {
            Ok(text) => Ok(serde_json::from_str(&text)?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(CursorsFile::default()),
            Err(e) => Err(SpoolError::Io(e)),
        }
    }

    /// Resume state for `"<agent>/<session_key>"`; `Ok(None)` when the agent
    /// key was never stored.
    pub fn read_cursor(&self, key: &str) -> Result<Option<CursorRecord>, SpoolError> {
        Ok(self.read_cursors()?.sessions.get(key).cloned())
    }

    /// Store resume state for `"<agent>/<session_key>"`, atomically
    /// (read-modify-write of the whole `cursors.json`).
    pub fn write_cursor(
        &self,
        key: &str,
        ulid: &str,
        cursor: Cursor,
        native_path: &str,
    ) -> Result<(), SpoolError> {
        let mut file = self.read_cursors()?;
        file.sessions.insert(
            key.to_string(),
            CursorRecord {
                ulid: ulid.to_string(),
                cursor,
                native_path: native_path.to_string(),
            },
        );
        atomic_write(
            &self.root.join("cursors.json"),
            serde_json::to_vec_pretty(&file)
                .expect("CursorsFile serializes")
                .as_slice(),
        )?;
        Ok(())
    }

    /// All cursor records keyed by `"<agent>/<session_key>"` (missing file = empty).
    pub fn cursor_records(&self) -> Result<BTreeMap<String, CursorRecord>, SpoolError> {
        Ok(self.read_cursors()?.sessions)
    }

    /// Append one [`LinkEntry`] object to `links.jsonl` (append-only).
    pub fn record_link(&self, entry: &LinkEntry) -> Result<(), SpoolError> {
        use std::io::Write as _;
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut file = opts.open(self.root.join("links.jsonl"))?;
        tighten_file(&self.root.join("links.jsonl"));
        writeln!(
            file,
            "{}",
            serde_json::to_string(entry).expect("LinkEntry serializes")
        )?;
        file.sync_all()?;
        Ok(())
    }

    /// All linked entries in file order.
    pub fn links(&self) -> Result<Vec<LinkEntry>, SpoolError> {
        let text = match std::fs::read_to_string(self.root.join("links.jsonl")) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(SpoolError::Io(e)),
        };
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).map_err(SpoolError::Json))
            .collect()
    }

    /// Read `sessions/<ulid>/link-watermark.json`; `Ok(None)` when the session
    /// was never linked.
    pub fn read_link_watermark(&self, ulid: &str) -> Result<Option<LinkWatermark>, SpoolError> {
        let path = self.known_session_dir(ulid)?.join("link-watermark.json");
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(SpoolError::Io(e)),
        }
    }

    /// Write `sessions/<ulid>/link-watermark.json` atomically (temp + rename).
    pub fn write_link_watermark(
        &self,
        ulid: &str,
        watermark: &LinkWatermark,
    ) -> Result<(), SpoolError> {
        let path = self.known_session_dir(ulid)?.join("link-watermark.json");
        atomic_write(
            &path,
            serde_json::to_vec_pretty(watermark)
                .expect("LinkWatermark serializes")
                .as_slice(),
        )?;
        Ok(())
    }
}
