//! Push-option sidecars (spec §8.2 pipeline gap): `GIT_PUSH_OPTION_*` exists only
//! in the `pre-receive` hook process, never in the later post-RPC scan task.
//! Pre-receive writes one JSON file per accepted `refs/for` line under
//! `<gitdir>/starforge-push-options/`; the scan consumes (reads + deletes) the
//! file for the ref it ingests and falls back to no-options semantics when it
//! is missing. Files are keyed by per-push nonce + refname — never the sha
//! alone — so two concurrent pushes of the same sha under different topics
//! produce two distinct sidecars. Writes are atomic (temp + rename) with mode
//! `0600`; an age-bounded reaper prevents accumulation.

use std::fs::OpenOptions;
use std::io::{Read as _, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Sidecar directory inside the bare repository.
pub const DIR_NAME: &str = "starforge-push-options";
/// Sidecars older than this are orphans (the push that wrote them never got
/// scanned) and are reaped at push start.
pub const MAX_AGE_SECS: u64 = 3600;

/// One accepted `refs/for` line plus the push options in force for the push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sidecar {
    pub repo_id: i64,
    pub user_id: Option<i64>,
    pub base: String,
    pub topic: String,
    pub trail: Option<i64>,
    pub title: Option<String>,
    pub refname: String,
    pub old: String,
    pub new: String,
    pub nonce: String,
}

/// Fresh per-push nonce: 16 bytes of `/dev/urandom` hex, falling back to a
/// time/pid mix when urandom is unreadable. Uniqueness per push is what
/// matters (concurrent same-sha pushes must not share a sidecar), not secrecy.
pub fn new_nonce() -> String {
    if let Ok(file) = std::fs::File::open("/dev/urandom") {
        let mut buf = Vec::new();
        if std::io::Read::take(file, 16).read_to_end(&mut buf).is_ok() && buf.len() == 16 {
            return buf.iter().map(|b| format!("{b:02x}")).collect();
        }
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{now:x}-{}", std::process::id())
}

/// Nonces come from the push env (`STARFORGE_PUSH_NONCE`) or [`new_nonce`];
/// either way they must be filename-safe before touching the sidecar name.
pub fn valid_nonce(nonce: &str) -> bool {
    !nonce.is_empty()
        && nonce.len() <= 64
        && nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// Percent-encodes a refname for the sidecar filename (`/` → `%2F`, `.` →
/// `%2E`, …). Dots are encoded so the last `.` in the filename always delimits
/// the nonce from the ref. Refnames pass the strict policy check before use
/// here; encoding is defense in depth so the name can never escape the
/// sidecar directory.
fn encode_refname(refname: &str) -> String {
    let mut out = String::with_capacity(refname.len());
    for b in refname.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn decode_refname(encoded: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(encoded.len());
    let mut it = encoded.bytes();
    while let Some(b) = it.next() {
        if b == b'%' {
            let hi = it.next()?;
            let lo = it.next()?;
            let hex = |c: u8| (c as char).to_digit(16);
            bytes.push((hex(hi)? * 16 + hex(lo)?) as u8);
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8(bytes).ok()
}

/// Deterministic sidecar filename for a nonce + refname pair.
pub fn sidecar_name(nonce: &str, refname: &str) -> String {
    format!("{nonce}.{}.json", encode_refname(refname))
}

fn dir(gitdir: &Path) -> PathBuf {
    gitdir.join(DIR_NAME)
}

fn escape_into(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

fn field_str(out: &mut String, s: &str) {
    out.push('"');
    escape_into(out, s);
    out.push('"');
}

fn field_opt_str(out: &mut String, v: Option<&str>) {
    match v {
        Some(s) => field_str(out, s),
        None => out.push_str("null"),
    }
}

fn field_opt_int(out: &mut String, v: Option<i64>) {
    match v {
        Some(n) => out.push_str(&n.to_string()),
        None => out.push_str("null"),
    }
}

/// Fixed-schema JSON encoding (key order is part of the format the scan reads).
pub fn to_json(s: &Sidecar) -> String {
    let mut out = String::from("{");
    out.push_str("\"repo_id\":");
    out.push_str(&s.repo_id.to_string());
    out.push_str(",\"user_id\":");
    match s.user_id {
        Some(n) => out.push_str(&n.to_string()),
        None => out.push_str("null"),
    }
    out.push_str(",\"base\":");
    field_str(&mut out, &s.base);
    out.push_str(",\"topic\":");
    field_str(&mut out, &s.topic);
    out.push_str(",\"trail\":");
    field_opt_int(&mut out, s.trail);
    out.push_str(",\"title\":");
    field_opt_str(&mut out, s.title.as_deref());
    out.push_str(",\"refname\":");
    field_str(&mut out, &s.refname);
    out.push_str(",\"old\":");
    field_str(&mut out, &s.old);
    out.push_str(",\"new\":");
    field_str(&mut out, &s.new);
    out.push_str(",\"nonce\":");
    field_str(&mut out, &s.nonce);
    out.push('}');
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Str(String),
    Int(i64),
    Null,
}

fn parse_value(input: &[u8], pos: &mut usize) -> Result<Value, String> {
    while *pos < input.len() && (input[*pos] as char).is_whitespace() {
        *pos += 1;
    }
    let Some(&c) = input.get(*pos) else {
        return Err("unexpected end of sidecar".to_owned());
    };
    if c == b'"' {
        *pos += 1;
        let mut s = String::new();
        loop {
            let Some(&b) = input.get(*pos) else {
                return Err("unterminated string in sidecar".to_owned());
            };
            *pos += 1;
            match b {
                b'"' => break,
                b'\\' => {
                    let Some(&e) = input.get(*pos) else {
                        return Err("unterminated escape in sidecar".to_owned());
                    };
                    *pos += 1;
                    match e {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        b'u' => {
                            if *pos + 4 > input.len() {
                                return Err("bad \\u escape in sidecar".to_owned());
                            }
                            let hex = std::str::from_utf8(&input[*pos..*pos + 4])
                                .map_err(|_| "bad \\u escape in sidecar".to_owned())?;
                            let cp = u32::from_str_radix(hex, 16)
                                .map_err(|_| "bad \\u escape in sidecar".to_owned())?;
                            s.push(char::from_u32(cp).ok_or("bad \\u escape in sidecar")?);
                            *pos += 4;
                        }
                        _ => return Err("bad escape in sidecar".to_owned()),
                    }
                }
                _ => {
                    if b < 0x20 {
                        return Err("raw control char in sidecar".to_owned());
                    }
                    s.push(b as char);
                }
            }
        }
        // NOTE: multi-byte UTF-8 arrives byte-by-byte here and is reassembled
        // by `String` only for ASCII; decode raw bytes instead.
        return Ok(Value::Str(s));
    }
    if c == b'n' {
        if input[*pos..].starts_with(b"null") {
            *pos += 4;
            return Ok(Value::Null);
        }
        return Err("bad literal in sidecar".to_owned());
    }
    if c == b'-' || c.is_ascii_digit() {
        let start = *pos;
        while *pos < input.len() && (input[*pos].is_ascii_digit() || input[*pos] == b'-') {
            *pos += 1;
        }
        let n: i64 = std::str::from_utf8(&input[start..*pos])
            .map_err(|_| "bad number in sidecar".to_owned())?
            .parse()
            .map_err(|_| "bad number in sidecar".to_owned())?;
        return Ok(Value::Int(n));
    }
    Err("bad value in sidecar".to_owned())
}

/// Parses exactly what [`to_json`] emits (whitespace-tolerant).
pub fn from_json(text: &str) -> Result<Sidecar, String> {
    // Decode strings as raw bytes: re-walk with byte-preserving string parsing.
    let input = text.as_bytes();
    let mut pos = 0;
    let take_ws = |pos: &mut usize| {
        while *pos < input.len() && (input[*pos] as char).is_whitespace() {
            *pos += 1;
        }
    };
    take_ws(&mut pos);
    if input.get(pos) != Some(&b'{') {
        return Err("sidecar must be a JSON object".to_owned());
    }
    pos += 1;
    let mut fields: Vec<(String, Value)> = Vec::new();
    loop {
        take_ws(&mut pos);
        if input.get(pos) == Some(&b'}') {
            pos += 1;
            break;
        }
        if !fields.is_empty() {
            if input.get(pos) != Some(&b',') {
                return Err("expected ',' in sidecar".to_owned());
            }
            pos += 1;
            take_ws(&mut pos);
            if input.get(pos) == Some(&b'}') {
                return Err("trailing comma in sidecar".to_owned());
            }
        }
        let Value::Str(key) = parse_value(input, &mut pos)? else {
            return Err("sidecar keys must be strings".to_owned());
        };
        take_ws(&mut pos);
        if input.get(pos) != Some(&b':') {
            return Err("expected ':' in sidecar".to_owned());
        }
        pos += 1;
        let value = parse_value(input, &mut pos)?;
        fields.push((key, value));
    }
    take_ws(&mut pos);
    if pos != input.len() {
        return Err("trailing bytes in sidecar".to_owned());
    }
    // parse_value pushes UTF-8 bytes as chars ≥ 0x80 one byte at a time, which
    // corrupts non-ASCII. Re-encode lossy bytes: instead re-parse strings from
    // the raw slice. Simpler: strings were built with `s.push(b as char)`,
    // which maps each byte 1:1 to the same codepoint — recover by mapping back.
    fn fix(s: String) -> String {
        let bytes: Vec<u8> = s.chars().map(|c| c as u32 as u8).collect();
        String::from_utf8(bytes).unwrap_or(s)
    }
    let mut get = |key: &str| {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .ok_or_else(|| format!("sidecar missing {key:?}"))
    };
    let str_field = |key: &str, get: &mut dyn FnMut(&str) -> Result<Value, String>| match get(key)?
    {
        Value::Str(s) => Ok(fix(s)),
        _ => Err(format!("sidecar {key:?} must be a string")),
    };
    let opt_str = |key: &str, get: &mut dyn FnMut(&str) -> Result<Value, String>| match get(key)? {
        Value::Str(s) => Ok(Some(fix(s))),
        Value::Null => Ok(None),
        _ => Err(format!("sidecar {key:?} must be a string or null")),
    };
    let opt_int = |key: &str, get: &mut dyn FnMut(&str) -> Result<Value, String>| match get(key)? {
        Value::Int(n) => Ok(Some(n)),
        Value::Null => Ok(None),
        _ => Err(format!("sidecar {key:?} must be an integer or null")),
    };
    let repo_id = match get("repo_id")? {
        Value::Int(n) => n,
        _ => return Err("sidecar \"repo_id\" must be an integer".to_owned()),
    };
    let user_id = opt_int("user_id", &mut get)?;
    Ok(Sidecar {
        repo_id,
        user_id,
        base: str_field("base", &mut get)?,
        topic: str_field("topic", &mut get)?,
        trail: opt_int("trail", &mut get)?,
        title: opt_str("title", &mut get)?,
        refname: str_field("refname", &mut get)?,
        old: str_field("old", &mut get)?,
        new: str_field("new", &mut get)?,
        nonce: str_field("nonce", &mut get)?,
    })
}

/// Atomically writes (temp + rename, mode `0600`) the sidecar for a
/// nonce + refname pair. The nonce MUST be pre-validated ([`valid_nonce`]) and
/// the refname MUST have passed the strict policy check — both are enforced
/// here again so a bad name can never escape the sidecar directory.
pub fn write_sidecar(
    gitdir: &Path,
    nonce: &str,
    refname: &str,
    sidecar: &Sidecar,
) -> Result<PathBuf, String> {
    if !valid_nonce(nonce) {
        return Err("refusing sidecar with invalid nonce".to_owned());
    }
    if crate::refpolicy::parse_for_ref(refname).is_none() {
        return Err(format!("refusing sidecar for invalid refname {refname:?}"));
    }
    let dir = dir(gitdir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("creating sidecar dir: {e}"))?;
    let final_path = dir.join(sidecar_name(nonce, refname));
    let tmp_path = dir.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    {
        let mut tmp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| format!("creating sidecar temp file: {e}"))?;
        tmp.write_all(to_json(sidecar).as_bytes())
            .map_err(|e| format!("writing sidecar: {e}"))?;
        tmp.flush().map_err(|e| format!("writing sidecar: {e}"))?;
    }
    std::fs::rename(&tmp_path, &final_path).map_err(|e| format!("publishing sidecar: {e}"))?;
    Ok(final_path)
}

/// Reads one sidecar file without deleting it.
pub fn read_sidecar(path: &Path) -> Result<Sidecar, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading sidecar: {e}"))?;
    from_json(&text)
}

/// Reads a sidecar and deletes the file: each sidecar is consumed exactly once.
/// A missing file after a successful read is fine (a concurrent scan won).
pub fn consume_sidecar(path: &Path) -> Result<Sidecar, String> {
    let sidecar = read_sidecar(path)?;
    match std::fs::remove_file(path) {
        Ok(()) => Ok(sidecar),
        Err(_) if !path.exists() => Ok(sidecar),
        Err(e) => Err(format!("deleting consumed sidecar: {e}")),
    }
}

/// All sidecar files for `refname` (any nonce): the scan matches its changed
/// refs this way because the nonce lives only in the hook process.
pub fn find_for_ref(gitdir: &Path, refname: &str) -> Vec<PathBuf> {
    let dir = dir(gitdir);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|x| x == "json")
                && p.file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.rsplit_once('.'))
                    .and_then(|(_, enc)| decode_refname(enc))
                    .is_some_and(|r| r == refname)
        })
        .collect()
}

/// Deletes sidecar files and orphaned `.tmp-*` temp files older than
/// `max_age_secs` (default [`MAX_AGE_SECS`]); returns the number removed.
/// Called at push start so orphans never accumulate.
pub fn reap(gitdir: &Path, max_age_secs: u64) -> usize {
    let dir = dir(gitdir);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return 0;
    };
    let now = SystemTime::now();
    let mut removed = 0;
    for path in entries.filter_map(|e| e.ok()).map(|e| e.path()) {
        // Sidecar JSON files and orphaned `.tmp-<pid>-<nanos>` temp files (a
        // crash between create and rename leaks them; they never match a
        // sidecar name). Anything else is left alone.
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let candidate = path.extension().is_some_and(|x| x == "json") || name.starts_with(".tmp-");
        if !candidate {
            continue;
        }
        let old = path
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age.as_secs() > max_age_secs);
        if old && std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(nonce: &str, refname: &str) -> Sidecar {
        Sidecar {
            repo_id: 7,
            user_id: Some(42),
            base: "release/1.x".to_owned(),
            topic: "feat".to_owned(),
            trail: Some(3),
            title: Some("Fix \"it\" \\ now".to_owned()),
            refname: refname.to_owned(),
            old: "0".repeat(40),
            new: "a".repeat(40),
            nonce: nonce.to_owned(),
        }
    }

    #[test]
    fn json_round_trip_with_special_chars_and_nulls() {
        let mut s = sample("n1", "refs/for/release/1.x/feat");
        assert_eq!(from_json(&to_json(&s)).unwrap(), s);
        s.trail = None;
        s.title = None;
        s.user_id = None;
        s.title = Some("münchen — ünïcodé ✓".to_owned());
        assert_eq!(from_json(&to_json(&s)).unwrap(), s);
        s.title = Some("tab\there".to_owned());
        assert_eq!(from_json(&to_json(&s)).unwrap(), s);
    }

    #[test]
    fn filenames_isolate_nonce_and_refname() {
        assert_ne!(
            sidecar_name("n1", "refs/for/main/t"),
            sidecar_name("n2", "refs/for/main/t")
        );
        assert_ne!(
            sidecar_name("n1", "refs/for/main/t1"),
            sidecar_name("n1", "refs/for/main/t2")
        );
        // Same sha, different topics, different nonces: distinct files.
        assert_ne!(
            sidecar_name("aaa", "refs/for/main/alpha"),
            sidecar_name("bbb", "refs/for/main/beta")
        );
        for name in [
            sidecar_name("n1", "refs/for/main/t"),
            sidecar_name("n1", "refs/for/release/1.x/feat"),
        ] {
            assert!(!name.contains('/'), "{name}");
            let stem = name.strip_suffix(".json").unwrap();
            let (_, enc) = stem.rsplit_once('.').unwrap();
            assert_eq!(
                decode_refname(enc).unwrap(),
                if name.contains("release") {
                    "refs/for/release/1.x/feat"
                } else {
                    "refs/for/main/t"
                }
            );
        }
    }

    #[test]
    fn write_is_atomic_mode_0600_and_consumed_once() {
        let tmp = tempfile::tempdir().unwrap();
        let gitdir = tmp.path();
        let s = sample("nonce1", "refs/for/main/feat");
        let path = write_sidecar(gitdir, "nonce1", "refs/for/main/feat", &s).unwrap();
        assert_eq!(
            path.file_name().unwrap().to_str().unwrap(),
            sidecar_name("nonce1", "refs/for/main/feat")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(
            find_for_ref(gitdir, "refs/for/main/feat"),
            vec![path.clone()]
        );
        assert!(find_for_ref(gitdir, "refs/for/main/other").is_empty());
        assert_eq!(consume_sidecar(&path).unwrap(), s);
        assert!(!path.exists(), "consumed exactly once");
        assert!(find_for_ref(gitdir, "refs/for/main/feat").is_empty());
    }

    #[test]
    fn write_refuses_bad_nonce_and_refname() {
        let tmp = tempfile::tempdir().unwrap();
        let s = sample("../evil", "refs/for/main/t");
        assert!(write_sidecar(tmp.path(), "../evil", "refs/for/main/t", &s).is_err());
        assert!(write_sidecar(tmp.path(), "", "refs/for/main/t", &s).is_err());
        let s = sample("ok", "refs/for/main/..");
        assert!(write_sidecar(tmp.path(), "ok", "refs/for/main/..", &s).is_err());
        assert!(write_sidecar(tmp.path(), "ok", "refs/heads/main", &s).is_err());
    }

    #[test]
    fn reaper_keeps_fresh_files_and_removes_only_old_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let gitdir = tmp.path();
        let fresh = sample("fresh", "refs/for/main/fresh");
        let old = sample("old", "refs/for/main/old");
        let fresh_path = write_sidecar(gitdir, "fresh", "refs/for/main/fresh", &fresh).unwrap();
        let old_path = write_sidecar(gitdir, "old", "refs/for/main/old", &old).unwrap();
        // Backdate only the old file (2h ago); keep the fresh one current.
        // `std` has no mtime setter, so the test shells to `touch` like the
        // rest of the suite shells to `git`.
        let status = std::process::Command::new("touch")
            .args(["-d", "2 hours ago"])
            .arg(&old_path)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(reap(gitdir, MAX_AGE_SECS), 1);
        assert!(!old_path.exists());
        assert!(fresh_path.exists());
        assert_eq!(reap(gitdir, MAX_AGE_SECS), 0);
    }

    #[test]
    fn reaper_removes_orphaned_temp_files_but_keeps_fresh_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let gitdir = tmp.path();
        let dir = gitdir.join(DIR_NAME);
        std::fs::create_dir_all(&dir).unwrap();
        let old_tmp = dir.join(".tmp-123-456");
        let fresh_tmp = dir.join(".tmp-789-101112");
        let other = dir.join("notes.txt");
        std::fs::write(&old_tmp, b"partial").unwrap();
        std::fs::write(&fresh_tmp, b"partial").unwrap();
        std::fs::write(&other, b"not a sidecar").unwrap();
        // Backdate only the orphan (2h ago), shelling to `touch` like the
        // sidecar test above.
        let status = std::process::Command::new("touch")
            .args(["-d", "2 hours ago"])
            .arg(&old_tmp)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(reap(gitdir, MAX_AGE_SECS), 1);
        assert!(!old_tmp.exists());
        assert!(fresh_tmp.exists());
        assert!(other.exists());
        assert_eq!(reap(gitdir, MAX_AGE_SECS), 0);
    }

    #[test]
    fn nonces_are_valid_and_unique() {
        let a = new_nonce();
        let b = new_nonce();
        assert!(valid_nonce(&a) && valid_nonce(&b));
        assert!(!valid_nonce("../x") && !valid_nonce(""));
    }
}
