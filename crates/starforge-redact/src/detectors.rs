//! Built-in secret detectors.
//!
//! Each detector scans free text for one secret shape and reports byte
//! spans ([`Match`]) on character boundaries. Detectors are the public
//! extension point: implement [`Detector`] to add a new shape without
//! touching the engine.
//!
//! # Overlap rule
//!
//! When matches from different detectors (or rules) overlap, the engine
//! keeps the **longest** match; ties break by **detector order** — the
//! built-in order below, then custom rules in [`RuleSet`](crate::RuleSet)
//! declaration order. A kept match suppresses every match it overlaps, so
//! one redaction increments exactly one counter.
//!
//! Built-in detector order (also the tie-break order):
//! `private-key`, `cloud-credential`, `known-token`, `credentialed-url`,
//! `connection-string`, `authorization`, `high-entropy`, `email`, `phone`.

use regex::Regex;

/// One suspicious span: byte indices into the scanned text.
///
/// Both indices always land on UTF-8 character boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    /// Byte offset where the span starts (inclusive).
    pub start: usize,
    /// Byte offset where the span ends (exclusive).
    pub end: usize,
}

impl Match {
    /// Build a match; panics in debug builds if either bound splits a char.
    pub fn new(start: usize, end: usize, haystack: &str) -> Self {
        debug_assert!(
            haystack.is_char_boundary(start),
            "match start splits a char"
        );
        debug_assert!(haystack.is_char_boundary(end), "match end splits a char");
        Self { start, end }
    }

    /// Length of the span in bytes.
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether the span is empty.
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

/// A reusable secret-shape scanner.
///
/// Implementations must be deterministic (same input yields the same
/// matches) and must only return [`Match`]es on character boundaries.
/// Returning an empty span is allowed; the engine ignores it.
pub trait Detector: Send + Sync {
    /// Kebab-case id used in `[redacted:<id>]` replacements and counters.
    fn id(&self) -> &'static str;
    /// Whether hits are precise enough to treat as secrets with confidence.
    fn high_confidence(&self) -> bool;
    /// All non-overlapping-or-not spans of this shape in `haystack`.
    fn find(&self, haystack: &str) -> Vec<Match>;
}

/// Built-in detector ids in tie-break order.
pub const BUILT_IN_ORDER: [&str; 9] = [
    "private-key",
    "cloud-credential",
    "known-token",
    "credentialed-url",
    "connection-string",
    "authorization",
    "high-entropy",
    "email",
    "phone",
];

fn all_matches(re: &Regex, haystack: &str) -> Vec<Match> {
    re.find_iter(haystack)
        .map(|m| Match::new(m.start(), m.end(), haystack))
        .collect()
}

fn group_matches(re: &Regex, group: usize, haystack: &str) -> Vec<Match> {
    re.captures_iter(haystack)
        .filter_map(|c| c.get(group))
        .map(|m| Match::new(m.start(), m.end(), haystack))
        .collect()
}

fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).expect("built-in detector pattern must compile")
}

/// PEM-armored private key (`-----BEGIN … PRIVATE KEY-----` + body).
pub struct PrivateKeyDetector {
    re: Regex,
}

impl PrivateKeyDetector {
    pub fn new() -> Self {
        Self {
            re: compile(
                "(?s)-----BEGIN [A-Za-z0-9 ]*PRIVATE KEY-----.*?-----END [A-Za-z0-9 ]*PRIVATE KEY-----",
            ),
        }
    }
}

impl Default for PrivateKeyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for PrivateKeyDetector {
    fn id(&self) -> &'static str {
        "private-key"
    }

    fn high_confidence(&self) -> bool {
        true
    }

    fn find(&self, haystack: &str) -> Vec<Match> {
        all_matches(&self.re, haystack)
    }
}

/// Cloud credentials: AWS access-key ids (`AKIA…`), AWS secret assignments,
/// and GCP service-account markers.
pub struct CloudCredentialDetector {
    res: Vec<Regex>,
}

impl CloudCredentialDetector {
    pub fn new() -> Self {
        Self {
            res: vec![
                compile("AKIA[0-9A-Z]{16}"),
                compile(
                    "(?i)(?:aws_secret_access_key|aws_secret|secret_access_key)\\s*[:=]\\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?",
                ),
                compile("\"type\"\\s*:\\s*\"service_account\""),
            ],
        }
    }
}

impl Default for CloudCredentialDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for CloudCredentialDetector {
    fn id(&self) -> &'static str {
        "cloud-credential"
    }

    fn high_confidence(&self) -> bool {
        true
    }

    fn find(&self, haystack: &str) -> Vec<Match> {
        self.res
            .iter()
            .flat_map(|re| all_matches(re, haystack))
            .collect()
    }
}

/// Well-known token prefixes with minimum-length checks.
pub struct KnownTokenDetector {
    re: Regex,
}

impl KnownTokenDetector {
    pub fn new() -> Self {
        Self {
            re: compile(
                "gh[opurs]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-ant-[A-Za-z0-9-]{20,}|sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{36,}|pypi-[A-Za-z0-9_-]{10,}",
            ),
        }
    }
}

impl Default for KnownTokenDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for KnownTokenDetector {
    fn id(&self) -> &'static str {
        "known-token"
    }

    fn high_confidence(&self) -> bool {
        true
    }

    fn find(&self, haystack: &str) -> Vec<Match> {
        all_matches(&self.re, haystack)
    }
}

/// `scheme://user:password@host`: only the `user:password` authority part is
/// reported so the host/path survive redaction.
pub struct CredentialedUrlDetector {
    re: Regex,
}

impl CredentialedUrlDetector {
    pub fn new() -> Self {
        Self {
            re: compile("://([^/\\s:@]+:[^/\\s@]+)@"),
        }
    }
}

impl Default for CredentialedUrlDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for CredentialedUrlDetector {
    fn id(&self) -> &'static str {
        "credentialed-url"
    }

    fn high_confidence(&self) -> bool {
        false
    }

    fn find(&self, haystack: &str) -> Vec<Match> {
        group_matches(&self.re, 1, haystack)
    }
}

/// ADO-style `Password=`/`Pwd=` assignments and `mongodb(+srv)://` URIs.
pub struct ConnectionStringDetector {
    res: Vec<Regex>,
}

impl ConnectionStringDetector {
    pub fn new() -> Self {
        Self {
            res: vec![
                compile("(?i)(?:Password|Pwd)\\s*=\\s*[^;\\s\"']+"),
                compile("mongodb(\\+srv)?://\\S+"),
            ],
        }
    }
}

impl Default for ConnectionStringDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ConnectionStringDetector {
    fn id(&self) -> &'static str {
        "connection-string"
    }

    fn high_confidence(&self) -> bool {
        false
    }

    fn find(&self, haystack: &str) -> Vec<Match> {
        self.res
            .iter()
            .flat_map(|re| all_matches(re, haystack))
            .collect()
    }
}

/// `Authorization: <scheme> <secret>` header values and bare
/// `Bearer <secret>` tokens. The longer header match wins over the bare
/// token it contains via the longest-first overlap rule.
pub struct AuthorizationDetector {
    res: Vec<Regex>,
}

impl AuthorizationDetector {
    pub fn new() -> Self {
        Self {
            res: vec![
                compile("(?i)Authorization\\s*:\\s*(?:Bearer|Basic|Token)\\s+\\S+"),
                compile("(?i)\\bBearer\\s+[A-Za-z0-9._~+/-]{6,}={0,3}"),
            ],
        }
    }
}

impl Default for AuthorizationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for AuthorizationDetector {
    fn id(&self) -> &'static str {
        "authorization"
    }

    fn high_confidence(&self) -> bool {
        false
    }

    fn find(&self, haystack: &str) -> Vec<Match> {
        self.res
            .iter()
            .flat_map(|re| all_matches(re, haystack))
            .collect()
    }
}

/// Shannon entropy of a token in bits per character.
pub fn shannon_entropy(token: &str) -> f64 {
    let mut counts = [0u64; 256];
    let mut len = 0u64;
    for b in token.bytes() {
        counts[b as usize] += 1;
        len += 1;
    }
    if len == 0 {
        return 0.0;
    }
    let n = len as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// High-entropy blobs: tokens of at least `min_len` characters from
/// `[A-Za-z0-9+/=_.-]` with Shannon entropy at or above `threshold`
/// bits per character. Defaults are 20 characters and 4.5 bits.
pub struct HighEntropyDetector {
    re: Regex,
    min_len: usize,
    threshold: f64,
}

impl HighEntropyDetector {
    pub fn new() -> Self {
        Self::with_config(20, 4.5)
    }

    pub fn with_config(min_len: usize, threshold: f64) -> Self {
        Self {
            re: compile(&format!("[A-Za-z0-9+/=_.-]{{{min_len},}}")),
            min_len,
            threshold,
        }
    }

    pub fn min_len(&self) -> usize {
        self.min_len
    }

    pub fn threshold(&self) -> f64 {
        self.threshold
    }
}

impl Default for HighEntropyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for HighEntropyDetector {
    fn id(&self) -> &'static str {
        "high-entropy"
    }

    fn high_confidence(&self) -> bool {
        false
    }

    fn find(&self, haystack: &str) -> Vec<Match> {
        all_matches(&self.re, haystack)
            .into_iter()
            .filter(|m| shannon_entropy(&haystack[m.start..m.end]) >= self.threshold)
            .collect()
    }
}

/// Email addresses. Off by default; enable via the `[pii]` rules section.
pub struct EmailDetector {
    re: Regex,
}

impl EmailDetector {
    pub fn new() -> Self {
        Self {
            re: compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"),
        }
    }
}

impl Default for EmailDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for EmailDetector {
    fn id(&self) -> &'static str {
        "email"
    }

    fn high_confidence(&self) -> bool {
        false
    }

    fn find(&self, haystack: &str) -> Vec<Match> {
        all_matches(&self.re, haystack)
            .into_iter()
            .filter(|m| {
                // Skip matches whose domain starts/ends with a separator.
                let s = &haystack[m.start..m.end];
                !s.contains("..") && !s.ends_with(['.', '-', '@'])
            })
            .collect()
    }
}

/// Phone numbers. Off by default; enable via the `[pii]` rules section.
pub struct PhoneDetector {
    re: Regex,
}

impl PhoneDetector {
    pub fn new() -> Self {
        Self {
            re: compile("\\+?[0-9][0-9\\s().-]{7,}[0-9]"),
        }
    }
}

impl Default for PhoneDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for PhoneDetector {
    fn id(&self) -> &'static str {
        "phone"
    }

    fn high_confidence(&self) -> bool {
        false
    }

    fn find(&self, haystack: &str) -> Vec<Match> {
        all_matches(&self.re, haystack)
            .into_iter()
            .filter(|m| {
                // Require at least 7 digits so short numeric runs pass through.
                haystack[m.start..m.end]
                    .bytes()
                    .filter(|b| b.is_ascii_digit())
                    .count()
                    >= 7
            })
            .collect()
    }
}
