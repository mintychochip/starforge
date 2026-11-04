//! Rule sets, the precompiled form, plain-text redaction, and fingerprinting.
//!
//! A [`RuleSet`] is the serializable configuration: built-in detectors,
//! literal strings, and custom `[[pattern]]` regexes plus the `[pii]` and
//! `[entropy]` tunables from `.starforge/redact.toml`. [`RuleSet::compile`]
//! precompiles every regex once into a [`Compiled`] set; all public
//! redaction functions take `&Compiled` so hot paths never recompile.
//!
//! Replacement text is exactly `[redacted:<id>]` where `<id>` is the
//! detector or rule id. Literal rules share the id `literal`; custom
//! patterns use their configured id.
//!
//! # Fingerprint encoding
//!
//! [`fingerprint`] hashes the canonical record list with BLAKE3 and returns
//! lowercase hex. Records, sorted byte-wise and joined with no separator
//! (each record already ends in `\0`):
//!
//! - per built-in detector: `<id>\0<pattern-source>\0<threshold>\0`,
//!   where `<threshold>` is `<min_len>:<threshold>` for `high-entropy`
//!   (from the rule set's entropy config) and empty otherwise;
//! - per literal: `literal:<text>\0<text>\0\0`;
//! - per custom pattern: `<id>\0<regex>\0\0`;
//! - entropy config: `entropy\0<min_len>\0<threshold>\0`;
//! - PII toggles: `pii:email\0<on|off>\0\0` and `pii:phone\0<on|off>\0\0`.
//!
//! Same rules in any order hash identically; any rule, toggle, or entropy
//! change alters the hash.
//!
//! # Safety notes
//!
//! Patterns run on the `regex` crate, which guarantees linear-time matching
//! (no backtracking engine), so a hostile custom pattern cannot hang the
//! scanner with catastrophic backtracking; it can still match more text
//! than intended, so review custom patterns. (M1c may add timeouts.)
//!
//! Everything here is pure: no filesystem, no network, no clock. Same
//! input yields byte-identical output.

use std::collections::BTreeMap;

use regex::Regex;
use serde::Deserialize;
use thiserror::Error;

use crate::detectors::{
    AuthorizationDetector, CloudCredentialDetector, ConnectionStringDetector,
    CredentialedUrlDetector, Detector, EmailDetector, HighEntropyDetector, KnownTokenDetector,
    Match, PhoneDetector, PrivateKeyDetector,
};

/// Id of a built-in detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuiltInId {
    PrivateKey,
    CloudCredential,
    KnownToken,
    CredentialedUrl,
    ConnectionString,
    Authorization,
    HighEntropy,
    Email,
    Phone,
}

impl BuiltInId {
    /// Kebab-case id used in replacements, counters, and fingerprints.
    pub fn id(self) -> &'static str {
        match self {
            Self::PrivateKey => "private-key",
            Self::CloudCredential => "cloud-credential",
            Self::KnownToken => "known-token",
            Self::CredentialedUrl => "credentialed-url",
            Self::ConnectionString => "connection-string",
            Self::Authorization => "authorization",
            Self::HighEntropy => "high-entropy",
            Self::Email => "email",
            Self::Phone => "phone",
        }
    }

    /// Look up a built-in by its kebab-case id.
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "private-key" => Some(Self::PrivateKey),
            "cloud-credential" => Some(Self::CloudCredential),
            "known-token" => Some(Self::KnownToken),
            "credentialed-url" => Some(Self::CredentialedUrl),
            "connection-string" => Some(Self::ConnectionString),
            "authorization" => Some(Self::Authorization),
            "high-entropy" => Some(Self::HighEntropy),
            "email" => Some(Self::Email),
            "phone" => Some(Self::Phone),
            _ => None,
        }
    }

    /// All built-ins in tie-break order.
    pub fn all() -> [Self; 9] {
        [
            Self::PrivateKey,
            Self::CloudCredential,
            Self::KnownToken,
            Self::CredentialedUrl,
            Self::ConnectionString,
            Self::Authorization,
            Self::HighEntropy,
            Self::Email,
            Self::Phone,
        ]
    }

    /// Canonical pattern source for fingerprinting.
    fn pattern_source(self) -> &'static str {
        match self {
            Self::PrivateKey => {
                "(?s)-----BEGIN [A-Za-z0-9 ]*PRIVATE KEY-----.*?-----END [A-Za-z0-9 ]*PRIVATE KEY-----"
            }
            Self::CloudCredential => {
                "AKIA[0-9A-Z]{16}|aws-secret-assign|\"type\":\"service_account\""
            }
            Self::KnownToken => {
                "gh[opurs]_|github_pat_|xox[baprs]-|sk-ant-|sk-|AIza|glpat-|npm_|pypi-"
            }
            Self::CredentialedUrl => "://(user:password)@",
            Self::ConnectionString => "(Password|Pwd)=|mongodb(+srv)://",
            Self::Authorization => "Authorization:<scheme> <secret>|Bearer <secret>",
            Self::HighEntropy => "shannon-entropy [A-Za-z0-9+/=_.-]",
            Self::Email => "email-address",
            Self::Phone => "phone-number",
        }
    }

    fn build(self, entropy_min_len: usize, entropy_threshold: f64) -> Box<dyn Detector> {
        match self {
            Self::PrivateKey => Box::new(PrivateKeyDetector::new()),
            Self::CloudCredential => Box::new(CloudCredentialDetector::new()),
            Self::KnownToken => Box::new(KnownTokenDetector::new()),
            Self::CredentialedUrl => Box::new(CredentialedUrlDetector::new()),
            Self::ConnectionString => Box::new(ConnectionStringDetector::new()),
            Self::Authorization => Box::new(AuthorizationDetector::new()),
            Self::HighEntropy => Box::new(HighEntropyDetector::with_config(
                entropy_min_len,
                entropy_threshold,
            )),
            Self::Email => Box::new(EmailDetector::new()),
            Self::Phone => Box::new(PhoneDetector::new()),
        }
    }
}

/// One redaction rule.
#[derive(Debug, Clone, PartialEq)]
pub enum Rule {
    /// A built-in detector by id.
    Detector(BuiltInId),
    /// A verbatim string; redacted under the shared id `literal`.
    Literal(String),
    /// A custom regex with its own id.
    Pattern {
        /// Counter key and `<id>` in `[redacted:<id>]`.
        id: String,
        /// Rust `regex` syntax (linear-time engine, no backtracking).
        regex: String,
    },
}

/// Serializable redaction configuration.
///
/// The scalar settings are `Option`s so a parsed file can distinguish
/// "absent" (`None`, inherit from the lower-precedence set) from
/// "explicitly set" (`Some`, wins on merge). [`RuleSet::built_in`] fills
/// every setting; [`RuleSet::parse_toml`] leaves omitted sections as
/// `None`; [`RuleSet::merge`] keeps `other`'s value when it is `Some` and
/// otherwise inherits `self`'s. Compilation and fingerprinting resolve
/// `None` to the defaults (PII off, 20 characters, 4.5 bits).
#[derive(Debug, Clone, PartialEq)]
pub struct RuleSet {
    /// Rules in match-priority order (built-ins first after a merge).
    pub detectors: Vec<Rule>,
    /// Whether the `email` detector runs (`None` = inherit).
    pub pii_email: Option<bool>,
    /// Whether the `phone` detector runs (`None` = inherit).
    pub pii_phone: Option<bool>,
    /// High-entropy token minimum length (`None` = inherit).
    pub entropy_min_len: Option<usize>,
    /// High-entropy Shannon threshold in bits per character (`None` = inherit).
    pub entropy_threshold: Option<f64>,
}

impl Default for RuleSet {
    /// Empty overlay: no rules, every setting unset (inherits on merge).
    fn default() -> Self {
        Self {
            detectors: Vec::new(),
            pii_email: None,
            pii_phone: None,
            entropy_min_len: None,
            entropy_threshold: None,
        }
    }
}

/// Rule configuration failures.
#[derive(Debug, Error)]
pub enum RuleError {
    /// The TOML did not parse.
    #[error("invalid redact.toml: {0}")]
    Toml(#[from] toml::de::Error),
    /// A custom pattern did not compile.
    #[error("bad regex for rule `{id}`: {source}")]
    BadRegex {
        /// Rule id from the `[[pattern]]` entry.
        id: String,
        /// Underlying regex error.
        source: regex::Error,
    },
    /// The entropy threshold (or minimum length) is out of range.
    #[error("bad entropy threshold {value}: must be within (0, 8] with min_len >= 1")]
    BadThreshold {
        /// Rejected threshold value.
        value: f64,
    },
}

#[derive(Debug, Default, Deserialize)]
struct TomlRules {
    #[serde(default)]
    pii: TomlPii,
    #[serde(default)]
    entropy: TomlEntropy,
    #[serde(default)]
    pattern: Vec<TomlPattern>,
}

#[derive(Debug, Default, Deserialize)]
struct TomlPii {
    #[serde(default)]
    email: Option<bool>,
    #[serde(default)]
    phone: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct TomlEntropy {
    #[serde(default)]
    min_len: Option<usize>,
    #[serde(default)]
    threshold: Option<f64>,
    #[serde(default)]
    literals: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TomlPattern {
    #[serde(default)]
    id: String,
    #[serde(default)]
    regex: String,
}

impl RuleSet {
    /// The default set: the seven non-PII built-in detectors, PII off,
    /// entropy at 20 characters / 4.5 bits (all settings explicitly set).
    pub fn built_in() -> Self {
        Self {
            detectors: vec![
                Rule::Detector(BuiltInId::PrivateKey),
                Rule::Detector(BuiltInId::CloudCredential),
                Rule::Detector(BuiltInId::KnownToken),
                Rule::Detector(BuiltInId::CredentialedUrl),
                Rule::Detector(BuiltInId::ConnectionString),
                Rule::Detector(BuiltInId::Authorization),
                Rule::Detector(BuiltInId::HighEntropy),
            ],
            pii_email: Some(false),
            pii_phone: Some(false),
            entropy_min_len: Some(20),
            entropy_threshold: Some(4.5),
        }
    }

    /// Effective `email` toggle, resolving an unset value to off.
    pub fn effective_pii_email(&self) -> bool {
        self.pii_email.unwrap_or(false)
    }

    /// Effective `phone` toggle, resolving an unset value to off.
    pub fn effective_pii_phone(&self) -> bool {
        self.pii_phone.unwrap_or(false)
    }

    /// Effective entropy minimum length, resolving an unset value to 20.
    pub fn effective_entropy_min_len(&self) -> usize {
        self.entropy_min_len.unwrap_or(20)
    }

    /// Effective entropy threshold, resolving an unset value to 4.5.
    pub fn effective_entropy_threshold(&self) -> f64 {
        self.entropy_threshold.unwrap_or(4.5)
    }

    /// Parse the `.starforge/redact.toml` grammar (`[pii]`, `[entropy]` with
    /// `literals`, and `[[pattern]]` entries). Omitted sections stay
    /// `None` so a later [`RuleSet::merge`] inherits rather than resets.
    pub fn parse_toml(text: &str) -> Result<Self, RuleError> {
        let parsed: TomlRules = toml::from_str(text)?;
        if let Some(threshold) = parsed.entropy.threshold
            && !(threshold > 0.0 && threshold <= 8.0)
        {
            return Err(RuleError::BadThreshold { value: threshold });
        }
        if let Some(min_len) = parsed.entropy.min_len
            && min_len < 1
        {
            return Err(RuleError::BadThreshold {
                value: min_len as f64,
            });
        }
        let mut detectors =
            Vec::with_capacity(parsed.entropy.literals.len() + parsed.pattern.len());
        for literal in parsed.entropy.literals {
            if !literal.is_empty() {
                detectors.push(Rule::Literal(literal));
            }
        }
        for p in parsed.pattern {
            Regex::new(&p.regex).map_err(|source| RuleError::BadRegex {
                id: p.id.clone(),
                source,
            })?;
            detectors.push(Rule::Pattern {
                id: p.id,
                regex: p.regex,
            });
        }
        Ok(Self {
            detectors,
            pii_email: parsed.pii.email,
            pii_phone: parsed.pii.phone,
            entropy_min_len: parsed.entropy.min_len,
            entropy_threshold: parsed.entropy.threshold,
        })
    }

    /// Order-preserving concat of rule lists (`self` then `other`) where a
    /// setting set (`Some`) in `other` wins and an unset (`None`) one
    /// inherits `self`'s. Absent TOML sections therefore never reset a
    /// lower-precedence file's toggles. Precedence across files is decided
    /// by the caller (M1c).
    pub fn merge(&self, other: &Self) -> Self {
        let mut detectors = self.detectors.clone();
        detectors.extend(other.detectors.iter().cloned());
        Self {
            detectors,
            pii_email: other.pii_email.or(self.pii_email),
            pii_phone: other.pii_phone.or(self.pii_phone),
            entropy_min_len: other.entropy_min_len.or(self.entropy_min_len),
            entropy_threshold: other.entropy_threshold.or(self.entropy_threshold),
        }
    }

    /// Precompile every regex once. Custom patterns are re-validated so a
    /// hand-built set with a bad regex fails here instead of panicking.
    /// Unset settings resolve to the defaults (PII off, 20 / 4.5).
    pub fn compile(&self) -> Result<Compiled, RuleError> {
        // PII detectors named explicitly still obey their toggle.
        let has = |id: BuiltInId| self.detectors.contains(&Rule::Detector(id));
        let min_len = self.effective_entropy_min_len();
        let threshold = self.effective_entropy_threshold();
        let email_on = self.effective_pii_email();
        let phone_on = self.effective_pii_phone();
        let mut entries = Vec::with_capacity(self.detectors.len() + 2);
        for rule in &self.detectors {
            match rule {
                Rule::Detector(id) => {
                    if matches!(id, BuiltInId::Email) && !email_on {
                        continue;
                    }
                    if matches!(id, BuiltInId::Phone) && !phone_on {
                        continue;
                    }
                    entries.push(CompiledEntry {
                        id: id.id().to_string(),
                        high_confidence: matches!(
                            id,
                            BuiltInId::PrivateKey
                                | BuiltInId::CloudCredential
                                | BuiltInId::KnownToken
                        ),
                        kind: EntryKind::BuiltIn(id.build(min_len, threshold)),
                    });
                }
                Rule::Literal(literal) => entries.push(CompiledEntry {
                    id: "literal".to_string(),
                    high_confidence: true,
                    kind: EntryKind::Literal(literal.clone()),
                }),
                Rule::Pattern { id, regex } => {
                    let re = Regex::new(regex).map_err(|source| RuleError::BadRegex {
                        id: id.clone(),
                        source,
                    })?;
                    entries.push(CompiledEntry {
                        id: id.clone(),
                        high_confidence: false,
                        kind: EntryKind::Pattern(re),
                    });
                }
            }
        }
        if email_on && !has(BuiltInId::Email) {
            entries.push(CompiledEntry {
                id: BuiltInId::Email.id().to_string(),
                high_confidence: false,
                kind: EntryKind::BuiltIn(BuiltInId::Email.build(min_len, threshold)),
            });
        }
        if phone_on && !has(BuiltInId::Phone) {
            entries.push(CompiledEntry {
                id: BuiltInId::Phone.id().to_string(),
                high_confidence: false,
                kind: EntryKind::BuiltIn(BuiltInId::Phone.build(min_len, threshold)),
            });
        }
        Ok(Compiled { entries })
    }
}

struct CompiledEntry {
    id: String,
    high_confidence: bool,
    kind: EntryKind,
}

enum EntryKind {
    BuiltIn(Box<dyn Detector>),
    Pattern(Regex),
    Literal(String),
}

impl EntryKind {
    fn find(&self, haystack: &str) -> Vec<Match> {
        match self {
            Self::BuiltIn(d) => d.find(haystack),
            Self::Pattern(re) => re
                .find_iter(haystack)
                .map(|m| Match::new(m.start(), m.end(), haystack))
                .collect(),
            Self::Literal(lit) => haystack
                .match_indices(lit.as_str())
                .map(|(start, _)| Match::new(start, start + lit.len(), haystack))
                .collect(),
        }
    }
}

/// Precompiled rule set: every regex compiled once, ready to scan.
///
/// Build with [`RuleSet::compile`]; pass by shared reference to
/// [`redact_text`], [`crate::redact_event`], and [`crate::redact_jsonl`].
pub struct Compiled {
    entries: Vec<CompiledEntry>,
}

impl Compiled {
    /// Number of compiled rules, in match-priority order.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no rules are active.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Ids of the active rules in match-priority order.
    pub fn rule_ids(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.id.as_str()).collect()
    }

    /// Whether the rule at `index` is high-confidence.
    pub fn is_high_confidence(&self, index: usize) -> Option<bool> {
        self.entries.get(index).map(|e| e.high_confidence)
    }
}

/// Redact `text`, returning the redacted string and per-id match counts.
///
/// Overlaps resolve longest-first, then by rule order; each kept match
/// contributes one count under its rule id and renders as
/// `[redacted:<id>]`. Deterministic: same input yields byte-identical output.
pub fn redact_text(rules: &Compiled, text: &str) -> (String, BTreeMap<String, u64>) {
    // (start, end, rule order)
    let mut spans: Vec<(usize, usize, usize)> = Vec::new();
    for (order, entry) in rules.entries.iter().enumerate() {
        for m in entry.kind.find(text) {
            if m.is_empty() {
                continue;
            }
            // Defensive: regex matches on &str are char-bounded, but never
            // emit a replacement that would split a character.
            if !text.is_char_boundary(m.start) || !text.is_char_boundary(m.end) {
                continue;
            }
            spans.push((m.start, m.end, order));
        }
    }
    // Longest first, then earliest rule wins the overlap.
    spans.sort_by(|a, b| {
        let len_a = a.1 - a.0;
        let len_b = b.1 - b.0;
        len_b.cmp(&len_a).then_with(|| a.2.cmp(&b.2))
    });
    let mut kept: Vec<(usize, usize, usize)> = Vec::with_capacity(spans.len());
    for span in spans {
        if kept.iter().any(|k| span.0 < k.1 && k.0 < span.1) {
            continue;
        }
        kept.push(span);
    }
    kept.sort_by_key(|k| (k.0, k.1));

    let mut out = String::with_capacity(text.len());
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut cursor = 0;
    for (start, end, order) in kept {
        if start < cursor {
            continue;
        }
        out.push_str(&text[cursor..start]);
        let id = &rules.entries[order].id;
        out.push_str("[redacted:");
        out.push_str(id);
        out.push(']');
        *counts.entry(id.clone()).or_insert(0) += 1;
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    (out, counts)
}

/// Lowercase BLAKE3 hex over the canonical record encoding (see module
/// docs). Detector order in the set does not affect the hash. Unset
/// settings resolve to the defaults, so an explicit default and an
/// omitted section hash identically.
pub fn fingerprint(rules: &RuleSet) -> String {
    let min_len = rules.effective_entropy_min_len();
    let threshold_value = rules.effective_entropy_threshold();
    let mut records: Vec<String> = Vec::with_capacity(rules.detectors.len() + 3);
    for rule in &rules.detectors {
        match rule {
            Rule::Detector(id) => {
                let threshold = if matches!(id, BuiltInId::HighEntropy) {
                    format!("{min_len}:{threshold_value}")
                } else {
                    String::new()
                };
                records.push(format!(
                    "{}\0{}\0{threshold}\0",
                    id.id(),
                    id.pattern_source()
                ));
            }
            Rule::Literal(literal) => {
                records.push(format!("literal:{literal}\0{literal}\0\0"));
            }
            Rule::Pattern { id, regex } => {
                records.push(format!("{id}\0{regex}\0\0"));
            }
        }
    }
    records.push(format!("entropy\0{min_len}\0{threshold_value}\0"));
    records.push(format!(
        "pii:email\0{}\0\0",
        if rules.effective_pii_email() {
            "on"
        } else {
            "off"
        }
    ));
    records.push(format!(
        "pii:phone\0{}\0\0",
        if rules.effective_pii_phone() {
            "on"
        } else {
            "off"
        }
    ));
    records.sort();
    let joined = records.join("");
    blake3::hash(joined.as_bytes()).to_hex().to_string()
}
