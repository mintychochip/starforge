//! Redaction engine: rule sets, detectors, and deterministic redaction.
//!
//! Scans free text and JSON values for secrets (API keys, tokens,
//! credentials, high-entropy blobs, and opt-in PII) and replaces each hit
//! with `[redacted:<id>]`. See [`detectors`] for the overlap rule and
//! detector order, and [`rules`] for the fingerprint encoding.
//!
//! Everything here is pure: no filesystem, no network, no clock. Same
//! input yields byte-identical output.

pub mod detectors;
pub mod json;
pub mod rules;

pub use detectors::{BUILT_IN_ORDER, Detector, Match};
pub use json::{redact_event, redact_jsonl, redact_value};
pub use rules::{BuiltInId, Compiled, Rule, RuleError, RuleSet, fingerprint, redact_text};
