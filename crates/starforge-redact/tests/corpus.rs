//! Redaction corpus: per-detector positives/negatives, JSONL structure,
//! redact_event per kind, fingerprint sensitivity, and TOML parse/merge.
//!
//! Written before the implementation (TDD step 1); must fail until the
//! `starforge_redact` API exists.

use starforge_format::{
    AssistantMessage, Compaction, Event, EventKind, FileChange, FileChangeKind, Reasoning,
    SubagentBoundary, System, ToolCall, ToolOutcome, ToolRef, ToolResult, UserMessage,
};
use starforge_redact::{
    BuiltInId, Compiled, Rule, RuleSet, fingerprint, redact_event, redact_jsonl, redact_text,
};

fn builtin() -> Compiled {
    RuleSet::built_in()
        .compile()
        .expect("built-in rules compile")
}

fn ev(kind: EventKind) -> Event {
    Event {
        v: 1,
        seq: 7,
        ts: "2026-11-04T00:00:00Z".to_string(),
        kind,
        extra: [(
            "note".to_string(),
            serde_json::json!({"secret": "nothing to hide"}),
        )]
        .into_iter()
        .collect(),
    }
}

// --- private-key ---

#[test]
fn private_key_pem_block_redacted() {
    let body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC";
    let text = format!(
        "key below\n-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\ndone"
    );
    let (out, counts) = redact_text(&builtin(), &text);
    assert!(out.contains("[redacted:private-key]"), "out: {out}");
    assert!(!out.contains("MIIEvQIBADANBgkqhkiG9w0"), "out: {out}");
    assert_eq!(counts.get("private-key"), Some(&1));
    assert_eq!(counts.len(), 1, "counts: {counts:?}");
}

#[test]
fn private_key_words_alone_not_redacted() {
    let text = "I lost my private key yesterday";
    let (out, counts) = redact_text(&builtin(), text);
    assert_eq!(out, text);
    assert!(counts.is_empty());
}

// --- cloud-credential ---

#[test]
fn cloud_credential_akia_redacted() {
    let text = "aws key AKIAIOSFODNN7EXAMPLE leaked";
    let (out, counts) = redact_text(&builtin(), text);
    assert!(out.contains("[redacted:cloud-credential]"), "out: {out}");
    assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "out: {out}");
    assert_eq!(counts.get("cloud-credential"), Some(&1));
}

#[test]
fn cloud_credential_secret_assignment_redacted() {
    let text = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY end";
    let (out, counts) = redact_text(&builtin(), text);
    assert!(out.contains("[redacted:cloud-credential]"), "out: {out}");
    assert!(!out.contains("wJalrXUtnFEMI"), "out: {out}");
    assert_eq!(counts.get("cloud-credential"), Some(&1));
}

#[test]
fn cloud_credential_gcp_marker_redacted() {
    let text = r#"config {"type": "service_account", "project": "x"} tail"#;
    let (out, counts) = redact_text(&builtin(), text);
    assert!(out.contains("[redacted:cloud-credential]"), "out: {out}");
    assert_eq!(counts.get("cloud-credential"), Some(&1));
}

#[test]
fn cloud_credential_negative() {
    let text = "AKIA is too short and no service account here";
    let (out, counts) = redact_text(&builtin(), text);
    assert_eq!(out, text);
    assert!(counts.is_empty());
}

// --- known-token ---

#[test]
fn known_token_prefixes_redacted() {
    let cases = [
        ("ghp_", "a".repeat(36)),
        ("gho_", "a".repeat(36)),
        ("ghu_", "a".repeat(36)),
        ("ghs_", "a".repeat(36)),
        ("ghr_", "a".repeat(36)),
        ("github_pat_", "b".repeat(22)),
        ("xoxb-", "c".repeat(12)),
        ("xoxp-", "c".repeat(12)),
        ("sk-ant-", "d".repeat(24)),
        ("sk-", "e".repeat(24)),
        ("AIza", "f".repeat(35)),
        ("glpat-", "g".repeat(20)),
        ("npm_", "h".repeat(36)),
        ("pypi-", "i".repeat(12)),
    ];
    for (prefix, body) in cases {
        let token = format!("{prefix}{body}");
        let text = format!("token {token} end");
        let (out, counts) = redact_text(&builtin(), &text);
        assert!(
            out.contains("[redacted:known-token]"),
            "prefix {prefix}: {out}"
        );
        assert!(!out.contains(&token), "prefix {prefix}: {out}");
        assert_eq!(counts.get("known-token"), Some(&1), "prefix {prefix}");
    }
}

#[test]
fn known_token_negative() {
    for text in [
        "sk-123 is too short",
        "skip this risk-assessment please",
        "ghp_abc too short",
        "no tokens here",
    ] {
        let (out, counts) = redact_text(&builtin(), text);
        assert_eq!(out, text, "input: {text}");
        assert!(counts.is_empty(), "input: {text}");
    }
}

// --- credentialed-url ---

#[test]
fn credentialed_url_redacts_authority_only() {
    let text = "see https://alice:s3cr3t@example.com/path for details";
    let (out, counts) = redact_text(&builtin(), text);
    assert_eq!(
        out,
        "see https://[redacted:credentialed-url]@example.com/path for details"
    );
    assert_eq!(counts.get("credentialed-url"), Some(&1));
}

#[test]
fn credentialed_url_negative() {
    let text = "see https://example.com/path for details";
    let (out, counts) = redact_text(&builtin(), text);
    assert_eq!(out, text);
    assert!(counts.is_empty());
}

// --- connection-string ---

#[test]
fn connection_string_ado_redacted() {
    let text = "Server=db;Password=s3cr3tPass;Database=main";
    let (out, counts) = redact_text(&builtin(), text);
    assert!(out.contains("[redacted:connection-string]"), "out: {out}");
    assert!(!out.contains("s3cr3tPass"), "out: {out}");
    assert_eq!(counts.get("connection-string"), Some(&1));
}

#[test]
fn connection_string_mongo_redacted() {
    let text = "uri mongodb+srv://alice:s3cr3t@cluster0.example.com/db here";
    let (out, counts) = redact_text(&builtin(), text);
    assert!(out.contains("[redacted:connection-string]"), "out: {out}");
    assert!(!out.contains("s3cr3t@cluster0"), "out: {out}");
    assert_eq!(counts.get("connection-string"), Some(&1));
}

#[test]
fn connection_string_negative() {
    let text = "my password is blue";
    let (out, counts) = redact_text(&builtin(), text);
    assert_eq!(out, text);
    assert!(counts.is_empty());
}

// --- authorization ---

#[test]
fn authorization_header_redacted_once() {
    let text = "Authorization: Bearer sometoken123 end";
    let (out, counts) = redact_text(&builtin(), text);
    assert!(out.contains("[redacted:authorization]"), "out: {out}");
    assert!(!out.contains("sometoken123"), "out: {out}");
    assert_eq!(counts.get("authorization"), Some(&1));
    assert_eq!(counts.len(), 1, "counts: {counts:?}");
}

#[test]
fn authorization_bare_bearer_redacted() {
    let text = "call with Bearer abcdefghij123456 now";
    let (out, counts) = redact_text(&builtin(), text);
    assert!(out.contains("[redacted:authorization]"), "out: {out}");
    assert!(!out.contains("abcdefghij123456"), "out: {out}");
    assert_eq!(counts.get("authorization"), Some(&1));
}

#[test]
fn authorization_negative() {
    let text = "no authorization configured here";
    let (out, counts) = redact_text(&builtin(), text);
    assert_eq!(out, text);
    assert!(counts.is_empty());
}

// --- high-entropy ---

#[test]
fn high_entropy_blob_redacted() {
    let text = "blob Xk9mQ2vL7pR4tW8yU1iO5pA3sD6fG0hJ end";
    let (out, counts) = redact_text(&builtin(), text);
    assert!(out.contains("[redacted:high-entropy]"), "out: {out}");
    assert!(!out.contains("Xk9mQ2vL7pR4"), "out: {out}");
    assert_eq!(counts.get("high-entropy"), Some(&1));
}

#[test]
fn high_entropy_negative_uuid_and_lorem() {
    let text = "id 550e8400-e29b-41d4-a716-446655440000 lorem ipsum dolor sit amet end";
    let (out, counts) = redact_text(&builtin(), text);
    assert_eq!(out, text);
    assert!(counts.is_empty());
}

// --- email / phone (off by default) ---

#[test]
fn pii_off_by_default() {
    let text = "mail user@example.com or call +1-555-123-4567 now";
    let (out, counts) = redact_text(&builtin(), text);
    assert_eq!(out, text);
    assert!(counts.is_empty());
}

#[test]
fn pii_enabled_via_toml_merge() {
    let site = RuleSet::parse_toml("[pii]\nemail = true\nphone = true\n").unwrap();
    let merged = RuleSet::built_in().merge(&site);
    let compiled = merged.compile().unwrap();
    let text = "mail user@example.com or call +1-555-123-4567 now";
    let (out, counts) = redact_text(&compiled, text);
    assert!(out.contains("[redacted:email]"), "out: {out}");
    assert!(out.contains("[redacted:phone]"), "out: {out}");
    assert!(!out.contains("user@example.com"), "out: {out}");
    assert!(!out.contains("+1-555-123-4567"), "out: {out}");
    assert_eq!(counts.get("email"), Some(&1));
    assert_eq!(counts.get("phone"), Some(&1));
}

// --- overlap rules ---

#[test]
fn overlap_longest_first_wins() {
    let rules = RuleSet {
        detectors: vec![
            Rule::Literal("secret123".to_string()),
            Rule::Pattern {
                id: "short".to_string(),
                regex: "secret".to_string(),
            },
        ],
        ..RuleSet::built_in()
    };
    let compiled = rules.compile().unwrap();
    let (out, counts) = redact_text(&compiled, "value secret123 end");
    assert_eq!(out, "value [redacted:literal] end", "out: {out}");
    assert_eq!(counts.get("literal"), Some(&1));
    assert!(!counts.contains_key("short"));
}

#[test]
fn overlap_tie_broken_by_detector_order() {
    // Realistic high-entropy ghp body: both known-token and high-entropy
    // match the full 40-char token; the earlier detector wins.
    let token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456709";
    assert_eq!(token.len(), 40);
    let (out, counts) = redact_text(&builtin(), &format!("token {token} end"));
    assert!(out.contains("[redacted:known-token]"), "out: {out}");
    assert_eq!(counts.len(), 1, "counts: {counts:?}");
    assert_eq!(counts.get("known-token"), Some(&1));

    // Same-span tie between custom rules: first rule in vec order wins.
    let rules = RuleSet {
        detectors: vec![
            Rule::Literal("abc".to_string()),
            Rule::Pattern {
                id: "abc-pat".to_string(),
                regex: "abc".to_string(),
            },
        ],
        ..RuleSet::built_in()
    };
    let compiled = rules.compile().unwrap();
    let (out, counts) = redact_text(&compiled, "x abc y");
    assert_eq!(out, "x [redacted:literal] y", "out: {out}");
    assert_eq!(counts.get("literal"), Some(&1));
}

// --- char boundaries ---

#[test]
fn multibyte_text_adjacent_to_secret() {
    let token = format!("ghp_{}", "a".repeat(36));
    let text = format!("héllo wörld {token} après");
    let (out, counts) = redact_text(&builtin(), &text);
    assert!(out.starts_with("héllo wörld "), "out: {out}");
    assert!(out.ends_with(" après"), "out: {out}");
    assert!(out.contains("[redacted:known-token]"), "out: {out}");
    assert_eq!(counts.get("known-token"), Some(&1));
}

// --- JSONL structure ---

#[test]
fn jsonl_structure_preserved() {
    let token = format!("ghp_{}", "a".repeat(36));
    let jsonl = format!(
        "{{\"kind\": \"note\", \"secret\": \"{token}\", \"nested\": {{\"k\": \"key AKIAIOSFODNN7EXAMPLE\"}}, \"n\": 3}}\nnot json at all, {token}\n"
    );
    let (out, counts) = redact_jsonl(&builtin(), &jsonl);
    assert!(out.ends_with('\n'), "out: {out:?}");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2, "out: {out:?}");
    assert!(
        out.contains("\"secret\":\"[redacted:known-token]\""),
        "out: {out}"
    );
    assert!(
        out.contains("\"k\":\"key [redacted:cloud-credential]\""),
        "out: {out}"
    );
    assert!(out.contains("\"n\":3"), "out: {out}");
    assert!(lines[1].contains("[redacted:known-token]"), "out: {out}");
    assert!(!out.contains(&token), "out: {out}");
    assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "out: {out}");
    // Keys intact.
    assert!(out.contains("\"secret\"") && out.contains("\"nested\"") && out.contains("\"k\""));
    assert_eq!(counts.get("known-token"), Some(&2));
    assert_eq!(counts.get("cloud-credential"), Some(&1));
}

// --- redact_event per kind ---

#[test]
fn redact_event_redacts_values_not_metadata() {
    let secret = format!("ghp_{}", "a".repeat(36));
    let kinds = vec![
        EventKind::UserMessage(UserMessage {
            text: secret.clone(),
        }),
        EventKind::AssistantMessage(AssistantMessage {
            text: secret.clone(),
            model: Some("m".to_string()),
            usage: Default::default(),
        }),
        EventKind::Reasoning(Reasoning {
            text: secret.clone(),
        }),
        EventKind::ToolCall(ToolCall {
            tool: ToolRef {
                name: "t".to_string(),
                input: serde_json::json!({"arg": secret}),
            },
        }),
        EventKind::ToolResult(ToolResult {
            result: ToolOutcome {
                output: secret.clone(),
                is_error: true,
                truncated: true,
                original_bytes: 99,
            },
        }),
        EventKind::FileChange(FileChange {
            path: "a/b.rs".to_string(),
            change: FileChangeKind::Modify,
            diff: Some(secret.clone()),
        }),
        EventKind::Compaction(Compaction {
            summary: Some(secret.clone()),
        }),
        EventKind::SubagentStart(SubagentBoundary {
            subagent_id: "s1".to_string(),
            task: secret.clone(),
        }),
        EventKind::SubagentEnd(SubagentBoundary {
            subagent_id: "s1".to_string(),
            task: secret.clone(),
        }),
        EventKind::System(System {
            text: secret.clone(),
        }),
    ];
    for kind in kinds {
        let before = ev(kind);
        let (after, counts) = redact_event(&builtin(), &before);
        // Metadata untouched.
        assert_eq!(after.v, before.v);
        assert_eq!(after.seq, 7);
        assert_eq!(after.ts, before.ts);
        assert_eq!(
            std::mem::discriminant(&after.kind),
            std::mem::discriminant(&before.kind)
        );
        assert_eq!(after.extra.keys().collect::<Vec<_>>(), vec!["note"]);
        // No secret text remains anywhere in the debug rendering.
        let rendered = format!("{after:?}");
        assert!(!rendered.contains(&secret), "kind leaked: {rendered}");
        assert!(
            rendered.contains("[redacted:known-token]"),
            "kind: {rendered}"
        );
        assert_eq!(counts.get("known-token"), Some(&1));
        // Untouched fields survive.
        match &after.kind {
            EventKind::AssistantMessage(m) => assert_eq!(m.model.as_deref(), Some("m")),
            EventKind::ToolResult(r) => {
                assert!(r.result.is_error && r.result.truncated);
                assert_eq!(r.result.original_bytes, 99);
            }
            EventKind::FileChange(f) => assert_eq!(f.path, "a/b.rs"),
            EventKind::SubagentStart(b) | EventKind::SubagentEnd(b) => {
                assert_eq!(b.subagent_id, "s1")
            }
            _ => {}
        }
    }
}

#[test]
fn redact_event_unknown_kind_extra_redacted() {
    let secret = format!("ghp_{}", "a".repeat(36));
    let mut event = ev(EventKind::Unknown("future-kind".to_string()));
    event
        .extra
        .insert("payload".to_string(), serde_json::json!(secret));
    let (after, _counts) = redact_event(&builtin(), &event);
    assert!(matches!(&after.kind, EventKind::Unknown(k) if k == "future-kind"));
    assert!(after.extra.contains_key("payload"));
    let rendered = format!("{after:?}");
    assert!(!rendered.contains(&secret), "leaked: {rendered}");
}

// --- fingerprint ---

#[test]
fn fingerprint_order_independent() {
    let a = RuleSet {
        detectors: vec![
            Rule::Pattern {
                id: "b".to_string(),
                regex: "b+".to_string(),
            },
            Rule::Detector(BuiltInId::KnownToken),
            Rule::Literal("zzz".to_string()),
        ],
        ..RuleSet::built_in()
    };
    let b = RuleSet {
        detectors: vec![
            Rule::Literal("zzz".to_string()),
            Rule::Pattern {
                id: "b".to_string(),
                regex: "b+".to_string(),
            },
            Rule::Detector(BuiltInId::KnownToken),
        ],
        ..RuleSet::built_in()
    };
    assert_eq!(fingerprint(&a), fingerprint(&b));
    assert_eq!(fingerprint(&a).len(), 64);
}

#[test]
fn fingerprint_change_sensitive() {
    let base = fingerprint(&RuleSet::built_in());
    let mut with_literal = RuleSet::built_in();
    with_literal
        .detectors
        .push(Rule::Literal("extra".to_string()));
    assert_ne!(fingerprint(&with_literal), base);
    let mut pii = RuleSet::built_in();
    pii.pii_email = Some(true);
    assert_ne!(fingerprint(&pii), base);
    let mut entropy = RuleSet::built_in();
    entropy.entropy_threshold = Some(5.0);
    assert_ne!(fingerprint(&entropy), base);
}

// --- TOML parse + merge ---

#[test]
fn toml_parse_and_merge() {
    let toml = r#"
[pii]
email = true

[entropy]
min_len = 24
threshold = 5.0
literals = ["secret-string"]

[[pattern]]
id = "internal-token"
regex = "INT-[0-9]{8}"
"#;
    let site = RuleSet::parse_toml(toml).unwrap();
    assert_eq!(site.pii_email, Some(true));
    assert_eq!(site.pii_phone, None);
    assert_eq!(site.entropy_min_len, Some(24));
    assert_eq!(site.entropy_threshold, Some(5.0));

    let merged = RuleSet::built_in().merge(&site);
    assert_eq!(merged.pii_email, Some(true));
    assert_eq!(merged.entropy_min_len, Some(24));
    let compiled = merged.compile().unwrap();
    let (out, counts) = redact_text(&compiled, "has secret-string and INT-12345678 here");
    assert!(out.contains("[redacted:literal]"), "out: {out}");
    assert!(out.contains("[redacted:internal-token]"), "out: {out}");
    assert_eq!(counts.get("literal"), Some(&1));
    assert_eq!(counts.get("internal-token"), Some(&1));
    // Built-ins still active after merge; repo order preserved (built-in first).
    let (out, _) = redact_text(&compiled, "plain text only");
    assert_eq!(out, "plain text only");
}

#[test]
fn toml_rejects_bad_regex_and_threshold() {
    let bad = RuleSet::parse_toml("[[pattern]]\nid = \"x\"\nregex = \"([\"\n");
    assert!(matches!(
        bad,
        Err(starforge_redact::RuleError::BadRegex { .. })
    ));
    let bad_t = RuleSet::parse_toml("[entropy]\nthreshold = 99.0\n");
    assert!(matches!(
        bad_t,
        Err(starforge_redact::RuleError::BadThreshold { .. })
    ));
}

#[test]
fn merge_absent_sections_inherit() {
    // Site sets PII + entropy; the higher-precedence repo file omits those
    // sections entirely. The repo's silence must not reset the site values.
    let site = RuleSet::parse_toml(
        "[pii]\nemail = true\nphone = true\n[entropy]\nmin_len = 24\nthreshold = 5.0\n",
    )
    .unwrap();
    let repo =
        RuleSet::parse_toml("[[pattern]]\nid = \"repo-pat\"\nregex = \"R[0-9]+\"\n").unwrap();
    assert_eq!(repo.pii_email, None);
    assert_eq!(repo.entropy_min_len, None);
    let merged = site.merge(&repo);
    assert_eq!(merged.pii_email, Some(true));
    assert_eq!(merged.pii_phone, Some(true));
    assert_eq!(merged.entropy_min_len, Some(24));
    assert_eq!(merged.entropy_threshold, Some(5.0));
    // Behavior survives: PII on, higher entropy floor active, both rule
    // lists present.
    let compiled = merged.compile().unwrap();
    let (out, counts) = redact_text(&compiled, "mail a@b.co blob Q7zKp2LmV9xRn4DwY6cFbH8 R42");
    assert!(out.contains("[redacted:email]"), "out: {out}");
    assert!(out.contains("Q7zKp2LmV9xRn4DwY6cFbH8"), "out: {out}");
    assert!(out.contains("[redacted:repo-pat]"), "out: {out}");
    assert_eq!(counts.get("email"), Some(&1));
    assert!(!counts.contains_key("high-entropy"), "counts: {counts:?}");
    // Explicit `Some` in the higher-precedence set still overrides.
    let off = RuleSet::parse_toml("[pii]\nemail = false\n").unwrap();
    let merged2 = site.merge(&off);
    assert_eq!(merged2.pii_email, Some(false));
    assert_eq!(merged2.pii_phone, Some(true));
    // Same set merged over itself is a fingerprint no-op for settings.
    assert_eq!(
        fingerprint(&site),
        fingerprint(&site.clone().merge(&RuleSet::default()))
    );
}

#[test]
fn known_token_openai_variants_redacted() {
    for token in [
        format!("sk-proj-{}", "a".repeat(20)),
        format!("sk_live_{}", "b".repeat(20)),
        format!("sk_test_{}", "c".repeat(20)),
    ] {
        let (out, counts) = redact_text(&builtin(), &format!("key {token} end"));
        assert!(
            out.contains("[redacted:known-token]"),
            "token {token}: {out}"
        );
        assert!(!out.contains(&token), "token {token}: {out}");
        assert_eq!(counts.get("known-token"), Some(&1), "token {token}");
    }
}

#[test]
fn cloud_credential_session_prefixes_redacted() {
    for prefix in ["ASIA", "ABIA", "ACCA"] {
        let key = format!("{prefix}IOSFODNN7EXAMPLE");
        let (out, counts) = redact_text(&builtin(), &format!("key {key} end"));
        assert!(
            out.contains("[redacted:cloud-credential]"),
            "key {key}: {out}"
        );
        assert!(!out.contains(&key), "key {key}: {out}");
        assert_eq!(counts.get("cloud-credential"), Some(&1), "key {key}");
    }
}

#[test]
fn jsonl_metadata_values_untouched() {
    let token = format!("ghp_{}", "a".repeat(36));
    let line = format!(
        "{{\"v\": 1, \"seq\": 7, \"ts\": \"2026-11-04T00:00:00Z\", \"kind\": \"note {token}\", \"payload\": \"key AKIAIOSFODNN7EXAMPLE\"}}"
    );
    let (out, counts) = redact_jsonl(&builtin(), &line);
    // Structural metadata passes through verbatim — even the token inside `kind`.
    assert!(
        out.contains(&format!("\"kind\":\"note {token}\"")),
        "out: {out}"
    );
    assert!(out.contains("\"v\":1"), "out: {out}");
    assert!(out.contains("\"seq\":7"), "out: {out}");
    assert!(
        out.contains("\"ts\":\"2026-11-04T00:00:00Z\""),
        "out: {out}"
    );
    // Payload values are still redacted.
    assert!(
        out.contains("\"payload\":\"key [redacted:cloud-credential]\""),
        "out: {out}"
    );
    assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "out: {out}");
    assert_eq!(counts.get("cloud-credential"), Some(&1));
    assert!(!counts.contains_key("known-token"), "counts: {counts:?}");
}

#[test]
fn entropy_min_len_override_behavioral() {
    // 23 chars, ~4.52 bits/char: detected under defaults (20 / 4.5).
    let text = "blob Q7zKp2LmV9xRn4DwY6cFbH8 end";
    let (out, counts) = redact_text(&builtin(), text);
    assert!(out.contains("[redacted:high-entropy]"), "out: {out}");
    assert_eq!(counts.get("high-entropy"), Some(&1));
    // A higher-precedence file raising only min_len suppresses it.
    let site = RuleSet::parse_toml("[entropy]\nmin_len = 24\n").unwrap();
    let merged = RuleSet::built_in().merge(&site);
    assert_eq!(merged.entropy_min_len, Some(24));
    assert_eq!(merged.entropy_threshold, Some(4.5));
    let (out2, counts2) = redact_text(&merged.compile().unwrap(), text);
    assert_eq!(out2, text);
    assert!(counts2.is_empty());
}

// --- determinism / replacement format ---

#[test]
fn redaction_is_deterministic() {
    let text = "key AKIAIOSFODNN7EXAMPLE plus blob Xk9mQ2vL7pR4tW8yU1iO5pA3sD6fG0hJ end";
    let (a, ca) = redact_text(&builtin(), text);
    let (b, cb) = redact_text(&builtin(), text);
    assert_eq!(a, b);
    assert_eq!(ca, cb);
    assert_eq!(
        a,
        "key [redacted:cloud-credential] plus blob [redacted:high-entropy] end"
    );
}
