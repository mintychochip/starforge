//! Trace Format v1 fixture tests: one valid [`SessionMeta`], one valid event
//! per kind (11), plus the invalid / forward-tolerance cases.

use std::collections::BTreeMap;

use proptest::prelude::*;
use serde_json::{Value, json};
use starforge_format::{Event, EventKind, FormatError, SessionMeta, parse_event};

fn valid_session_json() -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "agent": {"name": "claude-code", "version": "1.2.3"},
        "models": ["claude-opus-4-6"],
        "title": "Fix the login bug",
        "started_at": "2026-11-04T12:00:00Z",
        "ended_at": "2026-11-04T13:00:00Z",
        "repo": {
            "remote_urls": ["https://example.com/acme/repo.git"],
            "branch": "main",
            "head_at_start": "0123456789abcdef0123456789abcdef01234567"
        },
        "parent_id": null,
        "usage": {"input": 10, "output": 20, "cache_read": 30, "cache_write": 40, "reasoning": 50},
        "files_touched": ["src/main.rs"],
        "redaction": {"fingerprint": "abc123", "counts": {"private-key": 1}},
        "capture": {"mode": "hook", "cli_version": "0.0.0", "adapter_version_verified": true}
    })
}

fn event_line(kind: &str, payload: Value) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("v".to_string(), json!(1));
    obj.insert("seq".to_string(), json!(7));
    obj.insert("ts".to_string(), json!("2026-11-04T12:00:00Z"));
    obj.insert("kind".to_string(), json!(kind));
    if let Value::Object(map) = payload {
        for (k, v) in map {
            obj.insert(k, v);
        }
    }
    Value::Object(obj).to_string()
}

fn all_kind_payloads() -> Vec<(&'static str, Value)> {
    vec![
        ("user_message", json!({"text": "hello"})),
        (
            "assistant_message",
            json!({"text": "hi", "model": "m", "usage": {"input": 1}}),
        ),
        ("reasoning", json!({"text": "thinking"})),
        (
            "tool_call",
            json!({"tool": {"name": "read", "input": {"path": "a"}}}),
        ),
        (
            "tool_result",
            json!({"result": {"output": "ok", "is_error": false, "truncated": false, "original_bytes": 2}}),
        ),
        (
            "file_change",
            json!({"path": "src/a.rs", "change": "modify", "diff": "--- a\n+++ b\n"}),
        ),
        ("compaction", json!({"summary": "squashed"})),
        (
            "subagent_start",
            json!({"subagent_id": "s-1", "task": "explore"}),
        ),
        (
            "subagent_end",
            json!({"subagent_id": "s-1", "task": "explore"}),
        ),
        ("system", json!({"text": "hook fired"})),
        // The eleventh case is the unknown kind, exercised below.
    ]
}

#[test]
fn valid_session_meta_parses() {
    let meta = SessionMeta::parse(&valid_session_json().to_string()).unwrap();
    assert_eq!(meta.format, "starforge.session/v1");
    assert_eq!(meta.id.to_string(), "01ARZ3NDEKTSV4RRFFQ69G5FAV");
    assert_eq!(meta.usage.input, 10);
    assert_eq!(meta.usage.reasoning, 50);
    assert_eq!(meta.files_touched, vec!["src/main.rs".to_string()]);
}

#[test]
fn session_meta_tolerates_unknown_fields() {
    let mut v = valid_session_json();
    v["future_field"] = json!("keep me");
    let meta = SessionMeta::parse(&v.to_string()).unwrap();
    let back = serde_json::to_string(&meta).unwrap();
    assert!(back.contains("starforge.session/v1"));
}

#[test]
fn one_valid_event_per_known_kind() {
    let mut kinds = all_kind_payloads();
    kinds.push(("some_future_kind", json!({"text": "x", "novel": [1, 2]})));
    assert_eq!(kinds.len(), 11);
    for (kind, payload) in kinds {
        let line = event_line(kind, payload);
        let event = parse_event(&line).unwrap();
        assert_eq!(event.v, 1);
        assert_eq!(event.seq, 7);
    }
}

#[test]
fn unknown_kind_parses_into_unknown_and_round_trips() {
    let line = event_line("some_future_kind", json!({"text": "x"}));
    let event = parse_event(&line).unwrap();
    assert!(matches!(&event, Event { kind: EventKind::Unknown(k), .. } if k == "some_future_kind"));
    let back = serde_json::to_string(&event).unwrap();
    assert!(back.contains("\"kind\":\"some_future_kind\""));
    let again = parse_event(&back).unwrap();
    assert!(matches!(&again, Event { kind: EventKind::Unknown(k), .. } if k == "some_future_kind"));
}

#[test]
fn unknown_extra_fields_round_trip() {
    let mut v: Value = serde_json::from_str(&event_line("system", json!({"text": "t"}))).unwrap();
    v["brand_new_field"] = json!({"nested": [1, 2, 3]});
    let line = v.to_string();
    let event = parse_event(&line).unwrap();
    assert!(event.extra.contains_key("brand_new_field"));
    let back = serde_json::to_string(&event).unwrap();
    assert!(back.contains("brand_new_field"));
    let again = parse_event(&back).unwrap();
    assert_eq!(
        again.extra.get("brand_new_field"),
        event.extra.get("brand_new_field")
    );
}

#[test]
fn v2_is_rejected() {
    let mut v: Value = serde_json::from_str(&event_line("system", json!({"text": "t"}))).unwrap();
    v["v"] = json!(2);
    match parse_event(&v.to_string()) {
        Err(FormatError::UnsupportedVersion(2)) => {}
        other => panic!("expected UnsupportedVersion(2), got {other:?}"),
    }
}

#[test]
fn missing_kind_is_rejected() {
    let mut v: Value = serde_json::from_str(&event_line("system", json!({"text": "t"}))).unwrap();
    v.as_object_mut().unwrap().remove("kind");
    match parse_event(&v.to_string()) {
        Err(FormatError::MissingKind) => {}
        other => panic!("expected MissingKind, got {other:?}"),
    }
}

#[test]
fn bad_ulid_is_rejected() {
    let mut v = valid_session_json();
    v["id"] = json!("not-a-ulid");
    match SessionMeta::parse(&v.to_string()) {
        Err(FormatError::BadUlid) => {}
        other => panic!("expected BadUlid, got {other:?}"),
    }
}

#[test]
fn bad_timestamp_is_rejected() {
    let mut v = valid_session_json();
    v["started_at"] = json!("yesterday-ish");
    match SessionMeta::parse(&v.to_string()) {
        Err(FormatError::BadTimestamp("started_at")) => {}
        other => panic!("expected BadTimestamp, got {other:?}"),
    }
    let line = event_line("system", json!({"text": "t"}));
    let mut ev: Value = serde_json::from_str(&line).unwrap();
    ev["ts"] = json!("not-a-time");
    match parse_event(&ev.to_string()) {
        Err(FormatError::BadTimestamp("ts")) => {}
        other => panic!("expected BadTimestamp, got {other:?}"),
    }
}

#[test]
fn bad_agent_name_is_rejected() {
    let mut v = valid_session_json();
    v["agent"] = json!({"name": "hal-9000", "version": "1"});
    match SessionMeta::parse(&v.to_string()) {
        Err(FormatError::BadAgent(name)) => assert_eq!(name, "hal-9000"),
        other => panic!("expected BadAgent, got {other:?}"),
    }
}

#[test]
fn wrong_format_tag_is_rejected() {
    let mut v = valid_session_json();
    v["format"] = json!("starforge.session/v2");
    match SessionMeta::parse(&v.to_string()) {
        Err(FormatError::BadFormatTag) => {}
        other => panic!("expected BadFormatTag, got {other:?}"),
    }
}

#[test]
fn missing_payload_field_is_rejected() {
    let line = event_line("user_message", json!({}));
    match parse_event(&line) {
        Err(FormatError::InvalidField { kind, field }) => {
            assert_eq!(kind, "user_message");
            assert_eq!(field, "text");
        }
        other => panic!("expected InvalidField, got {other:?}"),
    }
}

// --- Property tests ---

fn ulid_strategy() -> impl Strategy<Value = String> {
    (any::<u64>(), any::<u128>())
        .prop_map(|(ms, rand)| ulid::Ulid::from_parts(ms, rand).to_string())
}

fn ts_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("2026-11-04T12:00:00Z".to_string()),
        Just("2026-01-01T00:00:00+02:00".to_string()),
        Just("2026-06-30T23:59:59.123456789Z".to_string()),
    ]
}

fn agent_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("claude-code".to_string()),
        Just("codex".to_string()),
        Just("pi".to_string()),
        Just("opencode".to_string()),
        Just("gemini".to_string()),
    ]
}

proptest! {
    #[test]
    fn session_meta_serde_round_trip(
        id in ulid_strategy(),
        agent in agent_strategy(),
        title in prop::option::of(any::<String>()),
        usage_vals in [any::<u64>(); 5],
    ) {
        let mut v = valid_session_json();
        v["id"] = Value::String(id);
        v["agent"] = json!({"name": agent, "version": "x"});
        v["title"] = title.map_or(Value::Null, Value::String);
        v["usage"] = json!({
            "input": usage_vals[0], "output": usage_vals[1],
            "cache_read": usage_vals[2], "cache_write": usage_vals[3],
            "reasoning": usage_vals[4],
        });
        let meta = SessionMeta::parse(&v.to_string()).unwrap();
        let back = serde_json::to_string(&meta).unwrap();
        let again = SessionMeta::parse(&back).unwrap();
        prop_assert_eq!(serde_json::to_value(&meta).unwrap(), serde_json::to_value(&again).unwrap());
    }

    #[test]
    fn event_serde_round_trip(
        seq in any::<u64>(),
        ts in ts_strategy(),
        text in any::<String>(),
        extras in prop::collection::btree_map(any::<String>(), any::<String>(), 0..4).prop_filter("no reserved keys", |m| !m.keys().any(|k| ["v", "seq", "ts", "kind", "text"].contains(&k.as_str()))),
    ) {
        let mut obj = serde_json::Map::new();
        obj.insert("v".to_string(), json!(1));
        obj.insert("seq".to_string(), json!(seq));
        obj.insert("ts".to_string(), Value::String(ts));
        obj.insert("kind".to_string(), json!("user_message"));
        obj.insert("text".to_string(), Value::String(text));
        for (k, val) in &extras {
            obj.insert(k.clone(), Value::String(val.clone()));
        }
        let line = Value::Object(obj).to_string();
        let event = parse_event(&line).unwrap();
        let back = serde_json::to_string(&event).unwrap();
        let again = parse_event(&back).unwrap();
        for (k, val) in &extras {
            prop_assert_eq!(
                again.extra.get(k).and_then(|x| x.as_str()),
                Some(val.as_str())
            );
        }
        let _ = again;
    }

    #[test]
    fn unknown_field_injection_preserved(
        extras in prop::collection::btree_map("[a-z][a-z0-9_]{0,15}", any::<String>(), 1..5),
    ) {
        let mut v: Value = serde_json::from_str(
            &event_line("reasoning", json!({"text": "t"})),
        ).unwrap();
        for (k, val) in &extras {
            if !["v", "seq", "ts", "kind", "text"].contains(&k.as_str()) {
                v[k] = Value::String(val.clone());
            }
        }
        let event = parse_event(&v.to_string()).unwrap();
        let back = serde_json::to_string(&event).unwrap();
        let again: Value = serde_json::from_str(&back).unwrap();
        for (k, val) in &extras {
            if !["v", "seq", "ts", "kind", "text"].contains(&k.as_str()) {
                prop_assert_eq!(again.get(k), Some(&Value::String(val.clone())));
            }
        }
    }

    #[test]
    fn any_v2_event_rejected(seq in any::<u64>()) {
        let mut v: Value = serde_json::from_str(
            &event_line("system", json!({"text": "t"})),
        ).unwrap();
        v["v"] = json!(2);
        v["seq"] = json!(seq);
        match parse_event(&v.to_string()) {
            Err(FormatError::UnsupportedVersion(2)) => {}
            other => panic!("expected UnsupportedVersion(2), got {other:?}"),
        }
    }
}

#[test]
fn usage_counts_default_to_zero() {
    let mut usage = BTreeMap::new();
    usage.insert("input".to_string(), 5u64);
    let v = serde_json::to_value(&usage).unwrap();
    let parsed: starforge_format::Usage = serde_json::from_value(v).unwrap();
    assert_eq!(parsed.input, 5);
    assert_eq!(parsed.output, 0);
}
