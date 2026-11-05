//! `trail review` and `trail merge` (J5).

use serde_json::{Value, json};

use super::{Format, TrailCtx, agent_unsupported, pretty, select_change};

/// Cap on inline comments per review, matching the server.
const MAX_COMMENTS: usize = 100;

/// Review verdicts: clap spelling vs API spelling differ (`--request-changes`
/// posts `"request_changes"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Approve,
    RequestChanges,
    Comment,
}

impl Verdict {
    /// API spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Approve => "approve",
            Verdict::RequestChanges => "request_changes",
            Verdict::Comment => "comment",
        }
    }

    /// Past-tense phrase for the text output.
    fn past(&self) -> &'static str {
        match self {
            Verdict::Approve => "approved",
            Verdict::RequestChanges => "requested changes on",
            Verdict::Comment => "commented on",
        }
    }

    /// Body used when neither `--body` nor `--body-file` is given. The server
    /// rejects empty review bodies, so omitting both still posts a review.
    pub fn default_body(&self) -> &'static str {
        match self {
            Verdict::Approve => "Approved.",
            Verdict::RequestChanges => "Changes requested.",
            Verdict::Comment => "Commented.",
        }
    }
}

/// One inline review comment. Exactly these five fields; unknown keys are
/// rejected (`deny_unknown_fields`), both here and on the server.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InlineComment {
    pub path: String,
    pub side: String,
    pub start_line: i64,
    pub end_line: i64,
    pub body: String,
}

/// D9: inline JSON array, `@<path>`, or `@-` (stdin). Client-side checks:
/// side ∈ base|head, start_line ≥ 1, end_line ≥ start_line, ≤ 100 entries.
/// Entry errors name the entry index (`comments[i]: …`).
pub fn parse_comments(arg: &str, stdin: impl std::io::Read) -> Result<Vec<InlineComment>, String> {
    let raw = match arg.strip_prefix('@') {
        None => arg.to_string(),
        Some("-") => read_reader(stdin, "stdin")?,
        Some(path) => std::fs::read_to_string(path)
            .map_err(|err| format!("cannot read comments file {path}: {err}"))?,
    };
    let value: Value =
        serde_json::from_str(&raw).map_err(|err| format!("comments: invalid JSON: {err}"))?;
    let items = value
        .as_array()
        .ok_or_else(|| "comments: expected a JSON array of inline comments".to_string())?;
    if items.len() > MAX_COMMENTS {
        return Err(format!(
            "comments[{MAX_COMMENTS}]: too many comments (max {MAX_COMMENTS})"
        ));
    }
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let entry: InlineComment =
            serde_json::from_value(item.clone()).map_err(|err| format!("comments[{i}]: {err}"))?;
        if !matches!(entry.side.as_str(), "base" | "head") {
            return Err(format!(
                "comments[{i}]: invalid side '{}' (expected base or head)",
                entry.side
            ));
        }
        if entry.start_line < 1 {
            return Err(format!("comments[{i}]: start_line must be at least 1"));
        }
        if entry.end_line < entry.start_line {
            return Err(format!(
                "comments[{i}]: end_line ({}) is before start_line ({})",
                entry.end_line, entry.start_line
            ));
        }
        out.push(entry);
    }
    Ok(out)
}

fn read_reader(mut stdin: impl std::io::Read, what: &str) -> Result<String, String> {
    let mut raw = String::new();
    stdin
        .read_to_string(&mut raw)
        .map_err(|err| format!("cannot read {what}: {err}"))?;
    Ok(raw)
}

/// Arguments for `trail review`.
#[derive(Debug, Clone)]
pub struct ReviewArgs {
    pub n: i64,
    pub change: Option<i64>,
    pub rev: Option<i64>,
    pub verdict: Verdict,
    pub body: String,
    pub comments: Vec<InlineComment>,
    pub session: Option<String>,
}

/// `trail review`: validates `--session` client-side, resolves the change
/// (D4, no sole-closed allowance), and posts one review with its inline
/// comments. A server refusal (e.g. an invalid comment, which the server
/// names `comments[i]`) prints the server's message; there is no retry.
pub async fn review(ctx: &TrailCtx, args: &ReviewArgs, format: Format) -> (String, u8) {
    if let Some(session) = args.session.as_deref()
        && session.parse::<ulid::Ulid>().is_err()
    {
        return (format!("error: invalid --session ULID: {session}"), 1);
    }
    let changes_resp = match ctx
        .api
        .get(&format!("trails/{}/changes", args.n), &[])
        .await
    {
        Ok(resp) => resp,
        Err(err) => return ctx.api.render_error(err),
    };
    let changes: Vec<Value> = changes_resp
        .get("changes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let k = match select_change(&changes, args.change, false) {
        Ok(k) => k,
        Err(msg) => return (format!("error: {msg}"), 1),
    };
    let mut body = json!({"verdict": args.verdict.as_str(), "body": args.body});
    if let Some(rev) = args.rev {
        body["revision"] = json!(rev);
    }
    if let Some(session) = args.session.as_deref() {
        body["session"] = json!(session);
    }
    if !args.comments.is_empty() {
        body["comments"] = serde_json::to_value(&args.comments).unwrap_or_else(|_| json!([]));
    }
    let resp = match ctx
        .api
        .post(&format!("trails/{}/changes/{k}/reviews", args.n), &body)
        .await
    {
        Ok(resp) => resp,
        Err(err) => return ctx.api.render_error(err),
    };
    match format {
        Format::Json => (pretty(&resp), 0),
        Format::Agent => agent_unsupported(),
        Format::Text => {
            let revision = resp.get("revision").and_then(Value::as_i64).unwrap_or(0);
            let id = resp.get("id").and_then(Value::as_i64).unwrap_or(0);
            let inline = resp
                .get("threads")
                .and_then(Value::as_array)
                .map_or(args.comments.len(), Vec::len);
            (
                format!(
                    "{} trail #{} change {k} revision {revision} (review {id}, {inline} inline comments): {}",
                    args.verdict.past(),
                    args.n,
                    ctx.api.web_url(&format!("trails/{}", args.n)),
                ),
                0,
            )
        }
    }
}

/// D5: `merge` when allowed, else the single allowed method; several remaining
/// methods error and list them.
pub fn default_method(allowed: &[String]) -> Result<String, String> {
    if allowed.iter().any(|method| method == "merge") {
        return Ok("merge".to_string());
    }
    if let [only] = allowed {
        return Ok(only.clone());
    }
    if allowed.is_empty() {
        return Err("no merge methods available".to_string());
    }
    Err(format!(
        "specify --method M (available: {})",
        allowed.join(", ")
    ))
}

/// Arguments for `trail merge`.
#[derive(Debug, Clone)]
pub struct MergeArgs {
    pub n: i64,
    pub change: Option<i64>,
    pub method: Option<String>,
}

/// `trail merge`: resolves the change (D4), reads `allowed_methods` from the
/// change detail, defaults the method (D5), and posts it. A refusal prints the
/// server's message, which carries the failing gate reasons.
pub async fn merge(ctx: &TrailCtx, args: &MergeArgs, format: Format) -> (String, u8) {
    let changes_resp = match ctx
        .api
        .get(&format!("trails/{}/changes", args.n), &[])
        .await
    {
        Ok(resp) => resp,
        Err(err) => return ctx.api.render_error(err),
    };
    let changes: Vec<Value> = changes_resp
        .get("changes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let k = match select_change(&changes, args.change, false) {
        Ok(k) => k,
        Err(msg) => return (format!("error: {msg}"), 1),
    };
    let detail = match ctx
        .api
        .get(&format!("trails/{}/changes/{k}", args.n), &[])
        .await
    {
        Ok(detail) => detail,
        Err(err) => return ctx.api.render_error(err),
    };
    let allowed: Vec<String> = detail
        .pointer("/change/allowed_methods")
        .or_else(|| detail.get("allowed_methods"))
        .and_then(Value::as_array)
        .map(|methods| {
            methods
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let method = match args.method.clone() {
        Some(method) => method,
        None => match default_method(&allowed) {
            Ok(method) => method,
            Err(msg) => return (format!("error: {msg}"), 1),
        },
    };
    let resp = match ctx
        .api
        .post(
            &format!("trails/{}/changes/{k}/merge", args.n),
            &json!({"method": method}),
        )
        .await
    {
        Ok(resp) => resp,
        Err(err) => return ctx.api.render_error(err),
    };
    match format {
        Format::Json => (pretty(&resp), 0),
        Format::Agent => agent_unsupported(),
        Format::Text => {
            let sha = resp.get("sha").and_then(Value::as_str).unwrap_or("?");
            let used = resp
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or(&method);
            (
                format!("merged trail #{} change {k} with {used}: {sha}", args.n),
                0,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn comment(side: &str, start: i64, end: i64) -> Value {
        json!({
            "path": "a.txt", "side": side,
            "start_line": start, "end_line": end, "body": "note",
        })
    }

    #[test]
    fn parse_inline_array() {
        let arg =
            serde_json::to_string(&vec![comment("head", 1, 2), comment("base", 3, 3)]).unwrap();
        let out = parse_comments(&arg, Cursor::new(Vec::new())).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].side, "head");
        assert_eq!(out[1].start_line, 3);
    }

    #[test]
    fn parse_at_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("comments.json");
        std::fs::write(
            &path,
            serde_json::to_string(&vec![comment("head", 1, 1)]).unwrap(),
        )
        .unwrap();
        let out = parse_comments(&format!("@{}", path.display()), Cursor::new(Vec::new())).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path, "a.txt");
    }

    #[test]
    fn parse_at_stdin() {
        let raw = serde_json::to_string(&vec![comment("base", 2, 4)]).unwrap();
        let out = parse_comments("@-", Cursor::new(raw.into_bytes())).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].side, "base");
    }

    #[test]
    fn parse_unknown_key_names_index() {
        let mut entry = comment("head", 1, 1);
        entry["nick"] = json!("x");
        let arg = serde_json::to_string(&vec![entry]).unwrap();
        let err = parse_comments(&arg, Cursor::new(Vec::new())).unwrap_err();
        assert!(err.contains("comments[0]"), "names the index: {err}");
    }

    #[test]
    fn parse_bad_side_names_index() {
        let arg = serde_json::to_string(&vec![comment("left", 1, 1)]).unwrap();
        let err = parse_comments(&arg, Cursor::new(Vec::new())).unwrap_err();
        assert!(err.contains("comments[0]"), "names the index: {err}");
    }

    #[test]
    fn parse_end_before_start_names_index() {
        let arg = serde_json::to_string(&vec![comment("head", 5, 2)]).unwrap();
        let err = parse_comments(&arg, Cursor::new(Vec::new())).unwrap_err();
        assert!(err.contains("comments[0]"), "names the index: {err}");
    }

    #[test]
    fn parse_second_entry_error_names_its_index() {
        let arg =
            serde_json::to_string(&vec![comment("head", 1, 1), comment("sideways", 1, 1)]).unwrap();
        let err = parse_comments(&arg, Cursor::new(Vec::new())).unwrap_err();
        assert!(err.contains("comments[1]"), "names the index: {err}");
    }

    #[test]
    fn parse_101_entries_rejected() {
        let many: Vec<Value> = (0..101).map(|_| comment("head", 1, 1)).collect();
        let arg = serde_json::to_string(&many).unwrap();
        let err = parse_comments(&arg, Cursor::new(Vec::new())).unwrap_err();
        assert!(err.contains("100"), "names the cap: {err}");
    }

    #[test]
    fn parse_non_array_rejected() {
        let err = parse_comments(r#"{"path": "a.txt"}"#, Cursor::new(Vec::new())).unwrap_err();
        assert!(err.contains("array"), "expected an array: {err}");
    }

    #[test]
    fn default_method_truth_table() {
        let m = |s: &[&str]| s.iter().map(|v| v.to_string()).collect::<Vec<_>>();
        assert_eq!(default_method(&m(&["merge", "squash"])).unwrap(), "merge");
        assert_eq!(
            default_method(&m(&["merge", "squash", "fast_forward"])).unwrap(),
            "merge"
        );
        assert_eq!(default_method(&m(&["squash"])).unwrap(), "squash");
        assert_eq!(
            default_method(&m(&["fast_forward"])).unwrap(),
            "fast_forward"
        );
        let err = default_method(&m(&["squash", "fast_forward"])).unwrap_err();
        assert!(err.contains("squash"), "lists methods: {err}");
        assert!(err.contains("fast_forward"), "lists methods: {err}");
        assert!(default_method(&[]).is_err());
    }
}
