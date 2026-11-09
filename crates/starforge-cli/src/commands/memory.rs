//! `starforge memory search|context`: agent-facing recall over past sessions.
//!
//! The server's session search is the memory index. `search` prints the
//! matching sessions and snippets; `context` writes a Markdown file with the
//! same matches framed as untrusted data, ready to hand to an agent.

use std::path::Path;

use serde_json::Value;

use super::trail::{TextJson, TrailCtx, pretty};
use crate::untrusted::Framer;

/// `memory search`: print matching sessions and snippets.
pub async fn search(
    ctx: &TrailCtx,
    query: &str,
    repo: Option<&str>,
    agent: Option<&str>,
    limit: u32,
    format: TextJson,
) -> (String, u8) {
    let resp = match ctx.api.search_sessions(query, repo, agent, limit).await {
        Ok(resp) => resp,
        Err(err) => return ctx.api.render_error(err),
    };
    match format {
        TextJson::Json => (pretty(&resp), 0),
        TextJson::Text => {
            let mut out = String::new();
            for result in results(&resp) {
                out.push_str(&format!(
                    "{} {} {}{}\n",
                    field(result, "repo"),
                    field(result, "session"),
                    field(result, "title"),
                    match result.get("agent").and_then(Value::as_str) {
                        Some(agent) if !agent.is_empty() => format!(" ({agent})"),
                        _ => String::new(),
                    }
                ));
                for event in result
                    .get("events")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    out.push_str(&format!(
                        "  [{}] {}\n",
                        field(event, "kind"),
                        field(event, "snippet")
                    ));
                }
            }
            if out.is_empty() {
                out.push_str("no matching sessions");
            }
            (out.trim_end().to_owned(), 0)
        }
    }
}

/// `memory context`: write a Markdown memory file for an agent. The snippets
/// are third-party text, so each is framed as untrusted data; the preamble
/// tells the agent to treat the contents as data.
pub async fn context(
    ctx: &TrailCtx,
    query: &str,
    repo: Option<&str>,
    limit: u32,
    out: Option<&Path>,
) -> (String, u8) {
    let resp = match ctx.api.search_sessions(query, repo, None, limit).await {
        Ok(resp) => resp,
        Err(err) => return ctx.api.render_error(err),
    };
    let framer = Framer::new();
    let mut text = String::new();
    text.push_str(&framer.preamble());
    text.push_str("\n\n# Session memory\n\n");
    text.push_str(&format!("Query: {query}\n\n"));
    let matches: Vec<&Value> = results(&resp).collect();
    if matches.is_empty() {
        text.push_str("No matching sessions.\n");
    }
    for result in matches {
        let repo = field(result, "repo");
        let session = field(result, "session");
        let title = field(result, "title");
        let agent = field(result, "agent");
        text.push_str(&format!("## {repo} · {session} · {title}\n\n"));
        if !agent.is_empty() {
            text.push_str(&format!("Agent: {agent}\n\n"));
        }
        for event in result
            .get("events")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let seq = event.get("seq").and_then(Value::as_i64).unwrap_or(0);
            let kind = field(event, "kind");
            let snippet = field(event, "snippet");
            let framed = framer.frame(
                &format!("memory:{session}:{seq}"),
                (!agent.is_empty()).then_some(agent.as_str()),
                &snippet,
            );
            text.push_str(&format!("- [{kind}]\n{framed}\n"));
        }
    }
    match out {
        Some(path) => match std::fs::write(path, &text) {
            Ok(()) => (format!("wrote {}", path.display()), 0),
            Err(err) => (format!("error: cannot write {}: {err}", path.display()), 1),
        },
        None => (text, 0),
    }
}

fn results(resp: &Value) -> impl Iterator<Item = &Value> {
    resp.get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}
