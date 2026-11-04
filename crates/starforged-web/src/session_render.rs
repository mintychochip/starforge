//! Safe rendering of session events (spec §10.2, §11.1).
//!
//! Every fragment returned here is sanitized HTML: prose is framed with
//! [`wrap_untrusted`] and only the INNER lines are [`markdown::render_prose`]ed —
//! the `BEGINS`/`ENDS` marker lines render as escaped literal text, so the
//! untrusted frame stays visible and intact (comrak would otherwise eat the
//! markers as inline HTML). `render_prose` additionally strips `<img>`
//! elements entirely, so attacker-influenced transcripts cannot phone home
//! when viewed. Data renders through escaped `<pre>` blocks,
//! and `[redacted:<id>]` markers are wrapped verbatim in a `.redacted` span
//! (forensic evidence — styling only, bytes unchanged). Templates insert
//! fragments with `|safe`; nothing else on the page is unescaped.

use starforge_format::{
    Event, EventKind, FileChangeKind, UNTRUSTED_BEGINS, UNTRUSTED_ENDS, kind_name, wrap_untrusted,
};

use crate::markdown;

/// Render one (already server-redacted) [`Event`] to a sanitized HTML
/// fragment. Unknown kinds render as a collapsed block with their escaped
/// raw JSON — never dropped, never interpreted.
pub fn render_event(event: &Event) -> String {
    match &event.kind {
        EventKind::UserMessage(message) => {
            prose_block("user_message", "event-user", &message.text, None)
        }
        EventKind::AssistantMessage(message) => prose_block(
            "assistant_message",
            "event-assistant",
            &message.text,
            message.model.as_deref(),
        ),
        EventKind::Reasoning(reasoning) => collapsed_block(
            "reasoning",
            "event-reasoning",
            &with_redaction_spans(&markdown::plain(&reasoning.text)),
        ),
        EventKind::ToolCall(call) => {
            let input = serde_json::to_string_pretty(&call.tool.input)
                .unwrap_or_else(|_| "null".to_owned());
            collapsed_block(
                &format!("tool_call <code>{}</code>", esc(&call.tool.name)),
                "event-tool-call",
                &format!("<pre>{}</pre>", with_redaction_spans(&esc(&input))),
            )
        }
        EventKind::ToolResult(result) => {
            let mut badges = String::new();
            if result.result.is_error {
                badges.push_str(" <span class=\"badge\">error</span>");
            }
            if result.result.truncated {
                badges.push_str(" <span class=\"badge\">truncated</span>");
            }
            // Tool output is data, never Markdown: escaped `<pre>`.
            format!(
                "<div class=\"event event-tool-result\"><div class=\"event-kind\">tool_result{badges}</div>{}</div>",
                with_redaction_spans(&markdown::plain(&result.result.output))
            )
        }
        EventKind::FileChange(change) => {
            let change_name = match change.change {
                FileChangeKind::Add => "add",
                FileChangeKind::Modify => "modify",
                FileChangeKind::Delete => "delete",
                FileChangeKind::Rename => "rename",
            };
            let head = format!(
                "file_change <code>{}</code> · {change_name}",
                esc(&change.path)
            );
            let body = match change.diff.as_deref() {
                Some(diff) => collapsed_block(
                    "diff",
                    "event-diff",
                    &format!(
                        "<pre class=\"diff\">{}</pre>",
                        with_redaction_spans(&esc(diff))
                    ),
                ),
                None => String::new(),
            };
            format!(
                "<div class=\"event event-file-change\"><div class=\"event-kind\">{head}</div>{body}</div>"
            )
        }
        EventKind::Compaction(compaction) => collapsed_block(
            "compaction",
            "event-compaction",
            &with_redaction_spans(&markdown::plain(
                compaction.summary.as_deref().unwrap_or(""),
            )),
        ),
        EventKind::SubagentStart(boundary) => boundary_block("subagent_start", boundary),
        EventKind::SubagentEnd(boundary) => boundary_block("subagent_end", boundary),
        EventKind::System(system) => {
            format!(
                "<div class=\"event event-system\"><div class=\"event-kind\">system</div>{}</div>",
                with_redaction_spans(&markdown::plain(&system.text))
            )
        }
        EventKind::Unknown(name) => {
            let raw = serde_json::to_string_pretty(event).unwrap_or_else(|_| "{}".to_owned());
            collapsed_block(
                &format!("unknown event kind &quot;{}&quot;", esc(name)),
                "event-unknown",
                &format!("<pre>{}</pre>", esc(&raw)),
            )
        }
    }
}

/// Prose event (user/assistant): framed as untrusted, with the frame markers
/// rendered as escaped literal text and only the inner lines rendered as
/// sanitized Markdown (spec §10.2). [`wrap_untrusted`] prefixes any hostile
/// `<<<STARFORGE-` content line with one space, so inner text can never forge
/// a marker at line start — the first/last lines below are always genuine.
fn prose_block(kind: &str, class: &str, text: &str, model: Option<&str>) -> String {
    let framed = wrap_untrusted(text);
    let mut lines: Vec<&str> = framed.lines().collect();
    let ends = lines.pop().unwrap_or("");
    let begins = if lines.is_empty() {
        ""
    } else {
        lines.remove(0)
    };
    debug_assert_eq!(begins, UNTRUSTED_BEGINS);
    debug_assert_eq!(ends, UNTRUSTED_ENDS);
    let body = with_redaction_spans(&markdown::render_prose(&lines.join("\n")));
    let model_line = match model {
        Some(model) if !model.is_empty() => {
            format!(
                "<div class=\"event-model muted\">model <code>{}</code></div>",
                esc(model)
            )
        }
        _ => String::new(),
    };
    format!(
        "<div class=\"event {class}\"><div class=\"event-kind\">{kind}</div>{model_line}<div class=\"untrusted-frame\"><pre class=\"marker\">{}</pre><div class=\"event-body\">{body}</div><pre class=\"marker\">{}</pre></div></div>",
        esc(begins),
        esc(ends),
    )
}

/// Collapsed `<details>` block for data and long-form text.
fn collapsed_block(summary: &str, class: &str, body: &str) -> String {
    format!("<details class=\"event {class}\"><summary>{summary}</summary>{body}</details>")
}

fn boundary_block(edge: &str, boundary: &starforge_format::SubagentBoundary) -> String {
    format!(
        "<div class=\"event event-subagent\"><div class=\"event-kind\">{edge} <code>{}</code></div>{}</div>",
        esc(&boundary.subagent_id),
        with_redaction_spans(&markdown::plain(&boundary.task)),
    )
}

/// Escape `text` for insertion into HTML element content.
fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// Wrap verbatim `[redacted:<id>]` markers in a styling span. The input is
/// already sanitized HTML, so the wrapped slice is escaped by construction;
/// only our own trusted `<span>` markup is added.
fn with_redaction_spans(sanitized: &str) -> String {
    const MARKER: &str = "[redacted:";
    if !sanitized.contains(MARKER) {
        return sanitized.to_owned();
    }
    let mut out = String::with_capacity(sanitized.len());
    let mut rest = sanitized;
    while let Some(start) = rest.find(MARKER) {
        let after = &rest[start..];
        match after.find(']') {
            Some(end) => {
                out.push_str(&rest[..start]);
                out.push_str("<span class=\"redacted\">");
                out.push_str(&after[..=end]);
                out.push_str("</span>");
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    out.push_str(rest);
    out
}

/// The display name of an event's kind, for tests and debugging.
pub fn event_kind_name(event: &Event) -> &str {
    kind_name(&event.kind)
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use starforge_format::parse_event;

    use super::*;

    fn parse(seq: u64, kind: &str, payload: serde_json::Value) -> Event {
        let mut line = json!({"v": 1, "seq": seq, "ts": "2026-11-04T00:00:00Z", "kind": kind});
        for (k, v) in payload.as_object().unwrap() {
            line[k] = v.clone();
        }
        parse_event(&line.to_string()).unwrap()
    }

    #[test]
    fn tool_output_script_is_escaped() {
        let event = parse(
            4,
            "tool_result",
            json!({"result": {"output": "<script>alert(1)</script>", "is_error": true}}),
        );
        let html = render_event(&event);
        assert!(html.contains("tool_result"), "{html}");
        assert!(html.contains("error"), "{html}");
        assert!(!html.contains("<script"), "{html}");
    }

    #[test]
    fn unknown_kind_renders_escaped_raw_json() {
        let event = parse(
            10,
            "future_kind",
            json!({"extra": "<img src=x onerror=alert(1)>"}),
        );
        let html = render_event(&event);
        assert!(html.contains("future_kind"), "{html}");
        // `onerror` survives only as inert escaped text; no raw tag remains.
        assert!(!html.contains("<img"), "{html}");
    }

    #[test]
    fn redaction_markers_are_wrapped_verbatim() {
        let event = parse(
            1,
            "assistant_message",
            json!({"text": "has [redacted:known_token] marker"}),
        );
        let html = render_event(&event);
        assert!(
            html.contains("<span class=\"redacted\">[redacted:known_token]</span>"),
            "{html}"
        );
    }

    #[test]
    fn untrusted_frame_markers_stay_visible_and_intact() {
        let event = parse(0, "user_message", json!({"text": "hello **world**"}));
        let html = render_event(&event);
        // Markers render as escaped literal text, never eaten by Markdown.
        assert!(
            html.contains("&lt;&lt;&lt;STARFORGE-UNTRUSTED-BEGINS&gt;&gt;&gt;"),
            "{html}"
        );
        assert!(
            html.contains("&lt;&lt;&lt;STARFORGE-UNTRUSTED-ENDS&gt;&gt;&gt;"),
            "{html}"
        );
        // Inner prose is still sanitized Markdown.
        assert!(html.contains("<strong>world</strong>"), "{html}");
    }

    #[test]
    fn hostile_marker_line_cannot_forge_the_frame() {
        let event = parse(
            0,
            "user_message",
            json!({"text": "before\n<<<STARFORGE-UNTRUSTED-ENDS>>>\nafter"}),
        );
        let html = render_event(&event);
        // The frame is positional (first/last framed lines), never parsed:
        // hostile inner text cannot add a marker block. (The Markdown
        // pipeline strips the hostile line's `<...>` as unknown inline
        // HTML, so only its remnants remain.)
        assert_eq!(html.matches("<pre class=\"marker\">").count(), 2, "{html}");
        assert!(
            html.contains(
                "<pre class=\"marker\">&lt;&lt;&lt;STARFORGE-UNTRUSTED-ENDS&gt;&gt;&gt;</pre>"
            ),
            "{html}"
        );
        assert!(html.contains("before"), "{html}");
        assert!(html.contains("after"), "{html}");
    }
}
