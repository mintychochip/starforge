//! Untrusted Markdown to safe HTML (spec §11.1): comrak with raw HTML disabled, then ammonia.

pub fn render(markdown: &str) -> String {
    let mut options = comrak::Options::default();
    options.extension.table = true;
    options.extension.strikethrough = true;
    options.extension.autolink = true;
    options.extension.tasklist = true;
    ammonia::clean(&comrak::markdown_to_html(markdown, &options))
}

/// Session-transcript prose: like [`render`], but `<img>` elements are
/// disallowed entirely. Agent transcripts are attacker-influenced, so a
/// `![alt](https://…)` image must not become a live fetch leaking the
/// viewer's IP/user-agent — not even a relative one (session prose has no
/// legitimate image use, and same-origin allow-listing would add an origin
/// check to every render). Only the session renderer uses this; repository
/// content (READMEs, blobs) keeps [`render`].
pub fn render_prose(markdown: &str) -> String {
    let mut options = comrak::Options::default();
    options.extension.table = true;
    options.extension.strikethrough = true;
    options.extension.autolink = true;
    options.extension.tasklist = true;
    ammonia::Builder::default()
        .rm_tags(&["img"])
        .clean(&comrak::markdown_to_html(markdown, &options))
        .to_string()
}

/// Plain text as escaped, preformatted HTML. Escapes markup characters only;
/// spaces and prose pass through byte-identically (unlike
/// `ammonia::clean_text`, which encodes spaces as `&#32;`).
pub fn plain(text: &str) -> String {
    format!("<pre>{}</pre>", escape(text))
}

/// Minimal element-content escaping: `<`, `>`, `&`, `"`, `'`.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_loses_scripts_and_javascript_links() {
        let html = render(
            "# Hi\n\n<script>alert(1)</script>\n\n[x](javascript:alert(1)) **b**\n\n| a |\n|---|\n| 1 |\n",
        );
        assert!(html.contains("<h1>Hi</h1>"), "{html}");
        assert!(html.contains("<strong>b</strong>"), "{html}");
        assert!(html.contains("<table>"), "{html}");
        assert!(!html.contains("<script"), "{html}");
        assert!(!html.contains("javascript:"), "{html}");
    }

    #[test]
    fn prose_strips_images_but_keeps_markdown() {
        let html = render_prose(
            "**bold** [ok](https://example.com) ![x](https://attacker.example/t.png) ![y](/static/y.png)\n\n| a |\n|---|\n| 1 |\n",
        );
        assert!(html.contains("<strong>bold</strong>"), "{html}");
        assert!(html.contains("<table>"), "{html}");
        assert!(html.contains("<a"), "{html}");
        assert!(!html.contains("<img"), "{html}");
        assert!(!html.contains("attacker.example"), "{html}");
        assert!(!html.contains("/static/y.png"), "{html}");
    }

    #[test]
    fn prose_strips_raw_img_elements() {
        let html = render_prose("before <img src=\"https://attacker.example/t.svg\"> after");
        assert!(!html.contains("<img"), "{html}");
        assert!(!html.contains("attacker.example"), "{html}");
        assert!(html.contains("before"), "{html}");
        assert!(html.contains("after"), "{html}");
    }

    #[test]
    fn plain_text_is_escaped() {
        assert_eq!(plain("<b>&"), "<pre>&lt;b&gt;&amp;</pre>");
    }

    #[test]
    fn plain_prose_passes_through_verbatim() {
        assert_eq!(
            plain("thinking it through 1 < 2"),
            "<pre>thinking it through 1 &lt; 2</pre>"
        );
    }
}
