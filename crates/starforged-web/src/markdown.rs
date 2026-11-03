//! Untrusted Markdown to safe HTML (spec §11.1): comrak with raw HTML disabled, then ammonia.

pub fn render(markdown: &str) -> String {
    let mut options = comrak::Options::default();
    options.extension.table = true;
    options.extension.strikethrough = true;
    options.extension.autolink = true;
    options.extension.tasklist = true;
    ammonia::clean(&comrak::markdown_to_html(markdown, &options))
}

/// Plain text as escaped, preformatted HTML.
pub fn plain(text: &str) -> String {
    format!("<pre>{}</pre>", ammonia::clean_text(text))
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
    fn plain_text_is_escaped() {
        assert_eq!(plain("<b>&"), "<pre>&lt;b&gt;&amp;</pre>");
    }
}
