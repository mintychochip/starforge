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
/// Context for rewriting repository-relative URLs in a document (a README).
///
/// `dir` is the repository-relative directory containing the document (`""` for the
/// repository root).
pub struct RepoDocContext<'a> {
    pub owner: &'a str,
    pub repo: &'a str,
    pub ref_name: &'a str,
    pub dir: &'a str,
}

/// Render repository Markdown like [`render`], rewriting relative link and image
/// URLs onto the tree/blob/raw routes so they resolve from the repository rather
/// than from the page URL. Raw HTML stays disabled and ammonia still strips
/// `javascript:` and friends.
pub fn render_repo_document(markdown: &str, ctx: &RepoDocContext) -> String {
    let mut options = comrak::Options::default();
    options.extension.table = true;
    options.extension.strikethrough = true;
    options.extension.autolink = true;
    options.extension.tasklist = true;
    let arena = comrak::Arena::new();
    let root = comrak::parse_document(&arena, markdown, &options);
    for node in root.descendants() {
        let mut data = node.data.borrow_mut();
        match &mut data.value {
            comrak::nodes::NodeValue::Link(link) => {
                link.url = rewrite_url(&link.url, ctx, false);
            }
            comrak::nodes::NodeValue::Image(image) => {
                image.url = rewrite_url(&image.url, ctx, true);
            }
            _ => {}
        }
    }
    let mut html = String::new();
    comrak::format_html(root, &options, &mut html).unwrap();
    ammonia::clean(&html)
}

fn has_scheme(url: &str) -> bool {
    let mut chars = url.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    for c in chars {
        if c == ':' {
            return true;
        }
        if c == '/' || c == '?' || c == '#' {
            return false;
        }
        if !(c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') {
            return false;
        }
    }
    false
}

fn rewrite_url(url: &str, ctx: &RepoDocContext, is_image: bool) -> String {
    if url.is_empty() || url.starts_with('#') || url.starts_with('?') || url.starts_with("//") {
        return url.to_owned();
    }
    if has_scheme(url) {
        return url.to_owned();
    }
    let (before_frag, frag) = match url.find('#') {
        Some(i) => (&url[..i], &url[i..]),
        None => (url, ""),
    };
    let (path_part, query) = match before_frag.find('?') {
        Some(i) => (&before_frag[..i], &before_frag[i..]),
        None => (before_frag, ""),
    };
    if path_part.is_empty() {
        return url.to_owned();
    }
    let is_root_relative = path_part.starts_with('/');
    let trailing_slash = path_part.ends_with('/');
    // Segments are percent-decoded once here because `content_href` encodes
    // every segment again: an author's `my%20file.md` must reach the router
    // as `my%20file.md`, not `my%2520file.md`.
    let mut segs: Vec<String> = if is_root_relative || ctx.dir.is_empty() {
        Vec::new()
    } else {
        ctx.dir
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    };
    for raw in path_part.split('/') {
        let decoded = percent_encoding::percent_decode_str(raw).decode_utf8_lossy();
        // A decoded `/` would add path structure the author never wrote (and
        // could smuggle `..` past the clamp below), so such a segment stays
        // literal; `content_href` then encodes its `%` like any other byte.
        let seg = if decoded.contains('/') {
            std::borrow::Cow::Borrowed(raw)
        } else {
            decoded
        };
        match seg.as_ref() {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            other => segs.push(other.to_owned()),
        }
    }
    let path = segs.join("/");
    let kind = if is_image {
        "raw"
    } else if trailing_slash || path.is_empty() {
        "tree"
    } else {
        "blob"
    };
    let mut href = crate::views::content_href(ctx.owner, ctx.repo, kind, ctx.ref_name, &path);
    href.push_str(query);
    href.push_str(frag);
    href
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

    fn ctx(dir: &str) -> RepoDocContext<'_> {
        RepoDocContext {
            owner: "alice",
            repo: "proj",
            ref_name: "main",
            dir,
        }
    }

    #[test]
    fn repo_document_relative_file_links_to_blob() {
        let html = render_repo_document("[x](docs/guide.md)", &ctx(""));
        assert!(
            html.contains(r#"href="/alice/proj/blob/main/docs/guide.md""#),
            "{html}"
        );
    }

    #[test]
    fn repo_document_trailing_slash_links_to_tree() {
        let html = render_repo_document("[x](docs/)", &ctx(""));
        assert!(
            html.contains(r#"href="/alice/proj/tree/main/docs""#),
            "{html}"
        );
    }

    #[test]
    fn repo_document_dotdot_normalizes_and_clamps_at_root() {
        let html = render_repo_document("[x](../guide.md)", &ctx("docs/sub"));
        assert!(
            html.contains(r#"href="/alice/proj/blob/main/docs/guide.md""#),
            "{html}"
        );
        let html = render_repo_document("[x](../../outside.md)", &ctx("docs"));
        assert!(
            html.contains(r#"href="/alice/proj/blob/main/outside.md""#),
            "{html}"
        );
        let html = render_repo_document("[x](..)", &ctx("docs"));
        assert!(html.contains(r#"href="/alice/proj/tree/main""#), "{html}");
    }

    #[test]
    fn repo_document_root_relative_resolves_from_repo_root() {
        let html = render_repo_document("[x](/docs/guide.md)", &ctx("docs/sub"));
        assert!(
            html.contains(r#"href="/alice/proj/blob/main/docs/guide.md""#),
            "{html}"
        );
    }

    #[test]
    fn repo_document_images_link_to_raw() {
        let html = render_repo_document("![x](img/logo.png)", &ctx(""));
        assert!(
            html.contains(r#"src="/alice/proj/raw/main/img/logo.png""#),
            "{html}"
        );
    }

    #[test]
    fn repo_document_leaves_absolute_and_anchor_urls_unchanged() {
        let html = render_repo_document(
            "[x](https://example.com/a) [y](#anchor) [z](mailto:a@example.com)",
            &ctx(""),
        );
        assert!(html.contains(r#"href="https://example.com/a""#), "{html}");
        assert!(html.contains(r##"href="#anchor""##), "{html}");
        assert!(html.contains(r#"href="mailto:a@example.com""#), "{html}");
    }

    #[test]
    fn repo_document_still_strips_javascript() {
        let html = render_repo_document("[x](javascript:alert(1))", &ctx(""));
        assert!(!html.contains("javascript:"), "{html}");
    }

    #[test]
    fn repo_document_preserves_fragment_and_query() {
        let html = render_repo_document("[x](docs/guide.md?draft=1#section)", &ctx(""));
        assert!(
            html.contains("/alice/proj/blob/main/docs/guide.md?draft=1#section"),
            "{html}"
        );
    }

    #[test]
    fn repo_document_encodes_paths_exactly_once() {
        let html = render_repo_document("[x](my%20file.md) [y](<a b.md>)", &ctx("docs"));
        assert!(
            html.contains("/alice/proj/blob/main/docs/my%20file.md"),
            "{html}"
        );
        assert!(
            html.contains("/alice/proj/blob/main/docs/a%20b.md"),
            "{html}"
        );
        assert!(!html.contains("%2520"), "{html}");
    }

    #[test]
    fn repo_document_encoded_dot_segments_still_clamp_at_root() {
        let html = render_repo_document("[x](%2e%2e/%2E%2E/%2e%2e/secret.md)", &ctx("docs"));
        assert!(
            html.contains(r#"href="/alice/proj/blob/main/secret.md""#),
            "{html}"
        );
    }

    #[test]
    fn repo_document_keeps_encoded_slashes_literal() {
        let html = render_repo_document("[x](a%2F..%2F..%2Fadmin)", &ctx(""));
        assert!(
            html.contains("/alice/proj/blob/main/a%252F..%252F..%252Fadmin"),
            "{html}"
        );
        assert!(!html.contains("/../"), "{html}");
    }
}
