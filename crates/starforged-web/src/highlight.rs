//! Syntax highlighting for the file view (forge-basics design §6): syntect with bat's syntaxes and themes
//! (two-face), CSS classes prefixed `hl-`, and one self-contained HTML fragment per line, so line anchors work.

use std::sync::LazyLock;

use syntect::html::{ClassStyle, css_for_theme_with_class_style, line_tokens_to_classed_spans};
use syntect::parsing::{ParseState, Scope, ScopeStack, SyntaxReference, SyntaxSet};
use syntect::util::LinesWithEndings;
use two_face::theme::EmbeddedThemeName;

/// Larger files are shown as plain text.
pub const MAX_HIGHLIGHT_BYTES: usize = 512 * 1024;
/// A file with a longer line is shown as plain text.
pub const MAX_HIGHLIGHT_LINE_CHARS: usize = 5_000;

const STYLE: ClassStyle = ClassStyle::SpacedPrefixed { prefix: "hl-" };

static SYNTAXES: LazyLock<SyntaxSet> = LazyLock::new(two_face::syntax::extra_newlines);

/// `/static/highlight.css`: bat's GitHub theme, and OneHalfDark under `prefers-color-scheme: dark`, matching
/// the interface, which follows the system color scheme.
pub static STYLESHEET: LazyLock<String> = LazyLock::new(|| {
    let themes = two_face::theme::extra();
    let light = css_for_theme_with_class_style(themes.get(EmbeddedThemeName::Github), STYLE)
        .expect("the GitHub theme converts to CSS");
    let dark = css_for_theme_with_class_style(themes.get(EmbeddedThemeName::OneHalfDark), STYLE)
        .expect("the OneHalfDark theme converts to CSS");
    format!("{light}\n@media (prefers-color-scheme: dark) {{\n{dark}\n}}\n")
});

/// The syntax for `file_name` (a full name such as `Makefile`, then its extension), then for the first line
/// (a shebang), else plain text.
fn syntax_for(file_name: &str, first_line: &str) -> &'static SyntaxReference {
    let syntaxes: &'static SyntaxSet = &SYNTAXES;
    let extension = file_name
        .rsplit_once('.')
        .map(|(_, ext)| ext)
        .unwrap_or_default();
    syntaxes
        .find_syntax_by_extension(file_name)
        .or_else(|| syntaxes.find_syntax_by_extension(extension))
        .or_else(|| syntaxes.find_syntax_by_first_line(first_line))
        .unwrap_or_else(|| syntaxes.find_syntax_plain_text())
}

/// Each line of `text` as HTML whose spans all close on that line: the scopes still open from earlier lines
/// are reopened first and closed at the end. syntect escapes the text. `None` when the file is over
/// [`MAX_HIGHLIGHT_BYTES`], has a line over [`MAX_HIGHLIGHT_LINE_CHARS`] characters, or cannot be parsed;
/// show it as plain text then. Slow for large files: call it on the blocking thread pool.
pub fn highlight_lines(file_name: &str, text: &str) -> Option<Vec<String>> {
    if text.len() > MAX_HIGHLIGHT_BYTES
        || text
            .lines()
            .any(|line| line.chars().count() > MAX_HIGHLIGHT_LINE_CHARS)
    {
        return None;
    }
    let syntaxes: &SyntaxSet = &SYNTAXES;
    let syntax = syntax_for(file_name, text.lines().next().unwrap_or_default());
    let mut state = ParseState::new(syntax);
    let mut stack = ScopeStack::new();
    let mut lines = Vec::new();
    for line in LinesWithEndings::from(text) {
        let ops = state.parse_line(line, syntaxes).ok()?;
        let mut html = String::new();
        for scope in stack.as_slice() {
            open_span(&mut html, *scope);
        }
        let (body, _) = line_tokens_to_classed_spans(line, &ops, STYLE, &mut stack).ok()?;
        html.push_str(&body.replace(['\n', '\r'], ""));
        for _ in 0..stack.len() {
            html.push_str("</span>");
        }
        lines.push(html);
    }
    Some(lines)
}

/// `<span class="hl-a hl-b">` for scope `a.b`, as syntect writes it.
fn open_span(html: &mut String, scope: Scope) {
    html.push_str("<span class=\"");
    for (i, atom) in scope.build_string().split('.').enumerate() {
        if i > 0 {
            html.push(' ');
        }
        html.push_str("hl-");
        html.push_str(atom);
    }
    html.push_str("\">");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn balanced(line: &str) -> bool {
        line.matches("<span").count() == line.matches("</span>").count()
    }

    #[test]
    fn source_text_is_escaped_and_every_line_stands_alone() {
        let source = "/* a block\n   comment <b> */\nfn main() {\n    let s = \"<script>alert(1)</script>\";\n}\n";
        let lines = highlight_lines("main.rs", source).unwrap();
        assert_eq!(lines.len(), 5);
        assert!(lines.iter().all(|l| balanced(l)), "{lines:#?}");
        assert!(
            lines[1].contains("hl-comment"),
            "a block comment keeps its classes on its second line: {}",
            lines[1]
        );
        assert!(
            lines[2].contains(r#"<span class="hl-storage hl-type hl-function hl-rust">fn</span>"#),
            "{}",
            lines[2]
        );
        assert!(
            lines[3].contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "{}",
            lines[3]
        );
        assert!(
            lines
                .iter()
                .all(|l| !l.contains("<script") && !l.contains("<b>")),
            "{lines:#?}"
        );
        assert!(lines.iter().all(|l| !l.contains('\n')));
    }

    #[test]
    fn languages_come_from_the_name_then_the_first_line() {
        let shell = highlight_lines("deploy", "#!/bin/bash\necho hi\n").unwrap();
        assert!(shell[1].contains("hl-shell"), "{}", shell[1]);
        let toml = highlight_lines("Cargo.toml", "[package]\n").unwrap();
        assert!(toml[0].contains("hl-toml"), "{}", toml[0]);
        let plain = highlight_lines("notes", "just words\n").unwrap();
        assert!(plain[0].contains("hl-text hl-plain"), "{}", plain[0]);
        assert_eq!(
            highlight_lines("empty.rs", "").unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn large_files_and_long_lines_are_not_highlighted() {
        assert!(highlight_lines("a.rs", &"x".repeat(MAX_HIGHLIGHT_LINE_CHARS)).is_some());
        assert!(highlight_lines("a.rs", &"x".repeat(MAX_HIGHLIGHT_LINE_CHARS + 1)).is_none());
        let big = "short line\n".repeat(MAX_HIGHLIGHT_BYTES / 11 + 1);
        assert!(big.len() > MAX_HIGHLIGHT_BYTES);
        assert!(highlight_lines("a.txt", &big).is_none());
    }

    #[test]
    fn the_stylesheet_has_light_and_dark_colors() {
        assert!(STYLESHEET.contains(".hl-comment"));
        assert!(STYLESHEET.contains("@media (prefers-color-scheme: dark)"));
    }
}
