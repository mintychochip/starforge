#!/usr/bin/env python3
"""Check Starforge technical documents against the project STE profile.

The profile applies the writing rules of ASD-STE100 Simplified Technical
English to docs/technical.  The checker enforces the mechanical rules.  A
reviewer enforces the rules that need judgement.

Usage:
    python3 scripts/ste_check.py                # check docs/technical
    python3 scripts/ste_check.py --strict       # warnings also fail
    python3 scripts/ste_check.py path ...       # check files or directories
    python3 scripts/ste_check.py --list-rules
"""

from __future__ import annotations

import argparse
import glob
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

# --------------------------------------------------------------------------
# Rules and word lists
# --------------------------------------------------------------------------

MAX_INSTRUCTION_WORDS = 20
MAX_DESCRIPTIVE_WORDS = 25
MAX_PARAGRAPH_SENTENCES = 6
MAX_HEADING_WORDS = 8

MODALS = re.compile(r"\b(should|would|could|might|may|shall)\b", re.IGNORECASE)

CONTRACTIONS = re.compile(
    r"\b(don't|doesn't|didn't|can't|couldn't|won't|wouldn't|shouldn't|"
    r"isn't|aren't|wasn't|weren't|hasn't|haven't|hadn't|it's|that's|"
    r"there's|we're|you're|we've|we'll|I'm|I've|let's)\b",
    re.IGNORECASE,
)

# term -> approved replacement
BANNED_TERMS: list[tuple[str, str]] = [
    (r"\brepos?\b", "repository or repositories"),
    (r"\blog in\b", "sign in"),
    (r"\blogged in\b", "signed in"),
    (r"\blogin\b", "sign-in or sign in"),
    (r"\be\.g\.", "for example"),
    (r"\bi\.e\.", "that is"),
    (r"\betc\.", "list the items"),
    (r"\bvia\b", "through"),
    (r"\bprior to\b", "before"),
    (r"\bsubsequent to\b", "after"),
    (r"\bin order to\b", "to"),
    (r"\butili[sz]e\b", "use"),
    (r"\bleverage\b", "use"),
    (r"\bensure\b", "make sure"),
    (r"\bcommence\b", "start"),
    (r"\bterminate\b", "stop"),
    (r"\bdemonstrate\b", "show"),
    (r"\bfacilitate\b", "help"),
    (r"\bapproximately\b", "about"),
    (r"\btherefore\b", "so"),
    (r"\bthus\b", "so"),
    (r"\bwhilst\b", "while"),
    (r"\bamongst\b", "among"),
    (r"\bwhitelist\b", "allowlist"),
    (r"\bblacklist\b", "denylist"),
    (r"\bquickly\b", "remove the word"),
    (r"\beasily\b", "remove the word"),
    (r"\bsimply\b", "remove the word"),
    (r"\bvery\b", "remove the word"),
    (r"\bplease\b", "remove the word"),
    (r"\bnote that\b", "remove the phrase"),
    (r"\bit should be noted\b", "remove the phrase"),
    (r"\ba lot of\b", "many"),
    (r"\bis able to\b", "can"),
    (r"\bhas the ability to\b", "can"),
    (r"\busing\b", "with, or rewrite the sentence"),
    (r"\bwe\b", "Starforge, you, or rewrite the sentence"),
    (r"\bour\b", "the, or rewrite the sentence"),
    (r"\bus\b", "Starforge, you, or rewrite the sentence"),
]

SPELLING = {
    "behaviour": "behavior",
    "behaviours": "behaviors",
    "colour": "color",
    "colours": "colors",
    "initialise": "initialize",
    "initialised": "initialized",
    "initialises": "initializes",
    "initialising": "initializing",
    "organisation": "organization",
    "organisations": "organizations",
    "licence": "license",
    "centre": "center",
    "cancelled": "canceled",
    "cancelling": "canceling",
    "defence": "defense",
    "artefact": "artifact",
    "artefacts": "artifacts",
    "grey": "gray",
    "catalogue": "catalog",
    "programme": "program",
    "synchronise": "synchronize",
    "synchronised": "synchronized",
    "normalise": "normalize",
    "serialise": "serialize",
    "serialised": "serialized",
    "authorise": "authorize",
    "authorised": "authorized",
    "recognise": "recognize",
    "recognised": "recognized",
    "finalise": "finalize",
    "finalised": "finalized",
    "minimise": "minimize",
    "maximise": "maximize",
}

IRREGULAR_PARTICIPLES = (
    "built|made|known|shown|written|given|taken|done|kept|sent|held|run|"
    "read|found|stored|set|used|called|named|put|cut|chosen|drawn|"
    "brought|caught|left|lost|paid|sold|told|thought|understood|won|"
    "seen|heard|meant|met|led|fed|bred|fought|sought|taught|worn|torn|"
    "born|broken|spoken|stolen|frozen|hidden|ridden|risen|risen|"
    "become|begun|drunk|sung|swum|rung|sunk|shrunk|spun|stung|stuck|"
    "struck|hung|dug|won|shut|split|spread|cost|hit|hurt|read"
)
PASSIVE = re.compile(
    r"\b(is|are|was|were|be|been|being)\s+(not\s+)?((?:[a-z]+ly)\s+)?"
    r"(" + IRREGULAR_PARTICIPLES + r"|[a-z]+ed)\b",
    re.IGNORECASE,
)

PROGRESSIVE = re.compile(
    r"\b(is|are|was|were|be|been|being)\s+((?:[a-z]+ly)\s+)?[a-z]+ing\b",
    re.IGNORECASE,
)

# First words that show an instruction.  The list covers the verbs used in
# technical procedures.  A sentence that starts with another word is treated
# as descriptive text.
IMPERATIVE_VERBS = {
    "add", "allow", "answer", "apply", "ask", "build", "call", "change",
    "check", "choose", "clean", "clear", "click", "close", "commit",
    "compare", "complete", "configure", "confirm", "connect", "copy",
    "create", "decrement", "define", "delete", "deploy", "disable",
    "discard", "display", "do", "download", "edit", "enable", "enter",
    "examine", "exclude", "execute", "export", "extract", "fetch", "find",
    "follow", "give", "go", "grant", "import", "increment", "install",
    "keep", "list", "load", "log", "make", "mark", "merge", "move",
    "open", "pass", "paste", "pick", "point", "press", "publish", "pull",
    "purge", "push", "put", "read", "rebuild", "receive", "record",
    "redact", "redirect", "refer", "refresh", "register", "reject",
    "release", "reload", "remove", "rename", "replace", "reply", "report",
    "request", "require", "reset", "restart", "restore", "resume",
    "retry", "return", "revert", "revoke", "run", "save", "scan", "search",
    "see", "select", "send", "set", "show", "sign", "start", "stop",
    "store", "submit", "sync", "test", "try", "turn", "type", "unlink",
    "unpublish", "update", "upload", "use", "validate", "verify", "view",
    "wait", "write",
}

PROPER_NOUNS = {
    "Starforge", "starforged", "starforge", "GitHub", "GitLab", "SQLite",
    "Postgres", "PostgreSQL", "Linux", "macOS", "Windows", "Rust", "Cargo",
    "OAuth", "OIDC", "SSH", "HTTP", "HTTPS", "API", "CLI", "Web", "Git",
    "Markdown", "JSON", "YAML", "TOML", "ULID", "BLAKE3", "SHA", "HMAC",
    "Tantivy", "Prometheus", "Playwright", "Docker", "Podman", "Alpine",
    "Unix", "Python", "JavaScript", "Node", "Chrome", "Chromium", "SMTP",
    "TLS", "CSRF", "CSP", "XSS", "SSRF", "MFA", "TOTP", "JWT", "PKCE",
    "APIs", "CLIs", "Trail", "Trails", "Starforge-Session", "Technical", "English",
}
PROPER_NOUNS_LOWER = {word.lower() for word in PROPER_NOUNS}

SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")
INLINE_CODE = re.compile(r"`[^`]*`")
LINK = re.compile(r"!?\[([^\]]*)\]\(([^)]+)\)")
HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
SOURCE_BLOCK = re.compile(r"<!--\s*ste-sources\s*\n(.*?)-->", re.DOTALL)

# Files that do not need a ste-sources block.
NO_SOURCE_BLOCK = {"README.md", "ste100.md", "glossary.md", "maintenance.md"}


@dataclass(frozen=True)
class Diagnostic:
    path: Path
    line: int
    severity: str  # "error" or "warning"
    code: str
    message: str

    def format(self, root: Path) -> str:
        try:
            shown = self.path.relative_to(root)
        except ValueError:
            shown = self.path
        return f"{shown}:{self.line}: {self.severity} {self.code}: {self.message}"


def mask_inline(text: str) -> str:
    """Replace values that STE does not count as prose words."""
    text = INLINE_CODE.sub("CODE", text)
    text = re.sub(r"https?://\S+", "URL", text)
    text = re.sub(r"\b\d+(?:\.\d+)+\b", "VERSION", text)
    text = re.sub(r"\b(?:e\.g|i\.e|etc)\.", "ABBR", text, flags=re.IGNORECASE)
    return text


def strip_code_and_links(text: str) -> str:
    """Remove inline code, link targets, and HTML comments from a line."""
    text = INLINE_CODE.sub("", text)
    text = LINK.sub(r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    return text


def words(text: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9_'-]+|CODE|URL|VERSION|ABBR", text)


def first_word(sentence: str) -> str:
    match = re.search(r"[A-Za-z0-9_'-]+|CODE|URL|VERSION", sentence)
    return match.group(0) if match else ""


def split_sentences(text: str) -> list[str]:
    masked = mask_inline(text)
    return [part.strip() for part in SENTENCE_SPLIT.split(masked) if part.strip()]


def is_procedural(sentence: str) -> bool:
    token = first_word(mask_inline(sentence)).lower()
    return token in IMPERATIVE_VERBS


def slugify(heading: str) -> str:
    text = heading.strip().lower()
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    return text.strip("-")


def heading_slugs(text: str) -> set[str]:
    slugs: set[str] = set()
    counts: dict[str, int] = {}
    for line in text.splitlines():
        match = re.match(r"^(#{1,6})\s+(.*?)\s*$", line)
        if not match:
            continue
        base = slugify(match.group(2))
        count = counts.get(base, 0)
        counts[base] = count + 1
        slugs.add(base if count == 0 else f"{base}-{count}")
    return slugs


def check_banned_terms(path: Path, line_no: int, prose: str, diagnostics: list[Diagnostic]) -> None:
    for pattern, replacement in BANNED_TERMS:
        for match in re.finditer(pattern, prose, re.IGNORECASE):
            diagnostics.append(
                Diagnostic(path, line_no, "error", "STE003",
                           f"use the approved term instead of '{match.group(0)}': {replacement}")
            )
    for term, replacement in SPELLING.items():
        if re.search(rf"\b{re.escape(term)}\b", prose, re.IGNORECASE):
            diagnostics.append(
                Diagnostic(path, line_no, "error", "STE003",
                           f"use American spelling '{replacement}' instead of '{term}'")
            )


def check_sentences(
    path: Path, line_no: int, text: str, diagnostics: list[Diagnostic]
) -> int:
    sentences = split_sentences(text)
    for sentence in sentences:
        count = len(words(sentence))
        procedural = is_procedural(sentence)
        limit = MAX_INSTRUCTION_WORDS if procedural else MAX_DESCRIPTIVE_WORDS
        if count > limit:
            kind = "instruction" if procedural else "descriptive sentence"
            diagnostics.append(
                Diagnostic(path, line_no, "error", "STE001",
                           f"{kind} has {count} words; the limit is {limit}")
            )
        if procedural and re.search(
            r",\s*(?:and|then)\s+(" + "|".join(sorted(IMPERATIVE_VERBS)) + r")\b",
            sentence,
            re.IGNORECASE,
        ):
            diagnostics.append(
                Diagnostic(path, line_no, "error", "STE005",
                           "put one instruction in each sentence")
            )
    return len(sentences)


def check_heading(path: Path, line_no: int, level: int, text: str,
                  diagnostics: list[Diagnostic]) -> None:
    clean = strip_code_and_links(text).strip()
    if clean.endswith("."):
        diagnostics.append(
            Diagnostic(path, line_no, "error", "STE010", "remove the period from the heading")
        )
    count = len(words(mask_inline(clean)))
    if count > MAX_HEADING_WORDS:
        diagnostics.append(
            Diagnostic(path, line_no, "warning", "STE010",
                       f"heading has {count} words; the limit is {MAX_HEADING_WORDS}")
        )
    parts = re.findall(r"[A-Za-z][A-Za-z0-9'-]*", clean)
    for index, part in enumerate(parts):
        if index == 0 or part.isupper() or part in PROPER_NOUNS:
            continue
        if part.lower() in PROPER_NOUNS_LOWER:
            continue
        if part[0].isupper() and not re.fullmatch(r"[A-Z]{2,}", part):
            diagnostics.append(
                Diagnostic(path, line_no, "warning", "STE011",
                           f"use sentence case in the heading: '{part}'")
            )
            break


def check_links(path: Path, line_no: int, text: str, root: Path,
                diagnostics: list[Diagnostic]) -> None:
    clean = INLINE_CODE.sub("", text)
    for match in LINK.finditer(clean):
        label, target = match.group(1), match.group(2).strip()
        if label.strip().lower() in {"here", "link", "this"}:
            diagnostics.append(
                Diagnostic(path, line_no, "warning", "STE012",
                           "use a descriptive link label")
            )
        if target.startswith(("http://", "https://", "mailto:", "#", "data:")):
            continue
        target = target.split(" ", 1)[0]
        target_path, _, anchor = target.partition("#")
        if not target_path:
            continue
        resolved = (path.parent / target_path).resolve()
        if not resolved.exists():
            diagnostics.append(
                Diagnostic(path, line_no, "error", "STE013",
                           f"linked path does not exist: {target_path}")
            )
            continue
        if anchor and resolved.suffix == ".md" and resolved.is_file():
            slugs = heading_slugs(resolved.read_text(encoding="utf-8"))
            if anchor not in slugs:
                diagnostics.append(
                    Diagnostic(path, line_no, "warning", "STE013",
                               f"anchor does not exist in {target_path}: #{anchor}")
                )


def check_markdown(path: Path, text: str, root: Path,
                   strict_sources: bool) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []

    # Source anchors.
    source_match = SOURCE_BLOCK.search(text)
    if source_match:
        for line in source_match.group(1).splitlines():
            source = line.strip()
            if not source:
                continue
            if not (root / source).exists():
                diagnostics.append(
                    Diagnostic(path, 1, "error", "STE030",
                               f"source path does not exist: {source}")
                )
    elif strict_sources and path.name not in NO_SOURCE_BLOCK:
        diagnostics.append(
            Diagnostic(path, 1, "error", "STE030",
                       "add a ste-sources comment with the code paths this page documents")
        )

    # H1 count.
    h1_count = sum(1 for line in text.splitlines() if re.match(r"^#\s+\S", line))
    if h1_count != 1:
        diagnostics.append(
            Diagnostic(path, 1, "error", "STE014",
                       f"document has {h1_count} level-1 headings; add exactly one")
        )

    in_fence = False
    fence_lang = ""
    in_comment = False
    paragraph: list[str] = []
    paragraph_line = 0

    def flush_paragraph() -> None:
        nonlocal paragraph, paragraph_line
        if not paragraph:
            return
        joined = " ".join(paragraph)
        sentence_count = check_sentences(path, paragraph_line, joined, diagnostics)
        if sentence_count > MAX_PARAGRAPH_SENTENCES:
            diagnostics.append(
                Diagnostic(path, paragraph_line, "warning", "STE004",
                           f"paragraph has {sentence_count} sentences; the limit is "
                           f"{MAX_PARAGRAPH_SENTENCES}")
            )
        check_banned_terms(path, paragraph_line, strip_code_and_links(joined), diagnostics)
        check_links(path, paragraph_line, joined, root, diagnostics)
        if re.search(r"\b(there is|there are)\b", joined, re.IGNORECASE):
            diagnostics.append(
                Diagnostic(path, paragraph_line, "warning", "STE020",
                           "rewrite the sentence without 'there is' or 'there are'")
            )
        paragraph = []
        paragraph_line = 0

    for line_no, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()

        if in_comment:
            if "-->" in stripped:
                in_comment = False
            continue
        if stripped.startswith("<!--"):
            flush_paragraph()
            if "-->" not in stripped:
                in_comment = True
            continue

        fence = re.match(r"^\s*(```+|~~~+)\s*(\S*)\s*$", raw)
        if fence:
            flush_paragraph()
            if not in_fence:
                in_fence = True
                fence_lang = fence.group(2)
                if not fence_lang:
                    diagnostics.append(
                        Diagnostic(path, line_no, "warning", "STE015",
                                   "add a language name to the code fence")
                    )
            else:
                in_fence = False
            continue
        if in_fence:
            continue

        if not stripped:
            flush_paragraph()
            continue

        heading = re.match(r"^(#{1,6})\s+(.*?)\s*$", raw)
        if heading:
            flush_paragraph()
            check_heading(path, line_no, len(heading.group(1)), heading.group(2), diagnostics)
            check_banned_terms(
                path, line_no, strip_code_and_links(heading.group(2)), diagnostics
            )
            continue

        if stripped.startswith("|"):
            flush_paragraph()
            continue

        if re.match(r"^\s*([-*+]|\d+\.)\s+", raw):
            flush_paragraph()
            item = re.sub(r"^\s*(?:[-*+]|\d+\.)\s+", "", raw)
            check_sentences(path, line_no, item, diagnostics)
            check_banned_terms(path, line_no, strip_code_and_links(item), diagnostics)
            check_links(path, line_no, item, root, diagnostics)
            continue

        quote = re.match(r"^\s*>\s?(.*)$", raw)
        if quote:
            flush_paragraph()
            content = quote.group(1)
            if content.startswith("**") and content.endswith("**"):
                content = content.strip("*")
            check_sentences(path, line_no, content, diagnostics)
            check_banned_terms(path, line_no, strip_code_and_links(content), diagnostics)
            check_links(path, line_no, content, root, diagnostics)
            continue

        paragraph.append(stripped)
        if not paragraph_line:
            paragraph_line = line_no

    flush_paragraph()

    # Prose punctuation and voices.  Table and code lines are excluded above.
    in_fence = False
    in_comment = False
    for line_no, raw in enumerate(text.splitlines(), 1):
        stripped_raw = raw.strip()
        if in_comment:
            if "-->" in stripped_raw:
                in_comment = False
            continue
        if stripped_raw.startswith("<!--"):
            if "-->" not in stripped_raw:
                in_comment = True
            continue
        if re.match(r"^\s*(```+|~~~+)", raw):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if raw.lstrip().startswith(("|", "```", "~~~")):
            continue
        prose = strip_code_and_links(raw)
        if ";" in prose:
            diagnostics.append(
                Diagnostic(path, line_no, "error", "STE004",
                           "replace the semicolon with a period or a comma")
            )
        if "\u2014" in prose:
            diagnostics.append(
                Diagnostic(path, line_no, "warning", "STE004",
                           "replace the em dash with a period or a comma")
            )
        if re.search(r"\band/or\b", prose, re.IGNORECASE):
            diagnostics.append(
                Diagnostic(path, line_no, "error", "STE003",
                           "use 'or' or 'and' instead of 'and/or'")
            )
        if re.search(r"[A-Za-z]&[A-Za-z]", prose):
            diagnostics.append(
                Diagnostic(path, line_no, "error", "STE003", "write 'and' instead of '&'")
            )
        if "(" in prose and ")" in prose:
            diagnostics.append(
                Diagnostic(path, line_no, "warning", "STE004",
                           "remove the parentheses or write a separate sentence")
            )
        for match in MODALS.finditer(prose):
            diagnostics.append(
                Diagnostic(path, line_no, "error", "STE002",
                           f"replace the modal verb '{match.group(0)}' with 'must' or 'can'")
            )
        for match in CONTRACTIONS.finditer(prose):
            diagnostics.append(
                Diagnostic(path, line_no, "error", "STE003",
                           f"write the full form of '{match.group(0)}'")
            )
        for match in PROGRESSIVE.finditer(prose):
            diagnostics.append(
                Diagnostic(path, line_no, "error", "STE006",
                           f"use a simple tense instead of '{match.group(0)}'")
            )
        stripped_line = raw.strip()
        procedural_line = (
            bool(re.match(r"^\s*([-*+]|\d+\.)\s+", raw))
            or is_procedural(re.sub(r"^\s*(?:[-*+]|\d+\.)\s+", "", raw))
        )
        for match in PASSIVE.finditer(prose):
            diagnostics.append(
                Diagnostic(
                    path,
                    line_no,
                    "error" if procedural_line else "warning",
                    "STE007",
                    f"use the active voice instead of '{match.group(0)}'",
                )
            )
        if re.match(r"^\s*(?:[-*+]|\d+\.)\s+\w+ing\b", raw):
            diagnostics.append(
                Diagnostic(path, line_no, "error", "STE006",
                           "start the item with an imperative verb")
            )

    return diagnostics


def config_pairs(root: Path) -> set[tuple[str, str]] | None:
    """Return every (section, key) pair declared in the server Config structs."""
    source = root / "crates" / "starforged" / "src" / "config.rs"
    if not source.is_file():
        return None
    text = source.read_text(encoding="utf-8")
    top = re.search(r"pub struct Config \{(.*?)\n\}", text, re.DOTALL)
    if not top:
        return None
    fields: dict[str, list[str]] = {}
    for struct, body in re.findall(r"pub struct (\w+Config) \{(.*?)\n\}", text, re.DOTALL):
        fields[struct] = re.findall(r"pub (\w+):", body)
    pairs: set[tuple[str, str]] = set()
    for section, struct in re.findall(r"pub (\w+): (\w+Config)", top.group(1)):
        for key in fields.get(struct, []):
            pairs.add((section, key))
    return pairs


def check_config_coverage(root: Path, diagnostics: list[Diagnostic]) -> None:
    page = root / "docs" / "technical" / "configuration.md"
    pairs = config_pairs(root)
    if not page.is_file() or pairs is None:
        return
    documented: set[tuple[str, str]] = set()
    for line in page.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\| `([a-z_]+)` \| `([a-z_]+)` \|", line)
        if match:
            documented.add((match.group(1), match.group(2)))
    for section, key in sorted(pairs - documented):
        diagnostics.append(
            Diagnostic(page, 1, "error", "STE033",
                       f"document the configuration key {section}.{key}")
        )
    for section, key in sorted(documented - pairs):
        diagnostics.append(
            Diagnostic(page, 1, "error", "STE033",
                       f"configuration.md documents an unknown key {section}.{key}")
        )


def workspace_crates(root: Path) -> list[str]:
    manifest = root / "Cargo.toml"
    if not manifest.is_file():
        return []
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    members = data.get("workspace", {}).get("members", [])
    names: list[str] = []
    for member in members:
        pattern = member if any(ch in member for ch in "*?[") else member
        for path in sorted(glob.glob(str(root / pattern))):
            crate_manifest = Path(path) / "Cargo.toml"
            if not crate_manifest.is_file():
                continue
            crate = tomllib.loads(crate_manifest.read_text(encoding="utf-8"))
            name = crate.get("package", {}).get("name")
            if name:
                names.append(name)
    return names


def check_collection(paths: list[Path], root: Path, strict_sources: bool) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        diagnostics.extend(check_markdown(path, text, root, strict_sources))

    doc_root = root / "docs" / "technical"
    if doc_root.is_dir() and any(doc_root in path.parents or doc_root == path.parent for path in paths):
        readme = doc_root / "README.md"
        docs = sorted(doc_root.glob("*.md"))
        if readme.is_file():
            index = readme.read_text(encoding="utf-8")
            for doc in docs:
                if doc.name != "README.md" and doc.name not in index:
                    diagnostics.append(
                        Diagnostic(readme, 1, "error", "STE031",
                                   f"add an index entry for {doc.name}")
                    )
        else:
            diagnostics.append(
                Diagnostic(doc_root, 1, "error", "STE031",
                           "add docs/technical/README.md as the index")
            )

        check_config_coverage(root, diagnostics)

        crates_page = doc_root / "crates.md"
        if crates_page.is_file():
            crates_text = crates_page.read_text(encoding="utf-8")
            for crate in workspace_crates(root):
                if f"`{crate}`" not in crates_text:
                    diagnostics.append(
                        Diagnostic(crates_page, 1, "error", "STE032",
                                   f"document the workspace crate {crate}")
                    )
    return diagnostics


RULES = """\
STE001  Sentences: instructions have 20 words or fewer, descriptive text 25 or fewer.
STE002  Modals: do not use should, would, could, might, may, or shall.
STE003  Words: use the approved term, American spelling, and no contractions.
STE004  Structure: one instruction per sentence, paragraphs of six sentences or fewer,
        no semicolons, and no parentheses or em dashes in prose.
STE005  Procedures: one instruction in each sentence.
STE006  Verbs: use simple tenses, not the progressive form.
STE007  Voice: use the active voice. Passive voice is an error in procedures.
STE010  Headings: sentence case, eight words or fewer, no final period.
STE011  Headings: use sentence case for each word.
STE012  Links: use a descriptive link label.
STE013  Links: relative links and anchors must resolve.
STE014  Structure: exactly one level-1 heading in each document.
STE015  Formatting: give each code fence a language.
STE020  Phrases: rewrite 'there is' and 'there are'.
STE030  Sources: list code paths in a ste-sources comment; the paths must exist.
STE031  Index: link each technical document from docs/technical/README.md.
STE032  Coverage: document every workspace crate in docs/technical/crates.md.
STE033  Coverage: document every configuration key in docs/technical/configuration.md.
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="files or directories to check")
    parser.add_argument("--root", default=".", help="repository root (default: .)")
    parser.add_argument("--strict", action="store_true", help="treat warnings as errors")
    parser.add_argument("--list-rules", action="store_true", help="print the rule list")
    args = parser.parse_args(argv)

    if args.list_rules:
        print(RULES, end="")
        return 0

    root = Path(args.root).resolve()
    paths: list[Path] = []
    raw_paths = args.paths or [str(root / "docs" / "technical")]
    for raw in raw_paths:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = (root / candidate) if (root / candidate).exists() else Path(raw)
        if candidate.is_dir():
            paths.extend(sorted(candidate.glob("*.md")))
        elif candidate.is_file():
            paths.append(candidate)
        else:
            print(f"ste_check: path not found: {raw}", file=sys.stderr)
            return 2

    diagnostics = check_collection(paths, root, strict_sources=True)
    for diagnostic in diagnostics:
        print(diagnostic.format(root))

    errors = sum(1 for item in diagnostics if item.severity == "error")
    warnings = sum(1 for item in diagnostics if item.severity == "warning")
    print(f"ste_check: {len(paths)} file(s), {errors} error(s), {warnings} warning(s)")
    if errors or (args.strict and warnings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
