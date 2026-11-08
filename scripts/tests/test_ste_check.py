"""Tests for scripts/ste_check.py."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "ste_check.py"
spec = importlib.util.spec_from_file_location("ste_check", SCRIPT)
assert spec and spec.loader
ste = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ste
spec.loader.exec_module(ste)


def codes(diagnostics):
    return [item.code for item in diagnostics]


class SentenceRules(unittest.TestCase):
    def check(self, text: str):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "page.md"
            path.write_text(text, encoding="utf-8")
            return ste.check_markdown(path, text, Path(tmp), strict_sources=False)

    def test_long_instruction_is_an_error(self):
        text = "# Title\n\n- " + " ".join(["copy"] + ["word"] * 20) + ".\n"
        self.assertIn("STE001", codes(self.check(text)))

    def test_inline_code_counts_as_one_word(self):
        line = "- Use `a-very-long-identifier-with-many-parts` now.\n"
        self.assertNotIn("STE001", codes(self.check("# Title\n\n" + line)))

    def test_descriptive_limit_is_25(self):
        line = " ".join(["word"] * 26) + ".\n"
        diagnostics = self.check("# Title\n\n" + line)
        self.assertIn("STE001", codes(diagnostics))

    def test_one_instruction_per_sentence(self):
        line = "- Open the file, and change the value.\n"
        self.assertIn("STE005", codes(self.check("# Title\n\n" + line)))

    def test_paragraph_limit(self):
        line = " ".join(["This is a sentence."] * 7) + "\n"
        self.assertIn("STE004", codes(self.check("# Title\n\n" + line)))


class WordRules(unittest.TestCase):
    def check(self, text: str):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "page.md"
            path.write_text(text, encoding="utf-8")
            return ste.check_markdown(path, text, Path(tmp), strict_sources=False)

    def test_modal_error(self):
        self.assertIn("STE002", codes(self.check("# Title\n\nYou should wait.\n")))

    def test_banned_term_error(self):
        self.assertIn("STE003", codes(self.check("# Title\n\nThe repo is public.\n")))

    def test_contraction_error(self):
        self.assertIn("STE003", codes(self.check("# Title\n\nDon't stop the server.\n")))

    def test_semicolon_error(self):
        self.assertIn("STE004", codes(self.check("# Title\n\nOne step; two steps.\n")))

    def test_american_spelling(self):
        self.assertIn("STE003", codes(self.check("# Title\n\nThe colour is red.\n")))

    def test_code_fence_is_skipped(self):
        text = "# Title\n\n```text\nYou should use the repo.\n```\n"
        self.assertNotIn("STE002", codes(self.check(text)))
        self.assertNotIn("STE003", codes(self.check(text)))


class VoiceRules(unittest.TestCase):
    def check(self, text: str):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "page.md"
            path.write_text(text, encoding="utf-8")
            return ste.check_markdown(path, text, Path(tmp), strict_sources=False)

    def test_passive_is_warning_in_description(self):
        diagnostics = self.check("# Title\n\nThe value is stored in the database.\n")
        passive = [item for item in diagnostics if item.code == "STE007"]
        self.assertTrue(passive)
        self.assertEqual(passive[0].severity, "warning")

    def test_passive_is_error_in_instruction(self):
        diagnostics = self.check("# Title\n\n- The value is deleted by the job.\n")
        passive = [item for item in diagnostics if item.code == "STE007"]
        self.assertTrue(passive)
        self.assertEqual(passive[0].severity, "error")

    def test_progressive_error(self):
        diagnostics = self.check("# Title\n\nThe server is running the job.\n")
        self.assertIn("STE006", codes(diagnostics))


class StructureRules(unittest.TestCase):
    def check(self, text: str, root: Path | None = None):
        with tempfile.TemporaryDirectory() as tmp:
            base = root or Path(tmp)
            path = base / "page.md"
            path.write_text(text, encoding="utf-8")
            return ste.check_markdown(path, text, base, strict_sources=True)

    def test_missing_source_block(self):
        self.assertIn("STE030", codes(self.check("# Title\n\nText.\n")))

    def test_missing_source_path(self):
        text = "# Title\n\n<!-- ste-sources\nmissing.rs\n-->\n\nText.\n"
        self.assertIn("STE030", codes(self.check(text)))

    def test_present_source_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "src.rs"
            source.write_text("", encoding="utf-8")
            text = "# Title\n\n<!-- ste-sources\nsrc.rs\n-->\n\nText.\n"
            self.assertNotIn("STE030", codes(self.check(text, Path(tmp))))

    def test_missing_relative_link(self):
        diagnostics = self.check("# Title\n\nSee [the guide](guide.md).\n")
        self.assertIn("STE013", codes(diagnostics))

    def test_resolved_relative_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "guide.md"
            target.write_text("# Guide\n", encoding="utf-8")
            diagnostics = self.check("# Title\n\nSee [the guide](guide.md).\n", Path(tmp))
            self.assertNotIn("STE013", codes(diagnostics))

    def test_heading_sentence_case(self):
        diagnostics = self.check("# Title\n\n## Bad Heading Case\n\nText.\n")
        self.assertIn("STE011", codes(diagnostics))

    def test_two_h1_headings(self):
        diagnostics = self.check("# One\n\n# Two\n")
        self.assertIn("STE014", codes(diagnostics))

    def test_paragraph_warnings_use_each_paragraph_line(self):
        text = (
            "# Title\n\n"
            + " ".join(["This is a sentence."] * 7)
            + "\n\nSome text.\n\n"
            + " ".join(["Another sentence."] * 7)
            + "\n"
        )
        diagnostics = self.check(text)
        lines = {item.line for item in diagnostics if item.code == "STE004"}
        self.assertEqual(lines, {3, 7})


class CollectionRules(unittest.TestCase):
    def test_crate_coverage_and_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs" / "technical").mkdir(parents=True)
            (root / "crates" / "demo" / "src").mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["crates/*"]\n', encoding="utf-8"
            )
            (root / "crates" / "demo" / "Cargo.toml").write_text(
                '[package]\nname = "demo"\nversion = "0.1.0"\n', encoding="utf-8"
            )
            (root / "docs" / "technical" / "crates.md").write_text(
                "# Crates\n\nText.\n", encoding="utf-8"
            )
            (root / "docs" / "technical" / "README.md").write_text(
                "# Index\n", encoding="utf-8"
            )
            page = root / "docs" / "technical" / "crates.md"
            diagnostics = ste.check_collection([page], root, strict_sources=False)
            self.assertIn("STE032", codes(diagnostics))
            (page).write_text("# Crates\n\nThe `demo` crate.\n", encoding="utf-8")
            diagnostics = ste.check_collection([page], root, strict_sources=False)
            self.assertIn("STE031", codes(diagnostics))


class ConfigCoverage(unittest.TestCase):
    def test_missing_and_unknown_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "crates" / "starforged" / "src").mkdir(parents=True)
            (root / "docs" / "technical").mkdir(parents=True)
            (root / "crates" / "starforged" / "src" / "config.rs").write_text(
                """
pub struct Config {
    pub server: ServerConfig,
}
pub struct ServerConfig {
    pub http_addr: String,
    pub base_url: String,
}
""",
                encoding="utf-8",
            )
            page = root / "docs" / "technical" / "configuration.md"
            page.write_text(
                "# Configuration\n\n| `server` | `http_addr` |\n| `server` | `old_key` |\n",
                encoding="utf-8",
            )
            diagnostics = []
            ste.check_config_coverage(root, diagnostics)
            messages = [item.message for item in diagnostics]
            self.assertTrue(any("server.base_url" in item for item in messages))
            self.assertTrue(any("server.old_key" in item for item in messages))


if __name__ == "__main__":
    unittest.main()
