import ast
import builtins
import importlib.util
import os
import pathlib
import sys
import unittest
from contextlib import ExitStack
from unittest import mock

CORE_PATH = pathlib.Path(__file__).parents[1] / "scripts" / "audit_core.py"
PATH_BEFORE = tuple(sys.path)
SPEC = importlib.util.spec_from_file_location("portability_audit_core_test", CORE_PATH)
core = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(core)
PATH_AFTER = tuple(sys.path)


class CoreAnalysisTests(unittest.TestCase):
    def skill(self, name="alpha", description="useful", newline="\n"):
        return newline.join(("---", f"name: {name}",
                             f"description: {description}", "---", "body")).encode()

    def codes(self, path, data):
        return tuple(code for code, _ in core.analyze_file(path, data)["findings"])

    def test_frontmatter_frames_and_supported_scalars(self):
        valid = (
            self.skill(), self.skill("  alpha  ", "  useful  "),
            self.skill("'alpha'", "'useful'"), self.skill('"alpha"', '"useful"'),
            self.skill("'a#{}[]'", "'d#{}[]'"), self.skill(newline="\r\n"),
            self.skill("alpha'", 'useful"'), self.skill("alpha''", 'useful""'),
        )
        for data in valid:
            with self.subTest(data=data[:20]):
                record = core.analyze_file("SKILL.md", data)
                self.assertEqual(record["metadata"], (True, True))
                self.assertFalse(any(code.startswith("META") for code, _ in record["findings"]))
        bad_frames = (b"", b" ---\nname: a\ndescription: b\n---",
                      b"--- \nname: a\ndescription: b\n---",
                      b"---\nname: a\ndescription: b\n ---", b"\xef\xbb\xbf---\n---")
        for data in bad_frames:
            with self.subTest(frame=data[:8]):
                record = core.analyze_file("SKILL.md", data)
                self.assertEqual(tuple(code for code, _ in record["findings"]),
                                 ("META001", "META002", "META003"))
                self.assertEqual({severity for _, severity in record["findings"]}, {"blocked"})

    def test_invalid_missing_duplicate_multiline_and_escaped_scalars(self):
        invalid = ("", " ", "alpha # comment", "alpha{value}", "alpha[value]",
                   "|", "|0", "|2-", ">fold", "'alpha", '""', '"a\\nb"',
                   "'a''b'")
        for value in invalid:
            with self.subTest(value=repr(value)):
                record = core.analyze_file("SKILL.md", self.skill(value))
                self.assertIn("META002", self.codes("SKILL.md", self.skill(value)))
                self.assertEqual(record["metadata"], (False, True))
        missing = b"---\ndescription: useful\n---"
        duplicate = b"---\nname: one\nname: two\ndescription: useful\n---"
        for data in (missing, duplicate):
            self.assertEqual(core.analyze_file("SKILL.md", data)["metadata"], (False, True))
        missing_description = b"---\nname: alpha\n---"
        duplicate_description = b"---\nname: alpha\ndescription: one\ndescription: two\n---"
        for data in (missing_description, duplicate_description):
            self.assertEqual(core.analyze_file("SKILL.md", data)["metadata"], (True, False))
            self.assertIn("META003", self.codes("SKILL.md", data))

    def test_nfc_metadata_comparison_is_value_redacted_and_case_sensitive(self):
        composed = self.skill("'caf\u00e9'", "'r\u00e9sum\u00e9'")
        decomposed = self.skill("'cafe\u0301'", "'re\u0301sume\u0301'")
        self.assertTrue(core.metadata_equal(composed, decomposed))
        self.assertTrue(core.metadata_equal(composed, decomposed, "description"))
        self.assertFalse(core.metadata_equal(composed, self.skill("CAF\u00c9")))
        self.assertFalse(core.metadata_equal(composed, decomposed, "unknown"))
        record = core.analyze_file("private/secret/SKILL.md", composed + b"\napi_key=hunter2")
        rendered = repr(record)
        for secret in ("private", "caf", "r.sum", "hunter2", "api_key"):
            self.assertNotIn(secret, rendered)

    def test_size_utf8_boundary_and_deterministic_order(self):
        self.assertEqual(core.analyze_file("note.txt", b"a" * core.MAX_BYTES)["findings"], ())
        for data in (b"a" * (core.MAX_BYTES + 1), b"\xff"):
            self.assertEqual(core.analyze_file("note.txt", data),
                             {"metadata": None, "findings": (("FILE001", "review"),)})
        sensitive = b"token /Users/alice/ $ARGUMENTS PreToolUse"
        first = core.analyze_file("note.txt", sensitive)
        self.assertEqual(first, core.analyze_file("note.txt", sensitive))
        self.assertEqual(tuple(code for code, _ in first["findings"]),
                         tuple(sorted(("ARGS001", "HOOK001", "PATH002", "SECRET001"))))

    def test_every_lexical_code_and_near_miss(self):
        hits = {
            "PATH001": b"/.CLAUDE/agents/ '.claude\\skills\\",
            "PATH002": b"/Users/alice/ /home/bob/ C:\\Users\\carol\\",
            "RUNTIME001": b"run CLAUDE; mcp__claudeTool",
            "HOOK001": b"PreToolUse PostToolUse PermissionRequest UserPromptSubmit SubagentStart SubagentStop PreCompact SessionStart SessionEnd",
            "ARGS001": b"$ARGUMENTS ${arguments} $(cmd)",
            "CONN001": b"mcpServers authorization headers transport ${API_KEY}",
            "SECRET001": b".env api-key token secret credential password",
        }
        for expected, text in hits.items():
            with self.subTest(code=expected):
                record = core.analyze_file("note.txt", text)
                self.assertEqual(self.codes("note.txt", text).count(expected), 1)
                self.assertEqual(dict(record["findings"])[expected], "review")
        misses = (b"/.claude/other/", b"/Users//", b"claudette",
                  b"pretooluse", b"$ARGUMENT", b"header", b"tokenize")
        for text in misses:
            with self.subTest(near=text):
                self.assertEqual(self.codes("note.txt", text), ())

    def test_backticks_only_in_shell_files_or_exact_commonmark_fences(self):
        command = b"`echo hello`"
        self.assertIn("ARGS001", self.codes("run.sh", command))
        for path in ("note.md", "run.py"):
            self.assertNotIn("ARGS001", self.codes(path, command))
        accepted = (
            b"```bash\n`echo one`\n```", b" ~~~zsh\n`echo two`\n ~~~   ",
            b"````shell\n```nested```\n`echo three`\n`````",
        )
        for text in accepted:
            self.assertIn("ARGS001", self.codes("note.md", text))
        for separator in ("\r", "\n", "\r\n"):
            text = f"```sh{separator}`echo ok`{separator}```".encode()
            self.assertIn("ARGS001", self.codes("note.md", text))
        for separator in ("\v", "\f", "\x85", "\u2028", "\u2029"):
            text = f"```sh{separator}`echo no`{separator}```".encode()
            self.assertNotIn("ARGS001", self.codes("note.md", text))
        rejected = (
            b"```python\n`echo no`\n```", b"```BASH\n`echo no`\n```",
            b"    ```sh\n`echo no`\n    ```", b"~~~text\n~~~bash\n`echo no`\n~~~\n~~~",
            b"`inline code` outside a fence",
        )
        for text in rejected:
            self.assertNotIn("ARGS001", self.codes("note.md", text))

    def test_exact_path_load_and_static_runtime_purity(self):
        self.assertEqual(PATH_BEFORE, PATH_AFTER)
        self.assertNotIn("portability_audit_core_test", sys.modules)
        tree = ast.parse(CORE_PATH.read_text(encoding="utf-8"))
        imports = {alias.name.split(".")[0] for node in ast.walk(tree)
                   if isinstance(node, ast.Import) for alias in node.names}
        self.assertEqual(imports, {"re", "unicodedata"})
        self.assertFalse(any(isinstance(node, ast.ImportFrom) for node in ast.walk(tree)))
        banned = {"open", "print", "input", "exec", "eval", "__import__"}
        calls = {node.func.id for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertTrue(banned.isdisjoint(calls))
        with ExitStack() as stack:
            sentinels = [stack.enter_context(mock.patch.object(os, name))
                         for name in ("open", "stat", "scandir", "read", "write", "getenv")]
            sentinels += [stack.enter_context(mock.patch.object(builtins, name,
                          side_effect=AssertionError(name))) for name in ("open", "print", "input", "__import__")]
            self.assertEqual(core.analyze_file("note.txt", b"portable"),
                             {"metadata": None, "findings": ()})
        for sentinel in sentinels[:6]:
            sentinel.assert_not_called()
