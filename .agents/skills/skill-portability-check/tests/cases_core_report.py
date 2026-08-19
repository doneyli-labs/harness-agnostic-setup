import ast
import builtins
import hashlib
import json
import os
import unittest
from contextlib import ExitStack
from unittest import mock

from cases_core_analysis import CORE_PATH, core


class CoreReportTests(unittest.TestCase):
    @staticmethod
    def record(key, name="alpha", files=(), findings=()):
        scalar = "'invalid" if name is None else name
        skill = f"---\nname: {scalar}\ndescription: useful\n---\nbody".encode()
        rows = [("SKILL.md", skill, core.analyze_file("SKILL.md", skill))]
        rows += [(path, data, core.analyze_file(path, data)) for path, data in files]
        combined = set(findings)
        for path, _, analysis in rows:
            combined.update((code, path, severity)
                            for code, severity in analysis["findings"])
        metadata = rows[0][2]["metadata"]
        return {"key": key, "name_valid": metadata is not None and metadata[0],
                "skill_bytes": skill, "files": tuple(rows),
                "findings": tuple(sorted(combined, key=lambda item: (item[0], item[1] or "")))}

    @staticmethod
    def codes(skill, side=None):
        return tuple(item["code"] for item in skill["findings"]
                     if side is None or item["side"] == side)

    def test_valid_name_matching_target_only_digests_and_deterministic_ids(self):
        source = (self.record("z", "beta", (("note.txt", b"same"),)),
                  self.record("a", "alpha", (("note.txt", b"same"),)))
        target = (self.record("unused", "target-only"),
                  self.record("elsewhere", "alpha", (("note.txt", b"same"),)),
                  self.record("other", "beta", (("note.txt", b"changed"),)))
        report = core.build_report(source, target, True)
        self.assertEqual(report, core.build_report(source, target, True))
        self.assertEqual([(skill["id"], skill["key"]) for skill in report["skills"]],
                         [("S001", "a"), ("S002", "z")])
        self.assertEqual(self.codes(report["skills"][0]), ())
        self.assertEqual(self.codes(report["skills"][1]), ("COMPARE002",))
        self.assertEqual(report["summary"], {"blocked": 0, "portable": 1, "review": 1})
        self.assertEqual(core.report_exit(report), 0)
        self.assertNotIn("target-only", repr(report))

    def test_invalid_exact_key_fallback_name_mismatch_and_no_target(self):
        invalid = self.record("same", None)
        matched = core.build_report((invalid,), (self.record("same", None),))
        self.assertNotIn("COMPARE001", self.codes(matched["skills"][0]))
        self.assertEqual(core.report_exit(matched), 1)
        for source, target in ((invalid, self.record("same", "valid")),
                               (self.record("same", "valid"), invalid)):
            report = core.build_report((source,), (target,))
            self.assertIn("COMPARE001", self.codes(report["skills"][0]))
        without = core.build_report((self.record("same", "valid"),))
        self.assertFalse(without["target_supplied"])
        self.assertFalse(any(code.startswith("COMPARE")
                             for code in self.codes(without["skills"][0])))

    def test_source_and_target_duplicates_coverage_and_file_gates(self):
        duplicate = (("META004", "SKILL.md", "blocked"),)
        sources = (self.record("a", "same", findings=duplicate),
                   self.record("b", "same", findings=duplicate))
        report = core.build_report(sources, (self.record("t", "same"),))
        for skill in report["skills"]:
            self.assertEqual(self.codes(skill), ("META004",))
            self.assertEqual(skill["status"], "blocked")
        target_dupes = (self.record("x", "unique"), self.record("y", "unique"))
        blocked = core.build_report((self.record("s", "unique"),), target_dupes)
        self.assertEqual(self.codes(blocked["skills"][0], "target"), ("META004",))
        self.assertEqual(core.report_exit(blocked), 1)
        coverage = (("COVERAGE001", None, "review"),)
        source = self.record("c", "coverage", findings=coverage)
        target = self.record("t", "coverage", findings=coverage)
        reviewed = core.build_report((source,), (target,))["skills"][0]
        self.assertEqual(self.codes(reviewed), ("COVERAGE001", "COVERAGE001"))
        self.assertEqual(reviewed["status"], "review")
        target_gap = next(item for item in reviewed["findings"] if item["side"] == "target")
        self.assertEqual((target_gap["file_id"], target_gap["path"]), (None, None))
        source_file = self.record("f", "files", (("bad.txt", None),))
        target_file = self.record("t", "files", (("other.txt", None),))
        gated = core.build_report((source_file,), (target_file,), True)["skills"][0]
        self.assertNotIn("COMPARE002", self.codes(gated))
        target_finding = next(item for item in gated["findings"]
                              if item["code"] == "FILE001" and item["side"] == "target")
        self.assertEqual((target_finding["file_id"], target_finding["path"]), (None, None))

    def test_prefix_framing_separates_unframed_concatenation_collision(self):
        left = self.record("left", "same", (("a", b"bc"),))
        right = self.record("right", "same", (("ab", b"c"),))

        def naive(record):
            return b"".join(path.encode() + data for path, data, _ in record["files"])

        def framed(record):
            files = tuple(sorted(record["files"]))
            chunks = [len(files).to_bytes(8, "big")]
            for path, data, _ in files:
                path_bytes, content = path.encode(), bytes(data)
                chunks.extend((len(path_bytes).to_bytes(8, "big"), path_bytes,
                               len(content).to_bytes(8, "big"), content))
            return b"".join(chunks)

        self.assertEqual(naive(left), naive(right))
        self.assertEqual(core._framed_digest(left), hashlib.sha256(framed(left)).digest())
        self.assertNotEqual(core._framed_digest(left), core._framed_digest(right))
        report = core.build_report((left,), (right,))
        self.assertIn("COMPARE002", self.codes(report["skills"][0]))

    def test_json_markdown_paths_schema_escaping_lf_and_redaction(self):
        key, path = "dir&<>|`/é", "a&<>|`.txt"
        secret = b"/Users/private/ api_key=hunter2"
        source = self.record(key, "private-name", ((path, secret), ("bad|.txt", None)),
                             (("PATH003", None, "review"),))
        target = self.record("target", "private-name", (("target.txt", None),))
        hidden = core.build_report((source,), (target,))
        encoded = core.serialize_report(hidden, "json")
        self.assertEqual(encoded, json.dumps(hidden, ensure_ascii=False, sort_keys=True,
                                             separators=(",", ":")) + "\n")
        parsed = json.loads(encoded)
        self.assertIsInstance(parsed["schema_version"], int)
        self.assertIsInstance(parsed["target_supplied"], bool)
        self.assertIsInstance(parsed["skills"], list)
        self.assertIsNone(parsed["skills"][0]["key"])
        path003 = next(item for item in parsed["skills"][0]["findings"]
                       if item["code"] == "PATH003")
        self.assertEqual((path003["file_id"], path003["path"]), (None, None))
        shown = core.build_report((source,), (target,), True)
        markdown = core.serialize_report(shown)
        expected = (
            "# Skill Portability Audit\nPaths: sensitive\nTarget supplied: yes\n\n"
            "| Skill | Status | Findings |\n|---|---|---|\n"
            "| S001 (`dir&amp;&lt;&gt;&#124;&#96;/é`) | review | "
            "FILE001@source:F003 (`bad&#124;.txt`), FILE001@target:-, "
            "PATH002@source:F002 (`a&amp;&lt;&gt;&#124;&#96;.txt`), PATH003@source:-, "
            "SECRET001@source:F002 (`a&amp;&lt;&gt;&#124;&#96;.txt`) |\n\n"
            "Summary: portable=0 review=1 blocked=0\n")
        self.assertEqual(markdown, expected)
        self.assertTrue(all(line.count("|") == 4 for line in markdown.splitlines()
                            if line.startswith("|")))
        self.assertTrue(markdown.endswith("\n") and not markdown.endswith("\n\n"))
        shown_json = json.loads(core.serialize_report(shown, "json"))
        self.assertEqual(shown_json["skills"][0]["key"], key)
        hidden_markdown = core.serialize_report(hidden)
        self.assertIn("Paths: hidden", hidden_markdown)
        self.assertNotIn(key, hidden_markdown)
        digest = core._framed_digest(self.record("digest", "digest", (("x", b"y"),))).hex()
        for value in ("private-name", "hunter2", "/Users/private/", "api_key",
                      "target.txt", digest):
            self.assertNotIn(value, encoded + markdown)
        with self.assertRaises(ValueError):
            core.serialize_report(hidden, "yaml")

    def test_static_and_runtime_purity_for_matching_and_serialization(self):
        tree = ast.parse(CORE_PATH.read_text(encoding="utf-8"))
        imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                   for alias in node.names}
        self.assertEqual(imports, {"hashlib", "json", "re", "unicodedata"})
        self.assertFalse(any(isinstance(node, ast.ImportFrom) for node in ast.walk(tree)))
        calls = {node.func.id for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertTrue({"open", "print", "input", "exec", "eval", "__import__"}.isdisjoint(calls))
        record = self.record("safe", "safe")
        with ExitStack() as stack:
            sentinels = [stack.enter_context(mock.patch.object(os, name))
                         for name in ("open", "stat", "scandir", "read", "write", "getenv")]
            sentinels += [stack.enter_context(mock.patch.object(builtins, name,
                          side_effect=AssertionError(name)))
                          for name in ("open", "print", "input", "__import__")]
            report = core.build_report((record,), (record,))
            self.assertTrue(core.serialize_report(report, "json").endswith("\n"))
        for sentinel in sentinels[:6]:
            sentinel.assert_not_called()


if __name__ == "__main__":
    unittest.main()
