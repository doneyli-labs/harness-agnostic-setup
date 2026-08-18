import contextlib, importlib.util, io, os, stat, tempfile, unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).parents[1] / "scripts" / "audit.py"
SPEC = importlib.util.spec_from_file_location("audit", SCRIPT)
audit = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(audit)
class AuditSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base, self.root = Path(self.temporary.name), Path(self.temporary.name) / "skills"
        self.root.mkdir()
    def tearDown(self):
        self.temporary.cleanup()
    def error(self, function, *args):
        with self.assertRaises(audit.AuditError) as caught:
            function(*args)
        return caught.exception
    def run_main(self, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = audit.main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()
    def skill(self, key, name="skill", description="safe", body=""):
        folder = self.root if key == "." else self.root / key
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "SKILL.md").write_text(f"---\nname: {name}\ndescription: {description}\n---\n{body}")
        return folder

    def test_cli_shape_and_path_free_usage_error(self):
        args = audit.parse_args(["--source", str(self.root), "--format", "json", "--show-paths"])
        self.assertEqual((args.format, args.show_paths, args.target), ("json", True, None))
        code, stdout, stderr = self.run_main(["--unknown", "/private/sensitive"])
        self.assertEqual((code, stdout, stderr), (2, "", "<cli>: CLI_USAGE\n"))
        self.assertNotIn("sensitive", stderr)

    def test_root_rejections_and_allowed_home_descendant(self):
        self.assertEqual(self.error(audit.validate_root, str(self.base / "private"), "<source>").reason, "ROOT_MISSING")
        regular = self.base / "file"; regular.write_text("x")
        self.assertEqual(self.error(audit.validate_root, str(regular), "<source>").reason, "ROOT_NOT_DIRECTORY")
        for forbidden in (Path("/"), Path.home(), Path.home().parent):
            with self.subTest(forbidden=forbidden):
                self.assertEqual(self.error(audit.validate_root, str(forbidden), "<source>").reason, "ROOT_FORBIDDEN")
        allowed = Path.home() / "content-system"
        self.assertEqual(audit.validate_root(str(allowed), "<source>"), allowed.resolve())

    def test_output_rejections(self):
        for path in (self.root, self.root / "report"):
            self.assertEqual(self.error(audit.validate_output, str(path), (self.root.resolve(),)).reason, "OUTPUT_IN_ROOT")
        bridge = self.base / "bridge"; bridge.symlink_to(self.root, target_is_directory=True)
        self.assertEqual(self.error(audit.validate_output, str(bridge / "report"), (self.root.resolve(),)).reason, "OUTPUT_IN_ROOT")
        existing = self.base / "existing"; existing.write_bytes(b"preserve")
        self.assertEqual(self.error(audit.validate_output, str(existing), (self.root.resolve(),)).reason, "OUTPUT_EXISTS")
        self.assertEqual(existing.read_bytes(), b"preserve")

    def test_normalization_collision_controls_and_surrogates(self):
        seen = {}
        self.assertEqual(audit._normalized_path(("e\u0301.md",), seen, "<source>"), "é.md")
        self.assertEqual(self.error(audit._normalized_path, ("é.md",), seen, "<source>").reason, "PATH_COLLISION")
        cases = (("bad\nname", "PATH_CONTROL"), ("bad\u200bname", "PATH_CONTROL"), ("bad\udcff", "PATH_ENCODING"))
        for value, reason in cases:
            with self.subTest(reason=reason):
                self.assertEqual(self.error(audit._check_text, value, "<source>").reason, reason)

    def test_in_root_symlink_is_recorded_and_not_followed(self):
        actual = self.root / "actual"; actual.mkdir(); (actual / "file.md").write_text("safe")
        (self.root / "alias").symlink_to(actual, target_is_directory=True)
        entries, findings = audit.walk_root(self.root.resolve(), "<source>", "source")
        self.assertEqual([(item.code, item.side, item.path) for item in findings], [("PATH003", "source", "alias")])
        self.assertFalse(any(item.path.startswith("alias/") for item in entries))
        self.assertIn("actual/file.md", [item.path for item in entries])

    def test_outside_symlink_fails_before_external_enumeration(self):
        outside = self.base / "outside"; outside.mkdir(); (outside / "must-not-read").write_text("secret")
        (self.root / "escape").symlink_to(outside, target_is_directory=True)
        original, calls = os.scandir, []
        def tracked(path):
            calls.append(path)
            return original(path)
        with mock.patch.object(audit.os, "scandir", side_effect=tracked):
            failure = self.error(audit.walk_root, self.root.resolve(), "<source>", "source")
        self.assertEqual((failure.label, failure.reason, len(calls)), ("<source>", "SYMLINK_OUTSIDE", 1))

    def test_secure_writer_mode_no_clobber_race_and_cleanup(self):
        output = self.base / "report"; audit.write_new(output, b"report\n")
        self.assertEqual((output.read_bytes(), stat.S_IMODE(output.stat().st_mode) & 0o177), (b"report\n", 0))
        output.chmod(0o640); before = output.read_bytes(), stat.S_IMODE(output.stat().st_mode)
        self.assertEqual(self.error(audit.write_new, output, b"replace").reason, "OUTPUT_EXISTS")
        self.assertEqual((output.read_bytes(), stat.S_IMODE(output.stat().st_mode)), before)
        raced = self.base / "raced"
        def win_race(source, destination, **kwargs):
            Path(destination).write_bytes(b"winner")
            raise FileExistsError
        with mock.patch.object(audit.os, "link", side_effect=win_race):
            self.assertEqual(self.error(audit.write_new, raced, b"loser").reason, "OUTPUT_EXISTS")
        self.assertEqual(raced.read_bytes(), b"winner")
        failed = self.base / "failed"
        with mock.patch.object(audit.os, "link", side_effect=OSError):
            self.assertEqual(self.error(audit.write_new, failed, b"data").reason, "OUTPUT_WRITE")
        self.assertFalse(failed.exists() or any(".tmp." in path.name for path in self.base.iterdir()))
    def test_main_read_only_incomplete_and_pathless_errors(self):
        marker = self.root / "marker"; marker.write_bytes(b"unchanged")
        before = [(path.name, path.read_bytes()) for path in self.root.iterdir()]
        code, stdout, stderr = self.run_main(["--source", str(self.root)])
        self.assertEqual((code, stdout, stderr), (2, "", "<source>: AUDIT_INCOMPLETE\n"))
        self.assertEqual([(path.name, path.read_bytes()) for path in self.root.iterdir()], before)
        self.assertNotIn(str(self.root), stderr)

    def test_main_target_and_output_errors_are_pathless(self):
        missing = self.base / "target-secret"
        result = self.run_main(["--source", str(missing)])
        self.assertEqual(result, (2, "", "<source>: ROOT_MISSING\n")); self.assertNotIn(str(missing), result[2])
        result = self.run_main(["--source", str(self.root), "--target", str(missing)])
        self.assertEqual(result, (2, "", "<target>: ROOT_MISSING\n")); self.assertNotIn(str(missing), result[2])
        output = self.root / "output-secret"
        result = self.run_main(["--source", str(self.root), "--output", str(output)])
        self.assertEqual(result, (2, "", "<output>: OUTPUT_IN_ROOT\n")); self.assertNotIn(str(output), result[2])
        self.assertFalse(output.exists())

    def test_source_discovery_exclusions_boundaries_and_stability(self):
        parent, child = self.skill(".", "parent"), self.skill("z-child", "child", body="/.claude/skills/tool")
        self.skill("a-first", "first"); (parent / "root.md").write_text("safe")
        for name in audit.EXCLUDED_DIRS:
            excluded = parent / name; excluded.mkdir(); (excluded / "never.md").write_bytes(b"\xff")
        (parent / ".env").write_text("secret"); (parent / ".env.local").write_text("secret"); (parent / "tool.rb").write_text("token")
        (parent / "alias").symlink_to(parent / "root.md")
        calls, real = [], audit._read_file
        def tracked(path):
            calls.append(path)
            return real(path)
        with mock.patch.object(audit, "_read_file", side_effect=tracked):
            results = audit.analyze_source(self.root.resolve())
        self.assertEqual(results, audit.analyze_source(self.root.resolve()))
        self.assertEqual([item.key for item in results], [".", "a-first", "z-child"])
        root_result, child_result = results[0], results[2]
        root_codes = [item.code for item in root_result.findings]
        self.assertEqual(root_codes.count("COVERAGE001"), 1); self.assertIn("PATH003", root_codes)
        self.assertEqual([item.path for item in root_result.files], sorted(item.path for item in root_result.files))
        self.assertEqual([item.file_id for item in root_result.files], [f"F{number:03d}" for number in range(1, len(root_result.files) + 1)])
        self.assertEqual(list(root_result.findings), sorted(root_result.findings, key=lambda item: (item.code, item.side, item.path or "")))
        self.assertNotIn("PATH001", root_codes); self.assertIn("PATH001", [item.code for item in child_result.findings])
        self.assertIn("vendor", audit.EXCLUDED_DIRS); self.assertNotIn("Vendor", audit.EXCLUDED_DIRS)
        self.assertFalse(any(set(path.relative_to(parent.resolve()).parts) & audit.EXCLUDED_DIRS or path.name.startswith(".env") or path.suffix == ".rb" for path in calls))

    def test_frontmatter_byte_zero_crlf_and_scalar_rejections(self):
        valid = self.root / "valid"; valid.mkdir()
        (valid / "SKILL.md").write_bytes("---\r\nname: 'nai\u0308ve'\r\ndescription: \"hash # allowed\"\r\n---\r\n".encode())
        cases = {
            "bom": "\ufeff---\nname: x\ndescription: y\n---\n",
            "unterminated": "---\nname: x\ndescription: y\n",
            "empty": "---\nname:\ndescription: y\n---\n",
            "duplicate": "---\nname: x\nname: y\ndescription: z\n---\n",
            "multiline": "---\nname: |\ndescription: y\n---\n",
            "escaped": '---\nname: "a\\b"\ndescription: y\n---\n',
            "unsupported": "---\nname: [x]\ndescription: y\n---\n",
            "description": "---\nname: x\ndescription: >\n---\n",
        }
        for key, text in cases.items():
            folder = self.root / key; folder.mkdir(); (folder / "SKILL.md").write_text(text)
        results = {item.key: item for item in audit.analyze_source(self.root.resolve())}
        self.assertEqual((results["valid"].name, results["valid"].description, results["valid"].status), ("naïve", "hash # allowed", "portable"))
        for key in ("bom", "unterminated"):
            self.assertEqual([item.code for item in results[key].findings], ["META001"])
        for key in ("empty", "duplicate", "multiline", "escaped", "unsupported"):
            self.assertIn("META002", [item.code for item in results[key].findings])
        self.assertIn("META003", [item.code for item in results["description"].findings])

    def test_duplicate_names_case_sensitive_and_status_precedence(self):
        self.skill("dup-a", "same"); self.skill("dup-b", "same"); self.skill("case", "Same")
        self.skill("review", "review", body="token"); self.skill("blocked", "", body="token")
        results = {item.key: item for item in audit.analyze_source(self.root.resolve())}
        for key in ("dup-a", "dup-b"):
            self.assertEqual((results[key].status, [item.code for item in results[key].findings].count("META004")), ("blocked", 1))
        self.assertEqual(results["case"].status, "portable")
        self.assertEqual((results["review"].status, results["blocked"].status), ("review", "blocked"))

    def test_every_lexical_rule_and_fenced_backticks(self):
        folder = self.skill(".", "lexical")
        signal = "/.CLAUDE/skills/x /Users/alice/project/ CLAUDE mcp__claudeTool PreToolUse $ARGUMENTS $( MCPSERVERS AUTHORIZATION HEADERS TRANSPORT ${API_KEY} TOKEN"
        (folder / "signals.md").write_text(signal); (folder / "lower.md").write_text("pretooluse")
        (folder / "run.sh").write_text("echo `date`")
        (folder / "shell.md").write_text("````bash\necho `date`\n````\n")
        (folder / "ignored.md").write_text("`prose`\n```python\n`code`\n```\n```bash extra\n`no`\n```\n")
        (folder / "note.txt").write_text("`prose`")
        result = audit.analyze_source(self.root.resolve())[0]
        by_path = {}
        for finding in result.findings:
            by_path.setdefault(finding.path, []).append(finding.code)
        expected = {"PATH001", "PATH002", "RUNTIME001", "HOOK001", "ARGS001", "CONN001", "SECRET001"}
        self.assertEqual(set(by_path["signals.md"]), expected)
        self.assertIn("PATH002", audit._lexical_codes("C:\\Users\\alice\\", ".txt"))
        self.assertNotIn("HOOK001", by_path.get("lower.md", ()))
        args_paths = {finding.path for finding in result.findings if finding.code == "ARGS001"}
        self.assertEqual(args_paths, {"signals.md", "run.sh", "shell.md"})
        self.assertEqual(len(by_path["signals.md"]), len(set(by_path["signals.md"])))

    def test_file_limit_encoding_read_failure_extensions_and_coverage(self):
        folder = self.skill(".", "files")
        mode = self.skill("mode", "mode"); mode_file = mode / "run.py"; mode_file.write_text("safe"); mode_file.chmod(0o700)
        for suffix in audit.ELIGIBLE - {".md"}:
            (folder / f"ok{suffix}").write_text("safe")
        (folder / "exact.txt").write_bytes(b"a" * audit.LIMIT)
        (folder / "large.py").write_bytes(b"a" * (audit.LIMIT + 1))
        (folder / "binary.json").write_bytes(b"\xff"); (folder / "denied.ts").write_text("safe")
        executable_py = folder / "executable.py"; executable_py.write_text("safe"); executable_py.chmod(0o700)
        (folder / "tool.go").write_text("secret"); executable = folder / "tool"; executable.write_text("token"); executable.chmod(0o700)
        real = audit._read_file
        def fail_one(path):
            return (None, None) if path.name == "denied.ts" else real(path)
        with mock.patch.object(audit, "_read_file", side_effect=fail_one):
            result, mode_result = audit.analyze_source(self.root.resolve())
        self.assertEqual((mode_result.status, [item.code for item in mode_result.findings]), ("review", ["COVERAGE001"]))
        failures = [item for item in result.findings if item.code == "FILE001"]
        self.assertEqual({item.path for item in failures}, {"binary.json", "denied.ts", "large.py"})
        self.assertTrue(all(item.file_id for item in failures)); self.assertEqual([item.code for item in result.findings].count("COVERAGE001"), 1)
        files = {item.path: item for item in result.files}
        self.assertEqual(len(files["exact.txt"].content), audit.LIMIT)
        self.assertTrue(audit.ELIGIBLE <= {Path(path).suffix for path in files})
        self.assertFalse({"executable.py", "tool.go", "tool"} & files.keys())

if __name__ == "__main__":
    unittest.main()
