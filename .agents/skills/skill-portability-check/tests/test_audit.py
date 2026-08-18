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

if __name__ == "__main__":
    unittest.main()
