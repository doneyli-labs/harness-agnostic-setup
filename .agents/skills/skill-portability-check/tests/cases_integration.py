import builtins
import contextlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

from cases_core_analysis import core
from cases_foundation import audit


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir()

    @staticmethod
    def skill(directory, name="alpha", description="useful"):
        directory.mkdir()
        text = f"---\nname: {name}\ndescription: {description}\n---\nbody"
        (directory / "SKILL.md").write_text(text, encoding="utf-8")
        return directory

    @staticmethod
    def capture(argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = audit.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def run_main(self, argv):
        account = types.SimpleNamespace(pw_dir=str(self.home))
        with mock.patch.object(audit, "_capable", return_value=True), \
                mock.patch.object(audit.pwd, "getpwuid", return_value=account), \
                mock.patch.object(audit, "_load_core", return_value=core):
            return self.capture(argv)

    @staticmethod
    def portable_markdown(target="no"):
        return (
            "# Skill Portability Audit\nPaths: hidden\n"
            f"Target supplied: {target}\n\n"
            "| Skill | Status | Findings |\n|---|---|---|\n"
            "| S001 | portable | none |\n\n"
            "Summary: portable=1 review=0 blocked=0\n")

    def test_no_target_markdown_is_exact_and_inputs_close_before_stdout(self):
        source = self.skill(self.root / "source")
        closed, real_close = [], audit._close_inputs

        def close_inputs(ledger, records):
            result = real_close(ledger, records)
            closed.append(True)
            return result

        class OrderedOutput(io.StringIO):
            def write(self, value):
                self.assert_closed()
                return super().write(value)

            @staticmethod
            def assert_closed():
                if not closed:
                    raise AssertionError("report preceded descriptor cleanup")

        output, errors = OrderedOutput(), io.StringIO()
        account = types.SimpleNamespace(pw_dir=str(self.home))
        with mock.patch.object(audit, "_capable", return_value=True), \
                mock.patch.object(audit.pwd, "getpwuid", return_value=account), \
                mock.patch.object(audit, "_load_core", return_value=core), \
                mock.patch.object(audit, "_close_inputs", side_effect=close_inputs), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = audit.main(["--source", str(source)])
        self.assertEqual((code, output.getvalue(), errors.getvalue()),
                         (0, self.portable_markdown(), ""))

    def test_matched_target_json_show_paths_has_exact_bytes(self):
        source = self.skill(self.root / "source")
        target = self.skill(self.root / "target")
        result = self.run_main(["--source", str(source), "--target", str(target),
                                "--format", "json", "--show-paths"])
        report = {"schema_version": 1, "target_supplied": True,
                  "summary": {"blocked": 0, "portable": 1, "review": 0},
                  "show_paths": True,
                  "skills": [{"id": "S001", "key": ".", "status": "portable",
                              "findings": []}]}
        expected = json.dumps(report, ensure_ascii=False, sort_keys=True,
                              separators=(",", ":")) + "\n"
        self.assertEqual(result, (0, expected, ""))
        self.assertNotIn(str(target), result[1])

    def test_review_and_blocked_reports_use_exit_zero_and_one(self):
        reviewed = self.skill(self.root / "reviewed")
        (reviewed / "note.txt").write_text("$ARGUMENTS", encoding="utf-8")
        review = self.run_main(["--source", str(reviewed)])
        self.assertEqual((review[0], review[2]), (0, ""))
        self.assertIn("| S001 | review | ARGS001@source:F002 |", review[1])
        self.assertTrue(review[1].endswith("\n") and not review[1].endswith("\n\n"))
        blocked = self.skill(self.root / "blocked", description="")
        refusal = self.run_main(["--source", str(blocked)])
        self.assertEqual((refusal[0], refusal[2]), (1, ""))
        self.assertIn("| S001 | blocked | META003@source:F001 |", refusal[1])

    def test_path003_aggregates_independently_and_never_resolves_target(self):
        source = self.skill(self.root / "source")
        target = self.skill(self.root / "target")
        forbidden = self.root / "forbidden-target"
        forbidden.write_text("api_key=do-not-read", encoding="utf-8")
        os.symlink(forbidden, source / "jump")
        os.symlink(forbidden, target / "jump")
        with mock.patch.object(audit.os, "readlink", side_effect=AssertionError("readlink")):
            result = self.run_main(["--source", str(source), "--target", str(target),
                                    "--format", "json", "--show-paths"])
        report = json.loads(result[1])
        findings = [finding for finding in report["skills"][0]["findings"]
                    if finding["code"] == "PATH003"]
        self.assertEqual(result[0::2], (0, ""))
        self.assertEqual([finding["side"] for finding in findings], ["source", "target"])
        self.assertTrue(all(finding["file_id"] is None and finding["path"] is None
                            for finding in findings))
        self.assertNotIn("do-not-read", result[1])

    def test_capability_output_core_and_operational_failures_emit_no_report(self):
        cases = (
            (False, ["--source", "secret", "--output", "api_key=x"],
             None, "SAFE_IO_UNAVAILABLE\n"),
            (True, ["--source", "secret", "--output", "api_key=x"],
             None, "SAFE_OUTPUT_UNAVAILABLE\n"),
            (True, ["--source", "secret"],
             audit.OperationalError("CORE_LOAD_UNAVAILABLE"), "CORE_LOAD_UNAVAILABLE\n"),
        )
        for capable, argv, load_error, expected in cases:
            with self.subTest(expected=expected), \
                    mock.patch.object(audit, "_capable", return_value=capable), \
                    mock.patch.object(audit, "_load_core", side_effect=load_error) as loader, \
                    mock.patch.object(audit, "_input_preflight") as preflight:
                result = self.capture(argv)
            self.assertEqual(result, (2, "", expected))
            preflight.assert_not_called()
            if not capable or "OUTPUT" in expected:
                loader.assert_not_called()
        missing = self.run_main(["--source", str(self.root / "private-missing")])
        self.assertEqual(missing, (2, "", "<source> PATH_UNSAFE\n"))
        self.assertNotIn("private", missing[2])

    def test_close_uncertainty_suppresses_report_and_preserves_safe_reason(self):
        source = self.skill(self.root / "source")
        phase, failed, real_close = {"inventory": False}, [], os.close

        def inventory(*_):
            phase["inventory"] = True
            return ()

        def close(descriptor):
            if phase["inventory"] and not failed:
                failed.append(descriptor)
                raise OSError("uncertain")
            return real_close(descriptor)

        try:
            with mock.patch.object(audit, "_inventory_at", side_effect=inventory), \
                    mock.patch.object(audit.os, "close", side_effect=close):
                result = self.run_main(["--source", str(source)])
        finally:
            first_failed = tuple(failed)
            for descriptor in first_failed:
                real_close(descriptor)
        self.assertEqual(result, (2, "", "<source> FD_CLOSE_FAILED\n"))
        self.assertEqual(len(first_failed), 1)
        failed.clear()

        def refusal(*_):
            phase["inventory"] = True
            raise audit.OperationalError("PATH_RACE")

        phase["inventory"] = False
        try:
            with mock.patch.object(audit, "_inventory_at", side_effect=refusal), \
                    mock.patch.object(audit.os, "close", side_effect=close):
                prior = self.run_main(["--source", str(source)])
        finally:
            for descriptor in failed:
                real_close(descriptor)
        self.assertEqual(prior, (2, "", "<source> PATH_RACE\n"))

    def test_supported_audit_calls_no_mutating_filesystem_api(self):
        source = self.skill(self.root / "source")
        real_open = os.open
        with contextlib.ExitStack() as stack:
            descriptor_open = stack.enter_context(mock.patch.object(
                audit.os, "open", wraps=real_open))
            file_open = stack.enter_context(mock.patch.object(builtins, "open"))
            names = "mkdir rename replace link unlink remove rmdir write fsync".split()
            mutators = [stack.enter_context(mock.patch.object(audit.os, name)) for name in names]
            result = self.run_main(["--source", str(source)])
        self.assertEqual(result, (0, self.portable_markdown(), ""))
        file_open.assert_not_called()
        for mutator in mutators:
            mutator.assert_not_called()
        write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        self.assertTrue(all(not call.args[1] & write_flags
                            for call in descriptor_open.call_args_list))

    def test_real_direct_script_subprocess_completes(self):
        source = self.skill(self.root / "source")
        skill_root = pathlib.Path(audit.__file__).parents[1]
        result = subprocess.run(
            [sys.executable, "-B", "scripts/audit.py", "--source", str(source)],
            cwd=skill_root, capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, self.portable_markdown(), ""))


if __name__ == "__main__":
    unittest.main()
