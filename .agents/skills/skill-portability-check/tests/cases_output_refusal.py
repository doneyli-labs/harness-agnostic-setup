import contextlib
import io
import os
import types
import unittest
from contextlib import ExitStack
from unittest import mock

from cases_foundation import audit


class OutputRefusalTests(unittest.TestCase):
    def run_main(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = audit.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_guard_treats_non_none_value_as_opaque(self):
        class OpaqueOutput:
            def __bool__(self):
                raise AssertionError("output truth-tested")
            def __eq__(self, other):
                raise AssertionError("output compared")
            def __fspath__(self):
                raise AssertionError("output path-converted")
            def __str__(self):
                raise AssertionError("output rendered")

        with self.assertRaises(audit.OperationalError) as error:
            audit._output_guard(types.SimpleNamespace(output=OpaqueOutput()))
        self.assertEqual(str(error.exception), "SAFE_OUTPUT_UNAVAILABLE")

    def test_cli_refuses_all_output_forms_before_any_access(self):
        values = (
            ("empty", ""), ("relative", "private/report.json"),
            ("absolute", os.sep + "private/report.json"),
            ("symlink-looking", os.sep + "tmp/output-link"),
            ("control", "private\x00report"),
            ("secret", "api_key=do-not-emit"),
        )
        os_names = "open stat scandir fstat getuid read close readlink link unlink fsync mkdir rename replace".split()
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(audit, "_capable", return_value=True))
            later = [stack.enter_context(mock.patch.object(audit, name))
                     for name in ("_input_preflight", "_home_path", "_path_plan", "_open_path")]
            filesystem = [stack.enter_context(mock.patch.object(audit.os, name)) for name in os_names]
            filesystem += [stack.enter_context(mock.patch.object(audit.pwd, "getpwuid")),
                           stack.enter_context(mock.patch("builtins.open"))]
            for label, value in values:
                with self.subTest(form=label):
                    result = self.run_main(["--source", "private-source", "--target",
                                            "private-target", "--output", value])
                    self.assertEqual(result, (2, "", "SAFE_OUTPUT_UNAVAILABLE\n"))
                    self.assertNotIn("private", result[2])
                    self.assertNotIn("api_key", result[2])
                    self.assertNotIn("Traceback", result[2])
        for function in (*later, *filesystem):
            function.assert_not_called()

    def test_capability_failure_precedes_output_guard(self):
        with mock.patch.object(audit, "_capable", return_value=False), \
                mock.patch.object(audit, "_output_guard") as guard, \
                mock.patch.object(audit, "_input_preflight") as preflight:
            result = self.run_main(["--source", "private-source",
                                    "--output", "api_key=do-not-emit"])
        self.assertEqual(result, (2, "", "SAFE_IO_UNAVAILABLE\n"))
        guard.assert_not_called()
        preflight.assert_not_called()

    def test_no_output_runs_guard_and_preflight_then_stops_incomplete(self):
        events, real_guard = [], audit._output_guard

        def guarding(args):
            events.append("guard")
            real_guard(args)
        with mock.patch.object(audit, "_capable", side_effect=lambda: events.append("capability") or True), \
                mock.patch.object(audit, "_output_guard", side_effect=guarding) as guard, \
                mock.patch.object(audit, "_input_preflight", side_effect=lambda _: events.append("preflight")) as preflight:
            result = self.run_main(["--source", "private-source"])
        self.assertEqual(result, (2, "", "AUDIT_INCOMPLETE\n"))
        self.assertEqual(events, ["capability", "guard", "preflight"])
        guard.assert_called_once()
        preflight.assert_called_once()
