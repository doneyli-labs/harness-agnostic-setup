import contextlib
import io
import os
import pathlib
import sys
import types
import unittest
from contextlib import ExitStack
from unittest import mock

from cases_foundation import audit


class CoreBootstrapTests(unittest.TestCase):
    def run_main(self, argv=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        args = ["--source", "private-source"] if argv is None else argv
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = audit.main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_exact_sibling_sequence_precedes_bytecode_and_ignores_sys_path(self):
        events, module = [], object()

        class PoisonPath:
            def __iter__(self):
                raise AssertionError("sys.path inspected")

            def __getitem__(self, key):
                raise AssertionError(f"sys.path indexed: {key}")

        loader = types.SimpleNamespace(
            exec_module=lambda value: events.append(("exec", value)))
        spec = types.SimpleNamespace(loader=loader)

        def locate(name, path):
            events.append(("spec", sys.dont_write_bytecode, name, path))
            return spec

        def create(value):
            events.append(("module", value))
            return module

        old_path, old_bytecode = sys.path, sys.dont_write_bytecode
        expected = os.path.join(os.path.dirname(audit.__file__), "audit_core.py")
        with mock.patch.object(audit.importlib.util, "spec_from_file_location", side_effect=locate), \
                mock.patch.object(audit.importlib.util, "module_from_spec", side_effect=create):
            try:
                sys.path, sys.dont_write_bytecode = PoisonPath(), False
                self.assertIs(audit._load_core(), module)
                self.assertIsInstance(sys.path, PoisonPath)
            finally:
                sys.path, sys.dont_write_bytecode = old_path, old_bytecode
        self.assertEqual(events, [
            ("spec", True, "skill_portability_audit_core", expected),
            ("module", spec), ("exec", module)])

    def test_null_spec_and_loader_are_fixed_path_free_failures(self):
        for candidate in (None, types.SimpleNamespace(loader=None)):
            with self.subTest(candidate=candidate), \
                    mock.patch.object(audit.importlib.util, "spec_from_file_location",
                                      return_value=candidate), \
                    mock.patch.object(audit.importlib.util, "module_from_spec") as create, \
                    mock.patch.object(audit, "_capable", return_value=True), \
                    mock.patch.object(audit, "_input_preflight") as preflight:
                result = self.run_main()
            self.assertEqual(result, (2, "", "CORE_LOAD_UNAVAILABLE\n"))
            create.assert_not_called()
            preflight.assert_not_called()

    def test_every_enumerated_loader_failure_is_fixed_and_uncached(self):
        failures = (ImportError, OSError, SyntaxError, UnicodeError, ValueError,
                    TypeError, AttributeError, RuntimeError)
        for failure in failures:
            loader = mock.Mock()
            loader.exec_module.side_effect = failure("private/source content")
            spec = types.SimpleNamespace(loader=loader)
            before, old_bytecode = set(sys.modules), sys.dont_write_bytecode
            with self.subTest(failure=failure.__name__), \
                    mock.patch.object(audit.importlib.util, "spec_from_file_location",
                                      return_value=spec), \
                    mock.patch.object(audit.importlib.util, "module_from_spec",
                                      return_value=object()), \
                    mock.patch.object(audit, "_capable", return_value=True), \
                    mock.patch.object(audit, "_input_preflight") as preflight:
                try:
                    sys.dont_write_bytecode = False
                    result = self.run_main()
                finally:
                    sys.dont_write_bytecode = old_bytecode
            self.assertEqual(result, (2, "", "CORE_LOAD_UNAVAILABLE\n"))
            self.assertEqual(set(sys.modules), before)
            self.assertNotIn("private", result[2])
            self.assertNotIn("Traceback", result[2])
            preflight.assert_not_called()

    def test_failed_loader_insertion_is_removed_before_refusal(self):
        name, inserted, missing = "skill_portability_audit_core", object(), object()
        previous = sys.modules.pop(name, missing)
        loader = mock.Mock()

        def fail(module):
            sys.modules[name] = inserted
            raise RuntimeError("private partial module")

        loader.exec_module.side_effect = fail
        spec = types.SimpleNamespace(loader=loader)
        try:
            with mock.patch.object(audit.importlib.util, "spec_from_file_location",
                                   return_value=spec), \
                    mock.patch.object(audit.importlib.util, "module_from_spec",
                                      return_value=inserted):
                with self.assertRaises(audit.OperationalError) as error:
                    audit._load_core()
            self.assertEqual(str(error.exception), "CORE_LOAD_UNAVAILABLE")
            self.assertNotIn(name, sys.modules)
        finally:
            if previous is not missing:
                sys.modules[name] = previous

    def test_successful_loader_insertion_is_removed_before_return(self):
        name, inserted, missing = "skill_portability_audit_core", object(), object()
        previous = sys.modules.pop(name, missing)
        loader = mock.Mock()
        loader.exec_module.side_effect = lambda module: sys.modules.__setitem__(name, module)
        spec = types.SimpleNamespace(loader=loader)
        try:
            with mock.patch.object(audit.importlib.util, "spec_from_file_location",
                                   return_value=spec), \
                    mock.patch.object(audit.importlib.util, "module_from_spec",
                                      return_value=inserted):
                self.assertIs(audit._load_core(), inserted)
            self.assertNotIn(name, sys.modules)
        finally:
            if previous is not missing:
                sys.modules[name] = previous

    def test_preexisting_cache_entry_is_restored_by_identity(self):
        name, prior, inserted = "skill_portability_audit_core", object(), object()
        missing = object()
        previous = sys.modules.get(name, missing)
        sys.modules[name] = prior
        loader = mock.Mock()
        loader.exec_module.side_effect = lambda module: sys.modules.__setitem__(name, module)
        spec = types.SimpleNamespace(loader=loader)
        try:
            with mock.patch.object(audit.importlib.util, "spec_from_file_location",
                                   return_value=spec), \
                    mock.patch.object(audit.importlib.util, "module_from_spec",
                                      return_value=inserted):
                self.assertIs(audit._load_core(), inserted)
            self.assertIs(sys.modules[name], prior)
        finally:
            if previous is missing:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous

    def test_missing_exact_sibling_is_redacted_without_partial_state(self):
        before, old_bytecode = set(sys.modules), sys.dont_write_bytecode
        with mock.patch.object(audit, "__file__", "/private/missing/audit.py"), \
                mock.patch.object(audit, "_capable", return_value=True), \
                mock.patch.object(audit, "_input_preflight") as preflight:
            try:
                result = self.run_main()
            finally:
                sys.dont_write_bytecode = old_bytecode
        self.assertEqual(result, (2, "", "CORE_LOAD_UNAVAILABLE\n"))
        self.assertEqual(set(sys.modules), before)
        self.assertNotIn("private", result[2])
        preflight.assert_not_called()

    def test_main_order_is_parse_gate_guard_load_input(self):
        events = []
        args = types.SimpleNamespace(output=None)
        calls = (
            (audit.PARSER, "parse_args", lambda _: events.append("parse") or args),
            (audit, "_capable", lambda: events.append("capability") or True),
            (audit, "_output_guard", lambda _: events.append("guard")),
            (audit, "_load_core", lambda: events.append("core")),
            (audit, "_input_preflight", lambda _: events.append("input")),
        )
        with ExitStack() as stack:
            for owner, name, action in calls:
                stack.enter_context(mock.patch.object(owner, name, side_effect=action))
            result = self.run_main(["ignored"])
        self.assertEqual(result, (2, "", "AUDIT_INCOMPLETE\n"))
        self.assertEqual(events, ["parse", "capability", "guard", "core", "input"])

    def test_capability_and_output_refusals_make_zero_loader_or_io_calls(self):
        io_names = "open stat scandir fstat getuid read close mkdir rename replace".split()
        old_bytecode = sys.dont_write_bytecode
        for capable, expected in ((False, "SAFE_IO_UNAVAILABLE\n"),
                                  (True, "SAFE_OUTPUT_UNAVAILABLE\n")):
            with self.subTest(capable=capable), ExitStack() as stack:
                stack.enter_context(mock.patch.object(audit, "_capable", return_value=capable))
                loader = stack.enter_context(mock.patch.object(audit, "_load_core"))
                preflight = stack.enter_context(mock.patch.object(audit, "_input_preflight"))
                filesystem = [stack.enter_context(mock.patch.object(audit.os, name))
                              for name in io_names]
                home = stack.enter_context(mock.patch.object(audit.pwd, "getpwuid"))
                sys.dont_write_bytecode = False
                result = self.run_main(["--source", "private-source",
                                        "--output", "private-output"])
            self.assertEqual(result, (2, "", expected))
            loader.assert_not_called()
            preflight.assert_not_called()
            home.assert_not_called()
            for function in filesystem:
                function.assert_not_called()
            self.assertFalse(sys.dont_write_bytecode)
        sys.dont_write_bytecode = old_bytecode

    def test_success_is_fresh_uncached_and_cli_remains_incomplete(self):
        scripts = pathlib.Path(audit.__file__).parent
        cache_before = tuple(scripts.glob("__pycache__/audit_core.*.pyc"))
        modules_before, old_bytecode = set(sys.modules), sys.dont_write_bytecode
        try:
            sys.dont_write_bytecode = False
            first, second = audit._load_core(), audit._load_core()
            self.assertTrue(sys.dont_write_bytecode)
            with mock.patch.object(audit, "_capable", return_value=True), \
                    mock.patch.object(audit, "_input_preflight"):
                result = self.run_main()
        finally:
            sys.dont_write_bytecode = old_bytecode
        self.assertIsNot(first, second)
        self.assertTrue(callable(first.analyze_file))
        self.assertEqual(set(sys.modules), modules_before)
        self.assertEqual(tuple(scripts.glob("__pycache__/audit_core.*.pyc")), cache_before)
        self.assertEqual(result, (2, "", "AUDIT_INCOMPLETE\n"))


if __name__ == "__main__":
    unittest.main()
