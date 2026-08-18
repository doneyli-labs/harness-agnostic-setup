import builtins
import contextlib
import importlib.util
import io
import os
import pathlib
import tempfile
import unittest
from contextlib import ExitStack
from unittest import mock

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "audit.py"


def load_module(name="portability_audit"):
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


audit = load_module()


class CapabilityGateTests(unittest.TestCase):
    def run_main(self, module=audit, argv=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        args = ["--source", "uninspected-source"] if argv is None else argv
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = module.main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_current_platform_has_every_required_capability(self):
        self.assertTrue(audit._capable())

    def test_each_required_primitive_is_individually_blocking(self):
        names = ("open", "stat", "link", "unlink", "scandir",
                 "fstat", "fsync", "getuid")
        for name in names:
            with self.subTest(name=name), mock.patch.object(audit.os, name, None):
                self.assertFalse(audit._capable())
        with mock.patch.object(audit.pwd, "getpwuid", None):
            self.assertFalse(audit._capable())
        with mock.patch.object(audit, "pwd", None):
            self.assertFalse(audit._capable())

    def test_each_required_capability_membership_is_blocking(self):
        cases = (
            ("supports_dir_fd", "open"), ("supports_dir_fd", "stat"),
            ("supports_dir_fd", "link"),
            ("supports_dir_fd", "unlink"), ("supports_fd", "scandir"),
            ("supports_follow_symlinks", "stat"),
            ("supports_follow_symlinks", "link"),
        )
        for container, name in cases:
            reduced = set(getattr(audit.os, container))
            reduced.discard(getattr(audit.os, name))
            with self.subTest(container=container, name=name):
                with mock.patch.object(audit.os, container, reduced):
                    self.assertFalse(audit._capable())

    def test_each_required_flag_is_individually_blocking(self):
        for name in ("O_DIRECTORY", "O_NOFOLLOW"):
            with self.subTest(name=name), mock.patch.object(audit.os, name, 0):
                self.assertFalse(audit._capable())

    def test_missing_pwd_import_is_safe_and_unrelated_failure_is_not_hidden(self):
        original_import = builtins.__import__

        def missing(module_name, *args, **kwargs):
            if module_name == "pwd":
                raise ModuleNotFoundError("pwd unavailable", name="pwd")
            return original_import(module_name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=missing):
            without_pwd = load_module("audit_without_pwd")
        self.assertIsNone(without_pwd.pwd)
        self.assertEqual(self.run_main(without_pwd),
                         (2, "", "SAFE_IO_UNAVAILABLE\n"))

        def unrelated(module_name, *args, **kwargs):
            if module_name == "pwd":
                raise ModuleNotFoundError("dependency unavailable", name="dependency")
            return original_import(module_name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=unrelated):
            with self.assertRaises(ModuleNotFoundError):
                load_module("audit_unrelated_import_failure")

    def test_unsupported_gate_is_exact_and_precedes_later_work(self):
        names = ("open", "stat", "link", "unlink", "scandir",
                 "fstat", "fsync", "getuid", "mkdir", "rename", "replace")
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "secret-output"
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(audit, "_capable", return_value=False))
                observed = {name: stack.enter_context(mock.patch.object(audit.os, name))
                            for name in names}
                home = stack.enter_context(mock.patch.object(audit.pwd, "getpwuid"))
                file_open = stack.enter_context(mock.patch("builtins.open"))
                result = self.run_main(argv=["--source", "secret-path",
                                             "--target", "secret-target",
                                             "--output", str(output)])
            self.assertFalse(output.exists())
        self.assertEqual(result, (2, "", "SAFE_IO_UNAVAILABLE\n"))
        self.assertNotIn("secret", result[2])
        self.assertNotIn("Traceback", result[2])
        for function in observed.values():
            function.assert_not_called()
        home.assert_not_called()
        file_open.assert_not_called()

    def test_supported_gate_does_not_access_home_paths_or_output(self):
        names = ("open", "stat", "link", "unlink", "scandir",
                 "fstat", "fsync", "getuid")
        originals = {name: getattr(audit.os, name) for name in names}
        observed = {name: mock.Mock(wraps=function)
                    for name, function in originals.items()}
        with tempfile.TemporaryDirectory() as temporary:
            root, output = pathlib.Path(temporary), pathlib.Path(temporary) / "report.json"
            with ExitStack() as stack:
                for name, function in observed.items():
                    stack.enter_context(mock.patch.object(audit.os, name, function))
                stack.enter_context(mock.patch.object(
                    audit.os, "supports_dir_fd",
                    {observed[name] for name in ("open", "stat", "link", "unlink")}))
                stack.enter_context(mock.patch.object(
                    audit.os, "supports_fd", {observed["scandir"]}))
                stack.enter_context(mock.patch.object(
                    audit.os, "supports_follow_symlinks", {observed["stat"], observed["link"]}))
                home = stack.enter_context(mock.patch.object(audit.pwd, "getpwuid"))
                file_open = stack.enter_context(mock.patch("builtins.open"))
                mutators = [stack.enter_context(mock.patch.object(audit.os, name))
                            for name in ("mkdir", "rename", "replace")]
                result = self.run_main(argv=[
                    "--source", str(root / "source"), "--target", str(root / "target"),
                    "--format", "json", "--show-paths", "--output", str(output)])
            self.assertFalse(output.exists())
        self.assertEqual(result, (2, "", "AUDIT_INCOMPLETE\n"))
        for function in observed.values():
            function.assert_not_called()
        for function in mutators:
            function.assert_not_called()
        home.assert_not_called()
        file_open.assert_not_called()

    def test_parser_surface_is_path_free_and_requires_valid_source(self):
        invalid = (
            [], ["--source"], ["--source", "private", "--format", "yaml"],
            ["--source", "private", "--unknown", "private-value"],
            ["--target", "private"], ["--source", "private", "--output"],
        )
        for argv in invalid:
            with self.subTest(argv=argv):
                result = self.run_main(argv=argv)
                self.assertEqual(result, (2, "", "CLI_INVALID\n"))
                self.assertNotIn("private", result[2])
                self.assertNotIn("Traceback", result[2])
        options = ("--source", "--target", "--format", "--show-paths", "--output")
        prefixes = tuple((option, option[:length]) for option in options
                         for length in range(3, len(option)))
        self.assertEqual(len(prefixes), 29)
        for option, prefix in prefixes:
            argv = [] if option == "--source" else ["--source", "private-source"]
            argv += [prefix] if option == "--show-paths" else [prefix, "private-value"]
            with self.subTest(option=option, prefix=prefix):
                result = self.run_main(argv=argv)
                self.assertEqual(result, (2, "", "CLI_INVALID\n"))
                self.assertNotIn("Traceback", result[2])
        for output_format in ("markdown", "json"):
            with self.subTest(output_format=output_format):
                with mock.patch.object(audit, "_capable", return_value=True):
                    result = self.run_main(argv=["--source", "private",
                                                 "--format", output_format])
                self.assertEqual(result, (2, "", "AUDIT_INCOMPLETE\n"))


class ValidationAndLedgerTests(unittest.TestCase):
    def test_invalid_paths_and_basenames_make_zero_filesystem_calls(self):
        paths = ("", ".", "..", "a//b", "a/../b", "a/\x1f/b",
                 "a/\u200b/b", "a/\ud800/b")
        names = ("", ".", "..", os.sep, f"a{os.sep}b", "bad\x1f",
                 "bad\u200b", "bad\ud800")
        api_names = ("open", "stat", "fstat", "readlink", "scandir", "getcwd")
        with ExitStack() as stack:
            observed = [stack.enter_context(mock.patch.object(audit.os, name))
                        for name in api_names]
            for path in paths:
                with self.subTest(kind="path", value=repr(path)):
                    self.assertRaises(audit.OperationalError, audit._path_plan, path)
            for name in names:
                with self.subTest(kind="basename", value=repr(name)):
                    self.assertRaises(audit.OperationalError, audit._safe_basename, name)
            with mock.patch.object(audit.os, "altsep", "\\"):
                for name in ("\\", "a\\b"):
                    self.assertRaises(audit.OperationalError,
                                      audit._safe_basename, name)
                for path in ("a\\..\\b", "a\\\\b"):
                    self.assertRaises(audit.OperationalError,
                                      audit._path_plan, path)
        for function in observed:
            function.assert_not_called()

    def test_valid_absolute_relative_and_altsep_plans_preserve_order(self):
        api_names = ("open", "stat", "fstat", "readlink", "scandir", "getcwd")
        with ExitStack() as stack:
            observed = [stack.enter_context(mock.patch.object(audit.os, name))
                        for name in api_names]
            self.assertEqual(audit._path_plan("/alpha/beta"),
                             (os.sep, ("alpha", "beta")))
            self.assertEqual(audit._path_plan("alpha/beta"),
                             (".", ("alpha", "beta")))
            self.assertEqual(audit._path_plan(os.sep), (os.sep, ()))
            with mock.patch.object(audit.os, "altsep", "\\"):
                self.assertEqual(audit._path_plan("\\alpha\\beta"),
                                 (os.sep, ("alpha", "beta")))
                self.assertEqual(audit._path_plan("alpha\\beta"),
                                 (".", ("alpha", "beta")))
        for function in observed:
            function.assert_not_called()

    def test_ledger_owns_and_releases_in_explicit_order(self):
        ledger = audit.FdLedger()
        self.assertEqual([ledger.own(fd) for fd in (11, 12, 13)], [11, 12, 13])
        self.assertEqual(ledger.owned, (11, 12, 13))
        self.assertEqual(ledger.release(12), 12)
        self.assertEqual(ledger.owned, (11, 13))
        self.assertEqual(ledger.failed, ())

    def test_duplicate_ownership_and_unknown_release_do_not_change_state(self):
        ledger = audit.FdLedger()
        ledger.own(11)
        with self.assertRaises(audit.OperationalError) as duplicate:
            ledger.own(11)
        self.assertEqual(str(duplicate.exception), "FD_OWNERSHIP")
        self.assertEqual(ledger.owned, (11,))
        with self.assertRaises(audit.OperationalError) as unknown:
            ledger.release(12)
        self.assertEqual(str(unknown.exception), "FD_OWNERSHIP")
        self.assertEqual(ledger.owned, (11,))

    def test_successful_cleanup_closes_every_descriptor_once(self):
        ledger = audit.FdLedger()
        for fd in (11, 12, 13):
            ledger.own(fd)
        with mock.patch.object(audit.os, "close") as close:
            ledger.cleanup()
        self.assertEqual([call.args[0] for call in close.call_args_list], [13, 12, 11])
        self.assertEqual(ledger.owned, ())
        self.assertEqual(ledger.failed, ())

    def test_multiple_real_close_failures_remain_owned_without_retry(self):
        descriptors = [os.open(os.devnull, os.O_RDONLY) for _ in range(3)]
        ledger, real_close = audit.FdLedger(), os.close
        for fd in descriptors:
            ledger.own(fd)

        def closing(fd):
            if fd != descriptors[1]:
                raise OSError("close state unknown")
            real_close(fd)
        try:
            with mock.patch.object(audit.os, "close", side_effect=closing) as close:
                with self.assertRaises(audit.OperationalError) as error:
                    ledger.cleanup()
                self.assertEqual(str(error.exception), "FD_CLOSE_FAILED")
                self.assertEqual(ledger.owned, (descriptors[0], descriptors[2]))
                self.assertEqual(ledger.failed, ledger.owned)
                self.assertEqual(close.call_count, 3)
                self.assertRaises(audit.OperationalError, ledger.cleanup)
                self.assertEqual(close.call_count, 3)
                state = ledger.owned, ledger.failed
                with self.assertRaises(audit.OperationalError) as uncertain:
                    ledger.release(descriptors[0])
                self.assertEqual(str(uncertain.exception), "FD_CLOSE_FAILED")
                self.assertEqual((ledger.owned, ledger.failed), state)
                self.assertEqual(close.call_count, 3)
        finally:
            for fd in ledger.owned:
                real_close(fd)

    def test_prior_operational_error_precedes_close_fallback(self):
        descriptor = os.open(os.devnull, os.O_RDONLY)
        ledger, real_close = audit.FdLedger(), os.close
        ledger.own(descriptor)
        prior = audit.OperationalError("PATH_UNSAFE")
        try:
            with mock.patch.object(audit.os, "close", side_effect=OSError) as close:
                with self.assertRaises(audit.OperationalError) as error:
                    ledger.cleanup(prior)
                self.assertIs(error.exception, prior)
                self.assertEqual(ledger.owned, (descriptor,))
                with self.assertRaises(audit.OperationalError) as fallback:
                    ledger.cleanup()
                self.assertEqual(str(fallback.exception), "FD_CLOSE_FAILED")
                self.assertEqual(close.call_count, 1)
        finally:
            real_close(descriptor)


if __name__ == "__main__":
    unittest.main()
