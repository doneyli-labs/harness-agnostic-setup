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


if __name__ == "__main__":
    unittest.main()
