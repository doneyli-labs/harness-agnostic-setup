import builtins
import contextlib
import importlib.util
import io
import os
import pathlib
import tempfile
import types
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
                stack.enter_context(mock.patch.object(audit, "_input_preflight", create=True))
                home = stack.enter_context(mock.patch.object(audit.pwd, "getpwuid"))
                file_open = stack.enter_context(mock.patch("builtins.open"))
                mutators = [stack.enter_context(mock.patch.object(audit.os, name)) for name in ("mkdir", "rename", "replace")]
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
                with mock.patch.object(audit, "_capable", return_value=True), \
                        mock.patch.object(audit, "_input_preflight", create=True):
                    result = self.run_main(argv=["--source", "private", "--format", output_format])
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


class DescriptorWalkTests(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.final = self.root / "alpha" / "beta"
        self.final.mkdir(parents=True)
    def changed(self, metadata):
        return types.SimpleNamespace(st_dev=metadata.st_dev, st_ino=metadata.st_ino + 1, st_mode=metadata.st_mode)
    def expected(self, path):
        parts = pathlib.Path(path).parts
        return tuple(audit._identity(os.stat(pathlib.Path(*parts[:index]))) for index in range(1, len(parts) + 1))
    def test_validation_precedes_anchor_and_each_dirfd_api_syscall(self):
        bad_paths = ("private/../secret", "private/\ud800/secret")
        bad_names = ("", ".", "..", os.sep, "bad\x00", "bad\u200b", "bad\ud800")
        with mock.patch.object(audit.os, "open") as opened, mock.patch.object(audit.os, "stat") as stated, \
                mock.patch.object(audit.os, "fstat") as fstated, mock.patch.object(audit.os, "close") as closed:
            for path in bad_paths:
                self.assertRaises(audit.OperationalError, audit._open_path, path)
            apis = ((audit._stat_at, (9,)), (audit._open_dir_at, (audit.FdLedger(), 9)))
            for function, prefix in apis:
                for name in bad_names:
                    self.assertRaises(audit.OperationalError, function, *prefix, name)
            with mock.patch.object(audit.os, "altsep", "\\"):
                for function, prefix in apis:
                    self.assertRaises(audit.OperationalError, function, *prefix, "a\\b")
        for function in (opened, stated, fstated, closed):
            function.assert_not_called()
    def test_valid_calls_walk_order_flags_dirfds_and_identity_trails(self):
        real_open, calls = audit.os.open, []
        def opening(name, flags, *args, **kwargs):
            fd = real_open(name, flags, *args, **kwargs)
            calls.append((name, flags, kwargs.get("dir_fd"), fd))
            return fd
        with mock.patch.object(audit.os, "open", side_effect=opening):
            descriptor, trail = audit._open_path(str(self.final))
        self.assertEqual(trail, self.expected(self.final))
        self.assertEqual([call[0] for call in calls], [os.sep, *self.final.parts[1:]])
        for index, (_, flags, dirfd, _) in enumerate(calls):
            self.assertTrue(flags & os.O_DIRECTORY and flags & os.O_NOFOLLOW)
            self.assertFalse(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT))
            self.assertEqual(dirfd, None if index == 0 else calls[index - 1][3])
        os.close(descriptor)
        previous = os.getcwd()
        self.addCleanup(os.chdir, previous)
        os.chdir(self.root)
        calls.clear()
        with mock.patch.object(audit.os, "open", side_effect=opening):
            descriptor, trail = audit._open_path("alpha/beta")
        self.assertEqual(([call[0] for call in calls], trail[0]), ([".", "alpha", "beta"], audit._identity(os.stat(self.root))))
        self.assertEqual(trail[-1], audit._identity(os.fstat(descriptor)))
        os.close(descriptor)
    def test_ownership_is_immediate_and_parent_survives_post_stat(self):
        metadata = types.SimpleNamespace(st_dev=1, st_ino=2, st_mode=0o040755)
        root_ledger = audit.FdLedger()
        with mock.patch.object(audit.os, "open", return_value=30), \
                mock.patch.object(audit.os, "fstat", side_effect=lambda fd: (self.assertIn(fd, root_ledger.owned) or metadata)):
            self.assertEqual(audit._open_path(os.sep, root_ledger), (30, ((1, 2),)))
        ledger, stat_calls = audit.FdLedger(), 0
        ledger.own(10)
        def statting(parent, name):
            nonlocal stat_calls
            stat_calls += 1
            if stat_calls == 2:
                self.assertEqual(ledger.owned, (10, 20))
            return metadata
        with mock.patch.object(audit, "_stat_at", side_effect=statting), \
                mock.patch.object(audit.os, "open", return_value=20), \
                mock.patch.object(audit.os, "fstat", side_effect=lambda fd: (
                    self.assertEqual(ledger.owned, (10, 20)) or metadata)):
            self.assertEqual(audit._open_dir_at(ledger, 10, "child"), (20, (1, 2)))
    def test_actual_pre_open_and_open_post_swaps_are_rejected(self):
        for boundary in ("pre-open", "open-post"):
            path = self.root / boundary / "swap" / "leaf"
            path.mkdir(parents=True)
            moved, real_open, real_stat = False, audit.os.open, audit._stat_at
            def opening(name, flags, *args, **kwargs):
                nonlocal moved
                parent = kwargs.get("dir_fd")
                if boundary == "pre-open" and name == "swap" and not moved:
                    os.rename(name, "old", src_dir_fd=parent, dst_dir_fd=parent)
                    os.mkdir(name, dir_fd=parent)
                    moved = True
                return real_open(name, flags, *args, **kwargs)
            def statting(parent, name):
                nonlocal moved
                if boundary == "open-post" and name == "swap" and not moved \
                        and getattr(statting, "seen", False):
                    os.rename(name, "old", src_dir_fd=parent, dst_dir_fd=parent)
                    os.mkdir(name, dir_fd=parent)
                    moved = True
                statting.seen = name == "swap" or getattr(statting, "seen", False)
                return real_stat(parent, name)
            with mock.patch.object(audit.os, "open", side_effect=opening), \
                    mock.patch.object(audit, "_stat_at", side_effect=statting):
                self.assertRaisesRegex(audit.OperationalError, "^PATH_RACE$", audit._open_path, str(path))
    def test_simulated_pre_open_post_identities_are_rejected(self):
        for phase in ("pre", "open", "post"):
            path = self.root / ("sim-" + phase) / "swap" / "leaf"
            path.mkdir(parents=True)
            calls, captured = 0, set()
            real_stat, real_open, real_fstat = audit._stat_at, audit.os.open, audit.os.fstat
            def statting(parent, name):
                nonlocal calls
                metadata = real_stat(parent, name)
                if name == "swap":
                    calls += 1
                    if (phase, calls) in (("pre", 1), ("post", 2)):
                        return self.changed(metadata)
                return metadata
            def opening(name, flags, *args, **kwargs):
                fd = real_open(name, flags, *args, **kwargs)
                if name == "swap":
                    captured.add(fd)
                return fd
            def fstatting(fd):
                metadata = real_fstat(fd)
                return self.changed(metadata) if phase == "open" and fd in captured else metadata
            with mock.patch.object(audit, "_stat_at", side_effect=statting), \
                    mock.patch.object(audit.os, "open", side_effect=opening), \
                    mock.patch.object(audit.os, "fstat", side_effect=fstatting):
                self.assertRaisesRegex(audit.OperationalError, "^PATH_RACE$", audit._open_path, str(path))
    def test_supplied_symlink_is_path_safe_without_readlink(self):
        link = self.root / "link"
        link.symlink_to("alpha")
        for readlink in (None, mock.Mock(side_effect=AssertionError("forbidden"))):
            ledger = audit.FdLedger()
            with mock.patch.object(audit.os, "readlink", readlink):
                with self.assertRaises(audit.OperationalError) as error:
                    audit._open_path(str(link), ledger)
            self.assertEqual(str(error.exception), "PATH_UNSAFE")
            self.assertEqual(ledger.owned, ())
            if isinstance(readlink, mock.Mock):
                readlink.assert_not_called()
    def test_fstat_path_and_primitive_failures_are_safe_and_clean(self):
        real_fstat = audit.os.fstat
        for failure_call in (1, 2):
            calls, ledger = 0, audit.FdLedger()
            def failing(fd):
                nonlocal calls
                calls += 1
                if calls == failure_call:
                    raise OSError("sensitive/path")
                return real_fstat(fd)
            with mock.patch.object(audit.os, "fstat", side_effect=failing):
                with self.assertRaises(audit.OperationalError) as error:
                    audit._open_path(str(self.final), ledger)
            self.assertEqual(str(error.exception), "PATH_UNSAFE")
            self.assertEqual(ledger.owned, ())
        nondir = self.root / "file"
        nondir.write_text("fixture", encoding="utf-8")
        for path in (self.root / "missing", nondir,
                     pathlib.Path(str(self.final) + "/bad\ud800")):
            with self.assertRaises(audit.OperationalError) as error:
                audit._open_path(str(path))
            self.assertEqual(str(error.exception), "PATH_UNSAFE")
        with mock.patch.object(audit.os, "stat", side_effect=OSError("sensitive/path")):
            with self.assertRaises(audit.OperationalError) as error:
                audit._stat_at(9, "safe")
        self.assertEqual(str(error.exception), "PATH_UNSAFE")
        with mock.patch.object(audit, "_stat_at", return_value=os.stat(self.root)), \
                mock.patch.object(audit.os, "open", side_effect=OSError("sensitive/path")):
            with self.assertRaises(audit.OperationalError) as error:
                audit._open_dir_at(audit.FdLedger(), 9, "safe")
        self.assertEqual(str(error.exception), "PATH_UNSAFE")
    def test_close_failure_integration_and_prior_precedence(self):
        for prior_code in (None, "PATH_RACE"):
            ledger, real_close = audit.FdLedger(), os.close
            failed = []
            def closing(fd):
                if not failed:
                    failed.append(fd)
                    raise OSError("state unknown")
                real_close(fd)
            patches = [mock.patch.object(audit.os, "close", side_effect=closing)]
            if prior_code:
                patches.append(mock.patch.object(
                    audit, "_open_dir_at", side_effect=audit.OperationalError(prior_code)))
            try:
                with patches[0]:
                    with patches[1] if prior_code else contextlib.nullcontext():
                        with self.assertRaises(audit.OperationalError) as error:
                            audit._open_path(str(self.final), ledger)
                self.assertEqual(str(error.exception), prior_code or "FD_CLOSE_FAILED")
                self.assertEqual((ledger.owned, ledger.failed), (tuple(failed),) * 2)
            finally:
                for fd in ledger.owned:
                    real_close(fd)
    def test_returned_descriptor_and_trail_survive_path_replacement(self):
        descriptor, trail = audit._open_path(str(self.final))
        original, moved = trail[-1], self.final.with_name("beta-old")
        self.final.rename(moved)
        self.final.mkdir()
        try:
            self.assertEqual(audit._identity(os.fstat(descriptor)), original)
            self.assertNotEqual(audit._identity(os.stat(self.final)), original)
            self.assertEqual(trail, self.expected(moved))
        finally:
            os.close(descriptor)
if __name__ == "__main__":
    unittest.main()
