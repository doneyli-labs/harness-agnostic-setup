"""Input-policy cases for the skill portability auditor."""
import contextlib
import io
import os
import pathlib
import tempfile
import types
import unittest
from unittest import mock

from cases_foundation import audit


class InputPolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = self.enterContext(tempfile.TemporaryDirectory())
        self.root = pathlib.Path(temporary).resolve()
        self.home = self.root / "nest" / "CaseHome"
        self.safe = self.root / "safe"
        self.home.mkdir(parents=True)
        self.safe.mkdir()

    @staticmethod
    def args(source, target=None):
        return types.SimpleNamespace(source=str(source), target=None if target is None else str(target))

    def home_record(self, path=None):
        return types.SimpleNamespace(pw_dir=str(self.home if path is None else path))

    def preflight(self, source, target=None, ledger=None, home=None):
        with mock.patch.object(audit.pwd, "getpwuid", return_value=self.home_record(home)):
            return audit._input_preflight(self.args(source, target), ledger)

    @staticmethod
    def run_main(argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = audit.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_home_descendant_and_same_source_target_are_allowed(self):
        descendant = self.home / "child"
        descendant.mkdir()
        ledger = audit.FdLedger()
        self.assertIsNone(self.preflight(descendant, descendant, ledger))
        self.assertEqual((ledger.owned, ledger.failed), ((), ()))

    def test_root_home_and_every_home_ancestor_guard_both_inputs(self):
        guarded = (self.home, *self.home.parents)
        for label in ("source", "target"):
            for path in guarded:
                ledger = audit.FdLedger()
                source, target = (path, None) if label == "source" else (self.safe, path)
                with self.subTest(label=label, path=str(path)):
                    with self.assertRaises(audit.OperationalError) as error:
                        self.preflight(source, target, ledger)
                    self.assertEqual(str(error.exception), f"<{label}> PATH_UNSAFE")
                    self.assertEqual((ledger.owned, ledger.failed), ((), ()))

    def test_guard_uses_identity_for_simulated_and_supported_case_aliases(self):
        alias, home_identity = self.root / "different-spelling", []
        alias.mkdir()
        real_open = audit._open_path
        def opening(path, ledger):
            descriptor, trail = real_open(path, ledger)
            if str(path) == str(self.home):
                home_identity.append(trail[-1])
            elif str(path) == str(alias):
                trail = (*trail[:-1], home_identity[0])
            return descriptor, trail
        with mock.patch.object(audit, "_open_path", side_effect=opening):
            with self.assertRaisesRegex(audit.OperationalError, "^<source> PATH_UNSAFE$"):
                self.preflight(alias)
        case_alias = self.home.with_name(self.home.name.swapcase())
        if case_alias.exists() and os.path.samefile(case_alias, self.home):
            with self.assertRaisesRegex(audit.OperationalError,
                                        "^<source> PATH_UNSAFE$"):
                self.preflight(case_alias)

    def test_home_and_input_lookup_open_missing_and_nondirectory_are_labeled(self):
        for failure in (KeyError("missing"), OSError("private/path")):
            with mock.patch.object(audit.pwd, "getpwuid", side_effect=failure):
                with self.assertRaisesRegex(audit.OperationalError, "^<home> PATH_UNSAFE$"):
                    audit._input_preflight(self.args(self.safe))
        with self.assertRaisesRegex(audit.OperationalError, "^<home> PATH_UNSAFE$"):
            self.preflight(self.safe, home=self.root / "missing-home")
        nondirectory = self.root / "file"
        nondirectory.write_text("fixture", encoding="utf-8")
        for label in ("source", "target"):
            for path in (self.root / "missing", nondirectory):
                ledger = audit.FdLedger()
                source, target = (path, None) if label == "source" else (self.safe, path)
                with self.assertRaises(audit.OperationalError) as error:
                    self.preflight(source, target, ledger)
                self.assertEqual(str(error.exception), f"<{label}> PATH_UNSAFE")
                self.assertEqual(ledger.owned, ())

    def test_relative_or_root_identity_home_is_rejected_before_source(self):
        for home in ("relative-home", os.sep):
            ledger = audit.FdLedger()
            with self.subTest(home=home), \
                    mock.patch.object(audit, "_open_path", wraps=audit._open_path) as opening:
                with self.assertRaisesRegex(audit.OperationalError,
                                            "^<home> PATH_UNSAFE$"):
                    self.preflight(os.sep, ledger=ledger, home=home)
                self.assertEqual(ledger.owned, ())
                expected = 0 if home == "relative-home" else 1
                self.assertEqual(opening.call_count, expected)

    def test_guard_rejects_simulated_root_identity_home_alias(self):
        real_open = audit._open_path
        def opening(path, ledger):
            descriptor, trail = real_open(path, ledger)
            if str(path) == str(self.home):
                trail = (*trail[:-1], trail[0])
            return descriptor, trail
        ledger = audit.FdLedger()
        with mock.patch.object(audit, "_open_path", side_effect=opening):
            with self.assertRaisesRegex(audit.OperationalError,
                                        "^<home> PATH_UNSAFE$"):
                self.preflight(os.sep, ledger=ledger)
        self.assertEqual(ledger.owned, ())

    def test_actual_component_swaps_are_separately_labeled(self):
        for label in ("home", "source", "target"):
            with self.subTest(label=label):
                victim = self.root / (label + "-victim") / "swap" / "leaf"
                victim.mkdir(parents=True)
                parent_identity = audit._identity(os.stat(victim.parent.parent))
                moved, real_open = False, audit.os.open
                def opening(name, flags, *args, **kwargs):
                    nonlocal moved
                    parent = kwargs.get("dir_fd")
                    if name == "swap" and parent is not None and not moved \
                            and audit._identity(os.fstat(parent)) == parent_identity:
                        os.rename(name, "swap-old", src_dir_fd=parent, dst_dir_fd=parent)
                        os.mkdir(name, dir_fd=parent)
                        moved = True
                    return real_open(name, flags, *args, **kwargs)
                home = victim if label == "home" else self.home
                source = victim if label == "source" else self.safe
                target = victim if label == "target" else None
                ledger = audit.FdLedger()
                with mock.patch.object(audit.os, "open", side_effect=opening):
                    with self.assertRaises(audit.OperationalError) as error:
                        self.preflight(source, target, ledger, home)
                self.assertEqual(str(error.exception), f"<{label}> PATH_RACE")
                self.assertEqual(ledger.owned, ())

    def test_simulated_component_swaps_are_separately_labeled(self):
        real_open = audit._open_path
        for label in ("home", "source", "target"):
            with self.subTest(label=label):
                victim = self.root / (label + "-simulated")
                victim.mkdir()
                def opening(path, ledger):
                    if str(path) == str(victim):
                        raise audit.OperationalError("PATH_RACE")
                    return real_open(path, ledger)
                home = victim if label == "home" else self.home
                source = victim if label == "source" else self.safe
                target = victim if label == "target" else None
                with mock.patch.object(audit, "_open_path", side_effect=opening):
                    with self.assertRaises(audit.OperationalError) as error:
                        self.preflight(source, target, home=home)
                self.assertEqual(str(error.exception), f"<{label}> PATH_RACE")

    def synthetic_results(self):
        descriptors = [os.open(self.safe, os.O_RDONLY | os.O_DIRECTORY) for _ in range(3)]
        trails = (((1, 1), (1, 2)), ((1, 3),), ((1, 4),))
        return descriptors, [(descriptor, trail) for descriptor, trail in zip(descriptors, trails)]

    def test_close_failures_track_all_and_preserve_policy_precedence(self):
        for policy_failure in (False, True):
            descriptors, results = self.synthetic_results()
            if policy_failure:
                results[1] = (descriptors[1], ((1, 2),))
            ledger, real_close = audit.FdLedger(), os.close
            failing = {descriptors[0], descriptors[2]} if not policy_failure else set(descriptors)
            held = []
            def closing(descriptor):
                held.append(ledger.owned)
                if descriptor in failing:
                    raise OSError("close state unknown")
                real_close(descriptor)
            try:
                with mock.patch.object(audit, "_open_path", side_effect=results), \
                        mock.patch.object(audit.os, "close", side_effect=closing):
                    with self.assertRaises(audit.OperationalError) as error:
                        self.preflight(self.safe, self.safe, ledger)
                expected = "<source> PATH_UNSAFE" if policy_failure else "<target> FD_CLOSE_FAILED"
                self.assertEqual(str(error.exception), expected)
                self.assertEqual(held[0], tuple(descriptors))
                self.assertEqual(ledger.owned, ledger.failed)
                self.assertEqual(set(ledger.failed), failing)
            finally:
                for descriptor in ledger.owned:
                    real_close(descriptor)

    def test_main_is_path_free_read_only_and_leaves_output_uninspected(self):
        output = self.root / "private-report"
        argv = ["--source", str(self.safe), "--target", str(self.safe), "--output", str(output)]
        real_descriptor_open, real_stat = os.open, os.stat
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(audit, "_capable", return_value=True))
            stack.enter_context(mock.patch.object(
                audit.pwd, "getpwuid", return_value=self.home_record()))
            scandir = stack.enter_context(mock.patch.object(audit.os, "scandir"))
            file_open = stack.enter_context(mock.patch("builtins.open"))
            descriptor_open = stack.enter_context(mock.patch.object(
                audit.os, "open", wraps=real_descriptor_open))
            descriptor_stat = stack.enter_context(mock.patch.object(
                audit.os, "stat", wraps=real_stat))
            mutators = [stack.enter_context(mock.patch.object(audit.os, name))
                        for name in ("mkdir", "rename", "replace", "link", "unlink")]
            stack.enter_context(mock.patch.object(audit, "_output_guard", create=True))
            result = self.run_main(argv)
        self.assertEqual(result, (2, "", "AUDIT_INCOMPLETE\n"))
        self.assertFalse(output.exists())
        scandir.assert_not_called()
        file_open.assert_not_called()
        for function in mutators:
            function.assert_not_called()
        for call in (*descriptor_open.mock_calls, *descriptor_stat.mock_calls):
            self.assertNotIn(output.name, str(call))
        with mock.patch.object(audit, "_capable", return_value=True), \
                mock.patch.object(audit.pwd, "getpwuid", return_value=self.home_record()):
            refusal = self.run_main(["--source", str(self.root / "private-missing")])
        self.assertEqual(refusal, (2, "", "<source> PATH_UNSAFE\n"))
        self.assertNotIn("private", refusal[2])
        self.assertNotIn("Traceback", refusal[2])
