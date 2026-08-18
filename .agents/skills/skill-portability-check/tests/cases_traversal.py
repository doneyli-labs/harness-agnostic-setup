"""Descriptor-authoritative traversal cases."""
import contextlib
import os
import pathlib
import tempfile
import types
import unittest
from unittest import mock

from cases_foundation import audit


class TraversalTests(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.real_close = os.close

    def open_root(self, path=None):
        ledger = audit.FdLedger()
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = ledger.own(os.open(path or self.root, flags))
        self.addCleanup(self.force_close, ledger)
        return ledger, descriptor

    def force_close(self, ledger):
        for descriptor in ledger.owned:
            try:
                self.real_close(descriptor)
            except OSError:
                pass

    @staticmethod
    def changed(metadata):
        return types.SimpleNamespace(st_dev=metadata.st_dev, st_ino=metadata.st_ino + 1, st_mode=metadata.st_mode)

    def test_malformed_file_operands_make_zero_syscalls_at_every_api(self):
        bad = ("", ".", "..", os.sep, "bad\x00", "bad\u200b", "bad\ud800")
        apis = (audit._open_file_at, audit._read_file_at)
        with mock.patch.object(audit.os, "stat") as stated, \
                mock.patch.object(audit.os, "open") as opened, \
                mock.patch.object(audit.os, "fstat") as fstated, \
                mock.patch.object(audit.os, "read") as read, \
                mock.patch.object(audit.os, "close") as closed:
            for function in apis:
                for name in bad:
                    self.assertRaises(audit.OperationalError, function, audit.FdLedger(), 9, name)
            with mock.patch.object(audit.os, "altsep", "!"):
                for function in apis:
                    self.assertRaises(audit.OperationalError, function, audit.FdLedger(), 9, "a!b")
            invalid_scan = contextlib.nullcontext([types.SimpleNamespace(name="bad\u200b")])
            with mock.patch.object(audit.os, "scandir", return_value=invalid_scan):
                self.assertRaises(audit.OperationalError, audit._traverse_at, audit.FdLedger(), 9)
        for syscall in (stated, opened, fstated, read, closed):
            syscall.assert_not_called()

    def test_traversal_uses_retained_descriptors_and_reads_eligible_files(self):
        child = self.root / "child"
        child.mkdir()
        (child / "a.md").write_bytes(b"alpha")
        (child / "ignored.bin").write_bytes(b"ignored")
        ledger, root_fd = self.open_root()
        real_scan, real_stat, real_open, real_fstat = os.scandir, audit._stat_at, os.open, os.fstat
        scans, file_stats = [], 0
        def scanning(descriptor):
            scans.append(audit._identity(os.fstat(descriptor)))
            return real_scan(descriptor)
        def statting(parent, name):
            nonlocal file_stats
            metadata = real_stat(parent, name)
            if name == "a.md":
                file_stats += 1
                if file_stats == 3:
                    self.assertEqual(len(ledger.owned), 3)
                    self.assertIn(parent, ledger.owned)
            return metadata
        def opening(name, flags, *args, **kwargs):
            descriptor = real_open(name, flags, *args, **kwargs)
            self.assertIn(kwargs.get("dir_fd"), ledger.owned)
            if name == "a.md":
                self.assertEqual(flags & (os.O_NOFOLLOW | os.O_NONBLOCK | os.O_DIRECTORY | os.O_WRONLY | os.O_RDWR | os.O_CREAT), os.O_NOFOLLOW | os.O_NONBLOCK)
            return descriptor
        with mock.patch.object(audit.os, "scandir", side_effect=scanning), \
                mock.patch.object(audit, "_stat_at", side_effect=statting), \
                mock.patch.object(audit.os, "open", side_effect=opening), \
                mock.patch.object(audit.os, "fstat", side_effect=lambda fd: (self.assertIn(fd, ledger.owned) or real_fstat(fd))):
            events = audit._traverse_at(ledger, root_fd)
        self.assertEqual(events, (("file", ("child", "a.md"), b"alpha"),))
        self.assertEqual(len(scans), 2)
        self.assertEqual(ledger.owned, (root_fd,))
        ledger.close(root_fd)

    def test_file_pre_open_post_identity_races_are_rejected_and_cleaned(self):
        path = self.root / "race.md"
        path.write_bytes(b"content")
        baseline, altered = os.stat(path), self.changed(os.stat(path))
        for phase in ("pre", "open", "post"):
            ledger, parent = self.open_root()
            stats = [altered if phase == "pre" else baseline, altered if phase == "post" else baseline]
            real_fstat = os.fstat
            def fstatting(descriptor):
                metadata = real_fstat(descriptor)
                return altered if phase == "open" and descriptor != parent else metadata
            with self.subTest(phase=phase), \
                    mock.patch.object(audit, "_stat_at", side_effect=stats), \
                    mock.patch.object(audit.os, "fstat", side_effect=fstatting):
                with self.assertRaisesRegex(audit.OperationalError, "^PATH_RACE$"):
                    audit._read_file_at(ledger, parent, path.name)
            self.assertEqual(ledger.owned, ())

    def test_open_file_descriptor_remains_authoritative_after_rename(self):
        path, moved = self.root / "authority.md", self.root / "old.md"
        path.write_bytes(b"original")
        ledger, parent = self.open_root()
        real_read, replaced = os.read, False
        def reading(descriptor, size):
            nonlocal replaced
            if not replaced:
                path.rename(moved)
                path.write_bytes(b"replacement")
                replaced = True
            return real_read(descriptor, size)
        with mock.patch.object(audit.os, "read", side_effect=reading):
            self.assertEqual(audit._read_file_at(ledger, parent, path.name), b"original")
        self.assertEqual(path.read_bytes(), b"replacement")
        self.assertEqual(ledger.owned, (parent,))
        ledger.close(parent)

    def test_directory_swap_is_rejected_by_traversal(self):
        child = self.root / "child"
        child.mkdir()
        ledger, parent = self.open_root()
        real_open, moved = os.open, False
        def opening(name, flags, *args, **kwargs):
            nonlocal moved
            if name == "child" and not moved:
                child.rename(self.root / "old-child")
                child.mkdir()
                moved = True
            return real_open(name, flags, *args, **kwargs)
        with mock.patch.object(audit.os, "open", side_effect=opening):
            with self.assertRaisesRegex(audit.OperationalError, "^PATH_RACE$"):
                audit._traverse_at(ledger, parent)
        self.assertEqual(ledger.owned, ())

    def test_nonblocking_gate_and_regular_to_fifo_swap_is_safe(self):
        with mock.patch.object(audit.os, "O_NONBLOCK", 0):
            self.assertFalse(audit._capable())
        path = self.root / "fifo.md"
        path.write_bytes(b"regular")
        ledger, parent = self.open_root()
        real_open = os.open
        def opening(name, flags, *args, **kwargs):
            if name == path.name:
                path.unlink()
                os.mkfifo(path)
                self.assertTrue(flags & os.O_NONBLOCK)
            return real_open(name, flags, *args, **kwargs)
        with mock.patch.object(audit.os, "open", side_effect=opening), \
                mock.patch.object(audit.os, "read") as read:
            with self.assertRaisesRegex(audit.OperationalError, "^PATH_(?:RACE|UNSAFE)$"):
                audit._read_file_at(ledger, parent, path.name)
        read.assert_not_called()
        self.assertEqual(ledger.owned, ())

    def test_symlink_precedes_exclusion_and_target_is_never_accessed(self):
        target = self.root.parent / (self.root.name + "-target")
        target.mkdir()
        self.addCleanup(target.rmdir)
        (target / "secret.md").write_bytes(b"never read")
        self.addCleanup((target / "secret.md").unlink)
        (self.root / "node_modules").symlink_to(target, target_is_directory=True)
        excluded = self.root / "vendor"
        excluded.mkdir()
        target_ids = {audit._identity(os.stat(target)), audit._identity(os.stat(excluded))}
        real_scan = os.scandir
        def scanning(descriptor):
            self.assertNotIn(audit._identity(os.fstat(descriptor)), target_ids)
            return real_scan(descriptor)
        for readlink in (None, mock.Mock(side_effect=AssertionError("forbidden"))):
            ledger, parent = self.open_root()
            with self.subTest(readlink=readlink), \
                    mock.patch.object(audit.os, "readlink", readlink), \
                    mock.patch.object(audit.os, "scandir", side_effect=scanning):
                events = audit._traverse_at(ledger, parent)
            self.assertEqual(events, (("PATH003", ("node_modules",), None), ("excluded", ("vendor",), None)))
            if isinstance(readlink, mock.Mock):
                readlink.assert_not_called()
            ledger.close(parent)

    def test_read_and_close_failures_preserve_precedence_and_uncertainty(self):
        path = self.root / "failure.md"
        path.write_bytes(b"content")
        ledger, parent = self.open_root()
        with mock.patch.object(audit.os, "read", side_effect=OSError("private/path")):
            with self.assertRaisesRegex(audit.OperationalError, "^PATH_UNSAFE$"):
                audit._read_file_at(ledger, parent, path.name)
        self.assertEqual(ledger.owned, ())
        for read_failure in (False, True):
            ledger, parent = self.open_root()
            read = mock.patch.object(audit.os, "read", side_effect=OSError("private/path")) if read_failure else contextlib.nullcontext()
            try:
                with read, mock.patch.object(audit.os, "close", side_effect=OSError("close state unknown")) as closed:
                    with self.assertRaises(audit.OperationalError) as error:
                        audit._read_file_at(ledger, parent, path.name)
                self.assertEqual(str(error.exception), "PATH_UNSAFE" if read_failure else "FD_CLOSE_FAILED")
                self.assertEqual(ledger.owned, ledger.failed)
                self.assertEqual(len(ledger.failed), 2)
                self.assertEqual(closed.call_count, 2)
            finally:
                for descriptor in ledger.owned:
                    self.real_close(descriptor)


if __name__ == "__main__":
    unittest.main()
