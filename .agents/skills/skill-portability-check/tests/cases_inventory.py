import os
import pathlib
import queue
import tempfile
import threading
import unittest
from unittest import mock

from cases_foundation import audit


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.base = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.root = self.base / "root"
        self.root.mkdir()
        self.core = audit._load_core()

    @staticmethod
    def skill(directory, name="portable", description="useful"):
        directory.mkdir(parents=True, exist_ok=True)
        data = f"---\nname: {name}\ndescription: {description}\n---\nbody".encode()
        (directory / "SKILL.md").write_bytes(data)
        return data

    @staticmethod
    def open_root(root):
        ledger = audit.FdLedger()
        descriptor, _ = audit._open_path(str(root), ledger)
        ledger.own(descriptor)
        return ledger, descriptor

    def inventory(self, root=None):
        ledger, descriptor = self.open_root(root or self.root)
        try:
            records = audit._inventory_at(ledger, descriptor, self.core)
            self.assertIn(descriptor, ledger.owned)
            return records
        finally:
            ledger.cleanup()

    @staticmethod
    def codes(record):
        return tuple(code for code, _, _ in record["findings"])

    def bounded(self, operation):
        outcome = queue.Queue()
        def run():
            try:
                outcome.put(operation())
            except (audit.OperationalError, AssertionError, OSError) as error:
                outcome.put(error)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(1.0)
        self.assertFalse(thread.is_alive(), "descriptor operation hung")
        return outcome.get_nowait()

    def test_nested_duplicates_invalid_fallback_nfc_and_determinism(self):
        self.skill(self.root, "same", "")
        (self.root / "notes.txt").write_text("/.claude/skills/", encoding="utf-8")
        nested = self.root / "nested"
        self.skill(nested, "same")
        (nested / "child.txt").write_text("token", encoding="utf-8")
        for key in ("d", "c"):
            self.skill(self.root / key, "'invalid")
        first, second = self.inventory(), self.inventory()
        self.assertEqual(first, second)
        self.assertEqual(tuple(item["key"] for item in first), (".", "c", "d", "nested"))
        self.assertEqual(tuple(path for path, _, _ in first[0]["files"]),
                         ("SKILL.md", "notes.txt"))
        for record in (first[0], first[3]):
            self.assertIn(("META004", "SKILL.md", "blocked"), record["findings"])
        for record in first[1:3]:
            self.assertFalse(record["name_valid"])
            self.assertNotIn("META004", self.codes(record))
            self.assertIsInstance(record["skill_bytes"], bytes)
        self.assertIn("META003", self.codes(first[0]))
        self.assertIn("PATH001", self.codes(first[0]))
        self.assertIn("SECRET001", self.codes(first[3]))
        with mock.patch.object(audit, "_scan_dir", return_value=("e\u0301", "\u00e9")):
            with self.assertRaises(audit.OperationalError) as error:
                audit._inventory_names(1)
        self.assertEqual(str(error.exception), "PATH_COLLISION")

    def test_exact_exclusions_symlink_first_and_zero_target_or_excluded_reads(self):
        self.skill(self.root)
        target = self.base / "private-target"
        self.skill(target, "must-not-discover")
        for name in audit.EXCLUDED_DIRECTORIES - {".git"}:
            directory = self.root / name
            directory.mkdir()
            (directory / "secret.txt").write_text("secret", encoding="utf-8")
        git_dir = self.root / "holder" / ".git"
        git_dir.mkdir(parents=True)
        (git_dir / "secret.txt").write_text("secret", encoding="utf-8")
        os.symlink(target, self.root / ".git")
        for name in (".env", ".env.private", "unsupported.rb", "unsupported.go", "binary"):
            (self.root / name).write_text("must-not-read", encoding="utf-8")
        (self.root / ".envish.txt").write_text("portable", encoding="utf-8")
        (self.root / "vendorx").mkdir()
        (self.root / "vendorx" / "inside.txt").write_text("portable", encoding="utf-8")
        real_scan, real_read, reads = audit._scan_dir, audit._inventory_read, []
        forbidden_ids = {audit._identity((self.root / name).stat())
                         for name in audit.EXCLUDED_DIRECTORIES - {".git"}}
        forbidden_ids.update((audit._identity(git_dir.stat()), audit._identity(target.stat())))
        def safe_scan(fd):
            self.assertNotIn(audit._identity(os.fstat(fd)), forbidden_ids)
            return real_scan(fd)
        def observed_read(ledger, parent, name, limit):
            reads.append(name)
            return real_read(ledger, parent, name, limit)
        with mock.patch.object(audit, "_scan_dir", side_effect=safe_scan), \
                mock.patch.object(audit, "_inventory_read", side_effect=observed_read), \
                mock.patch.object(audit.os, "readlink", side_effect=AssertionError, create=True):
            record = self.inventory()[0]
        self.assertEqual(set(reads), {".envish.txt", "inside.txt", "SKILL.md"})
        self.assertEqual(self.codes(record), ("COVERAGE001", "PATH003"))

    def test_only_post_stable_open_content_failures_become_file001(self):
        self.skill(self.root)
        (self.root / "invalid.txt").write_bytes(b"\xff")
        (self.root / "large.py").write_bytes(b"a" * (self.core.MAX_BYTES + 1))
        failed = self.root / "read-failure.txt"
        failed.write_text("private", encoding="utf-8")
        failed_id, real_read = audit._identity(failed.stat()), audit.os.read
        def guarded_read(fd, size):
            if audit._identity(os.fstat(fd)) == failed_id:
                raise PermissionError("private")
            return real_read(fd, size)
        with mock.patch.object(audit.os, "read", side_effect=guarded_read):
            record = self.inventory()[0]
        files = {path: data for path, data, _ in record["files"]}
        self.assertIsNone(files["read-failure.txt"])
        self.assertEqual(len(files["large.py"]), self.core.MAX_BYTES + 1)
        for path in ("invalid.txt", "large.py", "read-failure.txt"):
            self.assertIn(("FILE001", path, "review"), record["findings"])

    def test_open_refusal_and_actual_aba_swaps_are_operational_and_bounded(self):
        target = self.base / "target.txt"
        target.write_text("must-not-read", encoding="utf-8")
        makers = {"symlink": lambda path: os.symlink(target, path),
                  "fifo": os.mkfifo, "directory": lambda path: path.mkdir(),
                  "missing": lambda path: None}
        for kind in ("permission", "symlink", "fifo", "directory", "missing"):
            with self.subTest(kind=kind):
                root = self.base / kind
                self.skill(root)
                victim, saved = root / "victim.txt", root / "original.txt"
                victim.write_text("original", encoding="utf-8")
                ledger, root_fd = self.open_root(root)
                real_open, real_read, failed_close, swapped = audit.os.open, audit.os.read, [], []
                skill_id = audit._identity((root / "SKILL.md").stat())
                def swapping_open(name, flags, *args, **kwargs):
                    if name != "victim.txt": return real_open(name, flags, *args, **kwargs)
                    self.assertEqual(flags & (audit.os.O_NOFOLLOW | audit.os.O_NONBLOCK), audit.os.O_NOFOLLOW | audit.os.O_NONBLOCK)
                    if kind == "permission": raise PermissionError("private")
                    swapped.append(True)
                    victim.rename(saved)
                    makers[kind](victim)
                    try: return real_open(name, flags, *args, **kwargs)
                    finally:
                        if victim.is_dir(): victim.rmdir()
                        elif victim.exists() or victim.is_symlink(): victim.unlink()
                        saved.rename(victim)
                def guarded_read(fd, size):
                    if audit._identity(os.fstat(fd)) != skill_id:
                        raise AssertionError("read after failed stable-open gate")
                    return real_read(fd, size)
                real_close = audit.os.close
                def guarded_close(fd):
                    if kind == "directory" and swapped and fd != root_fd and not failed_close:
                        failed_close.append(fd)
                        raise OSError("private")
                    return real_close(fd)
                with mock.patch.object(audit.os, "open", side_effect=swapping_open), \
                        mock.patch.object(audit.os, "read", side_effect=guarded_read), \
                        mock.patch.object(audit.os, "close", side_effect=guarded_close):
                    result = self.bounded(lambda: audit._inventory_at(
                        ledger, root_fd, self.core))
                expected = "PATH_RACE" if kind in ("fifo", "directory") else "PATH_UNSAFE"
                self.assertIsInstance(result, audit.OperationalError)
                self.assertEqual(str(result), expected)
                self.assertEqual(ledger.failed, tuple(failed_close))
                self.assertEqual(ledger.owned, tuple(failed_close))
                self.assertEqual(victim.read_text(encoding="utf-8"), "original")
                for fd in ledger.failed: real_close(fd)

    def test_retained_root_descriptor_is_authoritative_after_replacement(self):
        original = self.skill(self.root, "original")
        ledger, descriptor = self.open_root(self.root)
        moved = self.base / "moved"
        self.root.rename(moved)
        self.skill(self.root, "replacement")
        records = audit._inventory_at(ledger, descriptor, self.core)
        self.assertIn(descriptor, ledger.owned)
        self.assertEqual(records[0]["skill_bytes"], original)
        self.assertNotEqual(records[0]["skill_bytes"], (self.root / "SKILL.md").read_bytes())
        ledger.cleanup()


if __name__ == "__main__":
    unittest.main()
