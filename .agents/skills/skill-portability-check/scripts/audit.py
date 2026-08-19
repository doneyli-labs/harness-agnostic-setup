#!/usr/bin/env python3
"""Fail-closed command shell for the skill portability auditor."""
import argparse
import importlib.util
import os
import stat
import sys
import unicodedata

try:
    import pwd
except ModuleNotFoundError as error:
    if error.name != "pwd":
        raise
    pwd = None


class OperationalError(RuntimeError):
    """An operational refusal whose message is safe to print."""


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise OperationalError("CLI_INVALID")


class FdLedger:
    """Ordered ownership record; failed closes remain owned and uncertain."""

    def __init__(self):
        self._owned = []
        self._failed = set()

    @property
    def owned(self):
        return tuple(self._owned)

    @property
    def failed(self):
        return tuple(fd for fd in self._owned if fd in self._failed)

    def own(self, fd):
        if fd in self._owned:
            raise OperationalError("FD_OWNERSHIP")
        self._owned.append(fd)
        return fd

    def release(self, fd):
        if fd not in self._owned:
            raise OperationalError("FD_OWNERSHIP")
        if fd in self._failed:
            raise OperationalError("FD_CLOSE_FAILED")
        self._owned.remove(fd)
        return fd

    def close(self, fd):
        if fd not in self._owned:
            raise OperationalError("FD_OWNERSHIP")
        if fd in self._failed:
            raise OperationalError("FD_CLOSE_FAILED")
        try:
            os.close(fd)
        except OSError:
            self._failed.add(fd)
            raise OperationalError("FD_CLOSE_FAILED") from None
        self._owned.remove(fd)

    def cleanup(self, prior=None):
        for fd in self._owned[::-1]:
            if fd in self._failed:
                continue
            try:
                os.close(fd)
            except OSError:
                self._failed.add(fd)
            else:
                self._owned.remove(fd)
        if prior is not None:
            raise prior
        if self._failed:
            raise OperationalError("FD_CLOSE_FAILED")


def _member(function, capability):
    return callable(function) and function in capability


def _capable():
    functions = {name: getattr(os, name, None) for name in
                 ("open", "stat", "scandir")}
    dir_fd = getattr(os, "supports_dir_fd", ()) or ()
    fd = getattr(os, "supports_fd", ()) or ()
    follow = getattr(os, "supports_follow_symlinks", ()) or ()
    return (
        all(_member(functions[name], dir_fd) for name in ("open", "stat"))
        and _member(functions["scandir"], fd)
        and _member(functions["stat"], follow)
        and callable(getattr(os, "fstat", None))
        and bool(getattr(os, "O_DIRECTORY", 0))
        and bool(getattr(os, "O_NOFOLLOW", 0))
        and bool(getattr(os, "O_NONBLOCK", 0))
        and pwd is not None
        and callable(getattr(pwd, "getpwuid", None))
        and callable(getattr(os, "getuid", None))
    )


def _unsafe_unicode(value):
    return (not isinstance(value, str)
            or any(unicodedata.category(char) in ("Cc", "Cf", "Cs")
                   for char in value))


def _safe_basename(name):
    separators = (os.sep,) if os.altsep is None else (os.sep, os.altsep)
    if (_unsafe_unicode(name) or name in ("", ".", "..")
            or any(separator in name for separator in separators)):
        raise OperationalError("PATH_UNSAFE")
    return name


def _path_plan(path):
    if _unsafe_unicode(path) or not path:
        raise OperationalError("PATH_UNSAFE")
    normalized = path.replace(os.altsep, os.sep) if os.altsep else path
    absolute = os.path.isabs(normalized)
    remainder = normalized[len(os.sep):] if absolute else normalized
    components = () if absolute and not remainder else tuple(remainder.split(os.sep))
    for component in components:
        _safe_basename(component)
    return (os.sep if absolute else "."), components


def _identity(metadata):
    return metadata.st_dev, metadata.st_ino


def _stat_at(parent, name):
    name = _safe_basename(name)
    try:
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    except (OSError, UnicodeError, ValueError):
        raise OperationalError("PATH_UNSAFE") from None


def _open_dir_at(ledger, parent, name):
    name = _safe_basename(name)
    before = _stat_at(parent, name)
    if not stat.S_ISDIR(before.st_mode):
        raise OperationalError("PATH_UNSAFE")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        child = ledger.own(os.open(name, flags, dir_fd=parent))
        opened = os.fstat(child)
    except (OSError, UnicodeError, ValueError):
        raise OperationalError("PATH_UNSAFE") from None
    after = _stat_at(parent, name)
    identities = {_identity(before), _identity(opened), _identity(after)}
    if not stat.S_ISDIR(opened.st_mode) or len(identities) != 1:
        raise OperationalError("PATH_RACE")
    return child, _identity(opened)


def _open_path(path, ledger=None):
    anchor, components = _path_plan(path)
    owner = FdLedger() if ledger is None else ledger
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        current = owner.own(os.open(anchor, flags))
        metadata = os.fstat(current)
        if not stat.S_ISDIR(metadata.st_mode):
            raise OperationalError("PATH_UNSAFE")
        trail = [_identity(metadata)]
        for component in components:
            child, identity = _open_dir_at(owner, current, component)
            owner.close(current)
            current = child
            trail.append(identity)
        return owner.release(current), tuple(trail)
    except OperationalError as error:
        owner.cleanup(error)
    except (OSError, UnicodeError, ValueError):
        owner.cleanup(OperationalError("PATH_UNSAFE"))


def _labeled(label, error):
    return OperationalError(f"<{label}> {error}")


def _home_path():
    try:
        home = pwd.getpwuid(os.getuid()).pw_dir
    except (AttributeError, KeyError, OSError):
        raise OperationalError("<home> PATH_UNSAFE") from None
    if not isinstance(home, str) or not os.path.isabs(home):
        raise OperationalError("<home> PATH_UNSAFE")
    return home


def _open_input(label, path, ledger):
    try:
        descriptor, trail = _open_path(path, ledger)
        ledger.own(descriptor)
        return descriptor, trail
    except OperationalError as error:
        raise _labeled(label, error) from None


def _close_inputs(ledger, records):
    reason = None
    for label, descriptor, _ in reversed(records):
        try:
            ledger.close(descriptor)
        except OperationalError as error:
            if reason is None:
                reason = _labeled(label, error)
    if reason is not None:
        ledger.cleanup(reason)


def _input_preflight(args, ledger=None):
    owner = FdLedger() if ledger is None else ledger
    records = []
    try:
        home = _open_input("home", _home_path(), owner)
        records.append(("home", *home))
        if home[1][-1] == home[1][0]:
            raise OperationalError("<home> PATH_UNSAFE")
        source = _open_input("source", args.source, owner)
        records.append(("source", *source))
        if args.target is not None:
            target = _open_input("target", args.target, owner)
            records.append(("target", *target))
        guarded = set(home[1])
        for label, _, trail in records[1:]:
            if trail[-1] in guarded:
                raise OperationalError(f"<{label}> PATH_UNSAFE")
    except OperationalError as error:
        owner.cleanup(error)
    _close_inputs(owner, records)


EXCLUDED_DIRECTORIES = frozenset((
    ".git", ".hg", ".svn", "__pycache__", ".cache", ".mypy_cache",
    ".pytest_cache", "node_modules", "vendor", "dist", "build", "target",
    "credentials", "secrets"))
ELIGIBLE_SUFFIXES = (
    ".md", ".txt", ".sh", ".py", ".js", ".ts", ".json", ".toml", ".yaml", ".yml")


def _scan_dir(directory):
    try:
        with os.scandir(directory) as entries:
            names = tuple(_safe_basename(entry.name) for entry in entries)
    except (OSError, UnicodeError, ValueError):
        raise OperationalError("PATH_UNSAFE") from None
    return tuple(sorted(names))


def _open_file_at(ledger, parent, name):
    name = _safe_basename(name)
    before = _stat_at(parent, name)
    if not stat.S_ISREG(before.st_mode):
        raise OperationalError("PATH_UNSAFE")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        child = ledger.own(os.open(name, flags, dir_fd=parent))
        opened = os.fstat(child)
    except (OSError, UnicodeError, ValueError):
        raise OperationalError("PATH_UNSAFE") from None
    after = _stat_at(parent, name)
    identities = {_identity(before), _identity(opened), _identity(after)}
    if not stat.S_ISREG(opened.st_mode) or len(identities) != 1:
        raise OperationalError("PATH_RACE")
    return child, _identity(opened)


def _read_file_at(ledger, parent, name):
    name = _safe_basename(name)
    try:
        descriptor, _ = _open_file_at(ledger, parent, name)
        chunks = []
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        ledger.close(descriptor)
        return b"".join(chunks)
    except OperationalError as error:
        ledger.cleanup(error)
    except (OSError, UnicodeError, ValueError):
        ledger.cleanup(OperationalError("PATH_UNSAFE"))


def _walk_entries(ledger, directory, prefix=()):
    events = []
    for name in _scan_dir(directory):
        metadata = _stat_at(directory, name)
        relative = (*prefix, name)
        if stat.S_ISLNK(metadata.st_mode):
            events.append(("PATH003", relative, None))
        elif stat.S_ISDIR(metadata.st_mode):
            if name in EXCLUDED_DIRECTORIES:
                events.append(("excluded", relative, None))
                continue
            child, _ = _open_dir_at(ledger, directory, name)
            events.extend(_walk_entries(ledger, child, relative))
            ledger.close(child)
        elif stat.S_ISREG(metadata.st_mode) and name.endswith(ELIGIBLE_SUFFIXES):
            events.append(("file", relative,
                           _read_file_at(ledger, directory, name)))
    return events


def _traverse_at(ledger, directory):
    try:
        return tuple(_walk_entries(ledger, directory))
    except OperationalError as error:
        ledger.cleanup(error)
    except (OSError, UnicodeError, ValueError):
        ledger.cleanup(OperationalError("PATH_UNSAFE"))


def _inventory_names(directory):
    pairs, seen = [], set()
    for raw in _scan_dir(directory):
        name = unicodedata.normalize("NFC", raw)
        _safe_basename(name)
        if name in seen:
            raise OperationalError("PATH_COLLISION")
        seen.add(name)
        pairs.append((name, raw))
    return tuple(sorted(pairs))


def _inventory_read(ledger, parent, name, limit):
    descriptor, _ = _open_file_at(ledger, parent, name)
    chunks, total, failed = [], 0, False
    try:
        while total <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except (OSError, ValueError):
        failed = True
    ledger.close(descriptor)
    return None if failed else b"".join(chunks)


def _inventory_dir(ledger, directory, prefix, current, records, core):
    entries = [(name, raw, _stat_at(directory, raw))
               for name, raw in _inventory_names(directory)]
    if any(name == "SKILL.md" and stat.S_ISREG(info.st_mode)
           for name, _, info in entries):
        current = {"key": "/".join(prefix) or ".", "_prefix": prefix,
                   "name_valid": False, "skill_bytes": None,
                   "files": [], "findings": set()}
        records.append(current)
    for name, raw, info in entries:
        full = (*prefix, name)
        if stat.S_ISLNK(info.st_mode):
            if current is not None:
                current["findings"].add(("PATH003", None, "review"))
        elif stat.S_ISDIR(info.st_mode):
            if name in EXCLUDED_DIRECTORIES:
                if current is not None:
                    current["findings"].add(("COVERAGE001", None, "review"))
                continue
            child, _ = _open_dir_at(ledger, directory, raw)
            _inventory_dir(ledger, child, full, current, records, core)
            ledger.close(child)
        elif stat.S_ISREG(info.st_mode) and current is not None:
            path = "/".join(full[len(current["_prefix"]):])
            if name == ".env" or name.startswith(".env.") \
                    or not name.endswith(ELIGIBLE_SUFFIXES):
                current["findings"].add(("COVERAGE001", None, "review"))
                continue
            data = _inventory_read(ledger, directory, raw, core.MAX_BYTES)
            analysis = core.analyze_file(path, data)
            current["files"].append((path, data, analysis))
            if path == "SKILL.md":
                current["skill_bytes"] = data
                metadata = analysis["metadata"]
                current["name_valid"] = metadata is not None and metadata[0]
            for code, severity in analysis["findings"]:
                current["findings"].add((code, path, severity))


def _finalize_inventory(records, core):
    for index, left in enumerate(records):
        if left["name_valid"] and any(
                index != other and right["name_valid"]
                and core.metadata_equal(left["skill_bytes"], right["skill_bytes"])
                for other, right in enumerate(records)):
            left["findings"].add(("META004", "SKILL.md", "blocked"))
    result = []
    for record in sorted(records, key=lambda item: item["key"]):
        result.append({"key": record["key"],
                       "name_valid": record["name_valid"],
                       "skill_bytes": record["skill_bytes"],
                       "files": tuple(sorted(record["files"])),
                       "findings": tuple(sorted(record["findings"],
                                                key=lambda item: (item[0], item[1] or "")))})
    return tuple(result)


def _inventory_at(ledger, directory, core):
    records = []
    try:
        _inventory_dir(ledger, directory, (), None, records, core)
        return _finalize_inventory(records, core)
    except OperationalError as error:
        ledger.cleanup(error)


def _parser():
    parser = SafeParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--source", required=True)
    parser.add_argument("--target")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--show-paths", action="store_true")
    parser.add_argument("--output")
    return parser


PARSER = _parser()


def _output_guard(args):
    if args.output is not None:
        raise OperationalError("SAFE_OUTPUT_UNAVAILABLE")


def _load_core():
    sys.dont_write_bytecode = True
    name = "skill_portability_audit_core"
    absent = object()
    previous = sys.modules.get(name, absent)
    failures = (ImportError, OSError, SyntaxError, UnicodeError, ValueError,
                TypeError, AttributeError, RuntimeError)
    try:
        path = os.path.join(os.path.dirname(__file__), "audit_core.py")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise RuntimeError("core loader unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except failures:
        raise OperationalError("CORE_LOAD_UNAVAILABLE") from None
    finally:
        if previous is absent:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


def main(argv=None):
    try:
        args = PARSER.parse_args(argv)
        if not _capable():
            raise OperationalError("SAFE_IO_UNAVAILABLE")
        _output_guard(args)
        _load_core()
        _input_preflight(args)
        raise OperationalError("AUDIT_INCOMPLETE")
    except OperationalError as error:
        sys.stderr.write(f"{error}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
