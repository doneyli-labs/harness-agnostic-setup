#!/usr/bin/env python3
"""Fail-closed command shell for the skill portability auditor."""
import argparse
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
                 ("open", "stat", "link", "unlink", "scandir")}
    dir_fd = getattr(os, "supports_dir_fd", ()) or ()
    fd = getattr(os, "supports_fd", ()) or ()
    follow = getattr(os, "supports_follow_symlinks", ()) or ()
    return (
        all(_member(functions[name], dir_fd)
            for name in ("open", "stat", "link", "unlink"))
        and _member(functions["scandir"], fd)
        and all(_member(functions[name], follow) for name in ("stat", "link"))
        and callable(getattr(os, "fstat", None))
        and callable(getattr(os, "fsync", None))
        and bool(getattr(os, "O_DIRECTORY", 0))
        and bool(getattr(os, "O_NOFOLLOW", 0))
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


def _parser():
    parser = SafeParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--source", required=True)
    parser.add_argument("--target")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--show-paths", action="store_true")
    parser.add_argument("--output")
    return parser


PARSER = _parser()


def main(argv=None):
    try:
        PARSER.parse_args(argv)
        if not _capable():
            raise OperationalError("SAFE_IO_UNAVAILABLE")
        raise OperationalError("AUDIT_INCOMPLETE")
    except OperationalError as error:
        sys.stderr.write(f"{error}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
