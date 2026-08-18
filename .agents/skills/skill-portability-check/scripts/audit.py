#!/usr/bin/env python3
"""Fail-closed safety foundation for the skill portability auditor."""
from __future__ import annotations
import argparse
import os
import secrets
import sys
import unicodedata
from collections import namedtuple
from pathlib import Path

Finding = namedtuple("Finding", "code side file_id path", defaults=(None, None))
Entry = namedtuple("Entry", "path absolute kind")

class AuditError(Exception):
    def __init__(self, label: str, reason: str):
        super().__init__(reason)
        self.label, self.reason = label, reason

class SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise AuditError("<cli>", "CLI_USAGE")

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = SafeParser(add_help=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--target")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--show-paths", action="store_true")
    parser.add_argument("--output")
    return parser.parse_args(argv)

def _within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents

def _check_text(value: str, label: str) -> str:
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise AuditError(label, "PATH_ENCODING") from exc
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value):
        raise AuditError(label, "PATH_CONTROL")
    return unicodedata.normalize("NFC", value)

def validate_root(raw: str, label: str) -> Path:
    try:
        root = Path(_check_text(raw, label)).resolve(strict=True)
    except FileNotFoundError as exc:
        raise AuditError(label, "ROOT_MISSING") from exc
    except (OSError, RuntimeError) as exc:
        raise AuditError(label, "ROOT_RESOLVE") from exc
    _check_text(os.fspath(root), label)
    if not root.is_dir():
        raise AuditError(label, "ROOT_NOT_DIRECTORY")
    home = Path.home().resolve(strict=True)
    if root.parent == root or _within(home, root):
        raise AuditError(label, "ROOT_FORBIDDEN")
    return root

def validate_output(raw: str, roots: tuple[Path, ...]) -> Path:
    label, checked = "<output>", _check_text(raw, "<output>")
    lexical = Path(os.path.abspath(checked))
    try:
        resolved = Path(checked).resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise AuditError(label, "OUTPUT_RESOLVE") from exc
    _check_text(os.fspath(resolved), label)
    if any(_within(path, root) for root in roots for path in (lexical, resolved)):
        raise AuditError(label, "OUTPUT_IN_ROOT")
    if os.path.lexists(lexical):
        raise AuditError(label, "OUTPUT_EXISTS")
    return lexical

def _normalized_path(raw: tuple[str, ...], seen: dict[str, tuple[str, ...]], label: str) -> str:
    normalized = "/".join(_check_text(part, label) for part in raw)
    prior = seen.setdefault(normalized, raw)
    if prior != raw:
        raise AuditError(label, "PATH_COLLISION")
    return normalized

def _directory_rows(directory: Path, label: str) -> list[tuple[str, str]]:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise AuditError(label, "NOFOLLOW_UNAVAILABLE")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(directory, flags)
        try:
            with os.scandir(descriptor) as iterator:
                rows = []
                for item in iterator:
                    kind = "symlink" if item.is_symlink() else "other"
                    if kind == "other" and item.is_dir(follow_symlinks=False):
                        kind = "directory"
                    elif kind == "other" and item.is_file(follow_symlinks=False):
                        kind = "file"
                    rows.append((item.name, kind))
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise AuditError(label, "ROOT_READ") from exc
    return rows

def walk_root(root: Path, label: str, side: str) -> tuple[list[Entry], list[Finding]]:
    entries, findings, seen = [], [], {}
    def visit(directory: Path, parent: tuple[str, ...]) -> None:
        for name, kind in _directory_rows(directory, label):
            raw, absolute = parent + (name,), directory / name
            relative = _normalized_path(raw, seen, label)
            if kind == "symlink":
                try:
                    destination = absolute.resolve(strict=True)
                except (OSError, RuntimeError) as exc:
                    raise AuditError(label, "SYMLINK_INVALID") from exc
                if not _within(destination, root):
                    raise AuditError(label, "SYMLINK_OUTSIDE")
                findings.append(Finding("PATH003", side, path=relative))
            else:
                entries.append(Entry(relative, absolute, kind))
                if kind == "directory":
                    visit(absolute, raw)
    visit(root, ())
    entries.sort(key=lambda item: item.path)
    findings.sort(key=lambda item: (item.code, item.side, item.path or ""))
    return entries, findings

def write_new(output: Path, payload: bytes) -> None:
    if os.path.lexists(output):
        raise AuditError("<output>", "OUTPUT_EXISTS")
    temporary = None
    try:
        for _ in range(16):
            candidate = output.with_name(f".{output.name}.tmp.{secrets.token_hex(8)}")
            try:
                descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                temporary = candidate
                break
            except FileExistsError:
                continue
        else:
            raise AuditError("<output>", "OUTPUT_TEMP")
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if not written:
                    raise OSError("zero-byte write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.link(temporary, output, follow_symlinks=False)
    except FileExistsError as exc:
        raise AuditError("<output>", "OUTPUT_EXISTS") from exc
    except OSError as exc:
        raise AuditError("<output>", "OUTPUT_WRITE") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise AuditError("<output>", "OUTPUT_CLEANUP") from exc

def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        source = validate_root(args.source, "<source>")
        target = validate_root(args.target, "<target>") if args.target else None
        roots = (source,) if target is None else (source, target)
        if args.output:
            validate_output(args.output, roots)
        walk_root(source, "<source>", "source")
        if target is not None:
            walk_root(target, "<target>", "target")
        raise AuditError("<source>", "AUDIT_INCOMPLETE")
    except AuditError as exc:
        print(f"{exc.label}: {exc.reason}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
