#!/usr/bin/env python3
"""Fail-closed safety foundation for the skill portability auditor."""
from __future__ import annotations
import argparse
import os
import re
import secrets
import stat
import sys
import unicodedata
from collections import namedtuple
from pathlib import Path

Finding = namedtuple("Finding", "code side file_id path", defaults=(None, None))
Entry = namedtuple("Entry", "path absolute kind")
SourceFile = namedtuple("SourceFile", "path file_id content text")
SkillResult = namedtuple("SkillResult", "key name description files findings status")
EXCLUDED_DIRS = frozenset({
    ".git", ".hg", ".svn", "__pycache__", ".cache", ".mypy_cache", ".pytest_cache",
    "node_modules", "vendor", "dist", "build", "target", "credentials", "secrets",
})
ELIGIBLE = frozenset({".md", ".txt", ".sh", ".py", ".js", ".ts", ".json", ".toml", ".yaml", ".yml"})
LIMIT = 1024 * 1024
BLOCKED = frozenset({"META001", "META002", "META003", "META004"})
FLAGS = re.IGNORECASE | re.MULTILINE
LEXICAL = (
    ("PATH001", re.compile(r'''(?:^|[\\/'"`])\.claude[\\/](?:skills|agents)(?:[\\/]|$)''', FLAGS)),
    ("PATH002", re.compile(r"/Users/[^/]+/|/home/[^/]+/|[A-Z]:\\Users\\[^\\]+\\", FLAGS)),
    ("RUNTIME001", re.compile(r"(?:^|[\s;&|()])claude(?=$|[\s;&|()])|\bmcp__claude[A-Za-z0-9_]*\b", FLAGS)),
    ("CONN001", re.compile(r"\bmcpServers\b|\bauthorization\b|\bheaders\b|\btransport\b|\$\{[A-Z_][A-Z0-9_]*\}", FLAGS)),
    ("SECRET001", re.compile(r"(?:^|[^A-Za-z0-9])(?:\.env|api[_-]?key|token|secret|credential|password)(?:$|[^A-Za-z0-9])", FLAGS)),
)
HOOK = re.compile(r"\b(?:PreToolUse|PostToolUse|PermissionRequest|UserPromptSubmit|SubagentStart|SubagentStop|PreCompact|SessionStart|SessionEnd)\b", re.MULTILINE)
ARGUMENT = re.compile(r"\$ARGUMENTS|\$\{ARGUMENTS\}|\$\(", FLAGS)
BACKTICK = re.compile(r"`[^`\r\n]+`")

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
                    if kind == "directory" and item.name in EXCLUDED_DIRS:
                        kind = "excluded"
                    elif kind == "file" and (item.name == ".env" or item.name.startswith(".env.")):
                        kind = "excluded"
                    elif kind == "file" and item.stat(follow_symlinks=False).st_mode & 0o111:
                        kind = "executable"
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

def _read_file(path: Path) -> tuple[bytes | None, str | None]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("not a regular file")
            chunks, remaining = [], LIMIT + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        finally:
            os.close(descriptor)
        content = b"".join(chunks)
        if len(content) > LIMIT:
            return None, None
        return content, content.decode("utf-8", "strict")
    except (OSError, UnicodeDecodeError):
        return None, None

def _scalar(lines: list[str], key: str) -> str | None:
    values = [line[len(key) + 1:].strip() for line in lines if line.startswith(key + ":")]
    if len(values) != 1 or not values[0]:
        return None
    value = values[0]
    if value[0] in "'\"":
        quote = value[0]
        if len(value) < 2 or value[-1] != quote or "\\" in value or quote in value[1:-1]:
            return None
        value = value[1:-1]
        return unicodedata.normalize("NFC", value) if value else None
    if any(char in value for char in "#{}[]") or re.fullmatch(r"[>|][+-]?\d?", value):
        return None
    return unicodedata.normalize("NFC", value)

def _metadata(text: str) -> tuple[str | None, str | None, tuple[str, ...]]:
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or lines[0] != "---":
        return None, None, ("META001",)
    try:
        end = lines.index("---", 1)
    except ValueError:
        return None, None, ("META001",)
    header = lines[1:end]
    name, description = _scalar(header, "name"), _scalar(header, "description")
    codes = (() if name is not None else ("META002",)) + (() if description is not None else ("META003",))
    return name, description, codes

def _shell_backtick(text: str, suffix: str) -> bool:
    if suffix == ".sh":
        return bool(BACKTICK.search(text))
    if suffix != ".md":
        return False
    fence = None
    for line in text.splitlines():
        if fence is not None:
            if re.fullmatch(re.escape(fence[0]) + "{" + str(len(fence)) + ",}", line):
                fence = None
            elif BACKTICK.search(line):
                return True
        else:
            opening = re.fullmatch(r"(`{3,}|~{3,})(sh|bash|zsh|shell)", line)
            if opening:
                fence = opening.group(1)
    return False

def _lexical_codes(text: str, suffix: str) -> tuple[str, ...]:
    codes = {code for code, pattern in LEXICAL if pattern.search(text)}
    if HOOK.search(text):
        codes.add("HOOK001")
    if ARGUMENT.search(text) or _shell_backtick(text, suffix):
        codes.add("ARGS001")
    return tuple(sorted(codes))

def _belongs(path: str, key: str, keys: tuple[str, ...]) -> bool:
    if key != "." and path != key and not path.startswith(key + "/"):
        return False
    children = (child for child in keys if child != key and child != "." and (key == "." or child.startswith(key + "/")))
    return not any(path == child or path.startswith(child + "/") for child in children)

def _status(findings: tuple[Finding, ...] | list[Finding]) -> str:
    if any(finding.code in BLOCKED for finding in findings):
        return "blocked"
    return "review" if findings else "portable"

def _analyze_skill(key: str, keys: tuple[str, ...], entries: list[Entry], path_findings: list[Finding]) -> SkillResult:
    owned = [entry for entry in entries if _belongs(entry.path, key, keys)]
    eligible = sorted((entry for entry in owned if entry.kind == "file" and Path(entry.path).suffix in ELIGIBLE), key=lambda entry: entry.path)
    gaps = any(entry.kind in {"excluded", "executable"} or (entry.kind == "file" and Path(entry.path).suffix not in ELIGIBLE) for entry in owned)
    findings = [finding for finding in path_findings if finding.path and _belongs(finding.path, key, keys)]
    files, name, description = [], None, None
    for number, entry in enumerate(eligible, 1):
        file_id = f"F{number:03d}"
        content, text = _read_file(entry.absolute)
        files.append(SourceFile(entry.path, file_id, content, text))
        if text is None:
            findings.append(Finding("FILE001", "source", file_id, entry.path))
            continue
        for code in _lexical_codes(text, Path(entry.path).suffix):
            findings.append(Finding(code, "source", file_id, entry.path))
        if entry.path.rsplit("/", 1)[-1] == "SKILL.md":
            name, description, meta = _metadata(text)
            findings.extend(Finding(code, "source", file_id, entry.path) for code in meta)
    if gaps:
        findings.append(Finding("COVERAGE001", "source"))
    findings.sort(key=lambda finding: (finding.code, finding.side, finding.path or ""))
    frozen = tuple(findings)
    return SkillResult(key, name, description, tuple(files), frozen, _status(frozen))

def analyze_source(root: Path) -> tuple[SkillResult, ...]:
    entries, path_findings = walk_root(root, "<source>", "source")
    keys = tuple(sorted("." if "/" not in entry.path else entry.path.rsplit("/", 1)[0]
                        for entry in entries if entry.kind in {"file", "executable"} and entry.path.rsplit("/", 1)[-1] == "SKILL.md"))
    results = [_analyze_skill(key, keys, entries, path_findings) for key in keys]
    counts = {result.name: sum(item.name == result.name for item in results) for result in results if result.name is not None}
    for index, result in enumerate(results):
        if result.name is not None and counts[result.name] > 1:
            findings = tuple(sorted(result.findings + (Finding("META004", "source"),), key=lambda item: (item.code, item.side, item.path or "")))
            results[index] = result._replace(findings=findings, status="blocked")
    return tuple(results)

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
        analyze_source(source)
        if target is not None:
            walk_root(target, "<target>", "target")
        raise AuditError("<source>", "AUDIT_INCOMPLETE")
    except AuditError as exc:
        print(f"{exc.label}: {exc.reason}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
