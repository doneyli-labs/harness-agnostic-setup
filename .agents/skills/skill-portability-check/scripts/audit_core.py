"""Pure, redacted content analysis for the skill portability auditor."""
import hashlib
import json
import re
import unicodedata

MAX_BYTES = 1 << 20
_FLAGS = re.IGNORECASE | re.MULTILINE
_PATTERNS = (
    ("PATH001", re.compile(r"(?:^|[\\/'\"`])\.claude[\\/](?:skills|agents)(?:[\\/]|$)", _FLAGS)),
    ("PATH002", re.compile(r"/Users/[^/]+/|/home/[^/]+/|[A-Z]:\\Users\\[^\\]+\\", _FLAGS)),
    ("RUNTIME001", re.compile(r"(?:^|[\s;&|()])claude(?=$|[\s;&|()])|\bmcp__claude[A-Za-z0-9_]*\b", _FLAGS)),
    ("ARGS001", re.compile(r"\$ARGUMENTS|\$\{ARGUMENTS\}|\$\(", _FLAGS)),
    ("CONN001", re.compile(r"\bmcpServers\b|\bauthorization\b|\bheaders\b|\btransport\b|\$\{[A-Z_][A-Z0-9_]*\}", _FLAGS)),
    ("SECRET001", re.compile(r"(?:^|[^A-Za-z0-9])(?:\.env|api[_-]?key|token|secret|credential|password)(?:$|[^A-Za-z0-9])", _FLAGS)),
)
_HOOK = re.compile(r"\b(?:PreToolUse|PostToolUse|PermissionRequest|UserPromptSubmit|SubagentStart|SubagentStop|PreCompact|SessionStart|SessionEnd)\b")
_BACKTICK = re.compile(r"`[^`\r\n]+`")
_FENCE = re.compile(r"^( {0,3})(`{3,}|~{3,})([^\r\n]*)$")
_SHELL = frozenset(("sh", "bash", "zsh", "shell"))


def _decode(data):
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_BYTES:
        return None
    try:
        return bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        return None


def _scalar(raw):
    value = raw.strip(" \t")
    if not value:
        return None
    quote = value[0]
    if quote in "'\"":
        if len(value) < 3 or value[-1] != quote:
            return None
        inner = value[1:-1]
        if "\\" in inner or quote in inner:
            return None
        return unicodedata.normalize("NFC", inner)
    if any(char in value for char in "#{}[]"):
        return None
    if value[0] in "|>":
        return None
    return unicodedata.normalize("NFC", value)


def _metadata(text):
    lines = text.replace("\r\n", "\n").split("\n")
    framed = bool(lines) and lines[0] == "---"
    end = next((index for index, line in enumerate(lines[1:], 1)
                if line == "---"), None) if framed else None
    codes = set()
    if end is None:
        codes.add("META001")
        block = ()
    else:
        block = lines[1:end]
    values = []
    for key, code in (("name", "META002"), ("description", "META003")):
        matches = [line[len(key) + 1:] for line in block
                   if line.startswith(key + ":")]
        value = _scalar(matches[0]) if len(matches) == 1 else None
        if value is None:
            codes.add(code)
        values.append(value)
    return (*values, codes)


def _shell_backtick(text, relative_path):
    if relative_path.endswith(".sh") and _BACKTICK.search(text):
        return True
    active = None
    for line in re.split(r"\r\n?|\n", text):
        if active is not None:
            char, length, shell = active
            close = rf" {{0,3}}{re.escape(char)}{{{length},}}[ \t]*"
            if re.fullmatch(close, line):
                active = None
            elif shell and _BACKTICK.search(line):
                return True
            continue
        match = _FENCE.fullmatch(line)
        if match:
            fence, info = match.group(2), match.group(3).strip(" \t")
            if fence[0] == "`" and "`" in info:
                continue
            active = (fence[0], len(fence), info in _SHELL)
    return False


def _lexical(text, relative_path):
    codes = {code for code, pattern in _PATTERNS if pattern.search(text)}
    if _HOOK.search(text):
        codes.add("HOOK001")
    if _shell_backtick(text, relative_path):
        codes.add("ARGS001")
    return codes


def analyze_file(relative_path, data):
    """Return a deterministic record containing no content or metadata values."""
    text = _decode(data)
    if text is None:
        return {"metadata": None, "findings": (("FILE001", "review"),)}
    codes = _lexical(text, relative_path)
    metadata = None
    if relative_path.rsplit("/", 1)[-1] == "SKILL.md":
        name, description, meta_codes = _metadata(text)
        codes.update(meta_codes)
        metadata = (name is not None, description is not None)
    findings = tuple((code, "blocked" if code.startswith("META") else "review")
                     for code in sorted(codes))
    return {"metadata": metadata, "findings": findings}


def metadata_equal(first, second, key="name"):
    """Compare one valid normalized scalar without returning either value."""
    if key not in ("name", "description"):
        return False
    decoded = (_decode(first), _decode(second))
    if None in decoded:
        return False
    left, right = (_metadata(text) for text in decoded)
    index = 0 if key == "name" else 1
    return left[index] is not None and left[index] == right[index]


def _has(record, code):
    return any(finding[0] == code for finding in record["findings"])


def _framed_digest(record):
    digest = hashlib.sha256()
    files = tuple(sorted(record["files"]))
    digest.update(len(files).to_bytes(8, "big"))
    for path, data, _ in files:
        path_bytes, content = path.encode("utf-8"), bytes(data)
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.digest()


def _target_match(source, targets):
    if source["name_valid"]:
        if _has(source, "META004"):
            return None, "source"
        matches = [target for target in targets if target["name_valid"]
                   and metadata_equal(source["skill_bytes"], target["skill_bytes"])]
        if len(matches) > 1:
            return None, "target"
    else:
        matches = [target for target in targets if not target["name_valid"]
                   and target["key"] == source["key"]]
    return (matches[0], None) if len(matches) == 1 else (None, None)


def _skill_result(source, targets, supplied, show_paths, skill_id):
    paths = sorted(path for path, _, _ in source["files"])
    file_ids = {path: f"F{index:03d}" for index, path in enumerate(paths, 1)}
    findings = set()
    for code, path, severity in source["findings"]:
        file_id = None if path is None or code == "PATH003" else file_ids.get(path)
        findings.add((code, "source", file_id, path if file_id else None, severity))
    match, duplicate = _target_match(source, targets) if supplied else (None, None)
    if supplied and duplicate == "target":
        findings.add(("META004", "target", None, None, "blocked"))
    elif supplied and duplicate != "source":
        if match is None:
            findings.add(("COMPARE001", "comparison", None, None, "review"))
        else:
            for code, _, severity in match["findings"]:
                findings.add((code, "target", None, None, severity))
            if not _has(source, "FILE001") and not _has(match, "FILE001") \
                    and _framed_digest(source) != _framed_digest(match):
                findings.add(("COMPARE002", "comparison", None, None, "review"))
    ordered = sorted(findings, key=lambda item: (item[0], item[1], item[3] or ""))
    severities = {item[4] for item in ordered}
    status = "blocked" if "blocked" in severities else "review" if ordered else "portable"
    public = [{"code": code, "side": side, "file_id": file_id,
               "path": path if show_paths and side == "source" else None}
              for code, side, file_id, path, _ in ordered]
    return {"id": skill_id, "key": source["key"] if show_paths else None,
            "status": status, "findings": public}


def build_report(source, target=None, show_paths=False):
    """Build the redacted deterministic report schema from sensitive records."""
    targets, supplied = (() if target is None else tuple(target)), target is not None
    skills = [_skill_result(record, targets, supplied, bool(show_paths),
                            f"S{index:03d}")
              for index, record in enumerate(sorted(source, key=lambda item: item["key"]), 1)]
    summary = {status: sum(skill["status"] == status for skill in skills)
               for status in ("blocked", "portable", "review")}
    return {"schema_version": 1, "target_supplied": supplied,
            "summary": summary, "show_paths": bool(show_paths), "skills": skills}


def _markdown_escape(value):
    for character, entity in (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"),
                              ("|", "&#124;"), ("`", "&#96;")):
        value = value.replace(character, entity)
    return value


def _markdown(report):
    lines = ["# Skill Portability Audit",
             f"Paths: {'sensitive' if report['show_paths'] else 'hidden'}",
             f"Target supplied: {'yes' if report['target_supplied'] else 'no'}", "",
             "| Skill | Status | Findings |", "|---|---|---|"]
    for skill in report["skills"]:
        label = skill["id"]
        if skill["key"] is not None:
            label += f" (`{_markdown_escape(skill['key'])}`)"
        rendered = []
        for finding in skill["findings"]:
            item = f"{finding['code']}@{finding['side']}:{finding['file_id'] or '-'}"
            if finding["path"] is not None:
                item += f" (`{_markdown_escape(finding['path'])}`)"
            rendered.append(item)
        lines.append(f"| {label} | {skill['status']} | {', '.join(rendered) or 'none'} |")
    summary = report["summary"]
    lines.extend(("", f"Summary: portable={summary['portable']} review={summary['review']} blocked={summary['blocked']}"))
    return "\n".join(lines) + "\n"


def serialize_report(report, output_format="markdown"):
    if output_format == "json":
        return json.dumps(report, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":")) + "\n"
    if output_format != "markdown":
        raise ValueError("unsupported report format")
    return _markdown(report)


def report_exit(report):
    return 1 if report["summary"]["blocked"] else 0
