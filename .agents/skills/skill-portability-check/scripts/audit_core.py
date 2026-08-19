"""Pure, redacted content analysis for the skill portability auditor."""
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
