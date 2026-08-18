# Compatibility rules

## What this audit proves

The auditor reads eligible text files under explicit skill roots and reports
common provider-specific assumptions. It does not inspect or validate chats,
settings, plugins, global hooks, connection configuration or sign-in state,
project memories, instruction files elsewhere, or subagent installation state.

`portable` means only that the auditor found no findings and completely covered
every non-symlink regular file under that skill with its eligible scanner. It
does not guarantee that imported runtime behavior, connections, or global setup
work. Any coverage gap keeps the result at `review`.

The workflow never copies, edits, moves, or deletes audited files. It never
authenticates, connects, or invokes imported tools. Without `--output`, the
auditor writes its one report to stdout and does not write a file. This skill
always uses that no-output mode.

## Finding glossary

Status precedence is `blocked > review > portable`. Use only the finding code,
side, and opaque IDs in a default report; do not include excerpts or hidden
paths.

| Code | Status | Meaning | Smallest manual fix |
|---|---|---|---|
| `META001` | blocked | `SKILL.md` lacks a valid frontmatter opener or terminator. | Add a valid byte-zero opener and closing delimiter. |
| `META002` | blocked | `name` is missing or unsupported. | Add one valid, nonempty string name. |
| `META003` | blocked | `description` is missing or unsupported. | Add one valid, nonempty string description. |
| `META004` | blocked | A name is duplicated, so matching is ambiguous. | Give each skill a unique stable name. |
| `PATH001` | review | A provider-specific skill or agent path appears. | Replace it with an explicit portable input. |
| `PATH002` | review | A user-specific absolute path appears. | Replace it with a supplied relative or explicit path. |
| `PATH003` | review | A symbolic link was skipped; its target and containment are unknown. | Audit an authorized real directory separately; do not infer where the link points. |
| `RUNTIME001` | review | A provider-specific runtime binding appears. | Replace or document the Codex equivalent. |
| `HOOK001` | review | A provider hook lifecycle token appears. | Review the hook against Codex behavior. |
| `ARGS001` | review | Argument or command interpolation appears. | Replace it with explicit validated input. |
| `CONN001` | review | Connection or environment-dependent setup appears. | Reconfigure it manually; do not copy values. |
| `SECRET001` | review | Sensitive-material vocabulary appears. | Remove embedded values and use approved setup. |
| `FILE001` | review | A file could not be safely read or decoded. | Review or repair it manually, then reaudit the explicit root. |
| `COVERAGE001` | review | An excluded subtree/file or unsupported regular file exists. | Review that gap separately; do not infer portability. |
| `COMPARE001` | review | No unique target match exists. | Install or identify the intended target skill manually. |
| `COMPARE002` | review | Matched source and target file digests differ. | Review the target difference; do not overwrite automatically. |

Target-side read failures are pathless. When no target is supplied, no
comparison code appears because no comparison was attempted.

## Official import limits

Current OpenAI documentation distinguishes two supported import surfaces:

- The ChatGPT desktop app can import from Claude Code, Claude Cowork, or Cursor.
- Codex CLI can import from Claude Code or Cursor; it does not list Cowork as a
  CLI source.
- Codex CLI imports at most 50 chats from the last 30 days. `/import` is not
  available during a running task, in a remote session, or while connected to a
  local app-server daemon.
- The supported flow imports only selected supported items and leaves the
  source agent setup unchanged. Follow the status card for plugins or
  connections that still need setup. Before relying on imported work, separately
  review permissions, sign-in and connection setup, hook differences, plugin
  follow-up, arguments, and placeholders.
- Automatic updates are a ChatGPT desktop setting that keeps imported work in
  sync with the original agent. Do not generalize that behavior to CLI imports
  or to this auditor.

The official docs do not define target collision or one-click undo semantics. A
personal backup is a precaution, not a proven rollback. If a separate authorized
destination is unavailable and target mutation is unacceptable, stop.

Sources:

- <https://learn.chatgpt.com/docs/import>
- <https://learn.chatgpt.com/docs/build-skills>

Codex discovers repo skills under `.agents/skills` and user skills under
`$HOME/.agents/skills`. A valid `SKILL.md` needs string `name` and `description`
metadata. Codex detects changes automatically; restart only if an update does
not appear. If another same-name skill exists, do not copy or overwrite it; run
the auditor directly from this clone.
