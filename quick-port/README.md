# Quick port: Claude skills to Codex

Bring supported Claude setup and recent work into Codex, then check eligible
imported skill text files for common Claude-specific assumptions before relying
on one important workflow.

## 1. Check authorization and destination risk

Import only material you are authorized to place in the destination account or
workspace. Do not import employer, customer, regulated, confidential, or
credential-bearing material without that authorization.

OpenAI documents that import leaves the existing agent setup unchanged. That is
a source-preserving import statement, not a guarantee about collisions or
changes in the destination. The official documentation does not define
target-collision behavior or one-click undo. A personal backup is a precaution,
not proven rollback. If no separate authorized destination is available and
destination mutation is unacceptable, stop here.

## 2. Choose the supported Claude path

- **ChatGPT desktop app:** import from Claude Code or Claude Cowork.
- **Codex CLI:** import from Claude Code. Start a local CLI session before a
  task begins.

This guide is based on OpenAI's current
[import documentation](https://learn.chatgpt.com/docs/import). Review it before
you import because supported items and interface labels can change.

## 3. Run the official import

### Desktop: Claude Code or Claude Cowork

1. Open **Settings > Import** in the ChatGPT desktop app. If **Import** is not a
   settings section, open **General > Import other agent setup**.
2. Select **Import**, choose Claude Code or Claude Cowork, then select
   **Continue**.
3. On **Select items to import**, handpick the supported setup, projects, and
   recent chats you are authorized to import, then continue.
4. When import finishes, open an imported project or chat.

The selectable supported items can include instructions, settings, skills,
plugins, existing project folders, Claude Code project memories, recent chats,
MCP server configuration, hooks, slash commands, and subagents. Availability
depends on what the import flow detects.

In **Settings > Import**, you can review import history. Desktop automatic
updates keep imported work synchronized with the original agent; do not assume
that this validates runtime compatibility.

### Codex CLI: Claude Code

1. Start a local Codex CLI session and enter `/import`.
2. Choose **Claude Code**.
3. Select the supported setup, project files, and recent chats to import.
4. Review the imported configuration before continuing.

The CLI imports at most 50 chats from the last 30 days. `/import` is unavailable
during a running task, in a remote session, or while connected to a local
app-server daemon.

## 4. Finish setup and review dependencies

The desktop app shows a status card when an imported plugin or connection needs
more setup. Select **Finish** and follow the prompts for each flagged item.

Before relying on imported work, review:

- tool restrictions and permissions;
- authentication, headers, environment variables, transports, and connections;
- hook behavior;
- plugins, marketplaces, and manual follow-up;
- command arguments, shell interpolation, and file-path placeholders.

The import status and history remain authoritative for chats, settings, plugins,
connections, commands, project memories, and subagents. The audit in the next
step covers eligible text files inside explicit skill roots only. It does not
validate instruction files elsewhere, global hooks, MCP configuration or
authentication, connection setup, or subagent installation state.

## 5. Audit explicit skill roots

Start Codex in this clone to make the repository skill discoverable. Provide
only explicit skill directories below the filesystem root and home directory;
the auditor will not discover other roots. `TARGET_ROOT` is optional.

```bash
python3 .agents/skills/skill-portability-check/scripts/audit.py \
  --source '<SOURCE_ROOT>' --format markdown

python3 .agents/skills/skill-portability-check/scripts/audit.py \
  --source '<SOURCE_ROOT>' --target '<TARGET_ROOT>' --format markdown
```

For use in another location, supported skill destinations are
`<repo>/.agents/skills` and `$HOME/.agents/skills`. If a same-name
`skill-portability-check` skill already exists, do not copy or overwrite it.
Run the auditor directly from this clone instead. Codex normally detects skill
changes automatically; if a newly copied skill does not appear, restart Codex
as the current [skills documentation](https://learn.chatgpt.com/docs/build-skills)
permits.

By default the report hides paths and uses opaque skill/file IDs. The optional
`--show-paths` report is sensitive. The status `portable` means only that the
auditor found no findings and completely covered every non-symlink regular file
under that skill with its eligible scanner. It does not guarantee runtime
behavior, connections, chats, global setup, or interoperability.

Paste this prompt into Codex:

```text
Audit imported skill files under these explicit directories only:
SOURCE_ROOT: <path to one skill root below filesystem root and home>
TARGET_ROOT: <optional imported skill root>

Do not discover other directories. Do not modify, move, delete, authenticate,
connect, or invoke an imported tool.

Inventory source skills, run skill-portability-check, and return a
content-redacted table with opaque skill/file IDs, portable/review/blocked
status, finding codes, and the smallest manual fix. Do not expose paths unless
I explicitly request the sensitive --show-paths report.
Recommend one synthetic local no-network smoke test. Stop before any change,
connection, authentication, or live workflow.
```

## 6. Smoke-test one important workflow

Choose one important imported skill and design a synthetic input with a known,
non-sensitive expected output. Keep the test local, no-network, no-auth,
connector-free, hook-free, and side-effect-free. Do not use employer or customer
data, credentials, live systems, or imported tools that can mutate state.

For example, for a workflow intended to deduplicate and sort lines, use:

```text
Input:
beta
alpha
beta

Expected:
alpha
beta
```

Adapt the fixture to the chosen workflow, but write down one exact expected
output before running it. Stop if the workflow cannot be exercised without
authentication, connections, network access, hooks, or side effects.

Record one result:

- `pass` — the observed output exactly matches the known output;
- `needs review` — the test ran safely but differed or remained ambiguous;
- `blocked` — the safe constraints prevented the test from running.

An audit result is not a substitute for this test, and neither validates chats,
settings, plugins, global hooks, MCP authentication, connections, memories, or
subagent installation state.

## 7. Harden portability later

The supported import is the move-now step. For durable portability, keep
behavior in the repository's canonical [`roles.yaml`](../roles.yaml),
instruction bodies in
[`roles/`](../roles/), harness-specific values in [`bindings/`](../bindings/),
and constraints in the [`schema`](../schemas/role-catalog.schema.json). Render
native files from those sources and detect drift instead of maintaining copies
by hand.
