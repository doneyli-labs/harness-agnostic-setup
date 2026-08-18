# Harness-Agnostic Agent Setup

**Claude unavailable and need to continue now?** Follow the
[quick-port guide](quick-port/) to import supported setup and recent work,
finish required setup, audit eligible skill text, and test one workflow safely.

**Want one durable source of truth?** Use the catalog, schema, and per-harness
bindings in this repository to define roles once and render each native shape.

A copy-pasteable template for defining an AI coding agent **once** and running it
in more than one harness (Claude Code, Codex, and anything you add next).

This is the build-along companion to the *Signal over Noise* issue
**"I Compile My AI Agents. I Don't Copy Them."** It ships the shape, not the
private machinery: the canonical catalog, the per-harness bindings, and the
schema. The compiler/renderer, installer, and drift doctor described in the
issue stay in a private repo. You have everything here to build your own.

## The idea in one line

Keep **one** canonical definition of each role. Generate a native file per
harness from it. Never hand-edit the generated files.

```
roles.yaml + roles/<role>.md            (canonical: behavior + instructions, harness-neutral)
        + bindings/claude.yaml / bindings/codex.yaml   (model, effort, permissions per harness)
        |
        v
   your renderer  ->  ~/.claude/agents/<role>.md   (YAML frontmatter)
                  ->  ~/.codex/agents/<role>.toml   (TOML)
```

## What's in here

The template is populated with two roles: `researcher` and
`standard_implementer`.

```
roles.yaml                     canonical role catalog (source of truth)
roles/                         canonical instruction bodies, one per role
bindings/claude.yaml           model + effort + permission for Claude Code
bindings/codex.yaml            model + effort + sandbox for Codex
schemas/role-catalog.schema.json   JSON Schema for roles.yaml
examples/rendered/             what the researcher role looks like after rendering, in each harness
```

## The mapping your renderer implements

One canonical role, two native shapes. The two harnesses express the same
guarantee differently, which is exactly why you render instead of copy.

| Canonical field | Claude `.md` frontmatter | Codex `.toml` |
|---|---|---|
| description | `description` | `description` |
| `mode: read` | `tools:` allow-list (mutation tools excluded) | `sandbox_mode = "read-only"` |
| `mode: write` | no `tools:` key (inherit all) | `sandbox_mode = "workspace-write"` |
| model | `model` | `model` |
| effort | `effort` | `model_reasoning_effort` |
| permission | `permissionMode` (camelCase) | (n/a, `sandbox_mode` carries it) |
| role name | `name` (`_` becomes `-`) | `name` |
| instructions body | markdown body | `developer_instructions = """..."""` |

## Build your own renderer (about 60 lines)

You do not need anything fancy. In pseudocode:

```
catalog  = load(roles.yaml)
binding  = load(bindings/<harness>.yaml)
for role, spec in catalog.roles:
    body    = read(spec.instructions)
    b       = binding.roles[role]
    write native file from (spec, b, body) using the mapping table above
    stamp a "GENERATED, do not hand-edit" header with a hash of the source
```

Two things worth adding once it works:

> A **drift check** that re-renders every role and diffs it against what is
> actually installed, so a hand-edit gets caught.

> A **transactional install** (back up the current files, write, verify, and
> roll back on any failure) so a half-applied update can never leave your two
> harnesses disagreeing.

## Model names

The values in `bindings/` are illustrative and current as of mid-2026
(`claude-sonnet-5`, `gpt-5.6-terra`, `gpt-5.6-luna`). Harness model names move
fast. Swap in whatever your harness supports.

For the implementation notes behind this kit, subscribe to
[Signal over Noise](https://doneyli.substack.com/subscribe).

## License

MIT. Fork it, change it, ship it.
