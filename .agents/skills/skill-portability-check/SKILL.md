---
name: skill-portability-check
description: "Audit explicit imported or copied Claude skill directories for Codex portability before a provider switch. Use for pre-switch reports or portability questions about existing skill files. Do not use for general Codex setup, creating skills, chats, settings, connections, or catalog design."
---

# Skill portability check

Audit existing skill files conservatively without changing or invoking them.
This workflow does not perform an import and does not assess the user's wider
agent configuration.

## Boundaries

- Require an explicit `SOURCE_ROOT`. Accept an explicit `TARGET_ROOT` only when
  the user wants a source-to-target comparison.
- Do not infer, discover, or scan any other directory. Do not accept the
  filesystem root, the user's home directory, or an ancestor of home.
- Treat the source as authoritative. A target is optional and never a reason to
  edit the source or target.
- No supported mode creates, modifies, or deletes any filesystem object.
  Completed reports are emitted to stdout only. `--output` is reserved and
  unsupported; this skill never passes it.
- Do not authenticate, connect services, inspect environment values, or invoke
  an imported skill, command, hook, plugin, or tool.
- Keep paths hidden unless the user explicitly requests the sensitive
  `--show-paths` report. Never expose source excerpts, matched values,
  environment values, absolute roots, or digests.

If `SOURCE_ROOT` is absent, ask for it and stop. If either supplied root is
unsafe or ambiguous, stop instead of broadening discovery.

## Audit workflow

1. Read [references/compatibility-rules.md](references/compatibility-rules.md)
   for scope, finding meanings, and import limitations.
2. Locate `scripts/audit.py` adjacent to this skill. Run it with Python 3 and
   only the roots the user supplied:

   ```text
   python3 <this-skill-directory>/scripts/audit.py --source "<SOURCE_ROOT>" --format markdown
   ```

   Add `--target "<TARGET_ROOT>"` only when the user supplied it. Use JSON only
   when requested. Do not add `--show-paths` unless the user explicitly accepts
   a sensitive path-bearing report.
3. Preserve the auditor's opaque skill/file IDs, statuses, finding codes, and
   deterministic order. Interpret exit `0` as completed without a blocked
   finding, exit `1` as completed with a blocked finding, and exit `2` as an
   operational failure. Review-only findings still exit `0`.
4. Return a content-redacted table or JSON report. Summarize each code and the
   smallest manual fix from the reference without reproducing file content or
   hidden paths.
5. Recommend one synthetic local known-output smoke test for the user's most
   important workflow. It must require no network, account, sign-in, connection,
   employer/customer data, hook, or side effect. Do not run it.
6. Stop before any change, authentication, connection, or live workflow.

## Status language

Use `blocked > review > portable` precedence. `portable` means only that the
auditor found no findings and completely covered every non-symlink regular file
under that skill with its eligible scanner. It does not guarantee that imported
runtime behavior, connections, or global setup work.

When no target was supplied, say that no source-to-target comparison occurred.
When coverage is incomplete, never label the skill portable.
