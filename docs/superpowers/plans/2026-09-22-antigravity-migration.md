# Antigravity CLI migration

**Goal:** Run the Gemini provider through `agy`, not the retired `gemini` CLI.

**Approved input:** Owner request to replace Gemini CLI with Antigravity CLI.
Preserve `.agent/` as canonical, provider-family independence, bounded memory,
manifest approval and the OS sandbox. Do not install tools, migrate personal
profiles, copy credentials, send project data or merge without authorization.

## Contract and sequence

1. Provider (`providers/gemini.py`, config/default answers, provider fixtures and
   tests): retain `gemini` as the model-family identity; resolve `agy`, require
   a Gemini model, use print/JSON/schema/plan flags, reject unsuccessful or
   malformed envelopes. RED: old argv and parser fail AGY-contract tests.
2. Isolation (`providers/base.py`, sandbox tests): canonicalize temporary paths
   on macOS; generate only minimal API-key-mode settings in disposable HOME.
   Do not load the user's profile, plugins or keychain for automatic reviews.
   RED: scratch writes fail through macOS's `/var` symlink; settings are absent.
3. Discovery/hooks (`adapters.py`, templates, CLI, adapter/context tests): share
   `.agents/skills` between Codex and AGY; replace legacy settings with AGY hooks.
   PreInvocation injects bounded context only on invocation 0; Stop never forces
   another model call or saves transcripts. Prune only unchanged manifest-owned
   legacy outputs; preserve local edits/unowned files. RED: old tree/hook shape.
4. Update current README, architecture source, context guide and security delta;
   add a decision and focused migration guide with upstream references. Preserve
   historical Gemini CLI evidence as historical, not AGY acceptance evidence.
5. Build/check generated adapters/docs. Run focused tests, full tests with Node
   24, quick gate, credential-free `agy --version/--help` probe and independent
   review. Report unconfigured gates and unavailable live authentication.

## Rollback and completion

Revert this migration commit to restore generated Gemini CLI outputs and its
adapter; no user-global configuration changes are made. Commit/push only the
verified task scope to a feature branch. Since GitHub merged the previous
context-efficiency branch during this task, use `feat/antigravity-cli` based on
updated main (same source tree as the implementation baseline). A mock acceptance pass is
not a live AGY review, cross-provider clearance, merge or release approval.
