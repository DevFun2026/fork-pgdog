# Gemini through Antigravity CLI (`agy`)

The executable is now `agy`. The provider-family ID stays `gemini` in review
commands, configuration and memory records: a different executable is not an
independent model provider. Do not label a Claude model selected inside AGY as
a Gemini author/reviewer. Existing review/memory records need no migration.

## Setup

Install/sign in to AGY yourself using the [official installation guide](https://antigravity.google/docs/cli/install/).
This template does not install tools, import your old profile or change global
settings. Interactive `agy` in the project reads `GEMINI.md`, `AGENTS.md`, shared
`.agents/skills`, and `.agents/hooks.json`.

```toml
[review.provider_commands]
claude = ["claude"]
codex = ["codex"]
gemini = ["agy"]
```

The review adapter adds `--model gemini-3.1-pro-high` when no model is specified.
This is a documented AGY model slug, not a claim of availability for every
account/API-key backend. Use `agy models` in your own authenticated session and
set a Gemini slug supported by your authentication route explicitly if needed:
`gemini = ["agy", "--model", "gemini-YOUR-SUPPORTED-MODEL"]`. Non-Gemini,
duplicate or missing model values are rejected. CLI capability probes do not
test model entitlement, quota or authentication.

```sh
./scripts/agent doctor --providers --json
./scripts/agent review --author-provider codex --reviewer-provider gemini
```

Review first produces a bounded package; approve its exact manifest separately
before execution. No fallback to the legacy `gemini` executable occurs.

## Automated review is isolated from interactive login

AGY's usual interactive login uses the host keyring. Automated review does not
mount the host HOME, copy token files, import plugins, or authorize that keyring.
It creates minimal `{"modelProvider":"gemini"}` settings under disposable HOME
and forwards only `GEMINI_API_KEY` for this provider. Supplying a key alone
without this setting is insufficient for AGY API-key mode. Set the key in your
process environment; never commit it or pass it in command arguments.

`GOOGLE_API_KEY`, Vertex settings and custom Gemini endpoint variables are not
forwarded. If API-key mode/model access is unavailable, the review remains
pending. A paid subscription login in interactive AGY is not proof of isolated
automated-review readiness. No live authenticated review is claimed by fixtures
or a successful `--help` probe.

The adapter uses `--print`, `--output-format json`, `--json-schema`, and
`--mode plan`, with a fresh disposable session. Plan mode is advisory, not a
security boundary. The existing OS sandbox denies project/package writes and
non-allowlisted host file reads. AGY may write session data only inside its
disposable HOME. No `--dangerously-skip-permissions` or conversation resume is
used. Only a `SUCCESS` envelope with valid `structured_output` can complete a
review; errors, partial/malformed output and conflicting response fields fail
closed.

## Native files and memory

Run `./scripts/agent adapters build`. It generates two skill trees, not three:
`.agents/skills` for AGY/Codex and `.claude/skills` for Claude. The old generated
`.gemini/skills` and `.gemini/settings.json` are retired using their ownership
manifest. Local edits block removal before writes; unowned legacy files are
preserved. Review/move any personal legacy skills manually; do not overwrite
the generated shared tree. Reverting the migration commit restores tracked
legacy outputs; global profiles are never changed.

AGY uses PreInvocation/Stop hooks, not Gemini CLI's SessionStart/AfterAgent.
PreInvocation accepts only integer `invocationNum: 0` and injects bounded memory
as project data, not a system instruction. Missing/invalid metadata yields no
injection. Stop prints a diagnostic checkpoint reminder and allows stopping;
it never forces another paid turn, captures transcripts or promotes records.
If a resumed conversation does not emit invocation 0, retrieve context manually
with `./scripts/agent memory bootstrap --query "focused task" --profile light`.

## Contract sources and evidence

Verified local executable: AGY `1.2.7`, successful no-network/no-credential
`--version` and `--help`. Help is emitted on stderr. A model-list probe could
not run without the local network listener, so no live model availability or
authenticated result is inferred from it. The older template-acceptance JSON
describes Gemini CLI at the time; it is not AGY evidence.

- [CLI migration: context and skills](https://antigravity.google/docs/cli/gcli-migration/)
- [Headless output and schema contract](https://antigravity.google/docs/cli/headless/)
- [Lifecycle hooks and their JSON contract](https://antigravity.google/docs/hooks/)
- [Model and execution modes](https://antigravity.google/docs/cli/modes/)

Upstream CLI contracts can change; rerun capability and real authenticated
smoke checks on your installed version before relying on automated clearance.
