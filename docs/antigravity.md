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

## Automated review authentication

Automated review runs AGY with a disposable HOME. It does not mount the host
HOME or copy host token files. The adapter does not write synthetic
`modelProvider` settings to select an authentication backend. AGY may support
its own cached or keyring-based sign-in; whether that authentication is
available to an isolated invocation depends on the installed AGY version and
platform. On macOS with AGY 1.2.17, a live invocation with the existing sandbox
and disposable HOME requested OAuth and timed out after 60 seconds; it did not
reuse the normal host session. A successful interactive login alone
does not establish automated-review readiness. The sandboxed route therefore
remains pending until native authentication works within that boundary.

On 2026-10-06, the user explicitly authorized one native-host invocation to
check the logged-in AGY CLI. That run returned `SUCCESS` with a schema-valid
`pass` and no findings, and an independent check confirmed the approved package
was unchanged. The result was a one-time host exception: it does not establish
that the normal sandboxed route can reuse host authentication or grant default
host access.

The provider environment allowlist can pass `GEMINI_API_KEY` when a user has
configured it in the process environment. That is separate from AGY's native
cached/keyring authentication. `GOOGLE_API_KEY`, Vertex settings and custom
Gemini endpoint variables are not forwarded. Never commit an API key or pass it
in command arguments. If the selected authentication route or model access is
unavailable, the review remains pending. Fixtures and successful `--help`
probes do not establish a live authenticated review.

The adapter uses `--print`, `--output-format json`, `--json-schema`, and
`--mode plan`, with a fresh disposable session. Plan mode is advisory, not a
security boundary. The existing OS sandbox denies project/package writes and
non-allowlisted host file reads. AGY may write session data only inside its
disposable HOME. No `--dangerously-skip-permissions` or conversation resume is
used. Only a `SUCCESS` envelope with valid `structured_output` can complete a
review. AGY may prepend explanatory prose before its terminal JSON objects; the
adapter accepts that prefix only when every subsequent terminal object agrees
with `structured_output`. Conflicting verdicts/findings, malformed embedded
objects, trailing prose, errors and non-`SUCCESS` envelopes fail closed.

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

Current local executable: AGY `1.2.17`; `--help` and a normal-host `agy models`
probe succeeded, with `gemini-3.1-pro-high` listed. The authorized native review
attempt inside the isolated provider environment requested OAuth and timed out.
Under a separate explicit user exception, a native-host invocation returned
schema-valid `pass` with zero findings and the approved payload stayed
unchanged. The automatic audit remains pending because that first invocation's
prose-prefixed response did not match the then-current parser. The parser now
checks every terminal JSON object against the schema result. Host success does
not establish sandboxed authentication readiness. The older template-acceptance
JSON describes Gemini CLI at the time; it is not AGY evidence.

- [CLI migration: context and skills](https://antigravity.google/docs/cli/gcli-migration/)
- [Headless output and schema contract](https://antigravity.google/docs/cli/headless/)
- [Lifecycle hooks and their JSON contract](https://antigravity.google/docs/hooks/)
- [Model and execution modes](https://antigravity.google/docs/cli/modes/)

Upstream CLI contracts can change; rerun capability and real authenticated
smoke checks on your installed version before relying on automated clearance.
