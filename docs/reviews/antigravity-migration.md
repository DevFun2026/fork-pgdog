# Antigravity migration verification — 2026-09-22

Scope: replacement of Gemini CLI execution with AGY, native discovery/hooks,
isolated settings and safe retirement of legacy generated files. Implementation
started at `be67e85ee2e5c6464e41786dd7ad796c82f5cf1c`. GitHub merged that
change as `2a602193ba9531b8eafee8d9badd220fc54776bf` (identical source tree), so
the migration branch `feat/antigravity-cli` is anchored to that updated main.

## Evidence

- RED: the initial nine focused tests failed against the old command, parser,
  hooks, native layout and temporary-path behavior. The new contract passed
  after implementation.
- Full suite after final fixes: **172 tests passed**, including six mock
  cross-provider directions and clean-export smoke.
- Command: `PATH="/Users/simon/.nvm/versions/node/v24.11.0/bin:$PATH" PYTHONPATH=.agent/runtime python3 -m unittest discover -s .agent/tests -q`.
- Focused migration suite: 13 tests passed. Coverage includes strict success
  envelopes, malformed schema data, model-family rejection, first-invocation
  hooks, non-restarting Stop, safe legacy retirement, disposable settings,
  macOS package-write denial and Linux settings-mount construction.
- `agent adapters check`, `agent docs check`, 21 skill contracts and
  `git diff --check` passed. Architecture HTML was regenerated from sources.
- Real credential-free capability probe identifies `gemini` as executable
  `/Users/simon/.local/bin/agy`, version `1.2.7`, with required JSON/plan flags.
  The probe uses no network and no provider credentials. Help is on stderr.
- Separate read-only code-review agent identified a retired-tree traversal
  defect for unowned symlinks. A regression failed before the fix and passed
  afterward. Cleanup no longer traverses retired trees. The reviewer rechecked
  this and the parser's malformed-type handling and reported no remaining
  Critical/Important findings. This is not cross-provider clearance.

## Limits

- No live authenticated AGY review or model-entitlement test was performed.
  API-key mode is configured according to official documentation, but actual
  backend/model compatibility still requires an approved live smoke test.
- No user profile/keychain was read or imported. An interactive subscription
  login is not automatic-review authentication under the isolated environment.
- Linux mount construction is covered; bubblewrap execution was not available
  on this macOS host.
- The quick gate returns `incomplete` (exit 5): product commands intentionally
  remain unconfigured in the reusable template. This is not a merge/release
  clearance; scanners and signed security/cross-review approval remain separate.
- Node 24 is used for existing sandbox tests because the host's dynamic
  Homebrew Node 26 needs a library outside the allowed runtime paths. No broad
  library/host grant was added for this migration.

See `docs/antigravity.md` for setup, contract sources and recovery. Historical
Gemini CLI evidence is preserved and must not be presented as AGY verification.
