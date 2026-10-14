# Full-read review infrastructure local evidence

Status: implementation verified locally; independent provider review and normal
security/CI/merge clearance remain pending. No feature review or release
clearance is implied.

The owner approved 30,000,000 aggregate bytes / 8,000,000 estimated tokens.
Project per-call limits remain 500,000 bytes / 96,000 estimated tokens and the
child target remains 250,000 bytes. Unconfigured projects retain conservative
runtime defaults (including the 64,000-token default per call).

Config behavior was implemented test-first: the approved-limit test failed with
2,500,000 != 30,000,000 before the config change; the two config/default tests
then passed. The focused profile splitter test initially failed because the
ordinary patch was indivisible; the completed partition suite passed 20/20.

The primary integration ran all 254 agent tests successfully outside the outer
Codex sandbox, including real macOS sandbox-exec tests and clean-export smoke.
The initial sandboxed run failed with sandbox_apply Operation not permitted;
these failures were not waived. Ruff, canonical quick (format/lint/changed tests),
documentation, adapter and skill checks passed. An initial 60-second lint timeout
was followed by a successful gate with a 600-second command limit.

A local capacity simulation of the complete fd34918d feature diff created 61
children, with 14,527,798 aggregate bytes / 4,842,618 estimated tokens including
integration reserve. All child budgets passed and loader revalidation matched.
The eight real profiles contained 26,086 catalog records across 52 profile
atoms; concatenation matched every original diff byte. This was a packaging
test only: its verification metadata explicitly says canonical full verification
is pending, no provider was called, and it cannot grant review clearance.

The infrastructure changes are isolated from the feature in a separate branch
based on remote main. They must pass independent review and normal gates before
entering the trusted base. Only then can the feature use the new trusted limits;
its actual root and integration manifests require separate exact approvals.
Private icondo metadata remains outside provider packages.
