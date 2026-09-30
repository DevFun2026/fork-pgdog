# Context efficiency

One canonical skill library is projected into two native directories for
three providers: `.agents/skills` is shared by Codex and Antigravity (`agy`),
while `.claude/skills` serves Claude. Disk copies do not by themselves multiply model context. Read one
applicable copy, search canonical source paths, and prefer the architecture
summary to the HTML intended for people.

## Retrieval and budgets

| Profile | Memory estimate cap | Review estimate cap | Memory records |
| --- | ---: | ---: | ---: |
| light | 600 | 8,000 | 3 |
| standard | 1,200 | 32,000 | 5 |
| deep | 2,400 | 64,000 | 10 |

Actual limits are the lower of the selected profile and configuration.
`memory.startup_char_budget` defaults to 4,000 and
`memory.startup_estimated_token_budget` to 1,200. Raise both deliberately in
project config if deep retrieval needs more space. Review also retains the byte
limit and `review.max_estimated_tokens` (64,000 by default), read from the trusted
base; candidate config cannot raise that approval boundary. An explicit
`review --max-estimated-tokens N` may choose a budget up to the trusted cap.

The offline estimator `utf8-div3-v1` computes `ceil(UTF-8 bytes / 3)`. It is a
planning heuristic, not an exact count or guaranteed upper bound for Claude,
Gemini or Codex. Review payload accounting includes instructions, serialized
manifest, diff, requirements, policy, schema, verification and context. It does
not include CLI/system wrappers, repeated tool reads, reasoning or model output.
Actual billing savings require provider usage measurements on comparable tasks.

```sh
./scripts/agent memory bootstrap --query "payments retry" --profile light --report
./scripts/agent memory search "payments retry" --limit 3 --profile standard
./scripts/agent memory show MEM-EXAMPLE-001
./scripts/agent workflow guide --task behavior
./scripts/agent review --author-provider codex --profile standard
```

Memory queries use deterministic weighted lexical relevance (ID, title,
components/paths, summary, type), with partial matches instead of requiring all
query terms. This is not semantic or cross-language search. Whole summaries are
selected within both budgets and the result limit; a summary too large to fit is
skipped. No match means focused source discovery is still needed. Startup hooks
use fresh architecture/constraint/decision/workflow records without a synthetic
multi-word query. Search excludes private records and refreshes stale detection;
`--include-stale` is explicit historical inspection. Canonical records remain
empty in a fresh template until project knowledge is reviewed and promoted.

`bootstrap --report` exposes payload bytes, characters, estimate, effective
budget and selected context. Search returns bounded JSON rows. `show` loads
selected full records with defaults of 16,000 characters / 4,800 estimated
tokens; overflow blocks without truncation. Use explicit `--char-budget` and
`--max-estimated-tokens` only when that full evidence is needed. Reports and CLI
JSON wrappers add a small overhead beyond the reported memory content.

## Review deduplication

For native `.agents/skills`, `.claude/skills`, and legacy `.gemini/skills` changes, the
runtime compares Git blob IDs AND file modes against `.agent/skills` at both
base and head. It only removes a copy from the review diff when the canonical
source is also changed and both endpoint comparisons prove equivalence.
Requested context files sharing that proof map to one canonical context file.

`manifest.json` retains full scope, `full_diff_sha256`, the projected
`diff_sha256`, and `omitted_generated` copy/source mappings. Reload and merge
recompute the proof using immutable Git revisions, without trusting a generated
ownership manifest or executing a branch's generator. Modified copies, mode
differences, old drift, and unproven outputs remain visible. Generated HTML is
not removed by this optimization. Secret scanning still covers the FULL diff.

Preview shows payload cost before any provider probing. Overflow blocks and
suggests reducing optional context or choosing a larger approved profile; it
never truncates a review diff. Resume checks current limits before probing.
Changing package content requires new exact manifest approval. Existing full-
diff packages remain readable; old runtimes cannot read new projected manifests
and must recreate review packages when rolling back.

## Planning tiers

- **Light:** small content-only change; inline scope and checks, focused diff,
  artifact validation. No separate spec/plan ceremony unless impact warrants it.
- **Standard:** behavior change; focused plan and regression tests, targeted
  verification, relevant reviews. Multi-step changes keep a versioned plan.
- **Deep:** architecture, security, policy, dependency or deployment change;
  versioned spec/plan, impact/threat analysis, required independent review.

`workflow guide --task content|behavior|interface|architecture|security` returns guidance
and a context profile. It is not an automatic risk classifier, does not advance
workflow state and does not weaken merge/release checks. Escalate based on actual
impact, even if the changed file is Markdown. Read selected skills on demand;
never load all recommended skill bodies automatically.

The interface route selects discovery, design-system, implementation or review
at the current phase. Four additional descriptions are discoverable; references,
licenses and artifact templates are not bootstrap context. See `docs/ux-ui.md`.
Backend-only route lists remain unchanged. This is selective-reading guidance,
not a guarantee about a provider's automatic loading or billed-token usage.
