# UX/UI, loaded by task

The template ships 21 core workflow skills and four optional-use UX/UI skills.
“Optional” means phase/task routing, not four more mandatory gates or a package
installer. Native agents can discover their descriptions; they read bodies,
references and artifacts only when relevant. Backend-only routes are unchanged.

```sh
./scripts/agent workflow guide --task interface
```

| Need now | Skill | Smallest useful output |
|---|---|---|
| Understand people, tasks and failure recovery | `ux-discovery` | Evidence ledger + journey/state + acceptance |
| Reuse visual decisions across screens | `ui-design-system` | Design master + only affected page delta |
| Implement an approved interface | `frontend-design` | Existing-stack implementation + state/evidence handoff |
| Evaluate an interface change | `ux-ui-review` | Prioritized findings + explicit tested/untested coverage |

Select the phase, not all four bodies. A button alignment correction does not
need a new research study or design system. A new permission-sensitive bulk
action still requires behavioral planning, security and ordinary review. UI
review supplements those reviews; it neither repeats the full code-review
report nor supplies independent cross-provider clearance.

## Artifacts and continuity

Each skill keeps selective methods in `references/` and original reusable
Markdown templates in `assets/`. A product may instantiate them as:

```text
docs/design/flows/invoice-approval.md  # evidence + journey/state + AC IDs
docs/design/MASTER.md                  # shared decisions, source, approval
docs/design/pages/invoice-queue.md     # page deltas, not a master copy
docs/design/implementation/invoice-queue.md
docs/reviews/invoice-queue-ux.md        # source-bound findings and coverage
```

These paths illustrate a future product, not an application added to this
template. Inline artifacts are sufficient for small bounded changes. Stable
IDs connect requirements to component states, implementation and review.
Missing research, screenshots, test tools or approvals stay explicit. An
internal walkthrough is not user research; screenshots do not prove keyboard,
touch gestures, server authorization or WCAG conformance.

For continuity, retrieve the relevant brief/master/page from their canonical
files. If project memory is used, follow existing reviewed promotion rules and
store only short pointers, decisions and freshness metadata—not full UI briefs,
private research transcripts or screenshots. This extension does not auto-write
memory or change its budget.

## Source and context boundaries

See [file-level audit](../.agent/sources/UX_UI_AUDIT.md),
[source manifest](../.agent/sources/SOURCES.md) and
[notices](../THIRD_PARTY_NOTICES.md). Selected references are adapted with local
licenses; other sources are comparison-only. No upstream pack, launcher,
framework, hook, font or design database is installed or fetched at runtime.

Use the existing standard context profile as a starting point. The guide is
advice, not a mechanism that prevents a host from loading extra content.
Metadata adds overhead; progressive reading reduces avoidable document reads
but no billed-token saving is claimed without comparable usage measurements.

Trial results and verification limits: [UX/UI review](reviews/ux-ui-skills.md).
