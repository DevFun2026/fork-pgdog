# Requirement traceability

| Requirement | Canonical implementation | Primary evidence |
|---|---|---|
| Provider-neutral workflow | `.agent/workflows/`, generated provider adapters | adapter drift check |
| Independent cross-provider review | review package, provider adapters, orchestrator | manifest-bound review and adjudication artifacts |
| Architecture documentation | project model and documentation generator | deterministic `system-summary.md` and `system.html` |
| Security review | security profile, threat model, scanner status | scope-bound security assessment and release gate |
| Progressive project memory | private checkpoint, reviewed promotion, canonical records | memory tests, checksums, stale-record filtering |
| Project starter lifecycle | init, workflow state, quick/merge/release gates | clean-fixture acceptance and CI workflows |
| UX-01–02, task-routed UX/UI and traceable artifacts | four `.agent/skills/` UX/UI contracts, references and assets; interface guide | routing tests and technique trials in `docs/reviews/ux-ui-skills.md` |
| UX-03–05, source boundaries and portable delivery | `.agent/sources/UX_UI_AUDIT.md`, local licenses, generated native resources | source/license metadata checks, adapter equality tests and scoped trial limitations |

The acceptance report must distinguish deterministic local evidence, real provider evidence, and hosted-CI evidence. Missing external evidence remains pending; it is never inferred from local tests.
