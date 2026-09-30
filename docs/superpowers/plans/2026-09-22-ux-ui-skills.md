# UX/UI extension and source audit

Status: implementation approved by user, 2026-09-22.

## Contract and scope

Add four provider-neutral technique skills under `.agent/skills/`: UX discovery,
design systems, frontend design, and UX/UI review. Each has a concise entrypoint,
selective references, and a reusable Markdown artifact. This is a starter
template, not an invoice application. Existing gates and provider identities do
not change. Optional means task-routed, not an installer feature: native tools
can still discover four additional metadata descriptions.

Acceptance:

- UX-01: `workflow guide --task interface` exposes the four skills, standard
  context, and unchanged gates; non-interface routes do not load them.
- UX-02: artifacts connect evidence, journey/state IDs, design decisions,
  implementation, and review; missing browser/research evidence is explicit.
- UX-03: selected upstream files have pinned provenance, reuse boundaries,
  licenses and notices. No upstream executable, binary launcher, unpinned
  downloader, framework dependency, or external hook is installed.
- UX-04: canonical resources propagate unchanged to both native destinations;
  focused documentation and generated architecture HTML describe the extension.
- UX-05: real technique trials exercise each skill. Report baseline strengths
  and limits honestly; structural tests are not proof of better UX.

## Sequence and files

1. Add failing interface routing and discovery tests in
   `.agent/tests/test_workflow.py` and `test_skills.py`. Confirm missing route
   and skill are the intended failures. No production app fixture is required.
2. For each skill separately: inspect a baseline response, author SKILL plus
   `references/` and `assets/`, run discovery validation and an independent
   application trial, then address concrete failures. These are technique and
   reference skills, not new authority/discipline rules. Do not add redundant
   pressure wording when baseline already respects existing safety rules.
3. Implement interface routing in runtime `workflow.py` and `cli.py`; verify
   existing routes and state transitions remain unchanged.
4. Update `.agent/sources/SOURCES.md`, source audit, and
   `THIRD_PARTY_NOTICES.md`; include original upstream license texts with
   adapted resources. The manifest's no-vendoring declaration is specifically
   about executable code, not a false claim that all documents are original.
5. Update README, AGENTS routing vocabulary, architecture model/contracts,
   `docs/ux-ui.md`, traceability. Build adapters and generated docs, never edit
   generated copies. Run focused tests, full suite, skills/adapters/docs/license
   checks, `git diff --check`, and quick verification with its real gate status.
6. Record evidence in `docs/reviews/ux-ui-skills.md`; inspect independent review
   findings before handoff. No live cross-provider egress is authorized by this
   plan. No merge/release clearance is implied by technique trials.

## Per-skill evaluation checklist

| Skill | Baseline | Application | Resource validation |
|---|---|---|---|
| ux-discovery | invoice workflow without research | evidence/flow handoff | skill and local links |
| ui-design-system | existing brand + phone page | master + scoped override | skill and local links |
| frontend-design | server HTML, unavailable screenshots | bounded implementation handoff | skill and local links |
| ux-ui-review | inaccessible control + retry replay | findings and coverage limits | skill and local links |

Detailed outcomes belong in the review report, not checked boxes inferred from
file existence. Initial UX baseline was already safe: no invented research,
irreversible approval, or claimed browser verification. Added value being tested
is reusable, traceable artifact structure, not a proven safety improvement.

## Rollback and authority

Revert this scoped extension and regenerate owned native files; retain user
project design documents. No external packs or migrations are installed. Ask
before credentials, network review egress, merge or release. Existing user
authorization for repository commits/pushes remains the applicable boundary.
