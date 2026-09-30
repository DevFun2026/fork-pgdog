# UX/UI extension: evaluation and verification

Date: 2026-09-22. Base: `6a44fb6c2a3fa9afd64b475b4ed636ce8351b741`.
Scope: four skill contracts, selective references and original artifact templates,
interface routing, source audit/notices, native generation and documentation.

## Technique trials

Baseline agent: `ux_baseline`; fresh application agents: `ux_application`,
`design_application`, `frontend_application`, `ux_review_application`.
All used `gpt-5.6-sol`, medium effort. These are same-provider bounded technique
evaluations, not cross-provider approval, user research or a product UI test.
Baseline was read before each skill was authored; application agents read the
applicable SKILL and local resources without the evaluation report or plan.
No application files were created. Skill validation ran after each addition.

| Trial | Task and constraints | Baseline | Application |
|---|---|---|---|
| UX discovery | Vietnamese invoice approval, laptop Finance 20–80/day, phone Manager, CSV errors, one-click demo request, no research | Already separated assumptions, required consequential approval, covered partial failure; no demonstrated safety failure | E-01–05 evidence ledger, J-01–02/S-01–06, D-01–03 decisions, AC-01–04; product/backend decisions and validation remain unapproved/unverified |
| Design system | Existing blue brand/buttons, dense queue, 390px phone, long names, no CSS supplied | Supplied plausible hex tokens, scoped CSS override; contrast needed validation | Provisional master + page delta, incumbent aliases explicitly unresolved, only proposed dimensions, states and content/recovery contracts; no final visual approval |
| Frontend design | Approved queue, existing SSR HTML/CSS + progressive enhancement, handoff only, no source paths or screenshots | Good state table and no-JS handoff, no false screenshot claim | Bounded handoff, refused to treat template/golden HTML as product source, retained stack, marked routes/IDs/data contract unprovided, distinguished SSR loading from enhanced loading |
| UX/UI review | Supplied nonsemantic approve div, outline:none, retry of all selected IDs, developer-only Chrome report, no browser | Source findings plus uncertainty around server effects and replacement focus | UX-F01/02 confirmed only the supplied semantic/recovery concerns; UX-Q01 required cascade/focus evidence; verdict fail with explicit untested scope, no duplicate financial-effect claim |

These small trials show usable artifact structure, not statistically demonstrated
quality gains. No matched multi-run benchmark, model-family matrix, usability
study or token-billing comparison was performed. Baseline strengths are retained,
not relabeled failures to justify new guidance. New CLI behavior had deterministic
RED: `interface` rejected by argparse; catalog test reported four missing skills.

## Concrete excerpts and observed limits

- UX trial linked AC-02 to S-04/S-05 (same selected scope/count/amount at CTA and
  confirmation), and marked AC-03 duplicate/retry safety dependent on backend
  evidence. It proposed partial CSV acceptance without product approval and
  correctly kept the overall brief provisional. A real product must resolve
  all-or-nothing versus partial import before implementation.
- Design trial returned `color.action.primary.bg → brand.blue.primary` with
  an unresolved incumbent value rather than an invented current palette. Its
  suggested 44px phone targets were proposals, not a universal AA claim.
  The agent requested clearer provisional handling; the page asset now explicitly
  permits missing IDs/source and prohibits presenting proposals as incumbent.
- Frontend trial explicitly said the repository was a template and no product
  source existed. All browser checks remained unverified. Its useful suggestion
  to separate no-JS and enhanced-JS contracts was added to the handoff asset.
- UX trial suggested fixed ceremony thresholds and additional policy wording;
  not added. Existing impact-based gates already cover consequential choices,
  and a missing user in a test is not permission to implement a risky action.

### Held-out review case

The first review method example overlaps the invoice trial; therefore that trial
alone is weak evidence of generalization. A fresh `ux_review_holdout` agent used
the same model/effort on appointment-booking evidence: drag-only date change,
reported 22px help icon with unknown spacing/hit area, preserved form values and
visible error, and an unavailable automated scan claimed to prove AA compliance.

It identified drag-only access as a failure, refused AA certification, did not
confirm target-size failure from the icon dimensions, and left error announcement
unverified. It nevertheless assigned Medium labels to unverified concerns; treat
those as questions, not confirmed Medium defects. Severity calibration remains
a limitation, not a proven pass. Its useful suggestions added explicit hit-area
measurement and primary W3C keyboard/dragging links. No browser was exercised.

## Local verification

Focused interface routing: 6 tests passed, including unchanged non-interface
routes/gates. Skill catalog: 25 valid skills, 5 tests passed. Adapter tests: 6
passed, including missing reference/license drift. License metadata tests: 3
passed; no legal/compliance conclusion is implied.

Full deterministic suite: **175 tests passed**, 39.333 seconds, command:

```sh
PATH="/Users/simon/.nvm/versions/node/v24.11.0/bin:$PATH" PYTHONPATH=.agent/runtime python3 -m unittest discover -s .agent/tests -q
```

`skills check` passed (25); `adapters check` and `docs check` passed after build;
`licenses audit --json` passed (14 source rows); `git diff --check` exit 0.
Local link validation covered all 13 UX/UI Markdown resources, including nested
references to retained licenses. Adapter regression checks detect missing native
reference/license files, not just SKILL body drift. These checks do not fetch
remote sources or certify licenses.

Context estimate using existing `utf8-div3-v1`: four names/descriptions total 235
estimated tokens; all four bodies total 2,820. Host wrappers, references, assets,
license text, tool reads, reasoning and outputs are excluded. Entry files are
279–318 words each. This is a selective-loading design, not billed savings.

Final read-only review (`ux_extension_review`) found no actionable defect in the
bounded canonical skills/resources, routing/tests, source boundaries and docs.
It independently checked native equality, 25-skill validation and whitespace.
Its UI UX Pro Max web requests hit cache misses; independent network provenance
confirmation remains a limit, separate from the author's successful pinned
GitHub API reads used to retain the license. This is not cross-provider clearance.
Product quick gate remains unconfigured in this starter; it must report incomplete,
not be changed to pass for this extension. No live provider egress, hosted CI,
merge, release or production/browser validation is included in these trials.
