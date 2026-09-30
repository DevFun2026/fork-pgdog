# Third-Party Notices

This repository contains imported PgDog source and the original Project AI
Template tooling. PgDog retains its upstream AGPL-3.0 license in `LICENSE`;
upstream component-specific notices and licenses remain in their original paths.
The template tooling retains its original Apache-2.0 license, preserved in
`docs/import/template-original/LICENSE`, and its original `NOTICE`.

The remaining notices below describe the template tooling and its references,
not the imported PgDog source. The original complete template notices are
preserved in `docs/import/template-original/THIRD_PARTY_NOTICES.md`.

## Adapted documentation

- Anthropic `skills/frontend-design/SKILL.md`, revision
  `34040c9c568585f6929bedeaad110ad08f079624`: Apache-2.0, copyright its
  contributors. Adapted and condensed in
  `.agent/skills/frontend-design/references/visual-direction.md` with explicit
  local changes and upstream link. Complete selected upstream license is
  `frontend-design/references/ANTHROPIC-LICENSE.txt` relative to `.agent/skills/`.
- Next Level Builder, copyright (c) 2024 Next Level Builder, MIT, revision
  `dcc40ff5133ef78276117db0cc34e7b83cc8aeba`: token-architecture reference and
  selected ux-guidelines.csv concepts adapted in
  `.agent/skills/ui-design-system/references/token-contract.md` and
  `.agent/skills/ux-ui-review/references/review-method.md`. Each directory
  includes `UI-UX-PRO-MAX-LICENSE.txt` with the complete notice and license.

These adapted files identify their changes. Native `.agents/skills/` and
`.claude/skills/` copies retain the same references and licenses. Original local
artifact templates and integration code remain Apache-2.0. No upstream search
dataset, bundled binary, native-platform guidance or visual asset is shipped.

## Conceptual references

- Agent Skills specification — Apache-2.0 for code/specification and CC-BY-4.0
  for documentation. Copyright its contributors.
- Superpowers — MIT. Copyright Jesse Vincent and contributors.
- Trail of Bits Skills — CC-BY-SA-4.0. Copyright Trail of Bits and contributors.
- MADR — MIT OR CC0-1.0. Copyright MADR contributors.
- OWASP ASVS, SAMM, and Cheat Sheet Series materials — CC-BY-SA-4.0. Copyright
  the OWASP Foundation and project contributors.
- Claude-Mem — Apache-2.0. Copyright Alex Newman and contributors.
- Impeccable — Apache-2.0 core text, copyright 2025 Paul Bakaus. No adapted text
  or third-party native platform references included.
- ECC — MIT, copyright (c) 2026 Affaan Mustafa; comparison only.
- Vercel Agent Skills — README declares MIT, license file not found in inspected
  tree; no reuse granted or assumed for its externally fetched guidelines.
- W3C WCAG 2.2 — document references only, no conformance claim.

Official URLs, revisions, concepts and reuse boundaries are recorded in
`.agent/sources/SOURCES.md`; `.agent/sources/UX_UI_AUDIT.md` distinguishes
adopted, adapted, deferred and rejected parts. The manifest validator checks
metadata structure, not legal clearance or a complete dependency/security audit.
