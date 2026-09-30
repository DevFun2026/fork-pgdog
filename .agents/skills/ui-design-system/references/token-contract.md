# A token contract that fits the product

Adapted from Next Level Builder's
[token-architecture.md](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill/blob/dcc40ff5133ef78276117db0cc34e7b83cc8aeba/.claude/skills/design-system/references/token-architecture.md).
Copyright (c) 2024 Next Level Builder. [MIT license](UI-UX-PRO-MAX-LICENSE.txt).
Modified 2026-09-22: condensed layer model, omitted upstream CSS/palette and
tooling assumptions; added source evidence, page deltas and alias verification.

Use only the layers that clarify this product:

| Layer | Meaning | Example contract, not a required spelling |
|---|---|---|
| Primitive | A measured/adopted value | brand.blue.600 = existing brand value |
| Semantic | Purpose, independent of a particular screen | action.primary.background → brand.blue.600 |
| Component | A justified local adjustment | approveButton.background → action.primary.background |

Do not rename a working system merely to match this vocabulary. For a tiny
surface, semantic tokens alone can be enough. Add component tokens where there
is a real independent reason to vary them, not for every CSS declaration.

Trace aliases until each resolves to a value. Check for missing references or
cycles; record type and unit. Inspect foreground/background together for each
state and supported theme. A name like “muted” or “accessible blue” proves
nothing about contrast. A proposed hex is not evidence of the current brand.

Master records reusable type hierarchy, spacing, color roles, radius, density,
focus and motion intent plus the source of each consequential choice. Include
component state contracts: trigger, visual result, semantics/keyboard behavior,
data effect and exit/recovery. A disabled-looking button is not an authorization
boundary, and pending is not successful completion.

Page documents contain deltas only: master revision, journey/state IDs, changed
tokens or layout rule, why global defaults do not fit, supported widths and
evidence. Page values override master only within that page and only if approved;
they never override product behavior, accessibility requirements or permissions.
If an override becomes common, propose promotion to the master explicitly.

Worked example (hypothetical): a desktop invoice queue keeps the brand and
button family. The page reduces secondary spacing but does not shrink touch
targets simply to fit more rows. On a phone, the layout prioritizes invoice ID,
amount and decision state; full supplier text remains accessible. Mark any
ellipsis/disclosure design as a decision to verify with keyboard and real long
Vietnamese names. “390px screenshot looks fine” is not proof of all widths or
zoom support. Dark mode is included only if supported, not as a universal task.

Implementation handoff: master ID + page delta + affected component/state IDs +
actual style/source locations + unresolved checks. No source updater or token
compiler is required by this reference.
