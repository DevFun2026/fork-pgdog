# Visual direction with an implementation consequence

Adapted from Anthropic's
[frontend-design skill](https://github.com/anthropics/skills/blob/34040c9c568585f6929bedeaad110ad08f079624/skills/frontend-design/SKILL.md),
Apache-2.0; copyright its contributors. Full selected upstream license:
[ANTHROPIC-LICENSE.txt](ANTHROPIC-LICENSE.txt).
Modified 2026-09-22: condensed design reasoning, removed provider-specific text;
added existing-stack, state-ID and evidence-handoff integration. This is not the
full upstream skill and does not install its surrounding repository.

## Pick an appropriate direction

Use the brief's audience, primary job, content and constraints to choose visual
priorities. A work queue needs comprehension, scannability and confident action;
a campaign page may need a memorable narrative. Neither needs the other's
composition by default. Respect explicit visual references and incumbent product
language over generic aesthetic heuristics.

Before changing code, describe the intended content hierarchy, page structure,
type roles, color use and purposeful motion. Explain how those choices support
the job. “Modern and clean” is not a decision. A useful decision is “keep amounts
aligned for comparison, place the action beside the selected-scope summary, and
use stronger type only for the next decision.”

Critique the proposed composition: what competes with the primary task? What
looks decorative but implies nonexistent functionality? Which content has been
repeated to fill space? Which visual rule conflicts with the brief? Resolve the
most consequential mismatch before implementation. Do not restart the entire
visual system for a small refinement.

## Implement the direction

Reuse the product's type and tokens; choose new ones only within authorized scope.
Make hierarchy visible through scale, spacing and grouping rather than endless
cards, badges or all-caps. No font family, color or common layout is banned
universally. Keep actual product vocabulary consistent across action and result.
Use representative content with truthful labels; label demonstration data as such.

Apply semantic HTML or native platform controls, visible focus, readable states
and purposeful transitions. Preserve state communication when reducing motion.
Content dictates responsive priorities: long Vietnamese strings, variable
amounts and empty tables can change layout more than a hero screenshot reveals.
Do not let visual truncation hide essential decisions or recovery information.

## Inspect and hand off

Begin with one scoped implementation and one evidence-led critique. Iterate for
named defects, not a speculative chain of complete aesthetic replacements.
Where tools exist, inspect narrow/wide renderings and changed states, exercise
keyboard operation, zoom and reduced-motion behavior. A screenshot proves only
that captured state; touch operation needs interaction evidence, not a resized
desktop window. Source inspection without a browser supports source findings,
not claims about measured contrast, final rendering or user preference.

Connect acceptance IDs to changed files and actual test results. If no product
source or browser is available, deliver a bounded handoff and explicit unverified
checks. Do not create application code merely to demonstrate this template.
