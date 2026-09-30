# Review a task, its states and the available evidence

Selected guidance adapted from Next Level Builder's
[ux-guidelines.csv](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill/blob/dcc40ff5133ef78276117db0cc34e7b83cc8aeba/src/ui-ux-pro-max/data/ux-guidelines.csv),
copyright (c) 2024 Next Level Builder. [MIT license](UI-UX-PRO-MAX-LICENSE.txt).
Modified 2026-09-22: synthesized selected interaction/recovery/accessibility
themes (source row IDs in `.agent/sources/UX_UI_AUDIT.md`), omitted CSV dataset
and scripts; added evidence levels, deduplication and qualified W3C criteria.

## Choose the evidence level

| Available input | Supports | Does not establish |
|---|---|---|
| Source snippet/diff | Markup semantics, data-flow concern, identified CSS rule | Final cascade/layout, browser or server behavior not shown |
| Screenshot | Captured visual hierarchy, content and state | Keyboard, assistive tech, touch gestures or unseen states |
| Reproduced interaction | Named task in named browser/device/data state | All devices or user groups |
| Tool measurement | Exact measured criterion and scope | Whole-product accessibility or usability |
| Stakeholder report | Attributed observation to investigate | Independently reproduced result |

No browser is a coverage limit, not a reason to suppress a provable source issue.
Conversely, a suspicious rule is not always a confirmed visual failure:
`outline:none` requires checking scope and alternative focus treatment. A retry
that resends successful IDs is a replay concern; duplicate financial effects
require server/idempotency evidence. Cite the missing evidence precisely.

## Task and recovery

Walk the changed journey: entry, selection, action, pending, success, partial
error and retry. Can the person tell exactly what is affected before committing?
Do filters, pagination or stale data silently change scope? Is completion truthful?
Do validation errors identify the field/record and preserve useful input? Are
empty states distinct from loading and network errors? Can recovery target failed
work without losing completed work? Treat permission denial as a state, not a
hidden button that substitutes for authorization. Link security questions to
existing security findings instead of repeating them as confirmed vulnerabilities.

## Interaction and content

Prefer native controls with names, labels and appropriate states. Exercise
keyboard order, activation, dialog focus entry/return and visible focus when
tools permit. Check associated form errors and announced asynchronous status;
do not use color alone for essential meaning. Pending controls need accurate
semantics and behavior, not just a faded style. Keep authentication compatible
with password managers and paste where relevant.

Inspect long localized labels, realistic counts, empty data, layout reflow and
essential content hidden by ellipsis. Test applicable narrow/wide widths and
zoom, touch actions and interrupted gestures, reduced motion and supported themes.
A mobile viewport is not a physical-device test. Reduced motion should preserve
feedback. Do not require dark mode or a particular animation library unless it
is part of the product contract.

## Numeric criteria without invented universal rules

For web work, choose the project's agreed target. These short explanations are
references, not a complete WCAG checklist or legal advice:

- [WCAG 2.2 SC 2.5.8, AA](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html):
  pointer targets have a 24 by 24 CSS-pixel minimum **with defined exceptions**, including spacing.
  A product may choose larger targets; 44px is not a universal AA requirement,
  and web CSS pixels are not interchangeable with native pt/dp rules.
  Measure the interactive hit area, not merely the visible icon artwork.
- [SC 2.4.11, AA](https://www.w3.org/WAI/WCAG22/Understanding/focus-not-obscured-minimum.html):
  author-created content must not entirely conceal a focused component. Do not
  mislabel the stronger entirely-visible expectation as this minimum criterion.
- [SC 1.4.3, AA](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html):
  ordinary text generally needs 4.5:1, large text 3:1, subject to the criterion's
  definitions and exceptions. Measure actual foreground/background pairs and
  state; token names and guessed colors are not contrast measurements.
- [SC 2.1.1, A](https://www.w3.org/WAI/WCAG22/Understanding/keyboard.html) and
  [SC 2.5.7, AA](https://www.w3.org/WAI/WCAG22/Understanding/dragging-movements.html):
  check keyboard operability and a non-drag single-pointer alternative where
  applicable. Keyboard support alone does not establish the pointer alternative;
  consult the criteria for their specific exceptions.

## Findings and verdict

Use Critical/High/Medium/Low only with the affected task and impact explained;
visual taste without a brief violation belongs under a suggestion, not a blocker.
For example, UX-F01: supplied approve-all `div` has no native button/keyboard
semantics; source evidence confirms that limitation, while runtime compensating
handlers remain unreviewed. Recommend a scoped control correction and keyboard
recheck, not a page redesign. Preserve any related CODE-F ID for adjudication.

Summarize confirmed defects and then coverage separately. A scoped verdict is
fail when confirmed required criteria fail; incomplete when needed evidence is
missing and no such failure is established; pass only when required scoped
checks were actually satisfied. Even a fail report lists untested areas.
No findings found in source-only review is not “UI passed”. Do not turn a
summed heuristic score into accessibility certification or release approval.
