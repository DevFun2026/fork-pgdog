# UX/UI source selection audit

Snapshot: 2026-09-22, public GitHub repository metadata and pinned file reads.
This is a targeted comparison of prominent relevant repositories, **not an
exhaustive ranking of GitHub or evidence that popularity proves quality**.
Stars change continuously. Revisions below resolve the inspected text, not an
approval to execute anything in those repositories.

| Repository | Stars at snapshot | Revision | Decision |
|---|---:|---|---|
| obra/superpowers | 289937 | 5bf4e78011075bcfc0dc295f0724994cd123ee71 | Existing lifecycle conceptual reference; not reimported |
| affaan-m/ECC | 264963 | bf70150eb2df8070024e5bdf08e4aa08959e2735 | Defer framework-specific patterns |
| anthropics/skills | 177559 | 34040c9c568585f6929bedeaad110ad08f079624 | Adapt selected visual-direction text |
| nextlevelbuilder/ui-ux-pro-max-skill | 129708 | dcc40ff5133ef78276117db0cc34e7b83cc8aeba | Adapt token and selected review guidance |
| pbakaus/impeccable | 69738 | 83c2c735777c68e30ea536ab9cc97f7843456945 | Conceptual comparison; no runtime or text import |
| vercel-labs/agent-skills | 31449 | 063bee94c3f4df8453406c830b0a7df0f2860278 | Exclude moving remote loader |

## Concrete review scope and boundaries

- **Anthropic**: read `skills/frontend-design/SKILL.md` and that directory's
  `LICENSE.txt` (Apache-2.0). Repository metadata has no overall license, so the
  conclusion is file-specific. Local adaptation retains brief-first visual
  direction and bounded critique. Omits provider assumptions and any universal
  style prescription. It runs without dependencies or network access.
- **UI UX Pro Max**: read `src/ui-ux-pro-max/data/ux-guidelines.csv`,
  `.claude/skills/design-system/references/token-architecture.md`, and root
  `LICENSE` (MIT). Selected CSV themes: IDs 28, 32–35, 37, 40–44, 54–55,
  61, 68, 71, 78–80, 99–104, 107, 109, 111–113, 117–119. Local synthesis
  covers semantic interaction states, recovery, responsive content and evidence.
  Token layers are adapted without upstream CSS literals or unresolved aliases.
  We do not import CSV databases, Python search/ranking, CLI installers or
  platform-specific rules. Numeric accessibility rules are checked against W3C,
  not blindly copied: 44px is not a universal WCAG AA requirement.
- **Impeccable**: read `.agent/skills/impeccable/SKILL.md`,
  `skill/reference/shape.md`, `skill/reference/audit.md`, root `LICENSE` and
  `NOTICE.md`. Separation of discovery/design/audit is a conceptual reference.
  Exclude the launcher's binary-download path, detector, command router and
  native-platform references; their dependencies/licenses are not inherited by
  this template. Do not copy health scores as accessibility certification or
  assume dark mode is required for every product.
- **ECC**: read `skills/frontend-patterns/SKILL.md` and root `LICENSE` (MIT).
  Examples assume React/Next patterns and mention SWR, React Query, Zustand,
  Zod, TanStack Virtual and Framer Motion. They are not universal dependencies.
  Code examples are not imported or security-certified. Stack-specific reuse
  requires its own project-scoped selection and tests.
- **Vercel**: read `skills/web-design-guidelines/SKILL.md`; inspect complete
  pinned tree for LICENSE/NOTICE paths (none) and README's MIT declaration.
  The skill fetches `vercel-labs/web-interface-guidelines/main/command.md` on
  execution. This mutable transitive input is not frozen by pinning the loader.
  Neither loader nor remote text is imported; remote text was not audited.
- **Superpowers**: retain existing source pin and independently worded lifecycle
  integration; this extension is not a new whole-repository audit.

## Local mapping

| Local resource | Reuse | Specific upstream input |
|---|---|---|
| ux-discovery entrypoint, journey method and brief | Original artifact contract | Impeccable shape: conceptual comparison only |
| ui-design-system/references/token-contract.md | Adapted documentation, MIT notice retained | UI UX Pro Max token-architecture.md |
| frontend-design/references/visual-direction.md | Adapted documentation, Apache license retained | Anthropic frontend-design/SKILL.md |
| ux-ui-review/references/review-method.md | Adapted documentation, MIT notice retained | Selected UI UX Pro Max CSV themes above; W3C references |
| All four assets/*.md | Original integration templates | No upstream template copied |

No new runtime dependency, network hook, automatic source updater, or remote
font/icon download. Upstream instructions remain untrusted source material;
licenses never grant workspace authority. Attribution and licenses travel with
generated native resources, which remain identical to canonical files.

## Verification limits and refresh procedure

Check canonical skill contracts, local links, native drift, source metadata and
scenario artifacts. These checks do not establish full license compliance,
malware absence, usability improvement or WCAG conformance. See
`docs/reviews/ux-ui-skills.md` for actual evaluation results.

For refresh: read metadata, pin commit, inspect selected text plus license and
NOTICE changes, inspect transitive downloads, record inclusion/exclusion,
update adapted notices, and rerun technique trials and repository checks.
Do not replace a pin automatically when a source gains stars.
