# Source provenance

Reviewed on 2026-09-22. Legacy lifecycle contracts reimplement general ideas
against this project's specification. The UX/UI extension also includes selected
adapted documentation, explicitly identified below and in local notices. This
project does not vendor third-party executable code, binary launchers, hooks,
packages, or visual assets. See `UX_UI_AUDIT.md` for file-level scope and limits.

| Source | Reviewed revision/version | License | Concepts used | Reuse boundary |
|---|---|---|---|---|
| [Agent Skills specification](https://github.com/agentskills/agentskills) | `69ef37e9424c0a7ea9dd2293b559e43ec8176379` | Apache-2.0 code/spec; CC-BY-4.0 docs | Portable `SKILL.md` shape, discovery metadata, progressive disclosure | Validator and original 21 contracts were authored for this repository; no specification text or library is copied |
| [Superpowers](https://github.com/obra/superpowers) | `5bf4e78011075bcfc0dc295f0724994cd123ee71` | MIT | Approval before implementation, planning, test-first work, systematic debugging, verification | Workflow contracts are independently worded and connected to this runtime; no scripts or skill bodies are vendored |
| [Trail of Bits Skills](https://github.com/trailofbits/skills) | `123037ec8aed26f0d86327cc39137ee5043e5deb` | CC-BY-SA-4.0 | Security review lenses, differential review, finding verification | Only high-level review concepts and attribution are used; no skill content is copied or adapted |
| [MADR](https://github.com/adr/madr) | `ba75bb1b20d42af5746b246ad348c202419ae681` | MIT OR CC0-1.0 | Decision context, alternatives, outcome, consequences, status/supersession | The ADR artifact contract is independently authored from the approved design spec |
| [OWASP ASVS](https://owasp.org/projects/asvs) | 5.0.0 | CC-BY-SA-4.0 | Version-qualified application-security requirement references | No control is copied and no compliance/certification is claimed |
| [OWASP SAMM](https://owaspsamm.org/model/) | 2.0 | CC-BY-SA-4.0 | Secure lifecycle and governance coverage | Used as a maturity reference, not a reproduced model or certification |
| [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html) | reviewed 2026-09-21 | CC-BY-SA-4.0 | Assets, actors, flows, boundaries, threats, responses, validation | Method concepts only; project threat model and wording are original |
| [Claude-Mem](https://github.com/thedotmack/claude-mem) | `4e98d977cc6d9c4fe18c60d4956d948f57e7a1f6` | Apache-2.0 | Persistent local memory, retrieval before broad rescanning, session continuity | The standard-library SQLite/Markdown memory design is independent; no code, prompts, UI, or protocol is copied |
| [Anthropic skills](https://github.com/anthropics/skills) | `34040c9c568585f6929bedeaad110ad08f079624` | Apache-2.0 for selected frontend-design skill | Brief-led visual direction, critique before implementation, product-specific content | Adapted into frontend-design/references/visual-direction.md; selected file license retained locally, not a repository-wide license claim |
| [UI UX Pro Max](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill) | `dcc40ff5133ef78276117db0cc34e7b83cc8aeba` | MIT | Token layers and selected UX state/accessibility guidance | Adapted into ui-design-system and ux-ui-review references with MIT notices; no search engine, datasets, installer or runtime imported |
| [Impeccable](https://github.com/pbakaus/impeccable) | `83c2c735777c68e30ea536ab9cc97f7843456945` | Apache-2.0 for reviewed core text | Discovery versus design versus measurable review; context-scoped reading | Conceptual comparison only; no text, launcher, detector or native-platform references imported |
| [ECC](https://github.com/affaan-m/ECC) | `bf70150eb2df8070024e5bdf08e4aa08959e2735` | MIT | Compared frontend implementation patterns against stack-neutral scope | Reviewed frontend-patterns only; no examples, dependencies, hooks or skills imported |
| [Vercel Agent Skills](https://github.com/vercel-labs/agent-skills) | `063bee94c3f4df8453406c830b0a7df0f2860278` | MIT declared in README; no license file in inspected tree | Compared web-design-guidelines loader and review presentation | No content imported; moving external main-branch guidance excluded; external guidance license not inferred from loader |
| [W3C WCAG 2.2](https://www.w3.org/TR/WCAG22/) | 2.2 | W3C document license; reference only | Qualified contrast, focus and target-size criteria | Links and original short explanations, not reproduced standard text or certification |

Revision SHAs were read from the official repositories. License obligations
remain with each source; see `THIRD_PARTY_NOTICES.md`.
