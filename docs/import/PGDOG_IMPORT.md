# PgDog import provenance

- Source: https://github.com/pgdogdev/pgdog
- Source branch: main
- Imported source commit: `57cf9d4caddb7c03e007382cad77aa06669e1220`
- Existing private repository commit: `f2caa6f2a272e266f25ec20983ca02340a18bc61`
- Destination: https://github.com/DevFun2026/fork-pgdog (private)

## Scope

Import the complete history reachable from the source commit, with a two-parent
merge retaining the original template history. No PgDog product code is edited.
This does not create a GitHub fork-network relationship. Additional upstream
branches and release tags are not published by this import.

## Overlapping paths

- `AGENTS.md` and `CLAUDE.md`: retain the existing template entry points;
  upstream originals are in `upstream-original/` beside this document.
- `LICENSE`: retain the exact upstream license; the original template license
  is in `template-original/`.
- `README.md`: add private-repository provenance before the upstream README;
  both originals are preserved beside this document.
- `.gitignore`: combine the upstream and original template rules; both originals
  are preserved beside this document.
- `THIRD_PARTY_NOTICES.md`: clarify that the original template notice does not
  relicense imported PgDog code. The original notice is preserved.

- Upstream `.claude/skills/bash/SKILL.md` and `rust/SKILL.md` are retained as
  `upstream-original/bash-SKILL.md` and `rust-SKILL.md` to avoid introducing
  ungenerated files into the template's managed adapter directory.

## Verification boundary

Verify every upstream blob and mode against the imported commit, with the four
intentional non-license overlapping paths and two relocated upstream skills
checked against archived originals.
Verify every original template blob and mode against the original commit, using
the archived copy for replaced paths. Verify both histories remain ancestors.

This is a source/history import, not a tested deployment or security approval.
Existing template project commands, scanner commands and independent-review
evidence are not configured for PgDog. Governance configuration and its gates
remain unchanged. Integration with Vault, EKS and query auditing is future work.

## Observed import checks

- Template adapter check: passed after preserving upstream-only skills outside
  the generated adapter directory.
- Template architecture documentation check: passed.
- Merge gate: blocked; `lint`, `test_full` and `build` are unconfigured.
- Independent provider review and required security scanner evidence are absent.
- Import remains on a review branch until repository merge requirements are
  satisfied or the repository owner explicitly authorizes an import exception.
