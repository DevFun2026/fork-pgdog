# Operations and recovery runbooks

## Start or resume work

1. Run `./scripts/agent doctor --json --providers`.
2. Run `./scripts/agent memory bootstrap --query "current task"`.
3. Inspect `./scripts/agent workflow status --json` and the current Git status.

## Review recovery

If a provider times out or is unauthenticated, preserve the review package, fix the provider session, then rerun with the same package path and approved manifest checksum. Never convert a provider failure into approval.

## Documentation recovery

Run `./scripts/agent docs build`, inspect the generated summary and HTML, then run `./scripts/agent docs check` after committing the intended change.

## Memory recovery

Use `memory doctor` and `memory rebuild-index`. Canonical Markdown records remain the recovery source; SQLite is a disposable index. Export/import is checksum-validated and transactional.

## Release rollback

Stop the release when any gate is blocked or incomplete. Preserve evidence, restore the last known-good release reference, follow project-specific data rollback instructions, and record residual risk before retrying.

## Architecture Pages publication and recovery

After the reviewed change is merged, enable GitHub Actions as the repository's
Pages source and allow only main in the github-pages deployment environment.
Run gh workflow run architecture-pages.yml --ref main, inspect the build/deploy
run, then verify the public site before setting it as the repository homepage.
A PR or a push never deploys this site. A manual run from another branch fails.

If a publication fails, retain the last successful deployment, inspect the
Actions logs and fix the source/model or Pages settings. Rebuild with the same
canonical generator. Restore a previous page through a reviewed source revert
and a new manual dispatch from main; do not publish unreviewed branch content.
