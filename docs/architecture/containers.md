# Containers and major units

- **Canonical core:** `.agent/` policies, skills, schemas, templates, and model.
- **Runtime:** Python 3.11 standard-library CLI invoked through `scripts/agent`.
- **Provider adapters:** capability detection and read-only structured review calls.
- **Review engine:** package construction, secret/path checks, orchestration, and adjudication.
- **Project Memory:** local SQLite candidates plus reviewed Markdown records.
- **Documentation generator:** deterministic Markdown and whole-system HTML.
- **CI wrappers:** GitHub Actions and GitLab CI calling identical local gates.
