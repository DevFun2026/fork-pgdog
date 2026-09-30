# Deployment and operation

The template is copied into a project repository rather than deployed as a service.
`scripts/agent` runs directly from the checkout on macOS, Linux, or WSL. No daemon,
telemetry, cloud memory, vector database, or product-environment installation is used.

Hosted CI uses thin wrappers. Provider-backed jobs are separate and protected.
Recovery relies on Git history, atomic generated-file replacement, SQLite transactions,
and preserved review packages. A release must document migration, backup, rollback,
unverified areas, and residual risks.
