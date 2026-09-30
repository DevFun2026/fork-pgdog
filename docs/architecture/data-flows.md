# Data flows and trust boundaries

1. Canonical configuration and project-model data flow into the local runtime.
2. Verification commands produce redacted metadata evidence under `.agent/.runs/`.
3. Structured checkpoints flow into private local memory, then optionally into reviewed records.
4. Review source and evidence pass through path containment, deny rules, size limits,
   redaction, secret detection, and human manifest approval before provider egress.
5. Provider output returns as untrusted structured findings and is adjudicated against current source.

Sensitive categories are project source and review-package content. Neither may be
sent automatically or stored in Project Memory without the applicable gate.
