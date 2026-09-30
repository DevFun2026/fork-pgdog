# Security controls

| Risk | Preventive control | Detective control | Recovery control | Evidence | Owner |
|---|---|---|---|---|---|
| Untrusted path | Containment and symlink rejection | Boundary tests | Remove unsafe artifact | Test output and commit | Project owner |
| Secret egress | Deny rules and preflight scan | Secret scanner | Revoke and rotate | Scanner evidence | Security owner |
| Package tampering | Manifest checksums | Pre-provider revalidation | Rebuild package | Manifest and audit record | Reviewer |
| Prompt injection | Treat repository content as data | Structured output validation | Discard invalid result | Review audit | Reviewer |

Map project-specific controls to requirements. A reference is not evidence that
the control exists or works.
