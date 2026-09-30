# Data Classification

| Data | Classification | Storage | Egress rule |
|---|---|---|---|
| Canonical policies and public docs | Public or internal | Git | Allowed by repository policy |
| Product source and diffs | Internal | Git and approved review package | Exact manifest approval required |
| Canonical Project Memory | Internal | Git Markdown records | Same review-package policy as source |
| Local candidates and run artifacts | Internal or sensitive | `.agent/.memory/`, `.agent/.runs/` | Denied by default |
| Credentials, private blocks, personal data | Secret or sensitive | Approved external secret/data store | Never auto-injected or exported |

Projects must classify their own user and business data before enabling review
egress or memory capture.
