# Data classification

| Category | Examples | Allowed storage | Allowed egress | Retention | Required controls |
|---|---|---|---|---|---|
| Public | Published documentation | Repository | Approved providers | Project policy | Integrity checks |
| Internal | Source and architecture | Repository, approved local cache | Manifest-approved review only | Project policy | Least privilege, checksums |
| Sensitive | Private product or user data | Explicit approved stores | Denied by default | Minimum necessary | Encryption, access log, redaction |
| Secret | Tokens, keys, credentials | Secret manager only | Never in review or memory | Rotate on exposure | Detection, masking, revocation |

Every project replaces the examples with its real data categories and owners.
