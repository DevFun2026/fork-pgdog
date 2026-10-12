# Security Controls

The runtime provides immutable configuration, argument-array process execution,
path containment, symlink rejection, atomic owner-only writes, output limits,
secret and private-block redaction, manifest-bound review packages, structured
provider output validation, evidence checksums, progressive gates, and reviewed
memory promotion.

Controls are verified by repository tests and gate evidence. OWASP ASVS, SAMM,
and threat-modeling materials are requirement references only; this template
does not claim certification or full coverage of any framework.

## Fork distribution controls

Pinned Docker bases, locked Cargo, excluded Git/private context and numeric
non-root image reduce build/runtime exposure. Chart schema rejects unknown or
conflicting inputs; literal TOML is never executed through tpl. Read-only root
and secret mounts, RuntimeDefault seccomp, no capabilities/escalation/token,
bounded tmp and backend-aware readiness are exercised by artifact/Kind tests.
Standard profile now requires dependency, license, SAST, IaC and container scans;
binding checks reject stale source/image/generated input and missing tool/DB coverage.

Read-only native validation has no package-write/OIDC credential. Protected
manual publication validates exact owner-approved receipt/source ancestry,
confirmed authenticated tag absence and exact tested archive identity before
copying; source-aware signatures/attestations are verified before chart publish.
These controls do not supply production TLS/network/Secret policy or signed
repository security clearance. A trusted independent signer is still required.


## Reference mapping

Strict-read controls and their SQL, role, catalog and deployment limits are
specified in [strict read/write operations](../operations/strict-read-endpoints.md).
The mode is explicitly selected at process creation, rejects unsafe reloads and
keeps the unrestricted endpoint separate. Parser admission and PostgreSQL READ
ONLY are independent controls; neither a manifest name nor the original PgDog
`read_only` routing setting alone authorizes a read query. Core and raw-wire tests
use disposable fixtures and compare state after denied writes.

| Template requirement | Reference baseline | Use |
|---|---|---|
| Technical application controls | OWASP ASVS 5.0.0 | Select applicable, version-qualified requirement IDs for the adopting project |
| Secure lifecycle and governance | OWASP SAMM 2.0 | Assess and improve practices; not a release certificate |
| Assets, actors, flows, boundaries, threats, mitigations, review | OWASP Threat Modeling Cheat Sheet, reviewed 2026-09-21 | Method guidance; project evidence remains authoritative |

References: <https://owasp.org/projects/asvs>,
<https://owaspsamm.org/model/>, and
<https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html>.
