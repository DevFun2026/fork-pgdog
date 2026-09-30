# Security Controls

The runtime provides immutable configuration, argument-array process execution,
path containment, symlink rejection, atomic owner-only writes, output limits,
secret and private-block redaction, manifest-bound review packages, structured
provider output validation, evidence checksums, progressive gates, and reviewed
memory promotion.

Controls are verified by repository tests and gate evidence. OWASP ASVS, SAMM,
and threat-modeling materials are requirement references only; this template
does not claim certification or full coverage of any framework.

## Reference mapping

| Template requirement | Reference baseline | Use |
|---|---|---|
| Technical application controls | OWASP ASVS 5.0.0 | Select applicable, version-qualified requirement IDs for the adopting project |
| Secure lifecycle and governance | OWASP SAMM 2.0 | Assess and improve practices; not a release certificate |
| Assets, actors, flows, boundaries, threats, mitigations, review | OWASP Threat Modeling Cheat Sheet, reviewed 2026-09-21 | Method guidance; project evidence remains authoritative |

References: <https://owasp.org/projects/asvs>,
<https://owaspsamm.org/model/>, and
<https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html>.
