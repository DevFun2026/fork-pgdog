# PG12 publication workflow implementation

Input: approved PG12 release scope, existing schema-3 owner-release contract and
[bounded retention specification](../specs/2026-10-13-pg12-release-evidence.md).
Base: exact source merge `3ae8a35536640eddf153c7724edc34d9ff568df8`.
Use the isolated source clone on `codex/pg12-release-workflow`; preserve the
original checkout and all immutable source review evidence.

1. Smaller worker owns only `.github/workflows/package.yml`: add separate
   per-architecture retention of both smoke JSON reports. Preserve native OCI
   upload/download inventory and all publisher permissions/guards. Run existing
   artifact and workflow contracts; no duplicate implementation or mirror-only
   YAML tests. No provider, cluster, commit or publication action by the worker.
2. Primary owns project model and focused release/spec/plan docs. Rebuild
   generated architecture output and inspect worker diff/inventory behavior.
3. Run meaningful artifact checks and canonical quick gate. Commit/push the
   exact workflow PR for reviewed-head CI; run canonical review gate with owned
   PostgreSQL/Toxiproxy fixtures, full PG12/PG18 and legacy coverage.
4. Prepare exact independent native AGY package and obtain its new manifest
   approval before egress. Adjudicate findings and run matching merge gate.
   Merge only with current successful CI and exact reviewed head/tree/parents.
5. Export fresh 0.2.1 receipt from original source and workflow review/assessment
   identities and four immutable quality/artifact CI witnesses. Obtain exact
   owner payload approval before comment/finalization. Dispatch on current
   workflow merge; native builds/scans, protected environment, byte-preserving
   publish, signature/attestation and chart pull-back remain required.
6. Verify full anonymous image/chart pulls and prepare icondo digest-pinned
   read/write values when real context, table inventory, epoch and TLS/CA inputs
   are supplied. This task does not apply to an unidentified production cluster.
