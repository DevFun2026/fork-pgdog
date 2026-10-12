# Publication native baseline dependencies

Scope: fix the environment regression demonstrated by publish run 38231991902, amd64 job114753554805: baseline Cargo linker invokes `/usr/bin/clang --ld-path=/usr/bin/mold`, which fails with invalid linker name. The package build job installs only skopeo; the artifact quality workflow already installs native dependencies. This is a necessary fix within the owner-authorized 0.2.0 release.

1. Preserve the failed run log as RED evidence. Keep source/app/config/baseline/scanner/publish gates unchanged.
2. Add the six existing artifact-quality native dependencies to the package build job, before build-artifact. Add actual compile/run linker smoke for the same absolute clang/mold flag; clean only its temporary files.
3. Validate workflow syntax, existing full artifact/runtime suites, docs/adapters, canonical quick/review evidence. The Linux linker smoke and native builds require Linux CI; local macOS cannot prove their execution.
4. Commit and open an isolated PR; preview exact independent AGY package and request its manifest approval. Merge only after independent review and all required CI/gates pass.
5. Re-export a receipt under the unchanged schema-3 merge-bound contract. Since the next workflow base is merged PR10, use that reviewed merge as the source boundary, retaining its original review/CI identity. Application tree remains unchanged. Obtain exact owner approval for the new concrete source/workflow payload before publication.
6. Retry only after successful checks and authenticated tag absence. Preserve signatures, protected environment, native smoke, baseline, scanners, byte identity and chart-last pullback. Rollback is to leave the failed release unpublished; no tag overwrite or gate bypass.

Deployment remains blocked for owner-confirmed PostgreSQL12: current strict-read registry supports only PG18. PG12 support is a separately approved feature scope; this linker fix does not change compatibility.
