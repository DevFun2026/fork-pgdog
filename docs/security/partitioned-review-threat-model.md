# Partitioned review threat-model delta

Scope: local packaging, cross-provider egress approval, result aggregation and
merge evidence. Existing provider subprocess/OS sandbox and secret/path rules
remain applicable. No actual provider review or signed security clearance is
claimed by this local assessment.

| Threat | Control and verification |
| --- | --- |
| Dropped/duplicated registry records or changed-file bytes | Recompute full Git projection and deterministic ranges; concatenate exact original bytes; reject gap/overlap/tampering. |
| Feature branch expands its own authority | Read partition enablement and aggregate/per-call caps from resolved trusted ancestor; default disabled. |
| Probe or egress before user approval | Root exact-hash check precedes child probes; integration has a different exact approval after outputs exist. |
| Child pass mistaken for whole-change pass | Suppress global artifact publication for children; require all children plus integration; merge reloads every result. |
| Edited or stale child results | Bind audit/output hashes and package hashes to immutable root state and integration manifest; reload before second invocation and merge. |
| Invalid provider output or identity | Validate schema, provider, exit/status/verdict; malformed or incomplete results remain pending. |
| Hidden extra files or symlink expansion | Inventory checks and existing denied-path/content scanning; isolated provider package with existing sandbox. |
| Aggregate resource/context overflow | Count actual complete invocation payloads, duplicated context, metadata, token rounding and integration reserve; reject overflow. |
| Lost cross-shard architecture reasoning | Explicit immutable integration contracts, complete scope and all outputs; reviewer must reject insufficient context. |

Residual risk: model reviews remain fallible; safe byte coverage does not itself
prove SQL correctness. Integration context selection requires manager judgment,
and provider findings still need reproduction/adjudication. Unknown or oversized
record formats deliberately block rather than degrade review completeness.
