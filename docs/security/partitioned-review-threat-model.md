# Partitioned review threat-model delta

Scope: local packaging, cross-provider egress approval, result aggregation and
merge evidence. Existing provider subprocess/OS sandbox and secret/path rules
remain applicable. No actual provider review or signed security clearance is
claimed by this local assessment.

| Threat | Control and verification |
| --- | --- |
| Dropped/duplicated registry or v2 dependency-profile records or changed-file bytes | Recompute full Git projection and deterministic ranges; concatenate exact original bytes; reject gap/overlap/tampering. |
| Feature branch expands its own authority | Read partition enablement and aggregate/per-call caps from resolved trusted ancestor; default disabled. |
| Probe or egress before user approval | Root exact-hash check precedes child probes; integration has a different exact approval after outputs exist. |
| Child pass mistaken for whole-change pass | Suppress global artifact publication for children; require all children plus integration; merge reloads every result. |
| Edited or stale child results | Bind audit/output hashes and package hashes to immutable root state and integration manifest; reload before second invocation and merge. |
| Invalid provider output or identity | Validate schema, provider, exit/status/verdict; malformed or incomplete results remain pending. |
| Hidden extra files or symlink expansion | Inventory checks and existing denied-path/content scanning; isolated provider package with existing sandbox. |
| Aggregate resource/context overflow | Count actual complete invocation payloads, duplicated context, metadata, token rounding and integration reserve; reject overflow. |
| Repeated or concurrent dispatch exceeds the approved operation | Persist an exclusive attempt claim before dispatch; reuse completed results and integration manifest; ambiguous attempts remain pending. |
| Lost cross-shard architecture reasoning | Explicit immutable integration contracts, complete scope and all outputs; reviewer must reject insufficient context. |

Residual risk: model reviews remain fallible; safe byte coverage does not itself
prove SQL correctness. Integration context selection requires manager judgment,
and provider findings still need reproduction/adjudication. Unknown or oversized
record formats deliberately block rather than degrade review completeness.

## Approved v2 profile extension

Only eight exact PG12/PG18 dependency profile paths may use catalog-record
partitioning. Envelope schema, selector and provenance validation precedes
splitting. Unsupported layouts and individual records exceeding a child payload
limit fail closed. Records and metadata remain original diff bytes, with range
and digest reconstruction revalidated when loading evidence.

The project aggregate ceiling becomes 30 MB / 8 million estimated tokens only
after the separately reviewed infrastructure is in the trusted base. Runtime
defaults and per-call caps stay unchanged. Larger aggregate authorization can
require many invocations; actual repeated context and integration reserve still
count against the ceiling. Neither approved design nor an infrastructure PASS
authorizes sending an unapproved feature manifest or grants feature clearance.

## Terminal retry delta

| Threat | Control / residual limitation |
| --- | --- |
| Reset an ambiguous marker to send source again | Preserve original artifacts/markers; separate exact retry approval and supervisor terminal receipt; reject unknown/running/timeout/fail outcomes. |
| Retry mutates earlier passing evidence | Separate clone/attempt, root-bound selection, reload prior artifacts and all child receipts before integration/clearance. |
| Command/model/prompt changes after preview | Bind executable digest, normalized full argv digest, model and complete prompt digest; compare actual transport before dispatch and native launch. |
| Concurrent or repeated retry exceeds authorization | Same exclusive root lock, one-use dispatch claim, monotonic bounded attempts, existing aggregate ceiling includes retry payloads. |
| Symlink or altered terminal evidence | Regular-file/ancestor checks, repository-contained paths and all raw evidence digests bound in the approved retry manifest. |
| Mutable local receipt treated as independent attestation | Receipt is dispatcher evidence within the existing local operator trust boundary, not a signature or security clearance. Exact human approval freezes its evidence; a compromised same-user host remains out of scope. |
| Orphan provider process remains active | Dedicated native process group and bounded cleanup. Only confirmed group termination can support eligibility; escaped-session processes remain a native-host exception risk. |

The original full-read root has three empty-output audits and one interrupted
attempt without these new supervisor receipts. Their absence remains a blocker;
this change does not retrospectively attest their termination. No global
provider tool permissions, API credentials, PgDog write restrictions or Standard
security profile are changed.
