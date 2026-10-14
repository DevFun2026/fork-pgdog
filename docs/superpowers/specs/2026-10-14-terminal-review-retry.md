# Supervised terminal child retry

Approved by the human on 2026-10-14 via the terminal-retry proposal. Approval covers implementation and independent infrastructure review; it does not approve any new provider payload hash.

## Contract
A retry is a fresh, separately approved read-only review attempt for exactly the original immutable child input. Keep the original marker, canonical audit, output and passing sibling rows byte-for-byte. Create a new child clone, retry manifest, dispatch marker and append-only attempt record. Only validated selected output can participate in root integration/clearance.

A supervisor receipt is required: the provider exited 0, owned initial process group ended, input/prompt identity is retained, and no valid verdict was produced. Bind root/child manifest hashes, invocation nonce/PID/PGID, native audit and raw stdout/stderr hashes, original canonical audit hash and full input inventory. PID must equal the dedicated PGID and the launch identity must bind that PID. Unknown/interrupted/timeout invocations and valid pass/fail results are ineligible; do not derive termination proof from a timestamp.

Preview is local. The retry manifest binds base/head, logical child and immediate prior source attempt, all earlier evidence, model, resolved executable digest, normalized complete argv digest, complete inline prompt digest and attempt limit. Exact approval must precede any capability probe or provider launch. Recheck the actual native transport immediately before launch. Hold the existing root operation lock for dispatch; duplicate/ambiguous claims cannot execute.

At most two retries per logical child are supported. The second must have its own supervised terminal receipt for the previous retry clone; it cannot reuse the initial receipt. Count every retry payload across the whole root against existing per-invocation and trusted aggregate ceilings, including integration. Reject source, receipt, manifest, output or ledger drift.

Reload the complete retry history at integration and clearance, include its hashes in integration context, and require every selected child plus separately approved integration to pass. Preserve historical integration context exactly when there are no retry records. Missing legacy receipt evidence keeps old attempts pending.

## Native transport boundary
Native logged-in AGY needs explicit host authorization and `--native-host`; it is not the default sandbox route. Every approved UTF-8 input byte is supplied inline with length/hash framing. Reads and checks refer to this attached data; runtime validates hashes, model reviews the source. Do not enable global provider permissions or `--dangerously-skip-permissions`.

Private create-once output files and a dedicated process group bound output and lifetime. RLIMIT pre-exec is limited to a single main-thread caller. Group cleanup cannot prove that a malicious process did not escape its session; host exception and same-user operator trust remain residual risks. Receipts are local dispatcher evidence, not signed security clearance.

## Acceptance
Meaningful RED/GREEN for terminal eligibility, missing/wrong approval, raw byte provenance, process identity, clone preservation, replay/locking/attempt limits, aggregate overflow across children, all-history tampering after PASS and unchanged historical behavior. Run full configured local gates and independent infrastructure review before feature use.
