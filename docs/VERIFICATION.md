# Verification for the PgDog fork

## Environment

- Rust follows `applications/pgdog/rust-toolchain.toml` (1.96, rustfmt, clippy); Cargo uses `--locked`.
- Python 3.11+, PostgreSQL 18 client/server, Toxiproxy 2.12.0 and nextest 0.9.78.
- PostgreSQL and Toxiproxy must be dedicated test instances. Upstream
  `applications/pgdog/integration/setup.sh` drops test databases and roles. Never point it at a
  shared or production database. Tests use synthetic credentials `pgdog`.
  Recreate fixtures before each full run: integration tests intentionally leave
  schema changes that can invalidate the next unit-test run.
- Use `./scripts/pgdog bash integration/ci/install-deps.sh` and
  `./scripts/pgdog bash integration/ci/setup.sh --with-toxi` only on disposable Ubuntu runners.
- For macOS, a Docker PostgreSQL instance can expose only `127.0.0.1:5432`.
  Tests also resolve `localhost`; ensure both IPv4 and IPv6 loopback reach the
  same test instance. Prepare Toxiproxy ports 5435–5438, API port 8474.
  Prefer a dedicated native PostgreSQL 18 cluster when Docker VM latency exceeds
  the upstream pool tests' 50 ms checkout budgets. Keep it separate from existing
  databases and stop only the test instance after verification.
  If a port is occupied, use a local config copy and set
  `PGDOG_TEST_CONFIG_DIR` to its directory. Do not stop unrelated services.
- On this workstation, `SDKROOT` needed to refer to the SDK inside Xcode;
  the CommandLineTools macOS 27 SDK was incompatible with the selected linker.
  An inherited obsolete `LDFLAGS` was removed for the build process only.

## Commands

Run repository gates from the root; `scripts/pgdog` runs Cargo commands inside
`applications/pgdog/`. Build output lives in `applications/pgdog/target/`.
GitHub validation runs only on pull requests or manual dispatch; publishing is
manual. GitLab accepts merge-request and web pipelines only.

```sh
./scripts/agent verify quick --timeout 3600 --json
./scripts/agent verify review --timeout 3600 --json
./scripts/agent verify merge --timeout 3600 --json
```

`quick` runs format, workspace Clippy with warnings denied, and focused library
unit/doc tests. `review` runs lint, `scripts/verify-pgdog full`, and workspace build.
The full script checks agent-runtime tests/adapters/docs/skills/notices, Rust
unit/doc tests and Rust PostgreSQL client integration tests. A test failure is
retained while other independent test phases continue. It needs prepared database
fixtures and builds/starts a local PgDog process for client integration tests.
`merge` additionally requires current documentation and independent review
artifacts bound to the exact trusted default branch, HEAD and working-tree digest.

The upstream CI matrix separately runs other language clients, TLS, COPY,
resharding, schema sync, network faults and load balancing. Its results must be
reported separately; local Rust tests do not establish that matrix passed.

## Security scanners

Install `cargo-deny 0.20.2` and Semgrep (`1.178.0` used for the initial run) on PATH:

```sh
./scripts/agent release run-scanner --scanner dependency --timeout 600
./scripts/agent release run-scanner --scanner license --timeout 600
./scripts/agent release run-scanner --scanner sast --timeout 600
```

`applications/pgdog/deny.toml` records an explicit SPDX allowlist, with no advisory exceptions.
Missing license metadata fails the scan. Semgrep's community `p/rust` rules are
fetched at run time, with metrics disabled: scanner reports are evidence for that
run, not a pinned/reproducible ruleset or comprehensive security clearance.
A finding is a review candidate; unsafe Rust matches are not automatically
confirmed exploitable vulnerabilities. Rule coverage and exclusions appear in logs.
Container/IaC scanners remain outside the approved standard profile's required
scanner list. EKS/Vault connectivity and production audit guarantees are untested.

## Independent review and release

```sh
./scripts/agent doctor --providers --json
./scripts/agent review --author-provider codex --reviewer-provider claude \
  --requirements docs/plans/2026-09-30-pgdog-quality-gates.md
```

A reviewer capability probe does not send repository content. Actual review needs
fresh passing `review` command evidence and user approval of the exact manifest.
The initial import is approximately 9.3 MB of diff, exceeding the current 500 KB
and 96,000 estimated-token limits. Do not switch the trusted base to an intermediate
commit, truncate the import, or auto-approve a manifest. A separately approved
large-import review procedure is needed if the full import cannot fit.

Release adds smoke/security gates and a detached security-approval signature from
an independent signer trusted in the base revision. `allowed_signers` is still a
template with no enrolled signer. No production release is authorized by this setup.

## Remediation details

The dependency lockfile includes patched advisory versions. `tikv-jemalloc-ctl`
is pinned to upstream commit `66b124bdf4f1c65f154135f4e9d4b25206540091`, which
removes the unmaintained `paste` macros; its sys dependency remains the existing
released 0.7.1 allocator binding. Review this temporary patch when the ctl fix is
released. Hickory 0.26 uses `TokioResolver`/`NetError`; DNS cache behavior retains
its existing tests.

Scoped `nosemgrep` comments document reviewed invariants: validated UTF-8,
borrowed plugin slices, trusted native plugin loading, bounded SIMD/FFI calls,
checked OS resource-limit pointers, test-only subprocess execution, SHA-1 shard
compatibility and TLS VerifyCa semantics. They suppress only the named rule at
the documented statement. Native plugins remain trusted code; VerifyCa checks
the certificate chain and signatures but intentionally omits hostname matching.
Use VerifyFull for hostname authentication. These dispositions are not a general
security approval of the imported project.

Environment-dependent tests now re-execute the exact test with variables supplied
at child startup, checking that exactly one test passed. Tests no longer mutate
the process environment while Tokio/other threads may read it. Ignored external
Azure/live-environment tests retain their explicit ignored status.

TLS reload integration tests honor `PGDOG_TEST_CONFIG_DIR`, matching the PgDog
process started by the gate. The replication test setup waits for an active source slot
with the existing bounded poll helper: the parent task reports "replicating"
before its child has created that slot. This also prevents fixture writes from
preceding the slot start LSN. The exact one-slot assertion remains.

Subscriber tests explicitly flush a synthetic WAL message before polling durable
commit status. Empty transactions do not request an async WAL flush; an unrelated
partial WAL page can otherwise keep the sampled insert position ahead of flush
beyond the five-second deadline. The fixture reproduces that tail while retaining
the assertions that acknowledgements advance only after durability and never to
an open transaction's future LSN. Production replication logic is unchanged.

The checkpoint fixture closes its final WAL segment before expecting every
completed segment to be recycled: a live phase record legitimately retains its
identity dependencies. Rotation support is compiled only for tests. The client-ID
fixture still holds and checks 500 clients, with at most 32 concurrent connection
handshakes to fit macOS's observed listen backlog of 128.


## CI trigger policy and regression checks

GitHub validation workflows run on pull requests or manual dispatch only.
Publishing and benchmark follow-up workflows require manual dispatch. GitLab
runs only for merge-request or manual web pipelines. Pushes do not trigger CI.

Auto-primary success fixtures use the same one-second checkout budget as the
other PostgreSQL fixtures. The former 50 ms override also bounded real database
connection startup and intermittently expired under Linux coverage. The explicit
no-primary timeout test retains its 10 ms budget and timeout assertion.

Native AGY terminal responses may contain repeated result JSON objects with
`toolAction`/`toolSummary` display strings. The parser requires every object to
agree with the strict `structured_output`, rejecting conflicts, extra fields,
trailing prose and malformed output. Native login review remains explicitly
approved and bound to its package; a parsed old review does not approve new code.

The partial-request disconnect fixture polls for zero active `ClientRead`
backends for at most one second, below the integration proxy's two-second query
timeout. Linux coverage observed two backends still cleaning up after the former
fixed 100 ms sleep. The zero-backend assertion and all 50 clients are retained.
The Rust client matrix runs serially and without fail-fast so every case runs.
