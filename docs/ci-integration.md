# CI Integration

Both GitHub Actions and GitLab CI call the same repository-owned runtime used
locally. The ordinary untrusted job runs without provider credentials on Linux;
GitHub also runs the unit suite on macOS. Failure artifacts contain only the
redacted evidence metadata written under `.agent/.runs/evidence/` and expire
after seven days.

The protected merge job is manual and fail-closed. Before enabling it as a
required check, an adopting project must add its protected mechanism for
restoring current documentation-impact, independent-review, and cross-review
artifacts. Those artifacts must identify the candidate commit/diff and come
from a manifest-approved review. The template deliberately does not synthesize
passing review evidence or expose provider secrets to fork code.
The protected jobs fetch full history for the remote default branch and create
`refs/remotes/origin/HEAD` before running governance gates. A shallow candidate
checkout without this immutable proper-ancestor anchor fails closed. GitHub uses
the job token only in the explicit fetch URL and does not persist it in Git
configuration; this supports private repositories while keeping checkout
credentials ephemeral.

Run the same checks locally:

```sh
./scripts/agent doctor --ci
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.agent/runtime python3 -m unittest discover -s .agent/tests -v
./scripts/agent adapters check
./scripts/agent docs check
./scripts/agent skills check
./scripts/agent licenses audit --json
bash scripts/release-smoke.sh
```

Provider-backed review also requires an OS read boundary: `sandbox-exec` on
macOS or `bwrap` on Linux. The provider process receives only the immutable
approved package plus exact external executable/support files; repository-local
provider executables and caller-selected host file/directory grants are rejected,
and its HOME is replaced with an isolated temporary directory. Capability probes
run without network or credentials and only after exact manifest approval. The
review invocation forwards only provider-specific authentication
variables plus a small network/locale allowlist, and Codex child commands inherit
no environment. Do not mount a general credential store.
If the sandbox, configured provider command, or required scanner is missing,
the job remains pending/blocked instead of synthesizing approval.
The shipped GitHub and GitLab jobs install the Linux `bubblewrap` package before
running the suite; self-hosted runners must provide the equivalent prerequisite.

Pin every third-party CI action to a full commit SHA. Keep provider-backed jobs
in a protected environment, trigger them only after exact review-manifest
approval, and never make their credentials available to pull requests from
forks.
