# Fork artifact migration, backup and rollback

Replacing the official PgDog distribution requires a fresh source-built image
and this repository's standalone chart. Copy reviewed configuration/users/TLS
through your existing protected object process, preserve previous image digests,
chart revisions and external object versions, and validate SQL/auth/drain in an
isolated cluster before switching application traffic. Confirm numeric UID/GID
10001 can read all required mounted files. Do not carry mutable main/latest tags
into the release record. No database/schema migration is part of this feature.

Use `helm history` and `helm rollback RELEASE REVISION --wait --timeout 5m`
with the explicit operator kube context/namespace. Check rollout, readiness and
actual SQL afterwards. A digest-pinned chart needs the previous image digest;
setting only a previous image tag leaves the current digest selected.
Helm restores chart-managed inline ConfigMaps/values, while external ConfigMaps,
users/TLS/config Secrets and database state require separate restoration from
their preserved versions. Rotate credentials/certificates in coordination with
the backend and explicitly restart Pods. Helm history is not an external Secret
backup. Do not forcibly delete active Pods when relying on SIGINT drain.

For a partial publication, inspect each image/platform/SHA tag, combined digest,
signature/attestation and chart version to record what exists. Do not rerun over
an existing immutable tag, relabel an old receipt, overwrite a chart or silently
roll back the registry. A new reviewed source/version or explicitly authorized
registry cleanup is required. Artifact deletion and visibility changes are
separate owner actions. Keep working previous artifacts available to operators.

Development rollback is an authorized reviewed revert of scoped feature commits;
retain unrelated work, upstream attribution, operator Secrets and PostgreSQL
data. The stateless chart does not provide durable 2PC WAL restore or a disaster
recovery system. Database backup/restore, network/TLS policy, registry writes and
incident response belong to the deployment owner.
