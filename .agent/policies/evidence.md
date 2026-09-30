# Evidence policy

Claims of correctness, completion, mergeability, or release readiness require
fresh evidence for the current commit and diff. Each command record contains
exactly command ID, commit, diff checksum, exit code, status, output checksum,
tool version, start time, and duration. Raw sensitive output is not committed.

Record exact commands and observed exit codes. Confirm expected tests were
discovered. Separate product failure from environment, permission, network,
credential, and tool-availability failure. A skipped, stale, missing, timed-out,
or malformed required result cannot pass a gate.

AI review is evidence, not proof. Findings require a source location and
reproduction or invariant. Rejections require explicit reasons. Security
reports state scope, checks, unverified areas, and residual risks.
