from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from agent_cli.config import ConfigError, ProjectConfig, load_config_at_revision
from agent_cli.evidence import EvidenceStore, record_result
from agent_cli.governance import GovernanceBaseError, resolve_trusted_base
from agent_cli.process import run_command
from agent_cli.review.package import ReviewPackageBlocked, load_package
from agent_cli.security import (
    ReleaseContext,
    SecurityAssessment,
    SecurityPolicyError,
    assess_repository,
    release_check,
    validate_signed_approval,
)
from agent_cli.workflow import WorkflowState

QUICK_COMMANDS = ("format_check", "lint", "test_changed")
MERGE_COMMANDS = ("lint", "test_full", "build")
RELEASE_COMMANDS = ("lint", "test_full", "build", "smoke")


@dataclass(frozen=True)
class GateResult:
    level: str
    status: str
    reasons: tuple[str, ...]
    executed: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _git_output(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ("git", *arguments),
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return ""
    return result.stdout


def git_identity(root: Path) -> tuple[str, str]:
    commit = _git_output(root, "rev-parse", "HEAD").strip()
    if len(commit) != 40:
        commit = "0" * 40
    diff = _git_output(root, "diff", "--binary", "HEAD").encode("utf-8")
    return commit, sha256(diff).hexdigest()


def tool_identity(
    argv: tuple[str, ...],
    root: Path,
    *,
    version_argv: tuple[str, ...] | None = None,
    support_paths: tuple[str, ...] = (),
) -> str:
    executable = shutil.which(argv[0])
    if executable is None:
        candidate = (root / argv[0]).resolve()
        executable = str(candidate) if candidate.is_file() else None
    if executable is None:
        return f"unresolved:{argv[0]}"
    path = Path(executable).resolve()
    version_command = version_argv or (str(path), "--version")
    version_executable = shutil.which(version_command[0])
    if version_executable is None:
        version_candidate = (root / version_command[0]).resolve()
        version_executable = str(version_candidate) if version_candidate.is_file() else None
    if version_executable is None:
        return f"unresolved-version-command:{version_command[0]}"

    artifact_paths: list[Path] = [path, Path(version_executable).resolve()]
    for value in (*argv[1:], *version_command[1:]):
        if "=" in value and value.split("=", 1)[1]:
            value = value.split("=", 1)[1]
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            resolved = candidate.resolve()
            if resolved.is_file():
                artifact_paths.append(resolved)
        except OSError:
            continue
    for value in support_paths:
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            resolved = candidate.resolve(strict=True)
            if resolved.is_dir():
                try:
                    resolved.relative_to(root.resolve())
                except ValueError:
                    pass
                else:
                    raise ValueError(
                        "scanner support directories must be outside the repository"
                    )
                artifact_paths.extend(
                    item.resolve()
                    for item in sorted(resolved.rglob("*"))
                    if item.is_file() and not item.is_symlink()
                )
            elif resolved.is_file():
                artifact_paths.append(resolved)
        except OSError as exc:
            raise ValueError(f"scanner support path is unavailable: {value}") from exc
    artifacts: list[str] = []
    for artifact in dict.fromkeys(artifact_paths):
        try:
            artifacts.append(
                f"{artifact}:{sha256(artifact.read_bytes()).hexdigest()}"
            )
        except OSError:
            artifacts.append(f"{artifact}:unreadable")
    identity_material = json.dumps(
        {
            "command": list(argv),
            "version_command": list(version_command),
            "support_paths": list(support_paths),
        },
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n" + "\n".join(sorted(artifacts))
    digest = sha256(identity_material.encode("utf-8")).hexdigest()
    version = ""
    try:
        probe = subprocess.run(
            (str(Path(version_executable).resolve()), *version_command[1:]),
            cwd=root,
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
        if probe.returncode == 0:
            version = (probe.stdout or probe.stderr).splitlines()[0].strip()[:200]
    except (OSError, subprocess.TimeoutExpired, IndexError):
        pass
    return f"{version or 'version-unavailable'};runtime-sha256:{digest}"


def _valid_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return True


def _read_json_object(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def collect_fresh_verification_evidence(
    root: Path, command_ids: tuple[str, ...]
) -> dict[str, object]:
    commit, diff_hash = git_identity(root)
    evidence_root = root / ".agent/.runs/evidence"
    records: dict[str, dict[str, object]] = {}
    if evidence_root.is_dir():
        for path in sorted(evidence_root.glob("*.json")):
            payload = _read_json_object(path)
            command_id = payload.get("command_id")
            if (
                isinstance(command_id, str)
                and command_id in command_ids
                and payload.get("commit") == commit
                and payload.get("diff_sha256") == diff_hash
                and payload.get("status") == "passed"
            ):
                records[command_id] = payload
    missing = [command_id for command_id in command_ids if command_id not in records]
    if missing:
        raise ValueError(
            "missing fresh verification evidence: " + ", ".join(missing)
        )
    return {
        "head_sha": commit,
        "working_tree_diff_sha256": diff_hash,
        "records": [records[command_id] for command_id in command_ids],
    }


def _working_tree_is_dirty(root: Path) -> bool:
    result = subprocess.run(
        ("git", "status", "--porcelain=v1", "--untracked-files=all"),
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0 and bool(result.stdout.strip())


def _bound_artifact_valid(
    root: Path,
    artifact: dict[str, object],
    *,
    current_head: str,
    current_worktree_diff: str,
    require_source: bool = False,
) -> bool:
    if (
        artifact.get("status") != "passed"
        or artifact.get("head_sha") != current_head
        or artifact.get("working_tree_diff_sha256") != current_worktree_diff
    ):
        return False
    if not require_source:
        return True
    source_path = artifact.get("source_path")
    source_sha = artifact.get("source_sha256")
    if not isinstance(source_path, str) or not isinstance(source_sha, str):
        return False
    try:
        path = (root / source_path).resolve()
        path.relative_to(root.resolve())
    except ValueError:
        return False
    return (
        path.is_file()
        and not path.is_symlink()
        and sha256(path.read_bytes()).hexdigest() == source_sha
    )


def _security_artifact_valid(
    root: Path,
    security: dict[str, object],
    *,
    current_head: str,
    approved_profile: str,
    trusted_base: str,
) -> bool:
    if security.get("status") != "passed" or security.get("head_sha") != current_head:
        return False
    base_sha = security.get("base_sha")
    diff_sha = security.get("diff_sha256")
    approval = security.get("approval_evidence")
    if (
        not isinstance(base_sha, str)
        or base_sha != trusted_base
        or not isinstance(diff_sha, str)
        or not isinstance(approval, dict)
    ):
        return False
    current_diff = _git_output(root, "diff", "--binary", base_sha, current_head)
    if sha256(current_diff.encode("utf-8")).hexdigest() != diff_sha:
        return False
    path_value = approval.get("path")
    signature_value = approval.get("signature_path")
    if not isinstance(path_value, str) or not isinstance(signature_value, str):
        return False
    try:
        evidence = (root / path_value).resolve()
        signature = (root / signature_value).resolve()
        evidence.relative_to(root.resolve())
        signature.relative_to(root.resolve())
        assessment = SecurityAssessment(
            approved_profile=str(security["approved_profile"]),
            assessed_profile=str(security["assessed_profile"]),
            reviewed_scope=tuple(security["reviewed_scope"]),
            review_lenses=tuple(security["review_lenses"]),
            required_artifacts=tuple(security["required_artifacts"]),
            checks_performed=tuple(security["checks_performed"]),
            unverified_areas=tuple(security["unverified_areas"]),
            residual_risks=tuple(security["residual_risks"]),
            base_sha=base_sha,
            head_sha=current_head,
            diff_sha256=diff_sha,
        )
        expected = assess_repository(
            root,
            approved_profile=approved_profile,
            base=base_sha,
            head=current_head,
        )
        if assessment != expected:
            return False
        validated = validate_signed_approval(root, assessment, evidence, signature)
    except (OSError, ValueError, KeyError, TypeError, SecurityPolicyError):
        return False
    return validated == approval


def _review_artifact_valid(
    root: Path,
    review: dict[str, object],
    *,
    kind: str,
    current_head: str,
    trusted_base: str,
) -> bool:
    if (
        review.get("status") not in {"passed", "blocked"}
        or review.get("verdict") not in {"pass", "fail"}
        or review.get("kind") != kind
        or review.get("head_sha") != current_head
        or review.get("base_sha") != trusted_base
        or review.get("author_provider") == review.get("reviewer_provider")
    ):
        return False
    package_value = review.get("package_path")
    manifest_sha = review.get("manifest_sha256")
    findings_sha = review.get("findings_sha256")
    if not all(isinstance(value, str) and value for value in (package_value, manifest_sha, findings_sha)):
        return False
    try:
        if review.get("partitioned") is True:
            from agent_cli.review.partition import load_partition
            from agent_cli.review.partition_orchestrator import PartitionOrchestrator
            operation = load_partition(root / str(package_value), root=root)
            if not PartitionOrchestrator({}).clearance_valid(operation):
                return False
            package = operation.root_package
            actual_manifest_sha = operation.manifest_sha256
        else:
            package = load_package(root / str(package_value), root=root)
            actual_manifest_sha = package.manifest_sha256
    except (ReviewPackageBlocked, ValueError, OSError):
        return False
    manifest = package.manifest
    if (
        actual_manifest_sha != manifest_sha
        or manifest.base_sha != review.get("base_sha")
        or manifest.head_sha != current_head
        or manifest.diff_sha256 != review.get("diff_sha256")
        or manifest.author_provider != review.get("author_provider")
        or manifest.reviewer_provider != review.get("reviewer_provider")
    ):
        return False
    current_diff = _git_output(root, "diff", "--binary", manifest.base_sha, current_head)
    current_scope = tuple(
        sorted(
            item
            for item in _git_output(
                root, "diff", "--name-only", manifest.base_sha, current_head
            ).splitlines()
            if item
        )
    )
    if (
        sha256(current_diff.encode("utf-8")).hexdigest() != (manifest.full_diff_sha256 or manifest.diff_sha256)
        or current_scope != manifest.scope
    ):
        return False
    findings_path = package.path / "findings.json"
    if not findings_path.is_file() or findings_path.is_symlink():
        return False
    findings_bytes = findings_path.read_bytes()
    if sha256(findings_bytes).hexdigest() != findings_sha:
        return False
    findings = _read_json_object(findings_path)
    finding_rows = findings.get("findings")
    if (
        findings.get("verdict") != review.get("verdict")
        or not isinstance(finding_rows, list)
    ):
        return False
    if review.get("verdict") == "pass" and finding_rows:
        return False
    adjudication = _read_json_object(root / ".agent/.runs/adjudication.json")
    if (
        adjudication.get("status") != "passed"
        or adjudication.get("head_sha") != current_head
        or adjudication.get("manifest_sha256") != manifest_sha
        or adjudication.get("findings_sha256") != findings_sha
        or adjudication.get("package_path") != package_value
        or adjudication.get("blocking_ids") != []
    ):
        return False
    decisions = adjudication.get("decisions")
    if not isinstance(decisions, list) or len(decisions) != len(finding_rows):
        return False
    rows_by_id = {
        row.get("id"): row
        for row in finding_rows
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    decisions_by_id = {
        row.get("id"): row
        for row in decisions
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    if len(rows_by_id) != len(finding_rows) or set(rows_by_id) != set(decisions_by_id):
        return False
    for finding_id, finding in rows_by_id.items():
        decision = decisions_by_id[finding_id]
        severity = finding.get("severity")
        disposition = decision.get("disposition")
        expected_block = severity in {"critical", "high"} and disposition != "rejected"
        if (
            decision.get("severity") != severity
            or disposition not in {"confirmed", "rejected", "needs-evidence"}
            or decision.get("blocks_merge") != expected_block
            or not isinstance(decision.get("reason"), str)
            or not str(decision.get("reason")).strip()
        ):
            return False
    return True


def _scanner_evidence(
    root: Path,
    checks: dict[str, object],
    *,
    current_head: str,
    current_worktree_diff: str,
    required_scanners: tuple[str, ...],
    scanner_commands: Mapping[str, tuple[str, ...]],
    scanner_version_commands: Mapping[str, tuple[str, ...]],
    scanner_support_paths: Mapping[str, tuple[str, ...]],
) -> dict[str, str]:
    if (
        checks.get("head_sha") != current_head
        or checks.get("working_tree_diff_sha256") != current_worktree_diff
        or checks.get("required") != list(required_scanners)
        or not isinstance(checks.get("results"), dict)
    ):
        return {}
    statuses: dict[str, str] = {}
    for scanner, raw in checks["results"].items():
        if not isinstance(scanner, str) or not isinstance(raw, dict):
            return {}
        status = raw.get("status")
        tool_version = raw.get("tool_version")
        output_path = raw.get("output_path")
        output_sha = raw.get("output_sha256")
        command_sha = raw.get("command_sha256")
        command = scanner_commands.get(scanner, ())
        version_command = scanner_version_commands.get(scanner, ())
        support_paths = scanner_support_paths.get(scanner, ())
        expected_command_sha = sha256(
            json.dumps(list(command), separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        try:
            expected_tool_identity = tool_identity(
                command,
                root,
                version_argv=version_command,
                support_paths=support_paths,
            )
        except ValueError:
            return {}
        if (
            status not in {"passed", "failed", "skipped", "timeout"}
            or not command
            or not version_command
            or not isinstance(tool_version, str)
            or not tool_version.strip()
            or tool_version != expected_tool_identity
            or command_sha != expected_command_sha
            or not isinstance(output_path, str)
            or not isinstance(output_sha, str)
        ):
            return {}
        try:
            path = (root / output_path).resolve()
            path.relative_to(root.resolve())
        except ValueError:
            return {}
        if not path.is_file() or path.is_symlink():
            return {}
        output_bytes = path.read_bytes()
        if sha256(output_bytes).hexdigest() != output_sha:
            return {}
        output = _read_json_object(path)
        if set(output) != {
            "scanner",
            "status",
            "exit_code",
            "timed_out",
            "started_at",
            "duration_ms",
            "stdout",
            "stderr",
        }:
            return {}
        exit_code = output.get("exit_code")
        timed_out = output.get("timed_out")
        duration_ms = output.get("duration_ms")
        if (
            (exit_code is not None and (not isinstance(exit_code, int) or isinstance(exit_code, bool)))
            or not isinstance(timed_out, bool)
            or not isinstance(duration_ms, int)
            or isinstance(duration_ms, bool)
            or duration_ms < 0
            or not _valid_utc_timestamp(output.get("started_at"))
            or (timed_out and exit_code is not None)
            or (not timed_out and exit_code is None)
        ):
            return {}
        derived_status = (
            "timeout"
            if timed_out
            else "passed"
            if exit_code == 0
            else "failed"
        )
        if (
            output.get("scanner") != scanner
            or output.get("status") != status
            or status != derived_status
            or not isinstance(output.get("stdout"), str)
            or not isinstance(output.get("stderr"), str)
        ):
            return {}
        statuses[scanner] = status
    return statuses


def _artifact_reasons(level: str, root: Path, config: ProjectConfig) -> list[str]:
    if level in {"quick", "review"}:
        return []
    run_root = root / ".agent/.runs"
    reasons: list[str] = []
    if _working_tree_is_dirty(root):
        reasons.append("unreviewed-working-tree")
    current_head, current_worktree_diff = git_identity(root)
    try:
        trusted_base, anchored_head = resolve_trusted_base(root, head=current_head)
        if anchored_head != current_head:
            raise GovernanceBaseError("governance head changed while validating artifacts")
        trusted_config = load_config_at_revision(root, trusted_base)
    except (ConfigError, GovernanceBaseError):
        return ["trusted-governance-base"]
    profile_rank = {"baseline": 0, "standard": 1, "high": 2}
    approved_profile = max(
        (config.security_profile, trusted_config.security_profile),
        key=profile_rank.__getitem__,
    )
    documentation = _read_json_object(run_root / "documentation-impact.json")
    documentation_bound = (
        documentation.get("head_sha") == current_head
        and documentation.get("working_tree_diff_sha256") == current_worktree_diff
    )
    if documentation.get("status") == "updated" and documentation_bound:
        files = documentation.get("files")
        if not isinstance(files, list) or not files or any(
            not isinstance(path, str) or not path for path in files
        ):
            reasons.append("documentation-impact")
    elif documentation.get("status") == "none" and documentation_bound:
        if not isinstance(documentation.get("rationale"), str) or not str(
            documentation.get("rationale")
        ).strip():
            reasons.append("documentation-impact")
    else:
        reasons.append("documentation-impact")

    for reason, filename, kind in (
        ("independent-code-review", "code-review.json", "independent-code-review"),
        ("cross-review", "cross-review.json", "cross-provider-review"),
    ):
        review = _read_json_object(run_root / filename)
        if not _review_artifact_valid(
            root,
            review,
            kind=kind,
            current_head=current_head,
            trusted_base=trusted_base,
        ):
            reasons.append(reason)
    if level == "release":
        security = _read_json_object(run_root / "security-clearance.json")
        checks = _read_json_object(run_root / "security-checks.json")
        required_scanners = tuple(
            dict.fromkeys(
                trusted_config.security.required_scanners
                + config.security.required_scanners
            )
        )
        scanner_commands = {
            scanner: (
                trusted_config.security.scanner_commands.get(scanner, ())
                or config.security.scanner_commands.get(scanner, ())
            )
            for scanner in set(required_scanners) | set(config.security.scanner_commands)
        }
        scanner_version_commands = {
            scanner: (
                trusted_config.security.scanner_version_commands.get(scanner, ())
                or config.security.scanner_version_commands.get(scanner, ())
            )
            for scanner in set(required_scanners) | set(config.security.scanner_commands)
        }
        scanner_support_paths = {
            scanner: (
                trusted_config.security.scanner_support_paths.get(scanner, ())
                or config.security.scanner_support_paths.get(scanner, ())
            )
            for scanner in set(required_scanners) | set(config.security.scanner_commands)
        }
        scanner_statuses = _scanner_evidence(
            root,
            checks,
            current_head=current_head,
            current_worktree_diff=current_worktree_diff,
            required_scanners=required_scanners,
            scanner_commands=scanner_commands,
            scanner_version_commands=scanner_version_commands,
            scanner_support_paths=scanner_support_paths,
        )
        required_artifacts = security.get("required_artifacts", [])
        threat_required = (
            isinstance(required_artifacts, list)
            and "threat_model_delta" in required_artifacts
        )
        release = release_check(
            ReleaseContext(
                merge_status="passed" if not reasons else "blocked",
                security_status=(
                    "passed"
                    if _security_artifact_valid(
                        root,
                        security,
                        current_head=current_head,
                        approved_profile=approved_profile,
                        trusted_base=trusted_base,
                    )
                    else "missing-or-stale"
                ),
                threat_model_delta_required=threat_required,
                threat_model_delta_present=_bound_artifact_valid(
                    root,
                    _read_json_object(run_root / "threat-model-delta.json"),
                    current_head=current_head,
                    current_worktree_diff=current_worktree_diff,
                    require_source=True,
                ),
                scanner_statuses=scanner_statuses,
                required_scanners=required_scanners,
                clean_checkout_smoke=_bound_artifact_valid(
                    root,
                    _read_json_object(run_root / "clean-checkout-smoke.json"),
                    current_head=current_head,
                    current_worktree_diff=current_worktree_diff,
                ),
                documentation_current=documentation_bound,
                release_notes=_bound_artifact_valid(
                    root,
                    _read_json_object(run_root / "release-notes.json"),
                    current_head=current_head,
                    current_worktree_diff=current_worktree_diff,
                    require_source=True,
                ),
                migration_backup_rollback=_bound_artifact_valid(
                    root,
                    _read_json_object(run_root / "migration-rollback.json"),
                    current_head=current_head,
                    current_worktree_diff=current_worktree_diff,
                    require_source=True,
                ),
                residual_risks=_bound_artifact_valid(
                    root,
                    _read_json_object(run_root / "residual-risks.json"),
                    current_head=current_head,
                    current_worktree_diff=current_worktree_diff,
                    require_source=True,
                ),
            )
        )
        reasons.extend(reason for reason in release.reasons if reason not in reasons)
    return reasons


def run_gate(
    level: str,
    config: ProjectConfig,
    root: str | Path,
    *,
    timeout: float = 60.0,
) -> GateResult:
    repository = Path(root).resolve()
    if level not in {"quick", "review", "merge", "release"}:
        raise ValueError(f"unknown gate level: {level}")

    required = {
        "quick": QUICK_COMMANDS,
        "review": MERGE_COMMANDS,
        "merge": MERGE_COMMANDS,
        "release": RELEASE_COMMANDS,
    }[level]
    configured = tuple(name for name in required if config.commands.get(name))
    if level == "quick" and not configured:
        return GateResult(
            level=level,
            status="incomplete",
            reasons=("no quick commands configured",),
            executed=(),
        )

    missing = tuple(name for name in required if not config.commands.get(name))
    if level != "quick" and missing:
        return GateResult(level=level, status="blocked", reasons=missing, executed=())

    commit, diff_hash = git_identity(repository)
    store = EvidenceStore(repository / ".agent/.runs/evidence")
    executed: list[str] = []
    failed: list[str] = []
    incomplete: list[str] = []
    for command_id in configured:
        argv = config.commands[command_id]
        started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        result = run_command(argv, cwd=repository, timeout=timeout)
        record = record_result(
            command_id=command_id.replace("_", "."),
            commit=commit,
            diff_sha256=diff_hash,
            result=result,
            started_at=started_at,
            tool_version=tool_identity(argv, repository),
        )
        store.write(record)
        executed.append(command_id)
        if result.timed_out:
            incomplete.append(command_id)
        elif result.exit_code != 0:
            failed.append(command_id)

    if incomplete:
        return GateResult(level, "incomplete", tuple(incomplete), tuple(executed))
    artifact_reasons = _artifact_reasons(level, repository, config)
    if failed or artifact_reasons:
        return GateResult(
            level,
            "blocked",
            tuple(failed + artifact_reasons),
            tuple(executed),
        )
    return GateResult(level, "passed", (), tuple(executed))


def read_workflow_state(root: str | Path) -> WorkflowState:
    path = Path(root) / ".agent/.runs/workflow-state.json"
    if not path.is_file():
        return WorkflowState.DISCOVERED
    data = json.loads(path.read_text(encoding="utf-8"))
    return WorkflowState(data["state"])
